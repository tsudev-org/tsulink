//! Phiên ghép đôi (`LOCAL_SYNC.md` mục 3, ADR-0003): mỗi cặp thiết bị một lần, mỗi app.
//!
//! - **Mã QR**: máy A mở [`PairingHost`], hiện [`PairingOffer`] (vân tay A + địa chỉ + mã `t` 128 bit, hạn 120 giây).
//!   Máy B quét, gọi [`join_qr`]: mTLS ghim vân tay A, gửi `t`. A kiểm `t` (một lần, còn hạn, so thời gian hằng) rồi
//!   lưu vân tay B; B lưu vân tay A.
//! - **So mã số** (không camera): B gọi [`join_sas`] tới A ([`PairingHost::accept_sas`]); A gửi **cam kết**
//!   SHA-256(nonce A) trước, B gửi nonce B, A mở nonce A, B kiểm cam kết ⇒ hai máy hiện cùng mã [`crate::sas::code`].
//!   Cam kết trước chặn kẻ đứng giữa thử nonce cho trùng mã. Người dùng xác nhận trên CẢ HAI máy
//!   ([`SasSession::finish`]); một bên từ chối ⇒ không ai lưu.
//! - Sai mã `t` hoặc so mã lệch: tối đa [`MAX_FAILURES`] lần trong 10 phút ⇒ khoá 10 phút ([`AttemptLimiter`]).
//!
//! Kết nối ghép đôi dùng ALPN riêng `tsulink-pair/1`, chỉ địa chỉ mạng nội bộ (L1), không bao giờ mang dữ liệu.

use crate::devices::{DeviceStore, PairedDevice};
use crate::identity::{DeviceIdentity, fingerprint_of};
use crate::pairing::PairingOffer;
use crate::tls::{ALPN_PAIR, pairing_client_config, pairing_server_config};
use crate::transport::{HANDSHAKE_TIMEOUT, check_addr};
use crate::{Error, frame};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use rustls::pki_types::ServerName;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::net::{IpAddr, SocketAddr};
use std::time::Duration;
use tokio::net::{TcpListener, TcpStream};
use tokio::time::{Instant, timeout, timeout_at};
use tokio_rustls::{TlsAcceptor, TlsConnector, TlsStream};

/// Số lần sai tối đa trong [`FAILURE_WINDOW_SECS`].
pub const MAX_FAILURES: usize = 5;
/// Cửa sổ đếm lần sai (10 phút).
pub const FAILURE_WINDOW_SECS: u64 = 600;
/// Thời gian khoá sau khi vượt [`MAX_FAILURES`] (10 phút).
pub const LOCK_SECS: u64 = 600;
/// Thời hạn đọc một tin trong phiên ghép đôi.
const MSG_TIMEOUT: Duration = Duration::from_secs(30);
/// Người dùng có tối đa 2 phút để so mã số.
const CONFIRM_TIMEOUT: Duration = Duration::from_secs(120);

/// Đếm lần ghép đôi sai: 5 lần/10 phút ⇒ khoá 10 phút. App giữ một đối tượng cho màn ghép đôi.
#[derive(Debug, Default, Clone)]
pub struct AttemptLimiter {
    failures: Vec<u64>,
    locked_until: u64,
}

impl AttemptLimiter {
    /// `Err(Locked)` nếu đang khoá tại `now`.
    pub fn check(&self, now: u64) -> Result<(), Error> {
        if now < self.locked_until {
            Err(Error::Locked(self.locked_until))
        } else {
            Ok(())
        }
    }

    /// Ghi một lần sai.
    pub fn failure(&mut self, now: u64) {
        self.failures
            .retain(|t| now.saturating_sub(*t) < FAILURE_WINDOW_SECS);
        self.failures.push(now);
        if self.failures.len() >= MAX_FAILURES {
            self.locked_until = now + LOCK_SECS;
            self.failures.clear();
        }
    }

    /// Ghép đôi thành công ⇒ xoá bộ đếm.
    pub fn success(&mut self) {
        self.failures.clear();
    }
}

#[derive(Serialize, Deserialize)]
struct Hello {
    alias: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    t: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    nonce: Option<String>,
}

#[derive(Serialize, Deserialize)]
struct Reply {
    ok: bool,
    #[serde(default)]
    alias: String,
}

#[derive(Serialize, Deserialize)]
struct Commit {
    commit: String,
}

#[derive(Serialize, Deserialize)]
struct Reveal {
    nonce: String,
    alias: String,
}

#[derive(Serialize, Deserialize)]
struct Confirm {
    confirm: bool,
}

fn clean_alias(a: &str) -> String {
    a.chars().filter(|c| !c.is_control()).take(64).collect()
}

fn commit_of(nonce: &[u8; 16]) -> String {
    Sha256::new()
        .chain_update(b"tsulink-sas-commit|")
        .chain_update(nonce)
        .finalize()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

fn rand16() -> Result<[u8; 16], Error> {
    let mut n = [0u8; 16];
    getrandom::fill(&mut n).map_err(|_| Error::Rng)?;
    Ok(n)
}

fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len()
        && std::hint::black_box(a.iter().zip(b).fold(0u8, |x, (p, q)| x | (p ^ q))) == 0
}

fn decode16(s: &str) -> Result<[u8; 16], Error> {
    URL_SAFE_NO_PAD
        .decode(s)
        .ok()
        .and_then(|v| v.try_into().ok())
        .ok_or(Error::Protocol("nonce"))
}

fn peer_fp(stream: &TlsStream<TcpStream>) -> Result<String, Error> {
    let certs = match stream {
        TlsStream::Client(s) => s.get_ref().1.peer_certificates(),
        TlsStream::Server(s) => s.get_ref().1.peer_certificates(),
    };
    certs
        .and_then(|c| c.first())
        .map(|c| fingerprint_of(c))
        .ok_or(Error::Protocol("thiếu chứng thư"))
}

fn alpn_ok(stream: &TlsStream<TcpStream>) -> bool {
    let p = match stream {
        TlsStream::Client(s) => s.get_ref().1.alpn_protocol(),
        TlsStream::Server(s) => s.get_ref().1.alpn_protocol(),
    };
    p == Some(ALPN_PAIR)
}

async fn read_msg<T: serde::de::DeserializeOwned>(
    s: &mut TlsStream<TcpStream>,
    t: Duration,
) -> Result<T, Error> {
    timeout(t, frame::read(s))
        .await
        .map_err(|_| Error::Timeout)?
}

/// Cổng của thiết bị chủ trong phiên ghép đôi (máy hiện QR hoặc máy được gọi để so mã số).
pub struct PairingHost {
    tcp: TcpListener,
    acceptor: TlsAcceptor,
    fingerprint: String,
    allow_loopback: bool,
}

impl std::fmt::Debug for PairingHost {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PairingHost")
            .field("addr", &self.tcp.local_addr().ok())
            .finish_non_exhaustive()
    }
}

impl PairingHost {
    /// Mở cổng ghép đôi (thường `0.0.0.0:0`); địa chỉ công cộng bị từ chối (L1).
    pub async fn bind(identity: &DeviceIdentity, bind: SocketAddr) -> Result<Self, Error> {
        Self::bind_inner(identity, bind, false).await
    }

    pub(crate) async fn bind_inner(
        identity: &DeviceIdentity,
        bind: SocketAddr,
        allow_loopback: bool,
    ) -> Result<Self, Error> {
        if !bind.ip().is_unspecified() {
            check_addr(bind, allow_loopback)?;
        }
        Ok(Self {
            tcp: TcpListener::bind(bind)
                .await
                .map_err(|e| Error::Io(e.kind()))?,
            acceptor: TlsAcceptor::from(pairing_server_config(identity)?),
            fingerprint: identity.fingerprint().to_owned(),
            allow_loopback,
        })
    }

    /// Cổng đang nghe.
    pub fn local_addr(&self) -> Result<SocketAddr, Error> {
        self.tcp.local_addr().map_err(|e| Error::Io(e.kind()))
    }

    /// Tạo lời mời QR cho các IP mạng nội bộ của máy này (cổng = cổng đang nghe).
    pub fn qr_offer(&self, app: &str, ips: &[IpAddr], now: u64) -> Result<PairingOffer, Error> {
        let port = self.local_addr()?.port();
        PairingOffer::new(
            app,
            &self.fingerprint,
            ips.iter().map(|ip| SocketAddr::new(*ip, port)).collect(),
            now,
        )
    }

    async fn next_tls(&mut self, deadline: Instant) -> Result<TlsStream<TcpStream>, Error> {
        loop {
            let (tcp, addr) = match timeout_at(deadline, self.tcp.accept()).await {
                Err(_) => return Err(Error::Expired),
                Ok(r) => r.map_err(|e| Error::Io(e.kind()))?,
            };
            if check_addr(addr, self.allow_loopback).is_err() {
                continue;
            }
            let Ok(Ok(tls)) = timeout(HANDSHAKE_TIMEOUT, self.acceptor.accept(tcp)).await else {
                continue;
            };
            let tls = TlsStream::Server(tls);
            if alpn_ok(&tls) {
                return Ok(tls);
            }
        }
    }

    /// Chờ máy quét QR tới tới khi `offer` hết hạn. Mã `t` dùng một lần (hàm nhận `offer` theo giá trị).
    /// Mã sai ⇒ đếm vào `limiter`, chờ tiếp; đủ 5 lần ⇒ [`Error::Locked`].
    pub async fn accept_qr(
        &mut self,
        offer: PairingOffer,
        my_alias: &str,
        store: &dyn DeviceStore,
        limiter: &mut AttemptLimiter,
        clock: impl Fn() -> u64,
    ) -> Result<PairedDevice, Error> {
        let now = clock();
        limiter.check(now)?;
        if offer.expires_at <= now {
            return Err(Error::Expired);
        }
        let deadline = Instant::now() + Duration::from_secs(offer.expires_at - now);
        loop {
            let mut s = self.next_tls(deadline).await?;
            let Ok(fp) = peer_fp(&s) else { continue };
            let Ok(hello) = read_msg::<Hello>(&mut s, MSG_TIMEOUT).await else {
                continue;
            };
            let now = clock();
            limiter.check(now)?;
            let good = now < offer.expires_at
                && hello
                    .t
                    .as_deref()
                    .and_then(|t| URL_SAFE_NO_PAD.decode(t).ok())
                    .is_some_and(|t| ct_eq(&t, &offer.token));
            if !good || fp == self.fingerprint {
                limiter.failure(now);
                let _ = frame::write(
                    &mut s,
                    &Reply {
                        ok: false,
                        alias: String::new(),
                    },
                )
                .await;
                limiter.check(now)?;
                continue;
            }
            limiter.success();
            let dev = PairedDevice {
                fingerprint: fp,
                alias: clean_alias(&hello.alias),
                paired_at: now,
                last_sync_at: now,
            };
            store.upsert(dev.clone())?;
            frame::write(
                &mut s,
                &Reply {
                    ok: true,
                    alias: clean_alias(my_alias),
                },
            )
            .await?;
            return Ok(dev);
        }
    }

    /// Chờ một máy gọi để so mã số (tới `wait`). Trả phiên đã có mã 6 chữ số để hiện.
    pub async fn accept_sas(
        &mut self,
        my_alias: &str,
        wait: Duration,
    ) -> Result<SasSession, Error> {
        let deadline = Instant::now() + wait;
        loop {
            let mut s = self.next_tls(deadline).await?;
            let Ok(fp) = peer_fp(&s) else { continue };
            if fp == self.fingerprint {
                continue;
            }
            let nonce = rand16()?;
            if frame::write(
                &mut s,
                &Commit {
                    commit: commit_of(&nonce),
                },
            )
            .await
            .is_err()
            {
                continue;
            }
            let Ok(hello) = read_msg::<Hello>(&mut s, MSG_TIMEOUT).await else {
                continue;
            };
            let Some(Ok(peer_nonce)) = hello.nonce.as_deref().map(decode16) else {
                continue;
            };
            frame::write(
                &mut s,
                &Reveal {
                    nonce: URL_SAFE_NO_PAD.encode(nonce),
                    alias: clean_alias(my_alias),
                },
            )
            .await?;
            let code = crate::sas::code(&self.fingerprint, &nonce, &fp, &peer_nonce)?;
            return Ok(SasSession {
                stream: s,
                peer_fingerprint: fp,
                peer_alias: clean_alias(&hello.alias),
                code,
            });
        }
    }
}

async fn dial(
    identity: &DeviceIdentity,
    expected: Option<&str>,
    addr: SocketAddr,
    allow_loopback: bool,
) -> Result<TlsStream<TcpStream>, Error> {
    check_addr(addr, allow_loopback)?;
    let connector = TlsConnector::from(pairing_client_config(identity, expected)?);
    let tls = timeout(HANDSHAKE_TIMEOUT, async {
        let tcp = TcpStream::connect(addr)
            .await
            .map_err(|e| Error::Io(e.kind()))?;
        connector
            .connect(ServerName::IpAddress(addr.ip().into()), tcp)
            .await
            .map_err(|e| Error::Tls(e.to_string()))
    })
    .await
    .map_err(|_| Error::Timeout)??;
    let tls = TlsStream::Client(tls);
    if !alpn_ok(&tls) {
        return Err(Error::Protocol("ALPN"));
    }
    Ok(tls)
}

/// Máy quét QR: ghép đôi với máy hiện QR. `uri` là chuỗi quét được.
pub async fn join_qr(
    identity: &DeviceIdentity,
    uri: &str,
    my_alias: &str,
    store: &dyn DeviceStore,
    now: u64,
) -> Result<PairedDevice, Error> {
    let offer = PairingOffer::parse(uri, now)?;
    join_offer(identity, &offer, my_alias, store, now, false).await
}

pub(crate) async fn join_offer(
    identity: &DeviceIdentity,
    offer: &PairingOffer,
    my_alias: &str,
    store: &dyn DeviceStore,
    now: u64,
    allow_loopback: bool,
) -> Result<PairedDevice, Error> {
    let mut last = Error::Malformed("a");
    for addr in &offer.addrs {
        let mut s = match dial(identity, Some(&offer.fingerprint), *addr, allow_loopback).await {
            Ok(s) => s,
            Err(e) => {
                last = e;
                continue;
            }
        };
        frame::write(
            &mut s,
            &Hello {
                alias: clean_alias(my_alias),
                t: Some(URL_SAFE_NO_PAD.encode(offer.token)),
                nonce: None,
            },
        )
        .await?;
        let reply: Reply = read_msg(&mut s, MSG_TIMEOUT).await?;
        if !reply.ok {
            return Err(Error::PairingRejected);
        }
        let dev = PairedDevice {
            fingerprint: offer.fingerprint.clone(),
            alias: clean_alias(&reply.alias),
            paired_at: now,
            last_sync_at: now,
        };
        store.upsert(dev.clone())?;
        return Ok(dev);
    }
    Err(last)
}

/// Máy gọi để so mã số (thấy máy kia qua khám phá, `paired == false`).
pub async fn join_sas(
    identity: &DeviceIdentity,
    addr: SocketAddr,
    my_alias: &str,
) -> Result<SasSession, Error> {
    join_sas_inner(identity, addr, my_alias, false).await
}

pub(crate) async fn join_sas_inner(
    identity: &DeviceIdentity,
    addr: SocketAddr,
    my_alias: &str,
    allow_loopback: bool,
) -> Result<SasSession, Error> {
    let mut s = dial(identity, None, addr, allow_loopback).await?;
    let fp = peer_fp(&s)?;
    if fp == identity.fingerprint() {
        return Err(Error::Protocol("tự ghép đôi"));
    }
    let commit: Commit = read_msg(&mut s, MSG_TIMEOUT).await?;
    let nonce = rand16()?;
    frame::write(
        &mut s,
        &Hello {
            alias: clean_alias(my_alias),
            t: None,
            nonce: Some(URL_SAFE_NO_PAD.encode(nonce)),
        },
    )
    .await?;
    let reveal: Reveal = read_msg(&mut s, MSG_TIMEOUT).await?;
    let peer_nonce = decode16(&reveal.nonce)?;
    if !ct_eq(commit_of(&peer_nonce).as_bytes(), commit.commit.as_bytes()) {
        return Err(Error::Protocol("cam kết nonce sai"));
    }
    let code = crate::sas::code(identity.fingerprint(), &nonce, &fp, &peer_nonce)?;
    Ok(SasSession {
        stream: s,
        peer_fingerprint: fp,
        peer_alias: clean_alias(&reveal.alias),
        code,
    })
}

/// Phiên so mã số đang chờ người dùng xác nhận.
pub struct SasSession {
    stream: TlsStream<TcpStream>,
    peer_fingerprint: String,
    peer_alias: String,
    code: String,
}

impl std::fmt::Debug for SasSession {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SasSession")
            .field("peer", &self.peer_fingerprint)
            .finish_non_exhaustive()
    }
}

impl SasSession {
    /// Mã 6 chữ số để hiện trên màn (hai máy phải trùng).
    pub fn code(&self) -> &str {
        &self.code
    }

    /// Tên bên kia tự khai.
    pub fn peer_alias(&self) -> &str {
        &self.peer_alias
    }

    /// Vân tay bên kia.
    pub fn peer_fingerprint(&self) -> &str {
        &self.peer_fingerprint
    }

    /// Gửi lựa chọn của người dùng (trùng mã ⇒ `true`), chờ bên kia. Chỉ khi CẢ HAI xác nhận mới lưu thiết bị.
    /// Lệch ⇒ đếm một lần sai vào `limiter` và trả [`Error::PairingRejected`].
    pub async fn finish(
        mut self,
        user_confirmed: bool,
        store: &dyn DeviceStore,
        limiter: &mut AttemptLimiter,
        now: u64,
    ) -> Result<PairedDevice, Error> {
        limiter.check(now)?;
        frame::write(
            &mut self.stream,
            &Confirm {
                confirm: user_confirmed,
            },
        )
        .await?;
        let peer: Result<Confirm, Error> = read_msg(&mut self.stream, CONFIRM_TIMEOUT).await;
        let both = user_confirmed && peer.as_ref().is_ok_and(|c| c.confirm);
        if !both {
            limiter.failure(now);
            return Err(Error::PairingRejected);
        }
        limiter.success();
        let dev = PairedDevice {
            fingerprint: self.peer_fingerprint,
            alias: self.peer_alias,
            paired_at: now,
            last_sync_at: now,
        };
        store.upsert(dev.clone())?;
        Ok(dev)
    }
}

#[cfg(test)]
mod tests;
