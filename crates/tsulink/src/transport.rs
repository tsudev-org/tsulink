//! Kết nối mTLS giữa hai thiết bị (`LOCAL_SYNC.md` mục 2, luật L1/L3/L4).
//!
//! - [`connect`]: gọi một thiết bị đã ghép đôi ở địa chỉ mạng nội bộ, ghim đúng vân tay của nó.
//! - [`Listener`]: cổng nghe chỉ mở khi màn "Đồng bộ thiết bị" đang mở (L4) - app giữ `Listener` khi màn mở và huỷ
//!   (drop) khi rời màn; [`Listener::accept`] trả [`Error::IdleTimeout`] sau [`IDLE_TIMEOUT`] không có kết nối mới.
//!   Kết nối từ địa chỉ không thuộc mạng nội bộ, bắt tay hỏng hoặc máy chưa ghép đôi bị đóng im lặng.

use crate::Error;
use crate::addr::is_local_network;
use crate::identity::{DeviceIdentity, fingerprint_of};
use crate::tls::{ALPN, PeerPins, client_config, server_config};
use rustls::pki_types::ServerName;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::net::{TcpListener, TcpStream};
use tokio::time::{Instant, timeout, timeout_at};
use tokio_rustls::{TlsAcceptor, TlsConnector, TlsStream};

/// Thời hạn bắt tay TCP + TLS.
pub const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);

/// Cổng nghe tự đóng sau 10 phút không có kết nối mới (L4).
pub const IDLE_TIMEOUT: Duration = Duration::from_secs(600);

/// Một kết nối mTLS đã xác thực.
#[derive(Debug)]
pub struct PeerConnection {
    /// Luồng TLS 1.3 (đọc/ghi qua `tokio::io`).
    pub stream: TlsStream<TcpStream>,
    /// Vân tay của thiết bị bên kia (đã khớp ghim).
    pub fingerprint: String,
    /// Địa chỉ của thiết bị bên kia.
    pub addr: SocketAddr,
}

fn io_err(e: std::io::Error) -> Error {
    Error::Io(e.kind())
}

pub(crate) fn check_addr(addr: SocketAddr, allow_loopback: bool) -> Result<(), Error> {
    if is_local_network(addr.ip()) || (allow_loopback && addr.ip().is_loopback()) {
        Ok(())
    } else {
        Err(Error::PublicAddress(addr.to_string()))
    }
}

/// Gọi thiết bị đã ghép đôi có vân tay `peer_fp` ở `addr` (phải thuộc mạng nội bộ).
///
/// Máy chủ kiểm ghim chứng thư của ta SAU khi bắt tay phía ta xong (TLS 1.3): nếu ta chưa được ghép đôi bên kia,
/// lần đọc đầu tiên trên luồng sẽ báo lỗi.
pub async fn connect(
    identity: &DeviceIdentity,
    peer_fp: &str,
    addr: SocketAddr,
) -> Result<PeerConnection, Error> {
    connect_inner(identity, peer_fp, addr, false).await
}

pub(crate) async fn connect_inner(
    identity: &DeviceIdentity,
    peer_fp: &str,
    addr: SocketAddr,
    allow_loopback: bool,
) -> Result<PeerConnection, Error> {
    check_addr(addr, allow_loopback)?;
    let connector = TlsConnector::from(client_config(identity, peer_fp)?);
    let fut = async {
        let tcp = TcpStream::connect(addr).await.map_err(io_err)?;
        tcp.set_nodelay(true).map_err(io_err)?;
        connector
            .connect(ServerName::IpAddress(addr.ip().into()), tcp)
            .await
            .map_err(|e| Error::Tls(e.to_string()))
    };
    let tls = timeout(HANDSHAKE_TIMEOUT, fut)
        .await
        .map_err(|_| Error::Timeout)??;
    if tls.get_ref().1.alpn_protocol() != Some(ALPN) {
        return Err(Error::Protocol("ALPN"));
    }
    Ok(PeerConnection {
        stream: TlsStream::Client(tls),
        fingerprint: peer_fp.to_owned(),
        addr,
    })
}

/// Cổng nghe mTLS của màn "Đồng bộ thiết bị".
pub struct Listener {
    tcp: TcpListener,
    acceptor: TlsAcceptor,
    deadline: Instant,
    allow_loopback: bool,
}

impl std::fmt::Debug for Listener {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Listener")
            .field("addr", &self.tcp.local_addr().ok())
            .finish_non_exhaustive()
    }
}

impl Listener {
    /// Mở cổng nghe. `bind` thường là `0.0.0.0:0` (hệ điều hành chọn cổng, khai cổng đó trong mã QR/khám phá) hoặc
    /// một địa chỉ mạng nội bộ cụ thể; địa chỉ công cộng bị từ chối (L1).
    pub async fn bind(
        identity: &DeviceIdentity,
        pins: Arc<dyn PeerPins>,
        bind: SocketAddr,
    ) -> Result<Self, Error> {
        Self::bind_inner(identity, pins, bind, false).await
    }

    pub(crate) async fn bind_inner(
        identity: &DeviceIdentity,
        pins: Arc<dyn PeerPins>,
        bind: SocketAddr,
        allow_loopback: bool,
    ) -> Result<Self, Error> {
        if !bind.ip().is_unspecified() {
            check_addr(bind, allow_loopback)?;
        }
        let tcp = TcpListener::bind(bind).await.map_err(io_err)?;
        Ok(Self {
            tcp,
            acceptor: TlsAcceptor::from(server_config(identity, pins)?),
            deadline: Instant::now() + IDLE_TIMEOUT,
            allow_loopback,
        })
    }

    /// Địa chỉ thật đang nghe (để lấy cổng).
    pub fn local_addr(&self) -> Result<SocketAddr, Error> {
        self.tcp.local_addr().map_err(io_err)
    }

    /// Chờ kết nối hợp lệ kế tiếp từ một thiết bị đã ghép đôi. Hết [`IDLE_TIMEOUT`] kể từ lần mở cổng/kết nối hợp lệ
    /// gần nhất ⇒ [`Error::IdleTimeout`]; app phải huỷ `Listener` (đóng cổng).
    pub async fn accept(&mut self) -> Result<PeerConnection, Error> {
        loop {
            let (tcp, addr) = match timeout_at(self.deadline, self.tcp.accept()).await {
                Err(_) => return Err(Error::IdleTimeout),
                Ok(r) => r.map_err(io_err)?,
            };
            if check_addr(addr, self.allow_loopback).is_err() {
                continue; // L1: đóng im lặng.
            }
            let Ok(Ok(tls)) = timeout(HANDSHAKE_TIMEOUT, self.acceptor.accept(tcp)).await else {
                continue; // Bắt tay hỏng hoặc máy chưa ghép đôi (L2).
            };
            let conn = tls.get_ref().1;
            if conn.alpn_protocol() != Some(ALPN) {
                continue;
            }
            let Some(fingerprint) = conn
                .peer_certificates()
                .and_then(|c| c.first())
                .map(|c| fingerprint_of(c))
            else {
                continue;
            };
            self.deadline = Instant::now() + IDLE_TIMEOUT;
            return Ok(PeerConnection {
                stream: TlsStream::Server(tls),
                fingerprint,
                addr,
            });
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tls::PinSet;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    const LO: &str = "127.0.0.1:0";

    async fn server(id: &DeviceIdentity, pins: Vec<String>) -> (Listener, SocketAddr) {
        let l = Listener::bind_inner(id, Arc::new(PinSet::new(pins)), LO.parse().unwrap(), true)
            .await
            .unwrap();
        let a = l.local_addr().unwrap();
        (l, a)
    }

    #[tokio::test]
    async fn hai_may_da_ghep_doi_noi_duoc_va_trao_du_lieu() {
        let a = DeviceIdentity::generate().unwrap();
        let b = DeviceIdentity::generate().unwrap();
        let (mut l, addr) = server(&a, vec![b.fingerprint().into()]).await;
        let srv = tokio::spawn(async move {
            let mut c = l.accept().await.unwrap();
            let mut buf = [0u8; 4];
            c.stream.read_exact(&mut buf).await.unwrap();
            c.stream.write_all(b"pong").await.unwrap();
            c.stream.flush().await.unwrap();
            (c.fingerprint, buf)
        });
        let mut c = connect_inner(&b, a.fingerprint(), addr, true)
            .await
            .unwrap();
        c.stream.write_all(b"ping").await.unwrap();
        let mut buf = [0u8; 4];
        c.stream.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"pong");
        let (fp, got) = srv.await.unwrap();
        assert_eq!(fp, b.fingerprint());
        assert_eq!(&got, b"ping");
        if let TlsStream::Client(s) = &c.stream {
            assert_eq!(
                s.get_ref().1.protocol_version(),
                Some(rustls::ProtocolVersion::TLSv1_3)
            );
        }
    }

    #[tokio::test]
    async fn van_tay_gia_mitm_bi_dong_ket_noi() {
        let that = DeviceIdentity::generate().unwrap();
        let mitm = DeviceIdentity::generate().unwrap();
        let b = DeviceIdentity::generate().unwrap();
        let (mut l, addr) = server(&mitm, vec![b.fingerprint().into()]).await;
        tokio::spawn(async move {
            let _ = l.accept().await;
        });
        // b ghim vân tay của `that`, nhưng bên kia trình chứng thư `mitm`.
        let err = connect_inner(&b, that.fingerprint(), addr, true)
            .await
            .unwrap_err();
        assert!(matches!(err, Error::Tls(_)), "{err:?}");
    }

    #[tokio::test]
    async fn may_chua_ghep_doi_bi_bo_qua() {
        let a = DeviceIdentity::generate().unwrap();
        let la = DeviceIdentity::generate().unwrap();
        let (mut l, addr) = server(&a, vec![]).await;
        let srv =
            tokio::spawn(async move { timeout(Duration::from_secs(2), l.accept()).await.is_err() });
        let mut c = connect_inner(&la, a.fingerprint(), addr, true)
            .await
            .unwrap();
        let mut buf = [0u8; 1];
        // Máy chủ từ chối chứng thư ⇒ lần đọc đầu lỗi hoặc EOF.
        let r = c.stream.read(&mut buf).await;
        assert!(matches!(r, Err(_) | Ok(0)), "{r:?}");
        assert!(
            srv.await.unwrap(),
            "accept không được trả kết nối chưa ghép đôi"
        );
    }

    #[tokio::test]
    async fn khong_co_duong_http_thuan() {
        let a = DeviceIdentity::generate().unwrap();
        let (mut l, addr) = server(&a, vec![]).await;
        let srv =
            tokio::spawn(async move { timeout(Duration::from_secs(2), l.accept()).await.is_err() });
        let mut tcp = TcpStream::connect(addr).await.unwrap();
        tcp.write_all(b"GET / HTTP/1.1\r\nHost: x\r\n\r\n")
            .await
            .unwrap();
        let mut buf = Vec::new();
        let _ = tcp.read_to_end(&mut buf).await;
        assert!(!buf.starts_with(b"HTTP/"), "không được trả lời HTTP");
        assert!(srv.await.unwrap());
    }

    #[tokio::test]
    async fn dia_chi_cong_cong_bi_tu_choi() {
        let a = DeviceIdentity::generate().unwrap();
        let err = connect(&a, a.fingerprint(), "8.8.8.8:443".parse().unwrap())
            .await
            .unwrap_err();
        assert_eq!(err, Error::PublicAddress("8.8.8.8:443".into()));
        // Bản công khai không nhận loopback.
        let err = connect(&a, a.fingerprint(), "127.0.0.1:9".parse().unwrap())
            .await
            .unwrap_err();
        assert!(matches!(err, Error::PublicAddress(_)));
        let err = Listener::bind(
            &a,
            Arc::new(PinSet::default()),
            "8.8.8.8:0".parse().unwrap(),
        )
        .await
        .unwrap_err();
        assert!(matches!(err, Error::PublicAddress(_)));
    }

    #[tokio::test(start_paused = true)]
    async fn cong_tu_dong_khi_khong_hoat_dong() {
        let a = DeviceIdentity::generate().unwrap();
        let (mut l, _) = server(&a, vec![]).await;
        assert_eq!(l.accept().await.unwrap_err(), Error::IdleTimeout);
    }
}
