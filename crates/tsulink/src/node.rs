//! Mặt tiền cho ràng buộc ngôn ngữ khác (ADR-0005): một [`Node`] = một thiết bị trong một app.
//!
//! Ràng buộc Flutter (`bindings/dart`, flutter_rust_bridge) và C ABI (`crates/tsulink-capi`, .NET) chỉ gọi module
//! này - không ràng buộc nào tự ghép các mảnh `session`/`transport`/`sync`, nên luật L1-L5 nằm ở MỘT chỗ.
//!
//! - **Dữ liệu** nằm trong `data_dir` do app chỉ: `rows.jsonl` + `rows-meta.json` ([`FileRowStore`]),
//!   `devices.json` ([`FileDeviceStore`]), `docs/<hex mã>.automerge`, `blobs/<BLAKE3>` (kho tệp định danh theo nội
//!   dung - tệp nhận về cũng vào đây). Khoá riêng của thiết bị KHÔNG nằm ở đây: app giữ trong kho bí mật của hệ điều
//!   hành và truyền vào [`Node::open`].
//! - **Runtime**: một tokio đa luồng (2 luồng) dùng chung cho mọi `Node` ([`runtime`]); hàm `async` ở đây chạy được
//!   từ bất kỳ executor nào vì phần việc mạng được [`spawn`] lên runtime đó.
//! - **Huỷ**: các thao tác chờ lâu nhận [`CancelToken`]; huỷ ⇒ [`Error::Cancelled`], dữ liệu cục bộ không hỏng
//!   (ADR-0004 mục 8).

use crate::devices::{DeviceStore, PairedDevice, PinsFromStore};
use crate::discovery::{Announcement, DiscoveredPeer, Discovery};
use crate::identity::DeviceIdentity;
use crate::session::{AttemptLimiter, PairingHost, SasSession};
use crate::store::{FileDeviceStore, FileRowStore, write_atomic};
use crate::sync::automerge::AutoCommit;
use crate::sync::file::{Manifest, is_valid_hash};
use crate::sync::hlc::Hlc;
use crate::sync::table::{Replica, RowStore};
use crate::sync::{Role, SyncConfig, SyncData, SyncReport};
use crate::transport::{Listener, connect};
use crate::{Error, addr, pairing::PairingOffer};
use std::collections::BTreeMap;
use std::future::Future;
use std::net::{IpAddr, SocketAddr};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, OnceLock};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::runtime::Runtime;
use tokio::sync::{Mutex, Notify};

static RT: OnceLock<Option<Runtime>> = OnceLock::new();

/// Runtime tokio dùng chung của Tsu Link (tạo lần đầu gọi).
pub fn runtime() -> Result<&'static Runtime, Error> {
    RT.get_or_init(|| {
        tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .thread_name("tsulink")
            .enable_all()
            .build()
            .ok()
    })
    .as_ref()
    .ok_or(Error::Io(std::io::ErrorKind::Other))
}

/// Chạy `fut` trên [`runtime`] và chờ kết quả từ executor bất kỳ.
pub async fn spawn<T, F>(fut: F) -> Result<T, Error>
where
    T: Send + 'static,
    F: Future<Output = Result<T, Error>> + Send + 'static,
{
    runtime()?.spawn(fut).await.map_err(|_| Error::Cancelled)?
}

/// Chặn luồng hiện tại tới khi `fut` xong (cho C ABI; KHÔNG gọi từ trong runtime).
pub fn block_on<T, F>(fut: F) -> Result<T, Error>
where
    T: Send + 'static,
    F: Future<Output = Result<T, Error>> + Send + 'static,
{
    runtime()?.block_on(spawn(fut))
}

/// Giờ hệ thống: (giây Unix, mili giây Unix).
fn now() -> (u64, u64) {
    let ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_millis() as u64);
    (ms / 1000, ms)
}

/// Thẻ huỷ dùng chung giữa app và một thao tác đang chờ.
#[derive(Debug, Clone, Default)]
pub struct CancelToken(Arc<(AtomicBool, Notify)>);

impl CancelToken {
    /// Thẻ mới, chưa huỷ.
    pub fn new() -> Self {
        Self::default()
    }

    /// Huỷ mọi thao tác đang chờ trên thẻ này (và mọi thao tác sau đó).
    pub fn cancel(&self) {
        self.0.0.store(true, Ordering::SeqCst);
        self.0.1.notify_waiters();
    }

    /// Đã huỷ chưa.
    pub fn is_cancelled(&self) -> bool {
        self.0.0.load(Ordering::SeqCst)
    }

    async fn cancelled(&self) {
        loop {
            let n = self.0.1.notified();
            tokio::pin!(n);
            n.as_mut().enable();
            if self.is_cancelled() {
                return;
            }
            n.await;
        }
    }
}

async fn with_cancel<T>(
    cancel: Option<CancelToken>,
    fut: impl Future<Output = Result<T, Error>>,
) -> Result<T, Error> {
    match cancel {
        None => fut.await,
        Some(c) => tokio::select! {
            r = fut => r,
            () = c.cancelled() => Err(Error::Cancelled),
        },
    }
}

/// Tiến độ truyền tệp: `(BLAKE3, byte đã có, tổng byte)`; gọi trên luồng của runtime.
pub type ProgressFn = Box<dyn FnMut(&str, u64, u64) + Send>;

/// Cấu hình mở một [`Node`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NodeConfig {
    /// Thư mục dữ liệu riêng của Tsu Link trong app.
    pub data_dir: PathBuf,
    /// Mã app (như trong QR và lời rao), vd. `qulythuchi`.
    pub app: String,
    /// Tên thiết bị hiện cho máy kia.
    pub alias: String,
    /// Phiên bản lược đồ dữ liệu của app (luật L5).
    pub schema_version: u32,
}

/// Một phiên bản bản ghi trong nhật ký máy này (để app chép ra kho/giao diện của mình).
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct Change {
    /// Số thứ tự trong nhật ký máy này - app nhớ số lớn nhất đã chép.
    pub seq: u64,
    /// Bảng.
    pub table: String,
    /// Khoá.
    pub key: String,
    /// Nội dung JSON; `None` = đã xoá.
    pub value: Option<serde_json::Value>,
    /// Mốc HLC.
    pub hlc: Hlc,
}

/// Một thiết bị trong một app (xem tài liệu module).
#[derive(Debug)]
pub struct Node {
    cfg: NodeConfig,
    identity: DeviceIdentity,
    replica: Replica<FileRowStore>,
    devices: Arc<FileDeviceStore>,
    docs: Mutex<BTreeMap<String, AutoCommit>>,
    limiter: Mutex<AttemptLimiter>,
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn check_name(s: &str, what: &'static str) -> Result<(), Error> {
    if s.is_empty() || s.len() > 256 {
        Err(Error::InvalidInput(what))
    } else {
        Ok(())
    }
}

impl Node {
    /// Mở thiết bị với danh tính `cert_der` + `key_pkcs8_der` (tạo bằng [`DeviceIdentity::generate`] lần đầu, app
    /// lưu khoá trong kho bí mật của hệ điều hành).
    pub fn open(
        cfg: NodeConfig,
        cert_der: &[u8],
        key_pkcs8_der: &[u8],
    ) -> Result<Arc<Self>, Error> {
        check_name(&cfg.app, "app")?;
        if cfg.alias.trim().is_empty() {
            return Err(Error::InvalidInput("alias"));
        }
        let identity = DeviceIdentity::from_der(cert_der, key_pkcs8_der)?;
        let store = FileRowStore::open(&cfg.data_dir)?;
        let devices = Arc::new(FileDeviceStore::open(&cfg.data_dir)?);
        let docs_dir = cfg.data_dir.join("docs");
        std::fs::create_dir_all(&docs_dir).map_err(|e| Error::Io(e.kind()))?;
        std::fs::create_dir_all(cfg.data_dir.join("blobs")).map_err(|e| Error::Io(e.kind()))?;
        let mut docs = BTreeMap::new();
        for ent in std::fs::read_dir(&docs_dir).map_err(|e| Error::Io(e.kind()))? {
            let p = ent.map_err(|e| Error::Io(e.kind()))?.path();
            let (Some(stem), Some("automerge")) = (
                p.file_stem().and_then(|s| s.to_str()),
                p.extension().and_then(|s| s.to_str()),
            ) else {
                continue;
            };
            let Some(id) = unhex(stem) else { continue };
            let bytes = std::fs::read(&p).map_err(|e| Error::Io(e.kind()))?;
            let doc = AutoCommit::load(&bytes).map_err(|_| Error::Corrupt("tài liệu Automerge"))?;
            docs.insert(id, doc);
        }
        let replica = Replica::new(identity.fingerprint(), store);
        Ok(Arc::new(Self {
            cfg,
            identity,
            replica,
            devices,
            docs: Mutex::new(docs),
            limiter: Mutex::new(AttemptLimiter::default()),
        }))
    }

    /// Vân tay của máy này.
    pub fn fingerprint(&self) -> &str {
        self.identity.fingerprint()
    }

    /// Cấu hình đã mở.
    pub fn config(&self) -> &NodeConfig {
        &self.cfg
    }

    // ---- Bảng ----

    /// Ghi `value` vào `(table, key)`.
    pub fn write(&self, table: &str, key: &str, value: serde_json::Value) -> Result<Hlc, Error> {
        check_name(table, "table")?;
        check_name(key, "key")?;
        self.replica.write(table, key, value, now().1)
    }

    /// Xoá `(table, key)` (bia mộ).
    pub fn delete(&self, table: &str, key: &str) -> Result<Hlc, Error> {
        check_name(table, "table")?;
        check_name(key, "key")?;
        self.replica.delete(table, key, now().1)
    }

    /// Nội dung hiện tại.
    pub fn read(&self, table: &str, key: &str) -> Option<serde_json::Value> {
        self.replica.read(table, key)
    }

    /// Nhật ký máy này sau `after` (tối đa `limit`): mọi thay đổi, kể cả nhận từ máy khác.
    pub fn changes_after(&self, after: u64, limit: usize) -> Vec<Change> {
        self.replica
            .store()
            .changes_after(after, limit)
            .into_iter()
            .map(|(seq, r)| Change {
                seq,
                table: r.table,
                key: r.key,
                value: r.value,
                hlc: r.hlc,
            })
            .collect()
    }

    /// Xoá hẳn bia mộ quá 180 ngày.
    pub fn purge_tombstones(&self) -> Result<usize, Error> {
        self.replica.purge_tombstones(now().1)
    }

    // ---- Tài liệu Automerge ----

    /// Mã các tài liệu.
    pub async fn doc_ids(&self) -> Vec<String> {
        self.docs.lock().await.keys().cloned().collect()
    }

    /// Bản lưu Automerge của tài liệu `id`.
    pub async fn doc_save(&self, id: &str) -> Option<Vec<u8>> {
        self.docs.lock().await.get_mut(id).map(AutoCommit::save)
    }

    /// Gộp bản lưu/thay đổi Automerge `bytes` (do app sửa bằng thư viện Automerge của nó) vào tài liệu `id`.
    pub async fn doc_merge(&self, id: &str, bytes: &[u8]) -> Result<(), Error> {
        check_name(id, "doc id")?;
        let mut incoming =
            AutoCommit::load(bytes).map_err(|_| Error::InvalidInput("bản lưu Automerge"))?;
        let mut docs = self.docs.lock().await;
        let doc = docs.entry(id.to_owned()).or_insert_with(AutoCommit::new);
        doc.merge(&mut incoming)
            .map_err(|_| Error::InvalidInput("bản lưu Automerge"))?;
        let saved = doc.save();
        write_atomic(&self.doc_path(id), &saved)
    }

    fn doc_path(&self, id: &str) -> PathBuf {
        self.cfg
            .data_dir
            .join("docs")
            .join(format!("{}.automerge", hex(id.as_bytes())))
    }

    async fn save_docs(&self, docs: &mut BTreeMap<String, AutoCommit>) -> Result<(), Error> {
        for (id, d) in docs.iter_mut() {
            write_atomic(&self.doc_path(id), &d.save())?;
        }
        Ok(())
    }

    // ---- Tệp ----

    fn blob(&self, hash: &str) -> PathBuf {
        self.cfg.data_dir.join("blobs").join(hash)
    }

    /// Chép tệp `src` vào kho tệp; trả BLAKE3 (app lưu mã này trong bản ghi).
    pub async fn file_import(&self, src: &Path) -> Result<String, Error> {
        let m = Manifest::of_file(src).await?;
        let dest = self.blob(&m.hash);
        if tokio::fs::try_exists(&dest).await.unwrap_or(false) {
            return Ok(m.hash);
        }
        let tmp = dest.with_extension("import");
        tokio::fs::copy(src, &tmp)
            .await
            .map_err(|e| Error::Io(e.kind()))?;
        let check = Manifest::of_file(&tmp).await?;
        if check.hash != m.hash {
            let _ = tokio::fs::remove_file(&tmp).await;
            return Err(Error::Corrupt("tệp đổi trong lúc chép"));
        }
        tokio::fs::File::open(&tmp)
            .await
            .map_err(|e| Error::Io(e.kind()))?
            .sync_all()
            .await
            .map_err(|e| Error::Io(e.kind()))?;
        tokio::fs::rename(&tmp, &dest)
            .await
            .map_err(|e| Error::Io(e.kind()))?;
        Ok(m.hash)
    }

    /// Đường dẫn tệp có BLAKE3 `hash` nếu đã có đủ trong kho.
    pub fn file_path(&self, hash: &str) -> Option<PathBuf> {
        if !is_valid_hash(hash) {
            return None;
        }
        let p = self.blob(hash);
        p.is_file().then_some(p)
    }

    // ---- Thiết bị ----

    /// Thiết bị đã ghép đôi.
    pub fn devices(&self) -> Vec<PairedDevice> {
        self.devices.list()
    }

    /// Gỡ thiết bị (hết tin cậy ngay - mTLS đọc thẳng kho).
    pub fn remove_device(&self, fingerprint: &str) -> Result<bool, Error> {
        self.devices.remove(fingerprint)
    }

    /// Gỡ thiết bị không đồng bộ quá 180 ngày.
    pub fn prune_stale_devices(&self) -> Result<usize, Error> {
        self.devices.prune_stale(now().0)
    }

    // ---- Ghép đôi ----

    /// Mở cổng ghép đôi tạm trên `port` (0 = hệ điều hành chọn) mọi giao diện.
    pub async fn pairing_host(self: &Arc<Self>, port: u16) -> Result<PairingHostHandle, Error> {
        let me = self.clone();
        let host = spawn(async move {
            PairingHost::bind(
                &me.identity,
                SocketAddr::new(IpAddr::from([0u8, 0, 0, 0]), port),
            )
            .await
        })
        .await?;
        Ok(PairingHostHandle {
            node: self.clone(),
            host: Arc::new(Mutex::new(host)),
            offer: Arc::new(std::sync::Mutex::new(None)),
        })
    }

    /// Quét QR của máy kia và ghép đôi.
    pub async fn join_qr(
        self: &Arc<Self>,
        uri: String,
        cancel: Option<CancelToken>,
    ) -> Result<PairedDevice, Error> {
        let me = self.clone();
        spawn(with_cancel(cancel, async move {
            crate::session::join_qr(
                &me.identity,
                &uri,
                &me.cfg.alias,
                me.devices.as_ref(),
                now().0,
            )
            .await
        }))
        .await
    }

    /// Nối tới cổng ghép đôi `addr` để so mã số (khi không quét được QR).
    pub async fn join_sas(
        self: &Arc<Self>,
        addr: SocketAddr,
        cancel: Option<CancelToken>,
    ) -> Result<SasHandle, Error> {
        let me = self.clone();
        let s = spawn(with_cancel(cancel, async move {
            crate::session::join_sas(&me.identity, addr, &me.cfg.alias).await
        }))
        .await?;
        Ok(SasHandle::new(self.clone(), s))
    }

    // ---- Đồng bộ ----

    /// Đồng bộ (bên gọi) với thiết bị đã ghép đôi `peer` ở `addr`; xin thêm các tệp `wanted` (BLAKE3) còn thiếu.
    pub async fn sync_with(
        self: &Arc<Self>,
        peer: String,
        addr: SocketAddr,
        wanted: Vec<String>,
        progress: Option<ProgressFn>,
        cancel: Option<CancelToken>,
    ) -> Result<SyncReport, Error> {
        if !crate::is_valid_fingerprint(&peer) {
            return Err(Error::BadFingerprint);
        }
        if self.devices.get(&peer).is_none() {
            return Err(Error::PairingRejected);
        }
        let me = self.clone();
        spawn(with_cancel(cancel, async move {
            let mut conn = connect(&me.identity, &peer, addr).await?;
            me.run_session(&mut conn.stream, Role::Initiator, &peer, wanted, progress)
                .await
        }))
        .await
    }

    /// Mở cổng đồng bộ trên `port` (0 = hệ điều hành chọn). Cổng tự hết hạn sau 10 phút không có kết nối (L4).
    pub async fn listen(self: &Arc<Self>, port: u16) -> Result<SyncListener, Error> {
        let me = self.clone();
        let l = spawn(async move {
            Listener::bind(
                &me.identity,
                Arc::new(PinsFromStore(me.devices.clone())),
                SocketAddr::new(IpAddr::from([0u8, 0, 0, 0]), port),
            )
            .await
        })
        .await?;
        Ok(SyncListener {
            node: self.clone(),
            inner: Arc::new(Mutex::new(l)),
        })
    }

    async fn run_session<S>(
        &self,
        s: &mut S,
        role: Role,
        peer: &str,
        wanted: Vec<String>,
        progress: Option<ProgressFn>,
    ) -> Result<SyncReport, Error>
    where
        S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
    {
        let mut wanted_paths = Vec::new();
        for h in wanted {
            if !is_valid_hash(&h) {
                return Err(Error::InvalidInput("BLAKE3"));
            }
            if self.file_path(&h).is_none() {
                let p = self.blob(&h);
                wanted_paths.push((h, p));
            }
        }
        let blobs = self.cfg.data_dir.join("blobs");
        let provider = move |h: &str| {
            let p = blobs.join(h);
            (is_valid_hash(h) && p.is_file()).then_some(p)
        };
        let cfg = SyncConfig {
            app: self.cfg.app.clone(),
            schema_version: self.cfg.schema_version,
        };
        let mut progress = progress.unwrap_or_else(|| Box::new(|_: &str, _, _| {}));
        let mut docs = self.docs.lock().await;
        let rep = crate::sync::run(
            s,
            role,
            &cfg,
            peer,
            SyncData {
                replica: &self.replica,
                docs: &mut docs,
                files: &provider,
                wanted: wanted_paths,
            },
            now().1,
            &mut *progress,
        )
        .await;
        // Tài liệu đã gộp tới đâu thì lưu tới đó, kể cả khi phiên đứt giữa chừng.
        self.save_docs(&mut docs).await?;
        let rep = rep?;
        self.devices.touch(peer, now().0)?;
        Ok(rep)
    }

    // ---- Khám phá ----

    /// Bắt đầu khám phá thiết bị cùng app trên mạng nội bộ.
    pub fn discovery(self: &Arc<Self>) -> Result<DiscoveryHandle, Error> {
        let _g = runtime()?.enter();
        let d = Discovery::start(
            &self.cfg.app,
            self.fingerprint(),
            Arc::new(PinsFromStore(self.devices.clone())),
        )?;
        Ok(DiscoveryHandle {
            node: self.clone(),
            inner: Arc::new(Mutex::new(d)),
        })
    }
}

fn unhex(s: &str) -> Option<String> {
    if !s.len().is_multiple_of(2) {
        return None;
    }
    let bytes: Option<Vec<u8>> = (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(s.get(i..i + 2)?, 16).ok())
        .collect();
    String::from_utf8(bytes?).ok()
}

/// Địa chỉ mạng nội bộ của máy này (để đưa vào QR). Bỏ loopback và địa chỉ công cộng (L1).
pub fn local_ips() -> Vec<IpAddr> {
    let mut v: Vec<IpAddr> = if_addrs::get_if_addrs()
        .unwrap_or_default()
        .into_iter()
        .filter(|i| !i.is_loopback())
        .map(|i| i.ip())
        .filter(|ip| addr::is_local_network(*ip))
        .collect();
    v.sort();
    v.dedup();
    v
}

/// Cổng ghép đôi đang mở.
#[derive(Debug, Clone)]
pub struct PairingHostHandle {
    node: Arc<Node>,
    host: Arc<Mutex<PairingHost>>,
    offer: Arc<std::sync::Mutex<Option<PairingOffer>>>,
}

impl PairingHostHandle {
    /// Cổng đang nghe.
    pub async fn port(&self) -> Result<u16, Error> {
        Ok(self.host.lock().await.local_addr()?.port())
    }

    /// Tạo URI cho mã QR (mã một lần mới, hạn 120 giây). `ips` rỗng ⇒ dùng [`local_ips`].
    pub async fn qr_uri(&self, ips: Vec<IpAddr>) -> Result<String, Error> {
        let ips = if ips.is_empty() { local_ips() } else { ips };
        if ips.is_empty() {
            return Err(Error::Io(std::io::ErrorKind::AddrNotAvailable));
        }
        let offer = self
            .host
            .lock()
            .await
            .qr_offer(&self.node.cfg.app, &ips, now().0)?;
        let uri = offer.to_uri();
        *self.offer.lock().unwrap_or_else(|e| e.into_inner()) = Some(offer);
        Ok(uri)
    }

    /// Chờ máy kia quét QR vừa tạo (tới khi mã hết hạn).
    pub async fn accept_qr(&self, cancel: Option<CancelToken>) -> Result<PairedDevice, Error> {
        let offer = self
            .offer
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .take()
            .ok_or(Error::InvalidInput("chưa tạo mã QR"))?;
        let (node, host) = (self.node.clone(), self.host.clone());
        spawn(with_cancel(cancel, async move {
            let mut limiter = node.limiter.lock().await;
            host.lock()
                .await
                .accept_qr(
                    offer,
                    &node.cfg.alias,
                    node.devices.as_ref(),
                    &mut limiter,
                    || now().0,
                )
                .await
        }))
        .await
    }

    /// Chờ máy kia nối để so mã số, tối đa `wait_secs` giây.
    pub async fn accept_sas(
        &self,
        wait_secs: u64,
        cancel: Option<CancelToken>,
    ) -> Result<SasHandle, Error> {
        let (node, host) = (self.node.clone(), self.host.clone());
        let s = spawn(with_cancel(cancel, async move {
            host.lock()
                .await
                .accept_sas(&node.cfg.alias, Duration::from_secs(wait_secs.min(600)))
                .await
        }))
        .await?;
        Ok(SasHandle::new(self.node.clone(), s))
    }
}

/// Phiên so mã số đang chờ người dùng xác nhận.
#[derive(Debug, Clone)]
pub struct SasHandle {
    node: Arc<Node>,
    code: String,
    peer_alias: String,
    peer_fingerprint: String,
    inner: Arc<std::sync::Mutex<Option<SasSession>>>,
}

impl SasHandle {
    fn new(node: Arc<Node>, s: SasSession) -> Self {
        Self {
            node,
            code: s.code().to_owned(),
            peer_alias: s.peer_alias().to_owned(),
            peer_fingerprint: s.peer_fingerprint().to_owned(),
            inner: Arc::new(std::sync::Mutex::new(Some(s))),
        }
    }

    /// Mã 6 chữ số để hai người so.
    pub fn code(&self) -> &str {
        &self.code
    }

    /// Tên máy kia.
    pub fn peer_alias(&self) -> &str {
        &self.peer_alias
    }

    /// Vân tay máy kia.
    pub fn peer_fingerprint(&self) -> &str {
        &self.peer_fingerprint
    }

    /// Người dùng bấm "Khớp" (`true`) hoặc "Không khớp" (`false`). Chỉ gọi được một lần.
    pub async fn finish(&self, confirmed: bool) -> Result<PairedDevice, Error> {
        let s = self
            .inner
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .take()
            .ok_or(Error::Closed)?;
        let node = self.node.clone();
        spawn(async move {
            let mut limiter = node.limiter.lock().await;
            s.finish(confirmed, node.devices.as_ref(), &mut limiter, now().0)
                .await
        })
        .await
    }
}

/// Cổng đồng bộ đang mở.
#[derive(Debug, Clone)]
pub struct SyncListener {
    node: Arc<Node>,
    inner: Arc<Mutex<Listener>>,
}

/// Kết quả một phiên phía bên nghe.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct ServedSync {
    /// Vân tay máy vừa đồng bộ.
    pub peer: String,
    /// Kết quả.
    pub report: SyncReport,
}

impl SyncListener {
    /// Cổng đang nghe.
    pub async fn port(&self) -> Result<u16, Error> {
        Ok(self.inner.lock().await.local_addr()?.port())
    }

    /// Chờ một thiết bị đã ghép đôi nối tới rồi đồng bộ trọn một phiên (bên nghe).
    pub async fn serve_one(
        &self,
        wanted: Vec<String>,
        progress: Option<ProgressFn>,
        cancel: Option<CancelToken>,
    ) -> Result<ServedSync, Error> {
        let (node, inner) = (self.node.clone(), self.inner.clone());
        spawn(with_cancel(cancel, async move {
            let mut conn = inner.lock().await.accept().await?;
            let peer = conn.fingerprint.clone();
            let report = node
                .run_session(&mut conn.stream, Role::Responder, &peer, wanted, progress)
                .await?;
            Ok(ServedSync { peer, report })
        }))
        .await
    }
}

/// Khám phá đang chạy.
#[derive(Debug, Clone)]
pub struct DiscoveryHandle {
    node: Arc<Node>,
    inner: Arc<Mutex<Discovery>>,
}

impl DiscoveryHandle {
    /// Rao máy này (cổng đồng bộ `port`) trên mọi giao diện; trả số giao diện gửi được.
    pub async fn announce(&self, port: u16) -> Result<usize, Error> {
        let msg = Announcement::new(
            &self.node.cfg.app,
            &self.node.cfg.alias,
            self.node.fingerprint(),
            port,
        );
        let inner = self.inner.clone();
        spawn(async move { Ok(inner.lock().await.announce(&msg).await) }).await
    }

    /// Thiết bị kế tiếp nghe thấy, chờ tối đa `wait_ms`; `None` nếu hết giờ.
    pub async fn next(
        &self,
        wait_ms: u64,
        cancel: Option<CancelToken>,
    ) -> Result<Option<DiscoveredPeer>, Error> {
        let inner = self.inner.clone();
        spawn(with_cancel(cancel, async move {
            let mut d = inner.lock().await;
            Ok(
                tokio::time::timeout(Duration::from_millis(wait_ms), d.next())
                    .await
                    .ok()
                    .flatten(),
            )
        }))
        .await
    }
}

#[cfg(test)]
mod tests;
