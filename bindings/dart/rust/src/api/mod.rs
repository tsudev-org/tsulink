//! Bề mặt API cho Dart. Kiểu `Link*` là đối tượng mờ (Dart giữ con trỏ, tự giải phóng); còn lại là DTO thuần.
//! Mọi hàm chờ là `async` (Dart nhận `Future`), chạy trên runtime tokio của lõi ([`tsulink::node::spawn`]); huỷ bằng
//! [`LinkCancel`]. Lỗi là [`LinkError`] với mã ổn định giống C ABI ([`tsulink::Error::code`]).
#![forbid(unsafe_code)]
#![deny(missing_docs)]

use flutter_rust_bridge::DartFnFuture;
use std::net::{IpAddr, SocketAddr};
use std::path::PathBuf;
use std::sync::Arc;
use tsulink::Error;
use tsulink::identity::DeviceIdentity;
use tsulink::node::{
    self, CancelToken, DiscoveryHandle, Node, NodeConfig, PairingHostHandle, ProgressFn, SasHandle,
    SyncListener,
};

/// Khởi tạo cầu nối (flutter_rust_bridge gọi một lần khi Dart nạp thư viện).
#[flutter_rust_bridge::frb(init)]
pub fn init_app() {
    flutter_rust_bridge::setup_default_user_utils();
}

/// Phiên bản lõi Rust.
#[flutter_rust_bridge::frb(sync)]
pub fn tsulink_version() -> String {
    env!("CARGO_PKG_VERSION").to_owned()
}

/// Lỗi trả về Dart.
#[derive(Debug, Clone)]
pub struct LinkError {
    /// Mã ổn định (bảng ở `crates/tsulink-capi/include/tsulink.h`): 17 = khác lược đồ (nhắc cập nhật app),
    /// 15 = bị từ chối/chưa ghép đôi, 14 = tạm khoá, 20 = đã huỷ...
    pub code: i32,
    /// Thông điệp tiếng Việt (để ghi nhật ký; giao diện dịch theo `code`).
    pub message: String,
}

impl From<Error> for LinkError {
    fn from(e: Error) -> Self {
        Self {
            code: e.code(),
            message: e.to_string(),
        }
    }
}

type R<T> = Result<T, LinkError>;

fn invalid(what: &'static str) -> LinkError {
    Error::InvalidInput(what).into()
}

/// Danh tính thiết bị. App lưu `key_pkcs8_der` trong kho bí mật của hệ điều hành (flutter_secure_storage...).
#[derive(Debug, Clone)]
pub struct LinkIdentity {
    /// Chứng thư DER.
    pub cert_der: Vec<u8>,
    /// Khoá riêng PKCS#8 DER.
    pub key_pkcs8_der: Vec<u8>,
}

/// Tạo danh tính mới (ECDSA P-256).
pub fn generate_identity() -> R<LinkIdentity> {
    let id = DeviceIdentity::generate()?;
    Ok(LinkIdentity {
        cert_der: id.cert_der().to_vec(),
        key_pkcs8_der: id.key_pkcs8_der().to_vec(),
    })
}

/// Địa chỉ mạng nội bộ của máy này (để đưa vào QR).
#[flutter_rust_bridge::frb(sync)]
pub fn local_ips() -> Vec<String> {
    node::local_ips().iter().map(ToString::to_string).collect()
}

/// Thiết bị đã ghép đôi.
#[derive(Debug, Clone)]
pub struct LinkDevice {
    /// Vân tay.
    pub fingerprint: String,
    /// Tên hiển thị.
    pub alias: String,
    /// Lúc ghép đôi (giây Unix).
    pub paired_at: i64,
    /// Lần đồng bộ gần nhất (giây Unix).
    pub last_sync_at: i64,
}

impl From<tsulink::devices::PairedDevice> for LinkDevice {
    fn from(d: tsulink::devices::PairedDevice) -> Self {
        Self {
            fingerprint: d.fingerprint,
            alias: d.alias,
            paired_at: d.paired_at as i64,
            last_sync_at: d.last_sync_at as i64,
        }
    }
}

/// Một thay đổi trong nhật ký máy này.
#[derive(Debug, Clone)]
pub struct LinkChange {
    /// Số thứ tự trong nhật ký máy này (app nhớ số lớn nhất đã chép).
    pub seq: i64,
    /// Bảng.
    pub table: String,
    /// Khoá.
    pub key: String,
    /// Nội dung JSON; `null` = đã xoá.
    pub value_json: Option<String>,
    /// Mốc HLC (mili giây).
    pub hlc_ms: i64,
}

/// Kết quả một phiên đồng bộ.
#[derive(Debug, Clone)]
pub struct LinkSyncReport {
    /// Số phiên bản bản ghi nhận về và đã thắng.
    pub rows: u32,
    /// Số tài liệu có thay đổi nhận về.
    pub docs: u32,
    /// Đường dẫn tệp đã nhận đủ.
    pub files: Vec<String>,
    /// BLAKE3 tệp máy kia không có.
    pub missing: Vec<String>,
}

impl From<tsulink::sync::SyncReport> for LinkSyncReport {
    fn from(r: tsulink::sync::SyncReport) -> Self {
        Self {
            rows: r.rows as u32,
            docs: r.docs as u32,
            files: r
                .files
                .iter()
                .map(|p| p.to_string_lossy().into_owned())
                .collect(),
            missing: r.missing,
        }
    }
}

/// Kết quả phiên phía bên nghe.
#[derive(Debug, Clone)]
pub struct LinkServed {
    /// Vân tay máy vừa đồng bộ.
    pub peer: String,
    /// Kết quả.
    pub report: LinkSyncReport,
}

/// Thiết bị nghe thấy qua khám phá.
#[derive(Debug, Clone)]
pub struct LinkPeer {
    /// Vân tay.
    pub fingerprint: String,
    /// Tên hiển thị.
    pub alias: String,
    /// `ip:cổng` để đồng bộ.
    pub addr: String,
    /// Đã ghép đôi chưa.
    pub paired: bool,
}

/// Tiến độ truyền tệp gửi về Dart: `(BLAKE3, byte đã có, tổng byte)`.
fn progress_of(
    f: impl Fn(String, i64, i64) -> DartFnFuture<()> + Send + Sync + 'static,
) -> Option<ProgressFn> {
    Some(Box::new(move |h: &str, done, total| {
        // Không chờ Dart: callback chạy trên luồng mạng, chờ UI là làm chậm truyền tệp.
        if let Ok(rt) = node::runtime() {
            rt.spawn(f(h.to_owned(), done as i64, total as i64));
        }
    }))
}

fn addr(s: &str) -> R<SocketAddr> {
    s.parse().map_err(|_| invalid("địa chỉ ip:cổng"))
}

/// Thẻ huỷ: truyền vào hàm chờ, gọi [`LinkCancel::cancel`] từ nút "Huỷ".
#[derive(Debug, Clone, Default)]
pub struct LinkCancel(CancelToken);

impl LinkCancel {
    /// Thẻ mới.
    #[flutter_rust_bridge::frb(sync)]
    pub fn new() -> Self {
        Self::default()
    }

    /// Huỷ mọi thao tác đang chờ trên thẻ.
    #[flutter_rust_bridge::frb(sync)]
    pub fn cancel(&self) {
        self.0.cancel();
    }
}

// Thẻ truyền THAM CHIẾU: truyền giá trị thì flutter_rust_bridge "chuyển" đối tượng Dart vào Rust (Dart không gọi
// `cancel()` được nữa).
fn tok(c: &LinkCancel) -> Option<CancelToken> {
    Some(c.0.clone())
}

/// Một thiết bị trong một app.
#[derive(Debug, Clone)]
pub struct LinkNode(Arc<Node>);

impl LinkNode {
    /// Mở thiết bị; dữ liệu Tsu Link nằm trong `data_dir`.
    pub fn open(
        data_dir: String,
        app: String,
        alias: String,
        schema_version: u32,
        identity: LinkIdentity,
    ) -> R<LinkNode> {
        Ok(Self(Node::open(
            NodeConfig {
                data_dir: PathBuf::from(data_dir),
                app,
                alias,
                schema_version,
            },
            &identity.cert_der,
            &identity.key_pkcs8_der,
        )?))
    }

    /// Vân tay máy này.
    #[flutter_rust_bridge::frb(sync, getter)]
    pub fn fingerprint(&self) -> String {
        self.0.fingerprint().to_owned()
    }

    /// Ghi bản ghi (JSON).
    pub fn write(&self, table: String, key: String, value_json: String) -> R<()> {
        let v = serde_json::from_str(&value_json).map_err(|_| invalid("value JSON"))?;
        self.0.write(&table, &key, v)?;
        Ok(())
    }

    /// Xoá bản ghi.
    pub fn delete(&self, table: String, key: String) -> R<()> {
        self.0.delete(&table, &key)?;
        Ok(())
    }

    /// Đọc bản ghi (JSON), `null` nếu chưa có/đã xoá.
    pub fn read(&self, table: String, key: String) -> Option<String> {
        self.0.read(&table, &key).map(|v| v.to_string())
    }

    /// Nhật ký máy này sau `after` (tối đa `limit`).
    pub fn changes_after(&self, after: i64, limit: u32) -> Vec<LinkChange> {
        self.0
            .changes_after(after.max(0) as u64, limit as usize)
            .into_iter()
            .map(|c| LinkChange {
                seq: c.seq as i64,
                table: c.table,
                key: c.key,
                value_json: c.value.map(|v| v.to_string()),
                hlc_ms: c.hlc.ms as i64,
            })
            .collect()
    }

    /// Xoá hẳn bia mộ quá 180 ngày.
    pub fn purge_tombstones(&self) -> R<u32> {
        Ok(self.0.purge_tombstones()? as u32)
    }

    /// Mã các tài liệu Automerge.
    pub async fn doc_ids(&self) -> R<Vec<String>> {
        let n = self.0.clone();
        Ok(node::spawn(async move { Ok(n.doc_ids().await) }).await?)
    }

    /// Bản lưu Automerge của tài liệu, `null` nếu chưa có.
    pub async fn doc_save(&self, id: String) -> R<Option<Vec<u8>>> {
        let n = self.0.clone();
        Ok(node::spawn(async move { Ok(n.doc_save(&id).await) }).await?)
    }

    /// Gộp bản lưu Automerge vào tài liệu.
    pub async fn doc_merge(&self, id: String, data: Vec<u8>) -> R<()> {
        let n = self.0.clone();
        Ok(node::spawn(async move { n.doc_merge(&id, &data).await }).await?)
    }

    /// Chép tệp vào kho tệp; trả BLAKE3.
    pub async fn file_import(&self, path: String) -> R<String> {
        let n = self.0.clone();
        Ok(node::spawn(async move { n.file_import(&PathBuf::from(path)).await }).await?)
    }

    /// Đường dẫn tệp trong kho, `null` nếu chưa có.
    pub fn file_path(&self, hash: String) -> Option<String> {
        self.0
            .file_path(&hash)
            .map(|p| p.to_string_lossy().into_owned())
    }

    /// Thiết bị đã ghép đôi.
    pub fn devices(&self) -> Vec<LinkDevice> {
        self.0.devices().into_iter().map(Into::into).collect()
    }

    /// Gỡ thiết bị.
    pub fn remove_device(&self, fingerprint: String) -> R<bool> {
        Ok(self.0.remove_device(&fingerprint)?)
    }

    /// Gỡ thiết bị không đồng bộ quá 180 ngày.
    pub fn prune_stale_devices(&self) -> R<u32> {
        Ok(self.0.prune_stale_devices()? as u32)
    }

    /// Mở cổng ghép đôi tạm (`port` 0 = hệ điều hành chọn).
    pub async fn open_pairing_host(&self, port: u16) -> R<LinkPairingHost> {
        Ok(LinkPairingHost(self.0.pairing_host(port).await?))
    }

    /// Quét QR của máy kia và ghép đôi.
    pub async fn join_qr(&self, uri: String, cancel: &LinkCancel) -> R<LinkDevice> {
        Ok(self.0.join_qr(uri, tok(cancel)).await?.into())
    }

    /// Nối tới cổng ghép đôi `addr` (`ip:cổng`) để so mã số.
    pub async fn join_sas(&self, addr: String, cancel: &LinkCancel) -> R<LinkSas> {
        let a = self::addr(&addr)?;
        Ok(LinkSas(self.0.join_sas(a, tok(cancel)).await?))
    }

    /// Đồng bộ (bên gọi) với thiết bị đã ghép đôi `peer` ở `addr`; xin thêm tệp `wanted` (BLAKE3).
    pub async fn sync_with(
        &self,
        peer: String,
        addr: String,
        wanted: Vec<String>,
        on_progress: impl Fn(String, i64, i64) -> DartFnFuture<()> + Send + Sync + 'static,
        cancel: &LinkCancel,
    ) -> R<LinkSyncReport> {
        let a = self::addr(&addr)?;
        Ok(self
            .0
            .sync_with(peer, a, wanted, progress_of(on_progress), tok(cancel))
            .await?
            .into())
    }

    /// Mở cổng đồng bộ (tự hết hạn sau 10 phút không có kết nối).
    pub async fn listen(&self, port: u16) -> R<LinkListener> {
        Ok(LinkListener(self.0.listen(port).await?))
    }

    /// Bắt đầu khám phá thiết bị cùng app.
    pub fn start_discovery(&self) -> R<LinkDiscovery> {
        Ok(LinkDiscovery(self.0.discovery()?))
    }
}

/// Cổng ghép đôi đang mở.
#[derive(Debug, Clone)]
pub struct LinkPairingHost(PairingHostHandle);

impl LinkPairingHost {
    /// Cổng đang nghe.
    pub async fn port(&self) -> R<u16> {
        Ok(self.0.port().await?)
    }

    /// URI mã QR mới (hạn 120 giây); `ips` rỗng ⇒ tự chọn địa chỉ nội bộ.
    pub async fn qr_uri(&self, ips: Vec<String>) -> R<String> {
        let ips = ips
            .iter()
            .map(|s| s.parse::<IpAddr>().map_err(|_| invalid("địa chỉ IP")))
            .collect::<R<Vec<_>>>()?;
        Ok(self.0.qr_uri(ips).await?)
    }

    /// Chờ máy kia quét QR vừa tạo.
    pub async fn accept_qr(&self, cancel: &LinkCancel) -> R<LinkDevice> {
        Ok(self.0.accept_qr(tok(cancel)).await?.into())
    }

    /// Chờ máy kia nối để so mã số (tối đa `wait_secs`, trần 600).
    pub async fn accept_sas(&self, wait_secs: u32, cancel: &LinkCancel) -> R<LinkSas> {
        Ok(LinkSas(
            self.0.accept_sas(u64::from(wait_secs), tok(cancel)).await?,
        ))
    }
}

/// Phiên so mã số 6 chữ số.
#[derive(Debug, Clone)]
pub struct LinkSas(SasHandle);

impl LinkSas {
    /// Mã để hai người so.
    #[flutter_rust_bridge::frb(sync, getter)]
    pub fn code(&self) -> String {
        self.0.code().to_owned()
    }

    /// Tên máy kia.
    #[flutter_rust_bridge::frb(sync, getter)]
    pub fn peer_alias(&self) -> String {
        self.0.peer_alias().to_owned()
    }

    /// Vân tay máy kia.
    #[flutter_rust_bridge::frb(sync, getter)]
    pub fn peer_fingerprint(&self) -> String {
        self.0.peer_fingerprint().to_owned()
    }

    /// Người dùng bấm "Khớp" (`true`) hay "Không khớp" (`false`); gọi một lần.
    pub async fn finish(&self, confirmed: bool) -> R<LinkDevice> {
        Ok(self.0.finish(confirmed).await?.into())
    }
}

/// Cổng đồng bộ đang mở.
#[derive(Debug, Clone)]
pub struct LinkListener(SyncListener);

impl LinkListener {
    /// Cổng đang nghe.
    pub async fn port(&self) -> R<u16> {
        Ok(self.0.port().await?)
    }

    /// Chờ một thiết bị đã ghép đôi rồi đồng bộ trọn một phiên.
    pub async fn serve_one(
        &self,
        wanted: Vec<String>,
        on_progress: impl Fn(String, i64, i64) -> DartFnFuture<()> + Send + Sync + 'static,
        cancel: &LinkCancel,
    ) -> R<LinkServed> {
        let s = self
            .0
            .serve_one(wanted, progress_of(on_progress), tok(cancel))
            .await?;
        Ok(LinkServed {
            peer: s.peer,
            report: s.report.into(),
        })
    }
}

/// Khám phá thiết bị cùng app.
#[derive(Debug, Clone)]
pub struct LinkDiscovery(DiscoveryHandle);

impl LinkDiscovery {
    /// Rao máy này (cổng đồng bộ `port`); trả số giao diện gửi được.
    pub async fn announce(&self, port: u16) -> R<u32> {
        Ok(self.0.announce(port).await? as u32)
    }

    /// Thiết bị kế tiếp nghe thấy, `null` nếu hết `wait_ms`.
    pub async fn next(&self, wait_ms: u32, cancel: &LinkCancel) -> R<Option<LinkPeer>> {
        Ok(self
            .0
            .next(u64::from(wait_ms), tok(cancel))
            .await?
            .map(|p| LinkPeer {
                fingerprint: p.fingerprint,
                alias: p.alias,
                addr: p.addr.to_string(),
                paired: p.paired,
            }))
    }
}
