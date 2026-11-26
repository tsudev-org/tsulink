//! Tsu Link - đồng bộ trực tiếp giữa thiết bị qua mạng nội bộ, không đi qua internet.
//!
//! Chuẩn: tsudev-standards `docs/LOCAL_SYNC.md` (v7.0.1+).
//!
//! - [`addr`]: chỉ nhận địa chỉ mạng nội bộ (luật L1);
//! - [`pairing`]: tạo/đọc URI mã QR `tsulink:1?...`, mã ghép đôi một lần, hạn 120 giây;
//! - [`sas`]: mã 6 chữ số để hai người so khi không quét được QR;
//! - [`session`] + [`devices`]: phiên ghép đôi QR/so mã số (cam kết nonce, khoá 10 phút sau 5 lần sai), kho thiết bị;
//! - [`frame`]: khung tin độ dài + JSON trên luồng mTLS;
//! - [`identity`]: danh tính thiết bị ECDSA P-256 + vân tay chứng thư;
//! - [`tls`] + [`transport`]: mTLS 1.3 ghim vân tay hai chiều, ALPN `tsulink/1`, cổng nghe tự đóng (L3, L4);
//! - [`discovery`]: khám phá multicast dùng chung kênh Lotus v2, thêm trường `tsulink`;
//! - [`tsubak`]: sao lưu/mang dữ liệu đi bằng tệp `.tsubak` (zip mở, mã hoá tuỳ chọn, vector chéo);
//! - [`sync`]: khung đồng bộ - bắt tay `schema_version`, bảng LWW theo HLC + bia mộ, Automerge, tệp khối 1 MiB BLAKE3
//!   nối lại (ADR-0004).
//!
//! Ràng buộc Flutter/C ABI làm ở các bản sau (phiếu `logs/handover/20261125-TL1_*`). Khám phá và mTLS dựng lại theo
//! lõi Lotus v2 của Lotus Share (ADR-0001).

#![forbid(unsafe_code)]
#![deny(missing_docs)]

pub mod addr;
pub mod devices;
pub mod discovery;
pub mod frame;
pub mod identity;
pub mod pairing;
pub mod sas;
pub mod session;
pub mod sync;
pub mod tls;
pub mod transport;
pub mod tsubak;

/// Lỗi của Tsu Link.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum Error {
    /// URI không đúng khuôn `tsulink:1?...`.
    #[error("URI ghép đôi sai khuôn: {0}")]
    Malformed(&'static str),
    /// Vân tay không phải 64 ký tự hex chữ HOA.
    #[error("vân tay không hợp lệ")]
    BadFingerprint,
    /// Địa chỉ không thuộc mạng nội bộ (luật L1).
    #[error("địa chỉ không thuộc mạng nội bộ: {0}")]
    PublicAddress(String),
    /// Mã ghép đôi đã hết hạn hoặc hạn quá xa (> 120 giây).
    #[error("mã ghép đôi hết hạn hoặc hạn không hợp lệ")]
    Expired,
    /// Không lấy được số ngẫu nhiên từ hệ điều hành.
    #[error("không lấy được số ngẫu nhiên")]
    Rng,
    /// Khoá/chứng thư thiết bị không hợp lệ hoặc không khớp nhau.
    #[error("danh tính thiết bị không hợp lệ")]
    Identity,
    /// Bắt tay TLS thất bại (gồm vân tay không khớp ghim).
    #[error("TLS: {0}")]
    Tls(String),
    /// Lỗi mạng.
    #[error("lỗi mạng: {0:?}")]
    Io(std::io::ErrorKind),
    /// Quá thời hạn kết nối/bắt tay.
    #[error("quá thời hạn kết nối")]
    Timeout,
    /// Cổng nghe không có kết nối mới trong 10 phút - app phải đóng cổng (luật L4).
    #[error("cổng nghe hết thời gian chờ")]
    IdleTimeout,
    /// Tệp sao lưu `.tsubak` hỏng, bị sửa, không an toàn hoặc không khớp app.
    #[error("sao lưu: {0}")]
    Backup(&'static str),
    /// Mật khẩu sao lưu sai (hoặc thiếu khi tệp có mã hoá).
    #[error("mật khẩu sao lưu không đúng")]
    WrongPassword,
    /// Mật khẩu sao lưu quá ngắn (< 10 ký tự sau NFKC).
    #[error("mật khẩu sao lưu cần ít nhất 10 ký tự")]
    WeakPassword,
    /// Quá 5 lần ghép đôi sai trong 10 phút - khoá tới thời điểm này (giây Unix).
    #[error("tạm khoá ghép đôi tới {0}")]
    Locked(u64),
    /// Bên kia từ chối ghép đôi (mã `t` sai/hết hạn, hoặc so mã số không được xác nhận ở cả hai máy).
    #[error("ghép đôi bị từ chối")]
    PairingRejected,
    /// Bên kia không nói đúng giao thức Tsu Link.
    #[error("sai giao thức: {0}")]
    Protocol(&'static str),
    /// Hai thiết bị khác phiên bản lược đồ dữ liệu - dừng đồng bộ, nhắc cập nhật app (luật L5).
    #[error("khác phiên bản dữ liệu (máy này {local}, máy kia {remote}) - cần cập nhật app")]
    SchemaMismatch {
        /// Lược đồ của máy này.
        local: u32,
        /// Lược đồ của máy kia.
        remote: u32,
    },
    /// Đồng hồ thiết bị kia nhanh hơn máy này quá 1 giờ - chỉnh giờ rồi đồng bộ lại.
    #[error("đồng hồ hai thiết bị lệch quá 1 giờ")]
    ClockSkew,
    /// Dữ liệu nhận về sai kiểm tra toàn vẹn (BLAKE3).
    #[error("dữ liệu hỏng: {0}")]
    Corrupt(&'static str),
}

/// Kiểm vân tay: SHA-256 chứng thư DER, hex chữ HOA, 64 ký tự (giống Lotus v2 mục 5.1).
pub fn is_valid_fingerprint(fp: &str) -> bool {
    fp.len() == 64
        && fp
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'A'..=b'F').contains(&b))
}
