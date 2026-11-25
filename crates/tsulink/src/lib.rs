//! Tsu Link - đồng bộ trực tiếp giữa thiết bị qua mạng nội bộ, không đi qua internet.
//!
//! Chuẩn: tsudev-standards `docs/LOCAL_SYNC.md` (v7.0.1+).
//!
//! - [`addr`]: chỉ nhận địa chỉ mạng nội bộ (luật L1);
//! - [`pairing`]: tạo/đọc URI mã QR `tsulink:1?...`, mã ghép đôi một lần, hạn 120 giây;
//! - [`sas`]: mã 6 chữ số để hai người so khi không quét được QR;
//! - [`identity`]: danh tính thiết bị ECDSA P-256 + vân tay chứng thư;
//! - [`tls`] + [`transport`]: mTLS 1.3 ghim vân tay hai chiều, ALPN `tsulink/1`, cổng nghe tự đóng (L3, L4);
//! - [`discovery`]: khám phá multicast dùng chung kênh Lotus v2, thêm trường `tsulink`.
//!
//! Phiên ghép đôi, khung đồng bộ CRDT, truyền tệp và `.tsubak` làm ở các bản sau (phiếu
//! `logs/handover/20261125-TL1_*`). Khám phá và mTLS dựng lại theo lõi Lotus v2 của Lotus Share (ADR-0001).

#![forbid(unsafe_code)]
#![deny(missing_docs)]

pub mod addr;
pub mod discovery;
pub mod identity;
pub mod pairing;
pub mod sas;
pub mod tls;
pub mod transport;

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
    /// Bên kia không nói đúng giao thức Tsu Link.
    #[error("sai giao thức: {0}")]
    Protocol(&'static str),
}

/// Kiểm vân tay: SHA-256 chứng thư DER, hex chữ HOA, 64 ký tự (giống Lotus v2 mục 5.1).
pub fn is_valid_fingerprint(fp: &str) -> bool {
    fp.len() == 64
        && fp
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'A'..=b'F').contains(&b))
}
