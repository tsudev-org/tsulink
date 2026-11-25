//! Tsu Link - đồng bộ trực tiếp giữa thiết bị qua mạng nội bộ, không đi qua internet.
//!
//! Chuẩn: tsudev-standards `docs/LOCAL_SYNC.md` (v7.0.1+). Bản 0.1 mới có phần **ghép đôi**:
//!
//! - [`addr`]: chỉ nhận địa chỉ mạng nội bộ (luật L1);
//! - [`pairing`]: tạo/đọc URI mã QR `tsulink:1?...`, mã ghép đôi một lần, hạn 120 giây;
//! - [`sas`]: mã 6 chữ số để hai người so khi không quét được QR.
//!
//! Khám phá multicast, mTLS ghim vân tay (tách từ lõi Lotus v2) và khung đồng bộ CRDT làm ở các bản sau
//! (phiếu `logs/handover/20261125-TL1_*`).

#![forbid(unsafe_code)]
#![deny(missing_docs)]

pub mod addr;
pub mod pairing;
pub mod sas;

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
}

/// Kiểm vân tay: SHA-256 chứng thư DER, hex chữ HOA, 64 ký tự (giống Lotus v2 mục 5.1).
pub fn is_valid_fingerprint(fp: &str) -> bool {
    fp.len() == 64
        && fp
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'A'..=b'F').contains(&b))
}
