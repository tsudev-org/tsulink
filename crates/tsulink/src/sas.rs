//! Mã 6 chữ số để hai người so khi ghép đôi không có camera (`LOCAL_SYNC.md` mục 3, v7.0.1+).
//!
//! `h = SHA-256("tsulink-sas|" || fp_nhỏ || fp_lớn || nonce_của_fp_nhỏ || nonce_của_fp_lớn)`;
//! mã = (4 byte đầu của `h`, big-endian) mod 1 000 000, in đủ 6 chữ số (giống so số của Bluetooth).
//! "nhỏ/lớn" so theo thứ tự byte của chuỗi vân tay hex chữ HOA nên hai máy ra cùng một mã.

use crate::{Error, is_valid_fingerprint};
use sha2::{Digest, Sha256};

/// Tính mã 6 chữ số từ vân tay và nonce (16 byte, ngẫu nhiên, mỗi phiên) của hai thiết bị.
pub fn code(
    fp_a: &str,
    nonce_a: &[u8; 16],
    fp_b: &str,
    nonce_b: &[u8; 16],
) -> Result<String, Error> {
    if !is_valid_fingerprint(fp_a) || !is_valid_fingerprint(fp_b) {
        return Err(Error::BadFingerprint);
    }
    if fp_a == fp_b {
        return Err(Error::Malformed("hai vân tay trùng nhau"));
    }
    let ((lo, n_lo), (hi, n_hi)) = if fp_a < fp_b {
        ((fp_a, nonce_a), (fp_b, nonce_b))
    } else {
        ((fp_b, nonce_b), (fp_a, nonce_a))
    };
    let h = Sha256::new()
        .chain_update(b"tsulink-sas|")
        .chain_update(lo.as_bytes())
        .chain_update(hi.as_bytes())
        .chain_update(n_lo)
        .chain_update(n_hi)
        .finalize();
    let v = u32::from_be_bytes([h[0], h[1], h[2], h[3]]) % 1_000_000;
    Ok(format!("{v:06}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    const A: &str = "AAAA456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF";
    const B: &str = "BBBB456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF";

    #[test]
    fn hai_ben_cung_ma() {
        let (na, nb) = ([1u8; 16], [2u8; 16]);
        let x = code(A, &na, B, &nb).unwrap();
        let y = code(B, &nb, A, &na).unwrap();
        assert_eq!(x, y);
        assert_eq!(x.len(), 6);
        assert!(x.bytes().all(|c| c.is_ascii_digit()));
    }

    #[test]
    fn vector_co_dinh() {
        // Vector đối chiếu chéo cho bản cài đặt ở ngôn ngữ khác (TS, Dart, C#) - đừng đổi.
        assert_eq!(code(A, &[1u8; 16], B, &[2u8; 16]).unwrap(), VECTOR_1);
    }

    #[test]
    fn doi_nonce_doi_ma() {
        assert_ne!(
            code(A, &[1u8; 16], B, &[2u8; 16]).unwrap(),
            code(A, &[1u8; 16], B, &[3u8; 16]).unwrap()
        );
    }

    #[test]
    fn tu_choi_van_tay_trung_hoac_sai() {
        assert!(code(A, &[0; 16], A, &[1; 16]).is_err());
        assert_eq!(
            code("abc", &[0; 16], B, &[1; 16]),
            Err(Error::BadFingerprint)
        );
    }

    const VECTOR_1: &str = include_str!("../../../conformance/sas-vector-1.txt");
}
