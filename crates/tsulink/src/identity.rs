//! Danh tính thiết bị (`LOCAL_SYNC.md` mục 2): mỗi bản cài một cặp khoá **ECDSA P-256** + chứng thư X.509 tự ký.
//!
//! Vân tay = SHA-256 của chứng thư DER, hex chữ HOA 64 ký tự (giống Lotus v2 mục 5.1). App giữ khoá trong kho khoá của
//! nền tảng (AndroidKeyStore, Keychain, DPAPI/CNG, Secret Service) qua [`DeviceIdentity::key_pkcs8_der`] và nạp lại bằng
//! [`DeviceIdentity::from_der`]; thư viện không tự ghi khoá ra đĩa.

use crate::Error;
use rcgen::{CertificateParams, DistinguishedName, DnType, KeyPair, PKCS_ECDSA_P256_SHA256};
use sha2::{Digest, Sha256};
use std::fmt;
use zeroize::Zeroizing;

/// Danh tính TLS của thiết bị này.
#[derive(Clone)]
pub struct DeviceIdentity {
    cert_der: Vec<u8>,
    key_der: Zeroizing<Vec<u8>>,
    fingerprint: String,
}

impl fmt::Debug for DeviceIdentity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Không bao giờ in khoá riêng.
        f.debug_struct("DeviceIdentity")
            .field("fingerprint", &self.fingerprint)
            .finish_non_exhaustive()
    }
}

impl DeviceIdentity {
    /// Sinh cặp khoá ECDSA P-256 mới và chứng thư tự ký (CN `Tsu Link`).
    pub fn generate() -> Result<Self, Error> {
        let key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).map_err(|_| Error::Rng)?;
        let mut params =
            CertificateParams::new(Vec::<String>::new()).map_err(|_| Error::Identity)?;
        let mut dn = DistinguishedName::new();
        dn.push(DnType::CommonName, "Tsu Link");
        params.distinguished_name = dn;
        let cert = params.self_signed(&key).map_err(|_| Error::Identity)?;
        Ok(Self::assemble(
            cert.der().to_vec(),
            Zeroizing::new(key.serialize_der()),
        ))
    }

    /// Nạp lại danh tính đã lưu: chứng thư DER + khoá riêng PKCS#8 DER. Khoá phải là ECDSA P-256 và khớp chứng thư.
    pub fn from_der(cert_der: &[u8], key_pkcs8_der: &[u8]) -> Result<Self, Error> {
        let key = KeyPair::try_from(key_pkcs8_der).map_err(|_| Error::Identity)?;
        if key.algorithm() != &PKCS_ECDSA_P256_SHA256 {
            return Err(Error::Identity);
        }
        let id = Self::assemble(cert_der.to_vec(), Zeroizing::new(key_pkcs8_der.to_vec()));
        // Khoá phải khớp chứng thư - rustls kiểm khi dựng cấu hình.
        crate::tls::certified_key(&id)?;
        Ok(id)
    }

    fn assemble(cert_der: Vec<u8>, key_der: Zeroizing<Vec<u8>>) -> Self {
        let fingerprint = fingerprint_of(&cert_der);
        Self {
            cert_der,
            key_der,
            fingerprint,
        }
    }

    /// Vân tay chứng thư của thiết bị này.
    pub fn fingerprint(&self) -> &str {
        &self.fingerprint
    }

    /// Chứng thư DER (công khai).
    pub fn cert_der(&self) -> &[u8] {
        &self.cert_der
    }

    /// Khoá riêng PKCS#8 DER - chỉ để app cất vào kho khoá nền tảng. Bộ nhớ được xoá khi huỷ.
    pub fn key_pkcs8_der(&self) -> &[u8] {
        &self.key_der
    }
}

/// Vân tay của một chứng thư DER: SHA-256, hex chữ HOA.
pub fn fingerprint_of(cert_der: &[u8]) -> String {
    use std::fmt::Write;
    Sha256::digest(cert_der)
        .iter()
        .fold(String::with_capacity(64), |mut s, b| {
            let _ = write!(s, "{b:02X}");
            s
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::is_valid_fingerprint;

    #[test]
    fn sinh_va_nap_lai() {
        let a = DeviceIdentity::generate().unwrap();
        assert!(is_valid_fingerprint(a.fingerprint()));
        let b = DeviceIdentity::from_der(a.cert_der(), a.key_pkcs8_der()).unwrap();
        assert_eq!(a.fingerprint(), b.fingerprint());
        assert!(!format!("{a:?}").contains("key"));
    }

    #[test]
    fn hai_ban_cai_khac_van_tay() {
        let a = DeviceIdentity::generate().unwrap();
        let b = DeviceIdentity::generate().unwrap();
        assert_ne!(a.fingerprint(), b.fingerprint());
    }

    #[test]
    fn khoa_khong_khop_chung_thu_bi_tu_choi() {
        let a = DeviceIdentity::generate().unwrap();
        let b = DeviceIdentity::generate().unwrap();
        assert_eq!(
            DeviceIdentity::from_der(a.cert_der(), b.key_pkcs8_der()).unwrap_err(),
            Error::Identity
        );
        assert_eq!(
            DeviceIdentity::from_der(a.cert_der(), b"rac").unwrap_err(),
            Error::Identity
        );
    }
}
