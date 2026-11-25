//! Cấu hình TLS của Tsu Link (`LOCAL_SYNC.md` mục 2, luật L3): rustls, **chỉ TLS 1.3**, ALPN [`ALPN`], mTLS bắt
//! buộc, hai bên ghim vân tay. Không có đường `http`, không dùng CA, không nối lại phiên (mỗi kết nối kiểm ghim lại).
//!
//! - Máy chủ chỉ nhận chứng thư máy khách có vân tay nằm trong [`PeerPins`] (thiết bị đã ghép đôi - luật L2).
//! - Máy khách chỉ nhận đúng vân tay đã ghim cho địa chỉ nó gọi (chống MITM).
//! - Chữ ký bắt tay vẫn được kiểm bằng khoá trong chứng thư (ECDSA P-256 hoặc Ed25519).

use crate::{Error, identity::DeviceIdentity, identity::fingerprint_of};
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::{CryptoProvider, WebPkiSupportedAlgorithms};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName, UnixTime};
use rustls::server::danger::{ClientCertVerified, ClientCertVerifier};
use rustls::server::{NoServerSessionStorage, ProducesTickets};
use rustls::sign::CertifiedKey;
use rustls::{
    CertificateError, ClientConfig, DigitallySignedStruct, DistinguishedName, ServerConfig,
    SignatureScheme,
};
use std::collections::HashSet;
use std::fmt;
use std::sync::{Arc, RwLock};

/// Giao thức ứng dụng đàm phán qua ALPN.
pub const ALPN: &[u8] = b"tsulink/1";

/// Lược đồ chữ ký nhận cho chứng thư thiết bị.
const SCHEMES: [SignatureScheme; 2] = [
    SignatureScheme::ECDSA_NISTP256_SHA256,
    SignatureScheme::ED25519,
];

/// Danh sách vân tay thiết bị đã ghép đôi mà máy chủ chấp nhận. App lưu danh sách (kho do app cấp); thư viện chỉ hỏi.
pub trait PeerPins: Send + Sync + fmt::Debug {
    /// `true` nếu vân tay (hex chữ HOA) thuộc một thiết bị đã ghép đôi.
    fn is_paired(&self, fingerprint: &str) -> bool;
}

/// Bộ ghim trong bộ nhớ, sửa được khi đang chạy (thêm sau ghép đôi, gỡ khi người dùng xoá thiết bị).
#[derive(Debug, Default)]
pub struct PinSet(RwLock<HashSet<String>>);

impl PinSet {
    /// Tạo bộ ghim từ danh sách vân tay; vân tay sai khuôn bị bỏ qua.
    pub fn new<I: IntoIterator<Item = S>, S: Into<String>>(fingerprints: I) -> Self {
        let set = PinSet::default();
        for fp in fingerprints {
            set.insert(fp);
        }
        set
    }

    /// Thêm một vân tay; trả `false` nếu sai khuôn.
    pub fn insert(&self, fingerprint: impl Into<String>) -> bool {
        let fp = fingerprint.into();
        if !crate::is_valid_fingerprint(&fp) {
            return false;
        }
        self.0.write().unwrap_or_else(|e| e.into_inner()).insert(fp);
        true
    }

    /// Gỡ một vân tay.
    pub fn remove(&self, fingerprint: &str) -> bool {
        self.0
            .write()
            .unwrap_or_else(|e| e.into_inner())
            .remove(fingerprint)
    }
}

impl PeerPins for PinSet {
    fn is_paired(&self, fingerprint: &str) -> bool {
        self.0
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .contains(fingerprint)
    }
}

fn provider() -> Arc<CryptoProvider> {
    Arc::new(rustls::crypto::ring::default_provider())
}

fn algorithms() -> WebPkiSupportedAlgorithms {
    rustls::crypto::ring::default_provider().signature_verification_algorithms
}

fn tls_err(e: rustls::Error) -> Error {
    Error::Tls(e.to_string())
}

fn key_der(id: &DeviceIdentity) -> PrivateKeyDer<'static> {
    PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(id.key_pkcs8_der().to_vec()))
}

fn cert_chain(id: &DeviceIdentity) -> Vec<CertificateDer<'static>> {
    vec![CertificateDer::from(id.cert_der().to_vec())]
}

/// Dựng khoá ký + chứng thư và kiểm khoá khớp chứng thư.
pub(crate) fn certified_key(id: &DeviceIdentity) -> Result<CertifiedKey, Error> {
    let signer = provider()
        .key_provider
        .load_private_key(key_der(id))
        .map_err(|_| Error::Identity)?;
    let ck = CertifiedKey::new(cert_chain(id), signer);
    ck.keys_match().map_err(|_| Error::Identity)?;
    Ok(ck)
}

fn tls12_refused() -> rustls::Error {
    rustls::Error::General("Tsu Link chỉ dùng TLS 1.3".into())
}

fn rejected() -> rustls::Error {
    rustls::Error::InvalidCertificate(CertificateError::ApplicationVerificationFailure)
}

/// Kiểm chứng thư máy khách: bắt buộc có, vân tay phải thuộc [`PeerPins`].
struct PinnedClientVerifier {
    pins: Arc<dyn PeerPins>,
    algs: WebPkiSupportedAlgorithms,
}

impl fmt::Debug for PinnedClientVerifier {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("PinnedClientVerifier")
    }
}

impl ClientCertVerifier for PinnedClientVerifier {
    fn offer_client_auth(&self) -> bool {
        true
    }

    fn client_auth_mandatory(&self) -> bool {
        true
    }

    fn root_hint_subjects(&self) -> &[DistinguishedName] {
        &[]
    }

    fn verify_client_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _now: UnixTime,
    ) -> Result<ClientCertVerified, rustls::Error> {
        if self.pins.is_paired(&fingerprint_of(end_entity)) {
            Ok(ClientCertVerified::assertion())
        } else {
            Err(rejected())
        }
    }

    fn verify_tls12_signature(
        &self,
        _: &[u8],
        _: &CertificateDer<'_>,
        _: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Err(tls12_refused())
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(message, cert, dss, &self.algs)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        SCHEMES.to_vec()
    }
}

/// Kiểm chứng thư máy chủ: đúng một vân tay đã ghim, bỏ qua tên máy (gọi theo IP, chứng thư không có SAN).
struct PinnedServerVerifier {
    expected: String,
    algs: WebPkiSupportedAlgorithms,
}

impl fmt::Debug for PinnedServerVerifier {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("PinnedServerVerifier")
            .field(&self.expected)
            .finish()
    }
}

impl ServerCertVerifier for PinnedServerVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        if fingerprint_of(end_entity) == self.expected {
            Ok(ServerCertVerified::assertion())
        } else {
            Err(rejected())
        }
    }

    fn verify_tls12_signature(
        &self,
        _: &[u8],
        _: &CertificateDer<'_>,
        _: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Err(tls12_refused())
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(message, cert, dss, &self.algs)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        SCHEMES.to_vec()
    }
}

/// Không phát vé nối lại phiên: mọi kết nối phải qua kiểm ghim đầy đủ.
#[derive(Debug)]
struct NoTickets;

impl ProducesTickets for NoTickets {
    fn enabled(&self) -> bool {
        false
    }
    fn lifetime(&self) -> u32 {
        0
    }
    fn encrypt(&self, _: &[u8]) -> Option<Vec<u8>> {
        None
    }
    fn decrypt(&self, _: &[u8]) -> Option<Vec<u8>> {
        None
    }
}

/// Cấu hình máy chủ: TLS 1.3, ALPN `tsulink/1`, chỉ nhận máy khách đã ghép đôi.
pub fn server_config(
    identity: &DeviceIdentity,
    pins: Arc<dyn PeerPins>,
) -> Result<Arc<ServerConfig>, Error> {
    let verifier = Arc::new(PinnedClientVerifier {
        pins,
        algs: algorithms(),
    });
    let mut cfg = ServerConfig::builder_with_provider(provider())
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(tls_err)?
        .with_client_cert_verifier(verifier)
        .with_single_cert(cert_chain(identity), key_der(identity))
        .map_err(|_| Error::Identity)?;
    cfg.alpn_protocols = vec![ALPN.to_vec()];
    cfg.session_storage = Arc::new(NoServerSessionStorage {});
    cfg.ticketer = Arc::new(NoTickets);
    cfg.send_tls13_tickets = 0;
    cfg.max_early_data_size = 0;
    Ok(Arc::new(cfg))
}

/// Cấu hình máy khách: TLS 1.3, ALPN `tsulink/1`, gửi chứng thư của mình, chỉ nhận máy chủ có đúng `expected_fp`.
pub fn client_config(
    identity: &DeviceIdentity,
    expected_fp: &str,
) -> Result<Arc<ClientConfig>, Error> {
    if !crate::is_valid_fingerprint(expected_fp) {
        return Err(Error::BadFingerprint);
    }
    let verifier = Arc::new(PinnedServerVerifier {
        expected: expected_fp.to_owned(),
        algs: algorithms(),
    });
    let mut cfg = ClientConfig::builder_with_provider(provider())
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(tls_err)?
        .dangerous()
        .with_custom_certificate_verifier(verifier)
        .with_client_auth_cert(cert_chain(identity), key_der(identity))
        .map_err(|_| Error::Identity)?;
    cfg.alpn_protocols = vec![ALPN.to_vec()];
    cfg.resumption = rustls::client::Resumption::disabled();
    cfg.enable_early_data = false;
    Ok(Arc::new(cfg))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bo_ghim_bo_qua_van_tay_sai_khuon() {
        let fp = "A".repeat(64);
        let set = PinSet::new([fp.clone(), "abc".into(), "a".repeat(64)]);
        assert!(set.is_paired(&fp));
        assert!(!set.is_paired("abc"));
        assert!(!set.is_paired(&"a".repeat(64)));
        assert!(set.remove(&fp));
        assert!(!set.is_paired(&fp));
    }

    #[test]
    fn cau_hinh_chi_tls13_va_alpn() {
        let id = DeviceIdentity::generate().unwrap();
        let s = server_config(&id, Arc::new(PinSet::default())).unwrap();
        assert_eq!(s.alpn_protocols, vec![ALPN.to_vec()]);
        assert_eq!(s.send_tls13_tickets, 0);
        let c = client_config(&id, id.fingerprint()).unwrap();
        assert_eq!(c.alpn_protocols, vec![ALPN.to_vec()]);
        assert_eq!(
            client_config(&id, "khong-phai-van-tay").unwrap_err(),
            Error::BadFingerprint
        );
    }
}
