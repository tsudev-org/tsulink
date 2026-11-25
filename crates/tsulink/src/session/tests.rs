//! `LOCAL_SYNC.md` mục 10 - ghép đôi: QR đúng ⇒ thành công; QR hết hạn/dùng lại ⇒ từ chối; vân tay giả ⇒ đóng kết
//! nối; so mã số lệch ⇒ huỷ; quá 5 lần sai ⇒ khoá.

use super::*;
use crate::devices::InMemoryDeviceStore;

const T0: u64 = 1_795_000_000;
const APP: &str = "qulythuchi";

async fn host(id: &DeviceIdentity) -> PairingHost {
    PairingHost::bind_inner(id, "127.0.0.1:0".parse().unwrap(), true)
        .await
        .unwrap()
}

/// Lời mời trỏ về loopback (PairingOffer::new chỉ nhận mạng nội bộ thật).
fn offer(h: &PairingHost, id: &DeviceIdentity, token: [u8; 16]) -> PairingOffer {
    PairingOffer {
        app: APP.into(),
        fingerprint: id.fingerprint().into(),
        addrs: vec![h.local_addr().unwrap()],
        token,
        expires_at: T0 + 120,
    }
}

#[tokio::test]
async fn qr_dung_thi_hai_ben_luu_van_tay_nhau() {
    let a = DeviceIdentity::generate().unwrap();
    let b = DeviceIdentity::generate().unwrap();
    let mut h = host(&a).await;
    let o = offer(&h, &a, [7; 16]);
    let o2 = o.clone();
    let sa = Arc::new(InMemoryDeviceStore::default());
    let sa2 = sa.clone();
    let srv = tokio::spawn(async move {
        let mut lim = AttemptLimiter::default();
        h.accept_qr(o2, "Máy A", sa2.as_ref(), &mut lim, || T0 + 5)
            .await
    });
    let sb = InMemoryDeviceStore::default();
    let got_b = join_offer(&b, &o, "Máy B", &sb, T0 + 5, true)
        .await
        .unwrap();
    let got_a = srv.await.unwrap().unwrap();
    assert_eq!(got_b.fingerprint, a.fingerprint());
    assert_eq!(got_b.alias, "Máy A");
    assert_eq!(got_a.fingerprint, b.fingerprint());
    assert_eq!(got_a.alias, "Máy B");
    assert!(sa.get(b.fingerprint()).is_some());
    assert!(sb.get(a.fingerprint()).is_some());
}

use std::sync::Arc;

#[tokio::test]
async fn qr_het_han_bi_tu_choi() {
    let a = DeviceIdentity::generate().unwrap();
    let mut h = host(&a).await;
    let o = offer(&h, &a, [7; 16]);
    let mut lim = AttemptLimiter::default();
    let r = h
        .accept_qr(o, "A", &InMemoryDeviceStore::default(), &mut lim, || {
            T0 + 120
        })
        .await;
    assert_eq!(r.unwrap_err(), Error::Expired);
}

#[tokio::test]
async fn ma_sai_bi_tu_choi_va_qr_chi_dung_mot_lan() {
    let a = DeviceIdentity::generate().unwrap();
    let b = DeviceIdentity::generate().unwrap();
    let c = DeviceIdentity::generate().unwrap();
    let mut h = host(&a).await;
    let o = offer(&h, &a, [7; 16]);
    let o2 = o.clone();
    let srv = tokio::spawn(async move {
        let mut lim = AttemptLimiter::default();
        let s = InMemoryDeviceStore::default();
        let r = h.accept_qr(o2, "A", &s, &mut lim, || T0 + 5).await;
        (r, h)
    });
    // Mã sai ⇒ bị từ chối, A vẫn chờ.
    let mut wrong = o.clone();
    wrong.token = [8; 16];
    let r = join_offer(&c, &wrong, "C", &InMemoryDeviceStore::default(), T0, true).await;
    assert_eq!(r.unwrap_err(), Error::PairingRejected);
    // Mã đúng ⇒ thành công.
    join_offer(&b, &o, "B", &InMemoryDeviceStore::default(), T0, true)
        .await
        .unwrap();
    let (r, h) = srv.await.unwrap();
    assert_eq!(r.unwrap().fingerprint, b.fingerprint());
    // Lời mời đã tiêu (accept_qr nhận theo giá trị); máy A không còn nghe ⇒ dùng lại QR không được gì.
    drop(h);
    let again = join_offer(&c, &o, "C", &InMemoryDeviceStore::default(), T0, true).await;
    assert!(again.is_err());
}

#[tokio::test]
async fn van_tay_gia_bi_dong_ket_noi() {
    let a = DeviceIdentity::generate().unwrap();
    let mitm = DeviceIdentity::generate().unwrap();
    let b = DeviceIdentity::generate().unwrap();
    // Kẻ đứng giữa nghe ở địa chỉ trong QR nhưng có chứng thư khác vân tay A.
    let mut h = host(&mitm).await;
    let o = offer(&h, &a, [7; 16]);
    let o2 = o.clone();
    tokio::spawn(async move {
        let mut lim = AttemptLimiter::default();
        let _ = h
            .accept_qr(o2, "M", &InMemoryDeviceStore::default(), &mut lim, || T0)
            .await;
    });
    let r = join_offer(&b, &o, "B", &InMemoryDeviceStore::default(), T0, true).await;
    assert!(matches!(r, Err(Error::Tls(_))), "{r:?}");
}

#[test]
fn khoa_10_phut_sau_5_lan_sai() {
    let mut l = AttemptLimiter::default();
    for i in 0..4 {
        l.failure(T0 + i);
        assert!(l.check(T0 + i).is_ok());
    }
    l.failure(T0 + 4);
    assert_eq!(
        l.check(T0 + 4).unwrap_err(),
        Error::Locked(T0 + 4 + LOCK_SECS)
    );
    assert!(l.check(T0 + 4 + LOCK_SECS - 1).is_err());
    assert!(l.check(T0 + 4 + LOCK_SECS).is_ok());
    // Lần sai cách nhau > 10 phút không cộng dồn.
    let mut l = AttemptLimiter::default();
    for i in 0..10 {
        l.failure(T0 + i * FAILURE_WINDOW_SECS);
    }
    assert!(l.check(T0 + 10 * FAILURE_WINDOW_SECS).is_ok());
}

#[tokio::test]
async fn qr_sai_5_lan_thi_khoa() {
    let a = DeviceIdentity::generate().unwrap();
    let c = DeviceIdentity::generate().unwrap();
    let mut h = host(&a).await;
    let o = offer(&h, &a, [7; 16]);
    let o2 = o.clone();
    let srv = tokio::spawn(async move {
        let mut lim = AttemptLimiter::default();
        h.accept_qr(o2, "A", &InMemoryDeviceStore::default(), &mut lim, || T0)
            .await
    });
    let mut wrong = o.clone();
    wrong.token = [9; 16];
    for _ in 0..5 {
        let r = join_offer(&c, &wrong, "C", &InMemoryDeviceStore::default(), T0, true).await;
        assert!(r.is_err());
    }
    assert_eq!(
        srv.await.unwrap().unwrap_err(),
        Error::Locked(T0 + LOCK_SECS)
    );
}

async fn sas_pair(
    confirm_a: bool,
    confirm_b: bool,
) -> (
    Result<PairedDevice, Error>,
    Result<PairedDevice, Error>,
    String,
    String,
) {
    let a = DeviceIdentity::generate().unwrap();
    let b = DeviceIdentity::generate().unwrap();
    let mut h = host(&a).await;
    let addr = h.local_addr().unwrap();
    let srv = tokio::spawn(async move {
        let s = h.accept_sas("Máy A", Duration::from_secs(5)).await.unwrap();
        let code = s.code().to_owned();
        let mut lim = AttemptLimiter::default();
        let st = InMemoryDeviceStore::default();
        (s.finish(confirm_a, &st, &mut lim, T0).await, code)
    });
    let s = join_sas_inner(&b, addr, "Máy B", true).await.unwrap();
    let code_b = s.code().to_owned();
    assert_eq!(s.peer_alias(), "Máy A");
    assert_eq!(s.peer_fingerprint(), a.fingerprint());
    let mut lim = AttemptLimiter::default();
    let rb = s
        .finish(confirm_b, &InMemoryDeviceStore::default(), &mut lim, T0)
        .await;
    let (ra, code_a) = srv.await.unwrap();
    (ra, rb, code_a, code_b)
}

#[tokio::test]
async fn so_ma_so_hai_may_cung_ma_va_ca_hai_xac_nhan() {
    let (ra, rb, ca, cb) = sas_pair(true, true).await;
    assert_eq!(ca, cb);
    assert_eq!(ca.len(), 6);
    assert!(ra.is_ok() && rb.is_ok());
}

#[tokio::test]
async fn so_ma_so_mot_ben_tu_choi_thi_khong_ai_luu() {
    let (ra, rb, _, _) = sas_pair(true, false).await;
    assert_eq!(ra.unwrap_err(), Error::PairingRejected);
    assert_eq!(rb.unwrap_err(), Error::PairingRejected);
}

#[test]
fn cam_ket_nonce_rang_buoc_dung_nonce() {
    let n = rand16().unwrap();
    let mut m = n;
    m[15] ^= 1;
    assert_ne!(commit_of(&n), commit_of(&m));
    assert_eq!(commit_of(&n).len(), 64);
}

#[tokio::test]
async fn dia_chi_cong_cong_bi_tu_choi() {
    let a = DeviceIdentity::generate().unwrap();
    let r = join_sas(&a, "8.8.8.8:443".parse().unwrap(), "A").await;
    assert!(matches!(r, Err(Error::PublicAddress(_))));
    assert!(matches!(
        PairingHost::bind(&a, "8.8.8.8:0".parse().unwrap()).await,
        Err(Error::PublicAddress(_))
    ));
}

#[tokio::test]
async fn ket_noi_dong_bo_khong_vao_duoc_cong_ghep_doi() {
    // ALPN khác nhau: máy khách đồng bộ (tsulink/1) không bắt tay được với cổng ghép đôi.
    let a = DeviceIdentity::generate().unwrap();
    let b = DeviceIdentity::generate().unwrap();
    let mut h = host(&a).await;
    let addr = h.local_addr().unwrap();
    tokio::spawn(async move {
        let _ = h.accept_sas("A", Duration::from_secs(3)).await;
    });
    let r = crate::transport::connect_inner(&b, a.fingerprint(), addr, true).await;
    assert!(r.is_err());
}
