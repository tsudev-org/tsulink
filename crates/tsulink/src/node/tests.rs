//! Test trọn đường của mặt tiền [`super::Node`] trên mạng thật: hai thiết bị trong cùng tiến trình, nối qua địa chỉ
//! mạng nội bộ của máy chạy test (loopback bị luật L1 chặn - đúng như app thật). Máy không có địa chỉ nội bộ nào ⇒
//! test tự bỏ qua và in lý do.

use super::*;
use serde_json::json;

fn tmp(name: &str) -> PathBuf {
    let mut rnd = [0u8; 8];
    getrandom::fill(&mut rnd).unwrap();
    let d = std::env::temp_dir().join(format!("tsulink-node-{name}-{}", hex(&rnd)));
    std::fs::create_dir_all(&d).unwrap();
    d
}

fn lan_ip() -> Option<IpAddr> {
    let ip = local_ips().into_iter().find(IpAddr::is_ipv4);
    if ip.is_none() {
        eprintln!("bỏ qua: máy không có địa chỉ IPv4 mạng nội bộ");
    }
    ip
}

fn node(dir: &Path, alias: &str, schema: u32) -> Arc<Node> {
    // Danh tính lưu cạnh dữ liệu chỉ trong test; app thật giữ khoá trong kho bí mật hệ điều hành.
    let (cert, key) = match (std::fs::read(dir.join("c")), std::fs::read(dir.join("k"))) {
        (Ok(c), Ok(k)) => (c, k),
        _ => {
            let id = DeviceIdentity::generate().unwrap();
            std::fs::write(dir.join("c"), id.cert_der()).unwrap();
            std::fs::write(dir.join("k"), id.key_pkcs8_der()).unwrap();
            (id.cert_der().to_vec(), id.key_pkcs8_der().to_vec())
        }
    };
    Node::open(
        NodeConfig {
            data_dir: dir.join("data"),
            app: "qulythuchi".into(),
            alias: alias.into(),
            schema_version: schema,
        },
        &cert,
        &key,
    )
    .unwrap()
}

async fn pair_qr(a: &Arc<Node>, b: &Arc<Node>, ip: IpAddr) {
    let host = a.pairing_host(0).await.unwrap();
    let uri = host.qr_uri(vec![ip]).await.unwrap();
    let h = host.clone();
    let acc = tokio::spawn(async move { h.accept_qr(None).await });
    let joined = b.join_qr(uri, None).await.unwrap();
    let accepted = acc.await.unwrap().unwrap();
    assert_eq!(joined.fingerprint, a.fingerprint());
    assert_eq!(accepted.fingerprint, b.fingerprint());
}

#[tokio::test(flavor = "multi_thread")]
async fn ghep_doi_qr_dong_bo_ban_ghi_tai_lieu_tep_roi_mo_lai() {
    let Some(ip) = lan_ip() else { return };
    let (da, db) = (tmp("a"), tmp("b"));
    let (a, b) = (node(&da, "Máy A", 3), node(&db, "Máy B", 3));
    pair_qr(&a, &b, ip).await;
    assert_eq!(a.devices().len(), 1);
    assert_eq!(b.devices()[0].alias, "Máy A");

    a.write("chi", "1", json!({"so_tien": 100})).unwrap();
    b.write("chi", "2", json!({"so_tien": 7})).unwrap();
    b.write("chi", "3", json!(3)).unwrap();
    b.delete("chi", "3").unwrap();
    let mut am = AutoCommit::new();
    {
        use automerge::transaction::Transactable;
        am.put(automerge::ROOT, "ghi_chu", "từ B").unwrap();
    }
    b.doc_merge("so-tay", &am.save()).await.unwrap();
    let src = db.join("anh.bin");
    std::fs::write(&src, vec![7u8; 1_500_000]).unwrap();
    let hash = b.file_import(&src).await.unwrap();
    assert_eq!(
        b.file_import(&src).await.unwrap(),
        hash,
        "nhập lại cùng tệp không đổi"
    );

    let l = b.listen(0).await.unwrap();
    let port = l.port().await.unwrap();
    let srv = tokio::spawn(async move { l.serve_one(vec![], None, None).await });
    let seen = Arc::new(std::sync::Mutex::new(0u64));
    let s2 = seen.clone();
    let rep = a
        .sync_with(
            b.fingerprint().to_owned(),
            SocketAddr::new(ip, port),
            vec![hash.clone()],
            Some(Box::new(move |_, done, _| *s2.lock().unwrap() = done)),
            None,
        )
        .await
        .unwrap();
    let served = srv.await.unwrap().unwrap();
    assert_eq!(served.peer, a.fingerprint());
    assert_eq!(served.report.rows, 1);
    assert_eq!(rep.rows, 2);
    assert_eq!(rep.docs, 1);
    assert_eq!(rep.files.len(), 1);
    assert_eq!(*seen.lock().unwrap(), 1_500_000);

    assert_eq!(a.read("chi", "2"), Some(json!({"so_tien": 7})));
    assert_eq!(a.read("chi", "3"), None);
    assert_eq!(b.read("chi", "1"), Some(json!({"so_tien": 100})));
    assert!(a.file_path(&hash).is_some());
    let ch = a.changes_after(0, 100);
    assert_eq!(ch.len(), 3, "1 sửa tại chỗ + 2 nhận về (gồm bia mộ)");
    assert!(ch.iter().any(|c| c.key == "3" && c.value.is_none()));

    // Mở lại: mọi thứ còn trên đĩa, đồng bộ lần hai không nhận gì mới.
    let fp_b = b.fingerprint().to_owned();
    drop(a);
    let a = node(&da, "Máy A", 3);
    assert_eq!(a.read("chi", "2"), Some(json!({"so_tien": 7})));
    assert_eq!(a.doc_ids().await, vec!["so-tay".to_owned()]);
    assert!(a.devices()[0].last_sync_at > 0);
    let l = b.listen(0).await.unwrap();
    let port = l.port().await.unwrap();
    let srv = tokio::spawn(async move { l.serve_one(vec![], None, None).await });
    let rep = a
        .sync_with(fp_b, SocketAddr::new(ip, port), vec![], None, None)
        .await
        .unwrap();
    srv.await.unwrap().unwrap();
    assert_eq!((rep.rows, rep.docs), (0, 0));
    for d in [da, db] {
        std::fs::remove_dir_all(d).unwrap();
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn so_ma_so_va_lech_luoc_do() {
    let Some(ip) = lan_ip() else { return };
    let (da, db) = (tmp("sa"), tmp("sb"));
    let (a, b) = (node(&da, "A", 1), node(&db, "B", 2));
    let host = a.pairing_host(0).await.unwrap();
    let port = host.port().await.unwrap();
    let h = host.clone();
    let acc = tokio::spawn(async move { h.accept_sas(30, None).await });
    let sb = b.join_sas(SocketAddr::new(ip, port), None).await.unwrap();
    let sa = acc.await.unwrap().unwrap();
    assert_eq!(sa.code(), sb.code());
    assert_eq!(sa.peer_fingerprint(), b.fingerprint());
    let fa = tokio::spawn({
        let sa = sa.clone();
        async move { sa.finish(true).await }
    });
    sb.finish(true).await.unwrap();
    fa.await.unwrap().unwrap();
    assert_eq!(sb.finish(true).await.unwrap_err(), Error::Closed);

    // Lược đồ khác ⇒ dừng, không trao dữ liệu.
    a.write("t", "k", json!(1)).unwrap();
    let l = b.listen(0).await.unwrap();
    let port = l.port().await.unwrap();
    let srv = tokio::spawn(async move { l.serve_one(vec![], None, None).await });
    let e = a
        .sync_with(
            b.fingerprint().into(),
            SocketAddr::new(ip, port),
            vec![],
            None,
            None,
        )
        .await
        .unwrap_err();
    assert_eq!(
        e,
        Error::SchemaMismatch {
            local: 1,
            remote: 2
        }
    );
    assert!(srv.await.unwrap().is_err());
    assert_eq!(b.read("t", "k"), None);
    for d in [da, db] {
        std::fs::remove_dir_all(d).unwrap();
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn huy_cho_va_tu_choi_thiet_bi_chua_ghep_doi() {
    let d = tmp("huy");
    let a = node(&d, "A", 1);
    let l = a.listen(0).await.unwrap();
    let c = CancelToken::new();
    let c2 = c.clone();
    let t = tokio::spawn(async move { l.serve_one(vec![], None, Some(c2)).await });
    tokio::time::sleep(Duration::from_millis(50)).await;
    c.cancel();
    assert_eq!(t.await.unwrap().unwrap_err(), Error::Cancelled);

    let la = "A".repeat(64);
    let e = a
        .sync_with(la, "192.168.1.2:1".parse().unwrap(), vec![], None, None)
        .await
        .unwrap_err();
    assert_eq!(e, Error::PairingRejected, "không nối tới máy chưa ghép đôi");
    let host = a.pairing_host(0).await.unwrap();
    assert_eq!(
        host.accept_qr(None).await.unwrap_err(),
        Error::InvalidInput("chưa tạo mã QR")
    );
    assert_eq!(
        a.write("", "k", json!(1)).unwrap_err(),
        Error::InvalidInput("table")
    );
    assert!(a.file_path("khong-phai-hash").is_none());
    std::fs::remove_dir_all(d).unwrap();
}

#[test]
fn ma_loi_on_dinh() {
    // Mã đã phát hành không được đổi (ràng buộc .NET/Dart so theo số).
    assert_eq!(Error::Malformed("x").code(), 1);
    assert_eq!(
        Error::SchemaMismatch {
            local: 1,
            remote: 2
        }
        .code(),
        17
    );
    assert_eq!(Error::Cancelled.code(), 20);
    assert_eq!(Error::Closed.code(), 22);
    assert_eq!(unhex(&hex("so-tay".as_bytes())).as_deref(), Some("so-tay"));
    assert_eq!(unhex("zz"), None);
}
