//! `LOCAL_SYNC.md` mục 10 - CRDT: hai máy sửa cùng bản ghi ngoại tuyến ⇒ gộp đúng quy tắc ADR-0004; xoá + sửa đồng
//! thời; đứt giữa chừng ⇒ nối lại, không nhân đôi; lược đồ khác ⇒ dừng. Thêm: Automerge, tệp khối BLAKE3, chạy thật
//! trên mTLS `tsulink/1`.

use super::table::{InMemoryRowStore, Replica, RowStore};
use super::*;
use automerge::transaction::Transactable;
use automerge::{ROOT, ReadDoc};
use serde_json::json;
use std::pin::Pin;
use std::task::{Context, Poll};
use tokio::io::{AsyncWriteExt, DuplexStream, ReadBuf};

const CFG: fn() -> SyncConfig = || SyncConfig {
    app: "qulythuchi".into(),
    schema_version: 3,
};
const FP_A: &str = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
const FP_B: &str = "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB";
const NOW: u64 = 1_795_000_000_000;

fn replica(fp: &str) -> Replica<InMemoryRowStore> {
    Replica::new(fp, InMemoryRowStore::new().unwrap())
}

fn no_files() -> impl FileProvider {
    |_: &str| None
}

fn pipe() -> (DuplexStream, DuplexStream) {
    tokio::io::duplex(4 << 20)
}

/// Luồng ghi được `left` byte rồi gãy (giả lập đứt Wi-Fi).
struct CutAfter<S> {
    inner: S,
    left: usize,
}

impl<S: AsyncRead + Unpin> AsyncRead for CutAfter<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for CutAfter<S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        if self.left == 0 {
            return Poll::Ready(Err(std::io::ErrorKind::BrokenPipe.into()));
        }
        let n = buf.len().min(self.left);
        let r = Pin::new(&mut self.inner).poll_write(cx, &buf[..n]);
        if let Poll::Ready(Ok(k)) = r {
            self.left -= k;
        }
        r
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

/// Thư mục tạm riêng cho mỗi test, tự xoá.
struct TmpDir(PathBuf);
impl TmpDir {
    fn new() -> Self {
        let mut r = [0u8; 8];
        getrandom::fill(&mut r).unwrap();
        let p = std::env::temp_dir().join(format!("tsulink-test-{:016x}", u64::from_le_bytes(r)));
        std::fs::create_dir_all(&p).unwrap();
        Self(p)
    }
}
impl Drop for TmpDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn random_bytes(n: usize) -> Vec<u8> {
    let mut v = vec![0u8; n];
    getrandom::fill(&mut v).unwrap();
    v
}

async fn sync_rows(a: &Replica<InMemoryRowStore>, b: &Replica<InMemoryRowStore>) -> (usize, usize) {
    let (mut x, mut y) = pipe();
    let fa = async {
        let n = pull_rows(&mut x, a, FP_B, NOW).await.unwrap();
        serve_rows(&mut x, a).await.unwrap();
        n
    };
    let fb = async {
        serve_rows(&mut y, b).await.unwrap();
        pull_rows(&mut y, b, FP_A, NOW).await.unwrap()
    };
    tokio::join!(fa, fb)
}

#[tokio::test]
async fn hai_may_sua_cung_ban_ghi_ngoai_tuyen_gop_theo_lww() {
    let a = replica(FP_A);
    let b = replica(FP_B);
    a.write("chi", "1", json!({"so_tien": 100}), NOW - 2000)
        .unwrap();
    a.write("chi", "chi-a", json!(1), NOW - 2000).unwrap();
    b.write("chi", "1", json!({"so_tien": 250}), NOW - 1000)
        .unwrap();
    b.write("chi", "chi-b", json!(2), NOW - 1000).unwrap();
    let (na, nb) = sync_rows(&a, &b).await;
    assert_eq!((na, nb), (2, 1)); // A nhận "1" (B sửa sau) + "chi-b"; B chỉ nhận "chi-a".
    for r in [&a, &b] {
        assert_eq!(r.read("chi", "1"), Some(json!({"so_tien": 250})));
        assert_eq!(r.read("chi", "chi-a"), Some(json!(1)));
        assert_eq!(r.read("chi", "chi-b"), Some(json!(2)));
    }
    // Lần hai: không còn gì mới (con trỏ đã lưu), không nhân đôi.
    assert_eq!(sync_rows(&a, &b).await, (0, 0));
}

#[tokio::test]
async fn xoa_va_sua_dong_thoi_qua_giao_thuc() {
    let a = replica(FP_A);
    let b = replica(FP_B);
    a.write("chi", "1", json!(1), NOW - 5000).unwrap();
    sync_rows(&a, &b).await;
    b.write("chi", "1", json!(2), NOW - 3000).unwrap();
    a.delete("chi", "1", NOW - 2000).unwrap();
    sync_rows(&a, &b).await;
    assert_eq!(a.read("chi", "1"), None);
    assert_eq!(b.read("chi", "1"), None);
    assert!(b.store().get("chi", "1").unwrap().value.is_none()); // bia mộ được truyền đi
}

#[tokio::test]
async fn ba_may_khong_sot_phien_ban_den_muon() {
    // A đã đọc hết nhật ký B; sau đó B nhận từ C một phiên bản có mốc NHỎ hơn mọi thứ A đã thấy.
    let a = replica(FP_A);
    let b = replica(FP_B);
    let c = replica("CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC");
    c.write("t", "tu-c", json!("c"), NOW - 9000).unwrap();
    b.write("t", "tu-b", json!("b"), NOW - 1000).unwrap();
    sync_rows(&a, &b).await;
    for (_, r) in c.store().changes_after(0, 10) {
        b.merge(r, NOW).unwrap();
    }
    sync_rows(&a, &b).await;
    assert_eq!(a.read("t", "tu-c"), Some(json!("c")));
}

#[tokio::test]
async fn dut_giua_chung_thi_noi_lai_khong_nhan_doi() {
    let a = replica(FP_A);
    let b = replica(FP_B);
    let total = ROWS_PER_BATCH * 2 + 100;
    for i in 0..total {
        b.write("chi", &format!("{i:05}"), json!({"i": i}), NOW - 10_000)
            .unwrap();
    }
    // Lần 1: luồng của B gãy sau khoảng 1,5 lô.
    let (mut x, y) = pipe();
    let mut y = CutAfter {
        inner: y,
        left: 120_000,
    };
    let (ra, _) = tokio::join!(pull_rows(&mut x, &a, FP_B, NOW), async {
        let r = serve_rows(&mut y, &b).await;
        drop(y);
        r
    });
    assert!(ra.is_err());
    let cur = a
        .store()
        .cursor(FP_B)
        .expect("lô đầu đã gộp và lưu con trỏ");
    assert!(cur.seq > 0 && (cur.seq as usize) < total);
    let first = a.store().changes_after(0, usize::MAX).len();
    assert_eq!(first, cur.seq as usize);
    // Lần 2: nối tiếp từ con trỏ, chỉ nhận phần còn lại.
    let (na, _) = sync_rows(&a, &b).await;
    assert_eq!(first + na, total);
    assert_eq!(a.store().changes_after(0, usize::MAX).len(), total);
    assert_eq!(a.read("chi", "00000"), Some(json!({"i": 0})));
    assert_eq!(
        a.read("chi", &format!("{:05}", total - 1)),
        Some(json!({"i": total - 1}))
    );
}

#[tokio::test]
async fn kho_lam_lai_thi_doc_lai_tu_dau() {
    let a = replica(FP_A);
    let b = replica(FP_B);
    b.write("t", "k", json!(1), NOW - 10).unwrap();
    sync_rows(&a, &b).await;
    // B cài lại app: kho mới, mã nhật ký mới, seq bắt đầu lại từ 1.
    let b2 = replica(FP_B);
    b2.write("t", "moi", json!(2), NOW - 5).unwrap();
    sync_rows(&a, &b2).await;
    assert_eq!(a.read("t", "moi"), Some(json!(2)));
    assert_eq!(b2.read("t", "k"), Some(json!(1))); // A trả lại dữ liệu cho B
}

#[tokio::test]
async fn khac_luoc_do_thi_dung() {
    let (mut x, mut y) = pipe();
    let old = SyncConfig {
        schema_version: 2,
        ..CFG()
    };
    let cfg = CFG();
    let (ra, rb) = tokio::join!(handshake(&mut x, &cfg), handshake(&mut y, &old));
    assert_eq!(
        ra,
        Err(Error::SchemaMismatch {
            local: 3,
            remote: 2
        })
    );
    assert_eq!(
        rb,
        Err(Error::SchemaMismatch {
            local: 2,
            remote: 3
        })
    );
    let other_app = SyncConfig {
        app: "tsuscan".into(),
        ..CFG()
    };
    let (mut x, mut y) = pipe();
    let (ra, _) = tokio::join!(handshake(&mut x, &cfg), handshake(&mut y, &other_app));
    assert_eq!(ra, Err(Error::Protocol("khác app")));
}

#[tokio::test]
async fn khac_luoc_do_thi_run_khong_dong_du_lieu() {
    let a = replica(FP_A);
    let b = replica(FP_B);
    b.write("t", "k", json!(1), NOW).unwrap();
    let (mut x, mut y) = pipe();
    let (mut da, mut db) = (BTreeMap::new(), BTreeMap::new());
    let (fa, fb) = (no_files(), no_files());
    let old = SyncConfig {
        schema_version: 2,
        ..CFG()
    };
    let cfg = CFG();
    let (mut pa, mut pb) = (|_: &str, _, _| {}, |_: &str, _, _| {});
    let (ra, rb) = tokio::join!(
        run(
            &mut x,
            Role::Initiator,
            &cfg,
            FP_B,
            SyncData {
                replica: &a,
                docs: &mut da,
                files: &fa,
                wanted: vec![]
            },
            NOW,
            &mut pa
        ),
        run(
            &mut y,
            Role::Responder,
            &old,
            FP_A,
            SyncData {
                replica: &b,
                docs: &mut db,
                files: &fb,
                wanted: vec![]
            },
            NOW,
            &mut pb
        )
    );
    assert!(matches!(ra, Err(Error::SchemaMismatch { .. })));
    assert!(matches!(rb, Err(Error::SchemaMismatch { .. })));
    assert_eq!(a.read("t", "k"), None);
}

fn doc_with(text: &str) -> AutoCommit {
    let mut d = AutoCommit::new();
    d.put(ROOT, "ghi_chu", text).unwrap();
    d
}

fn doc_text(d: &AutoCommit, key: &str) -> Option<String> {
    d.get(ROOT, key)
        .unwrap()
        .map(|(v, _)| v.into_string().unwrap_or_default())
}

#[tokio::test]
async fn automerge_gop_tai_lieu_hai_chieu_va_tao_tai_lieu_thieu() {
    let mut base = doc_with("chung");
    let mut da = BTreeMap::new();
    let mut db = BTreeMap::new();
    let mut fork = base.fork();
    base.put(ROOT, "a_sua", "tu A").unwrap();
    fork.put(ROOT, "b_sua", "tu B").unwrap();
    da.insert("so-chi".to_string(), base);
    db.insert("so-chi".to_string(), fork);
    db.insert("chi-co-o-b".to_string(), doc_with("rieng B"));
    let (mut x, mut y) = pipe();
    let (ra, rb) = tokio::join!(
        sync_docs(&mut x, Role::Initiator, &mut da),
        sync_docs(&mut y, Role::Responder, &mut db)
    );
    assert_eq!(ra.unwrap(), 2);
    assert_eq!(rb.unwrap(), 1);
    for docs in [&mut da, &mut db] {
        let d = docs.get_mut("so-chi").unwrap();
        assert_eq!(doc_text(d, "a_sua").as_deref(), Some("tu A"));
        assert_eq!(doc_text(d, "b_sua").as_deref(), Some("tu B"));
        assert_eq!(doc_text(d, "ghi_chu").as_deref(), Some("chung"));
    }
    assert_eq!(
        doc_text(&da["chi-co-o-b"], "ghi_chu").as_deref(),
        Some("rieng B")
    );
    assert_eq!(
        da.get_mut("so-chi").unwrap().get_heads(),
        db.get_mut("so-chi").unwrap().get_heads()
    );
    // Lần hai: không có thay đổi.
    let (mut x, mut y) = pipe();
    let (ra, rb) = tokio::join!(
        sync_docs(&mut x, Role::Initiator, &mut da),
        sync_docs(&mut y, Role::Responder, &mut db)
    );
    assert_eq!((ra.unwrap(), rb.unwrap()), (0, 0));
}

#[tokio::test]
async fn tep_khoi_blake3_dut_giua_chung_noi_lai_tu_khoi_thieu() {
    let dir = TmpDir::new();
    let src = dir.0.join("nguon.bin");
    let body = random_bytes(3 * file::CHUNK_SIZE + 12345);
    std::fs::write(&src, &body).unwrap();
    let hash = file::hash_hex(&body);
    let dest = dir.0.join("dich.bin");
    std::fs::write(&dest, b"ban cu").unwrap();
    let src2 = src.clone();
    let provider =
        move |h: &str| (h == file::hash_hex(&std::fs::read(&src2).unwrap())).then(|| src2.clone());

    // Lần 1: đứt sau khoảng 1,5 khối.
    let (mut x, y) = pipe();
    let mut y = CutAfter {
        inner: y,
        left: file::CHUNK_SIZE * 3 / 2,
    };
    let mut on_progress = |_: &str, _, _| {};
    let (r, _) = tokio::join!(fetch_file(&mut x, &hash, &dest, &mut on_progress), async {
        let r = serve_files(&mut y, &provider).await;
        drop(y);
        r
    });
    assert!(r.is_err());
    assert_eq!(std::fs::read(&dest).unwrap(), b"ban cu"); // bản cũ còn nguyên khi chưa đủ
    let part = dir.0.join("dich.bin.tsulink-part");
    assert_eq!(
        std::fs::metadata(&part).unwrap().len(),
        file::CHUNK_SIZE as u64
    );

    // Lần 2: nối từ khối 1, không nhận lại khối 0.
    let (mut x, mut y) = pipe();
    let mut seen = Vec::new();
    let (r, s) = tokio::join!(
        async {
            let r = fetch_file(&mut x, &hash, &dest, &mut |_, got, _| seen.push(got)).await;
            finish_files(&mut x).await.unwrap();
            r
        },
        serve_files(&mut y, &provider)
    );
    s.unwrap();
    assert_eq!(r.unwrap(), Some(dest.clone()));
    assert_eq!(seen.first(), Some(&(file::CHUNK_SIZE as u64)));
    assert_eq!(seen.last(), Some(&(body.len() as u64)));
    assert_eq!(std::fs::read(&dest).unwrap(), body);
    assert!(!part.exists());
}

#[tokio::test]
async fn tep_do_bi_sua_thi_bo_khoi_hong_va_nhan_lai() {
    let dir = TmpDir::new();
    let body = random_bytes(2 * file::CHUNK_SIZE + 7);
    let src = dir.0.join("nguon.bin");
    std::fs::write(&src, &body).unwrap();
    let dest = dir.0.join("dich.bin");
    // Tệp dở: khối 0 đúng, khối 1 bị lật một byte.
    let mut bad = body[..2 * file::CHUNK_SIZE].to_vec();
    bad[file::CHUNK_SIZE + 5] ^= 1;
    std::fs::write(dir.0.join("dich.bin.tsulink-part"), &bad).unwrap();
    let m = file::Manifest::of_file(&src).await.unwrap();
    let rx = file::Receiver::open(&dest, m.clone()).await.unwrap();
    assert_eq!(rx.next_chunk(), 1);
    drop(rx);
    let (mut x, mut y) = pipe();
    let hash = m.hash.clone();
    let p = src.clone();
    let provider = move |_: &str| Some(p.clone());
    let (r, s) = tokio::join!(
        async {
            let r = fetch_file(&mut x, &hash, &dest, &mut |_, _, _| {}).await;
            finish_files(&mut x).await.unwrap();
            r
        },
        serve_files(&mut y, &provider)
    );
    s.unwrap();
    r.unwrap();
    assert_eq!(std::fs::read(&dest).unwrap(), body);
}

#[tokio::test]
async fn khoi_sai_blake3_bi_tu_choi() {
    let dir = TmpDir::new();
    let body = random_bytes(file::CHUNK_SIZE + 1);
    let src = dir.0.join("nguon.bin");
    std::fs::write(&src, &body).unwrap();
    let m = file::Manifest::of_file(&src).await.unwrap();
    let mut rx = file::Receiver::open(&dir.0.join("dich.bin"), m)
        .await
        .unwrap();
    let mut chunk = body[..file::CHUNK_SIZE].to_vec();
    chunk[0] ^= 0xff;
    assert_eq!(
        rx.push(&chunk).await,
        Err(Error::Corrupt("khối sai BLAKE3"))
    );
    assert_eq!(rx.next_chunk(), 0);
    rx.push(&body[..file::CHUNK_SIZE]).await.unwrap();
    rx.push(&body[file::CHUNK_SIZE..]).await.unwrap();
    assert!(rx.finish().await.is_ok());
}

#[tokio::test]
async fn tep_rong_va_tep_may_kia_khong_co() {
    let dir = TmpDir::new();
    let empty = dir.0.join("rong");
    std::fs::write(&empty, b"").unwrap();
    let e = empty.clone();
    let provider = move |h: &str| (h == file::hash_hex(b"")).then(|| e.clone());
    let (mut x, mut y) = pipe();
    let dest = dir.0.join("rong-nhan");
    let none_hash = file::hash_hex(b"khong co");
    let (r, s) = tokio::join!(
        async {
            let a = fetch_file(&mut x, &file::hash_hex(b""), &dest, &mut |_, _, _| {}).await;
            let b = fetch_file(&mut x, &none_hash, &dir.0.join("x"), &mut |_, _, _| {}).await;
            finish_files(&mut x).await.unwrap();
            (a, b)
        },
        serve_files(&mut y, &provider)
    );
    s.unwrap();
    assert_eq!(r.0.unwrap(), Some(dest.clone()));
    assert_eq!(std::fs::read(&dest).unwrap(), b"");
    assert_eq!(r.1.unwrap(), None);
}

#[tokio::test]
async fn khung_qua_lon_bi_tu_choi() {
    let (mut x, mut y) = pipe();
    x.write_all(&((frame::MAX_BLOB as u32) + 1).to_be_bytes())
        .await
        .unwrap();
    assert_eq!(
        recv(&mut y).await.unwrap_err(),
        Error::Protocol("khung quá lớn")
    );
}

#[tokio::test]
async fn tron_phien_tren_mtls_tsulink_1() {
    use crate::identity::DeviceIdentity;
    use crate::tls::PinSet;
    use crate::transport::{Listener, connect_inner};
    use std::sync::Arc;

    let ia = DeviceIdentity::generate().unwrap();
    let ib = DeviceIdentity::generate().unwrap();
    let (fa, fb) = (ia.fingerprint().to_owned(), ib.fingerprint().to_owned());
    let mut l = Listener::bind_inner(
        &ib,
        Arc::new(PinSet::new(vec![fa.clone()])),
        "127.0.0.1:0".parse().unwrap(),
        true,
    )
    .await
    .unwrap();
    let addr = l.local_addr().unwrap();

    let dir = TmpDir::new();
    let anh = random_bytes(file::CHUNK_SIZE + 99);
    let anh_hash = file::hash_hex(&anh);
    let anh_b = dir.0.join("anh-b.jpg");
    std::fs::write(&anh_b, &anh).unwrap();

    let a = replica(&fa);
    a.write("chi", "1", json!({"so_tien": 50}), NOW - 100)
        .unwrap();
    let fb2 = fb.clone();
    let srv = tokio::spawn(async move {
        let b = replica(&fb2);
        b.write("chi", "2", json!({"anh": anh_hash}), NOW - 50)
            .unwrap();
        let mut docs = BTreeMap::from([("ghi-chu".to_string(), doc_with("tu B"))]);
        let p = anh_b.clone();
        let files =
            move |h: &str| (h == file::hash_hex(&std::fs::read(&p).unwrap())).then(|| p.clone());
        let mut c = l.accept().await.unwrap();
        let rep = run(
            &mut c.stream,
            Role::Responder,
            &CFG(),
            &c.fingerprint,
            SyncData {
                replica: &b,
                docs: &mut docs,
                files: &files,
                wanted: vec![],
            },
            NOW,
            &mut |_, _, _| {},
        )
        .await
        .unwrap();
        (rep, b.read("chi", "1"))
    });

    let mut c = connect_inner(&ia, &fb, addr, true).await.unwrap();
    let mut docs = BTreeMap::new();
    let dest = dir.0.join("anh-a.jpg");
    let rep = run(
        &mut c.stream,
        Role::Initiator,
        &CFG(),
        &fb,
        SyncData {
            replica: &a,
            docs: &mut docs,
            files: &no_files(),
            wanted: vec![(file::hash_hex(&anh), dest.clone())],
        },
        NOW,
        &mut |_, _, _| {},
    )
    .await
    .unwrap();
    let (rep_b, b_has) = srv.await.unwrap();
    assert_eq!(rep.rows, 1);
    assert_eq!(rep.docs, 1);
    assert_eq!(rep.files, vec![dest.clone()]);
    assert_eq!(rep_b.rows, 1);
    assert_eq!(b_has, Some(json!({"so_tien": 50})));
    assert_eq!(std::fs::read(&dest).unwrap(), anh);
    assert_eq!(
        doc_text(&docs["ghi-chu"], "ghi_chu").as_deref(),
        Some("tu B")
    );
}
