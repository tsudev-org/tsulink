//! Test C ABI qua đúng các hàm `extern "C"` (như .NET gọi), trên mạng nội bộ thật.

use std::collections::BTreeSet;
use std::ffi::{CStr, CString, c_char, c_void};
use std::ptr::{null, null_mut};
use std::sync::atomic::{AtomicU64, Ordering};
use tsulink::*;
use tsulink_core::Error;

fn c(s: &str) -> CString {
    CString::new(s).unwrap()
}

/// Lấy chuỗi ra rồi giải phóng.
fn take(p: *mut c_char) -> Option<String> {
    if p.is_null() {
        return None;
    }
    let s = unsafe { CStr::from_ptr(p) }.to_str().unwrap().to_owned();
    unsafe { tsulink_string_free(p) };
    Some(s)
}

fn last_error() -> String {
    unsafe { CStr::from_ptr(tsulink_last_error()) }
        .to_string_lossy()
        .into_owned()
}

#[track_caller]
fn ok(rc: i32) {
    assert_eq!(rc, 0, "lỗi {rc}: {}", last_error());
}

struct Dev {
    node: *mut TsulinkNode,
    dir: std::path::PathBuf,
}
// SAFETY (test): TsulinkNode dùng được từ nhiều luồng (hợp đồng của thư viện).
unsafe impl Send for Dev {}
unsafe impl Sync for Dev {}

impl Drop for Dev {
    fn drop(&mut self) {
        unsafe { tsulink_node_free(self.node) };
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

fn open(alias: &str, schema: u32) -> Dev {
    let (mut cert, mut cl, mut key, mut kl) = (null_mut(), 0, null_mut(), 0);
    ok(unsafe { tsulink_identity_generate(&mut cert, &mut cl, &mut key, &mut kl) });
    let dir = std::env::temp_dir().join(format!(
        "tsulink-capi-{alias}-{}-{:?}",
        std::process::id(),
        std::thread::current().id()
    ));
    let _ = std::fs::remove_dir_all(&dir);
    let cfg = serde_json::json!({
        "data_dir": dir, "app": "qulythuchi", "alias": alias, "schema_version": schema
    })
    .to_string();
    let mut node = null_mut();
    ok(unsafe { tsulink_node_open(c(&cfg).as_ptr(), cert, cl, key, kl, &mut node) });
    unsafe {
        tsulink_bytes_free(cert, cl);
        tsulink_bytes_free(key, kl);
    }
    Dev { node, dir }
}

fn fingerprint(d: &Dev) -> String {
    let mut out = null_mut();
    ok(unsafe { tsulink_node_fingerprint(d.node, &mut out) });
    take(out).unwrap()
}

fn lan_ip() -> Option<String> {
    let mut out = null_mut();
    ok(unsafe { tsulink_local_ips(&mut out) });
    let ips: Vec<String> = serde_json::from_str(&take(out).unwrap()).unwrap();
    let ip = ips.into_iter().find(|i| !i.contains(':'));
    if ip.is_none() {
        eprintln!("bỏ qua: máy không có địa chỉ IPv4 mạng nội bộ");
    }
    ip
}

static PROGRESS: AtomicU64 = AtomicU64::new(0);

unsafe extern "C" fn on_progress(user: *mut c_void, hash: *const c_char, done: u64, _total: u64) {
    assert_eq!(user as usize, 0x7505);
    assert_eq!(unsafe { CStr::from_ptr(hash) }.to_bytes().len(), 64);
    PROGRESS.store(done, Ordering::SeqCst);
}

#[test]
fn ghep_doi_qr_dong_bo_va_doc_lai_qua_c_abi() {
    let Some(ip) = lan_ip() else { return };
    let (a, b) = (open("A", 4), open("B", 4));
    let (fa, fb) = (fingerprint(&a), fingerprint(&b));

    // Ghép đôi bằng QR: A mở cổng, B quét.
    let mut host = null_mut();
    ok(unsafe { tsulink_pairing_host_open(a.node, 0, &mut host) });
    let ips = c(&format!("[\"{ip}\"]"));
    let mut uri = null_mut();
    ok(unsafe { tsulink_pairing_host_qr_uri(host, ips.as_ptr(), &mut uri) });
    let uri = take(uri).unwrap();
    assert!(uri.starts_with("tsulink:1?"));
    let host_addr = host as usize;
    let t = std::thread::spawn(move || {
        let mut out = null_mut();
        let rc = unsafe { tsulink_pairing_host_accept_qr(host_addr as *const _, null(), &mut out) };
        (rc, take(out))
    });
    let mut dev = null_mut();
    ok(unsafe { tsulink_join_qr(b.node, c(&uri).as_ptr(), null(), &mut dev) });
    let dev: serde_json::Value = serde_json::from_str(&take(dev).unwrap()).unwrap();
    assert_eq!(dev["fingerprint"], fa.as_str());
    let (rc, acc) = t.join().unwrap();
    ok(rc);
    assert!(acc.unwrap().contains(&fb));
    unsafe { tsulink_pairing_host_free(host) };

    // Dữ liệu ở B: bản ghi, tài liệu rỗng, tệp.
    ok(unsafe {
        tsulink_node_write(
            b.node,
            c("chi").as_ptr(),
            c("1").as_ptr(),
            c(r#"{"so_tien":42}"#).as_ptr(),
        )
    });
    let src = b.dir.join("anh.bin");
    std::fs::write(&src, vec![3u8; 2_100_000]).unwrap();
    let mut hash = null_mut();
    ok(unsafe { tsulink_node_file_import(b.node, c(src.to_str().unwrap()).as_ptr(), &mut hash) });
    let hash = take(hash).unwrap();

    // B nghe, A đồng bộ và xin tệp.
    let mut l = null_mut();
    ok(unsafe { tsulink_listen(b.node, 0, &mut l) });
    let mut port = 0u16;
    ok(unsafe { tsulink_listener_port(l, &mut port) });
    let l_addr = l as usize;
    let t = std::thread::spawn(move || {
        let mut out = null_mut();
        let rc = unsafe {
            tsulink_listener_serve_one(
                l_addr as *const _,
                null(),
                None,
                null_mut(),
                null(),
                &mut out,
            )
        };
        (rc, take(out))
    });
    let wanted = c(&format!("[\"{hash}\"]"));
    let mut rep = null_mut();
    ok(unsafe {
        tsulink_sync_with(
            a.node,
            c(&fb).as_ptr(),
            c(&format!("{ip}:{port}")).as_ptr(),
            wanted.as_ptr(),
            Some(on_progress),
            0x7505 as *mut c_void,
            null(),
            &mut rep,
        )
    });
    let rep: serde_json::Value = serde_json::from_str(&take(rep).unwrap()).unwrap();
    assert_eq!(rep["rows"], 1);
    assert_eq!(rep["files"].as_array().unwrap().len(), 1);
    assert_eq!(PROGRESS.load(Ordering::SeqCst), 2_100_000);
    let (rc, served) = t.join().unwrap();
    ok(rc);
    assert!(served.unwrap().contains(&fa));
    unsafe { tsulink_listener_free(l) };

    let mut v = null_mut();
    ok(unsafe { tsulink_node_read(a.node, c("chi").as_ptr(), c("1").as_ptr(), &mut v) });
    assert_eq!(take(v).unwrap(), r#"{"so_tien":42}"#);
    let mut v = null_mut();
    ok(unsafe { tsulink_node_read(a.node, c("chi").as_ptr(), c("khong-co").as_ptr(), &mut v) });
    assert!(v.is_null());
    let mut p = null_mut();
    ok(unsafe { tsulink_node_file_path(a.node, c(&hash).as_ptr(), &mut p) });
    assert_eq!(std::fs::read(take(p).unwrap()).unwrap().len(), 2_100_000);
    let mut ch = null_mut();
    ok(unsafe { tsulink_node_changes_after(a.node, 0, 100, &mut ch) });
    assert!(take(ch).unwrap().contains("\"seq\":1"));
    let mut devs = null_mut();
    ok(unsafe { tsulink_node_devices(a.node, &mut devs) });
    assert!(take(devs).unwrap().contains(&fb));
}

#[test]
fn loi_tra_ma_on_dinh_va_thong_diep() {
    let a = open("loi", 1);
    // Tham số NULL.
    let rc = unsafe { tsulink_node_write(a.node, null(), c("k").as_ptr(), c("1").as_ptr()) };
    assert_eq!(rc, 21);
    assert!(last_error().contains("table"));
    // JSON hỏng.
    let rc =
        unsafe { tsulink_node_write(a.node, c("t").as_ptr(), c("k").as_ptr(), c("{").as_ptr()) };
    assert_eq!(rc, 21);
    // Địa chỉ công cộng bị luật L1 chặn trước khi nối - nhưng thiết bị lạ bị chặn trước nữa.
    let mut out = null_mut();
    let rc = unsafe {
        tsulink_sync_with(
            a.node,
            c(&"A".repeat(64)).as_ptr(),
            c("8.8.8.8:53").as_ptr(),
            null(),
            None,
            null_mut(),
            null(),
            &mut out,
        )
    };
    assert_eq!(rc, 15);
    let mut sas = null_mut();
    let rc = unsafe { tsulink_join_sas(a.node, c("8.8.8.8:53").as_ptr(), null(), &mut sas) };
    assert_eq!(rc, 3, "{}", last_error());
    // Thành công xoá thông điệp lỗi.
    ok(unsafe { tsulink_node_write(a.node, c("t").as_ptr(), c("k").as_ptr(), c("1").as_ptr()) });
    assert_eq!(last_error(), "");
    // Huỷ khi đang chờ.
    let mut l = null_mut();
    ok(unsafe { tsulink_listen(a.node, 0, &mut l) });
    let cancel = tsulink_cancel_new();
    let (la, ca) = (l as usize, cancel as usize);
    let t = std::thread::spawn(move || {
        let mut out = null_mut();
        unsafe {
            tsulink_listener_serve_one(
                la as *const _,
                null(),
                None,
                null_mut(),
                ca as *const _,
                &mut out,
            )
        }
    });
    std::thread::sleep(std::time::Duration::from_millis(100));
    unsafe { tsulink_cancel_trigger(cancel) };
    assert_eq!(t.join().unwrap(), 20);
    unsafe {
        tsulink_cancel_free(cancel);
        tsulink_listener_free(l);
        tsulink_string_free(null_mut());
        tsulink_node_free(null_mut());
    }
    let v = unsafe { CStr::from_ptr(tsulink_version()) }
        .to_str()
        .unwrap();
    assert_eq!(v, env!("CARGO_PKG_VERSION"));
}

fn names(src: &str, prefix: &str) -> BTreeSet<String> {
    src.match_indices(prefix)
        .filter_map(|(i, _)| {
            let rest = &src[i + prefix.len()..];
            let end = rest.find(|ch: char| !(ch.is_ascii_alphanumeric() || ch == '_'))?;
            rest[end..]
                .starts_with('(')
                .then(|| format!("tsulink_{}", &rest[..end]))
        })
        .collect()
}

#[test]
fn header_khop_ham_xuat() {
    let h = include_str!("../include/tsulink.h");
    let rs = include_str!("../src/lib.rs");
    let in_h = names(h, " tsulink_")
        .into_iter()
        .chain(names(h, "*tsulink_"))
        .collect::<BTreeSet<_>>();
    let in_rs = names(rs, "extern \"C\" fn tsulink_");
    assert!(in_rs.len() >= 45, "{in_rs:?}");
    assert_eq!(in_h, in_rs, "tsulink.h lệch src/lib.rs");
    // Bảng mã lỗi trong header khớp Error::code().
    let cases = [
        ("TSULINK_E_MALFORMED", Error::Malformed("x")),
        (
            "TSULINK_E_PUBLIC_ADDRESS",
            Error::PublicAddress(String::new()),
        ),
        ("TSULINK_E_PAIRING_REJECTED", Error::PairingRejected),
        (
            "TSULINK_E_SCHEMA_MISMATCH",
            Error::SchemaMismatch {
                local: 0,
                remote: 1,
            },
        ),
        ("TSULINK_E_CLOCK_SKEW", Error::ClockSkew),
        ("TSULINK_E_CANCELLED", Error::Cancelled),
        ("TSULINK_E_INVALID_INPUT", Error::InvalidInput("x")),
        ("TSULINK_E_CLOSED", Error::Closed),
    ];
    for (name, e) in cases {
        let line = h
            .lines()
            .find(|l| l.starts_with(&format!("#define {name} ")))
            .unwrap_or_else(|| panic!("thiếu {name}"));
        assert_eq!(
            line.rsplit(' ').next().unwrap(),
            e.code().to_string(),
            "{name}"
        );
    }
    assert_eq!(h.matches("#define TSULINK_E_").count(), 22);
}
