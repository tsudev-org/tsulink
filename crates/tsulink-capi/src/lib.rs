//! C ABI của Tsu Link (ADR-0005) - bọc [`tsulink_core::node`] cho .NET (P/Invoke) và ngôn ngữ có FFI C.
//!
//! Quy ước (khớp `include/tsulink.h`):
//!
//! - Mọi hàm trả `int32_t`: `0` = thành công, số dương = mã lỗi ổn định ([`tsulink_core::Error::code`]), `-1` = lỗi nội
//!   bộ (panic). Thông điệp lỗi tiếng Việt của lần gọi hỏng gần nhất TRÊN LUỒNG ĐÓ: [`tsulink_last_error`].
//! - Chuỗi vào là UTF-8 kết thúc NUL. Chuỗi ra (`char**`) do thư viện cấp, gọi [`tsulink_string_free`]; byte ra do
//!   [`tsulink_bytes_free`]. Kết quả có cấu trúc là JSON.
//! - Đối tượng là con trỏ mờ, giải phóng bằng hàm `_free` của nó (NULL thì bỏ qua). Một đối tượng dùng được từ nhiều
//!   luồng; hàm chờ (ghép đôi, đồng bộ, khám phá) CHẶN luồng gọi - .NET gọi trong `Task.Run` và huỷ bằng
//!   `TsulinkCancel`.
//! - Callback tiến độ chạy trên luồng nền của thư viện, không được gọi ngược vào thư viện trên cùng đối tượng.

#![deny(missing_docs)]

use std::cell::RefCell;
use std::ffi::{CStr, CString, c_char, c_void};
use std::net::{IpAddr, SocketAddr};
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::path::PathBuf;
use std::sync::Arc;
use tsulink_core::Error;
use tsulink_core::identity::DeviceIdentity;
use tsulink_core::node::{
    self, CancelToken, DiscoveryHandle, Node, NodeConfig, PairingHostHandle, ProgressFn, SasHandle,
    SyncListener,
};

/// Lỗi nội bộ (panic bị chặn ở biên).
pub const TSULINK_PANIC: i32 = -1;

thread_local! {
    static LAST_ERROR: RefCell<CString> = RefCell::new(CString::default());
}

fn set_last(msg: &str) {
    let c = CString::new(msg.replace('\0', " ")).unwrap_or_default();
    LAST_ERROR.with(|l| *l.borrow_mut() = c);
}

fn guard(f: impl FnOnce() -> Result<(), Error>) -> i32 {
    match catch_unwind(AssertUnwindSafe(f)) {
        Ok(Ok(())) => {
            set_last("");
            0
        }
        Ok(Err(e)) => {
            set_last(&e.to_string());
            e.code()
        }
        Err(_) => {
            set_last("lỗi nội bộ của tsulink");
            TSULINK_PANIC
        }
    }
}

/// # Safety
/// `p` là NULL hoặc chuỗi C hợp lệ kết thúc NUL, sống suốt lần gọi.
unsafe fn cstr<'a>(p: *const c_char, what: &'static str) -> Result<&'a str, Error> {
    if p.is_null() {
        return Err(Error::InvalidInput(what));
    }
    // SAFETY: bên gọi bảo đảm `p` trỏ tới chuỗi C hợp lệ (hợp đồng của hàm).
    unsafe { CStr::from_ptr(p) }
        .to_str()
        .map_err(|_| Error::InvalidInput(what))
}

/// # Safety
/// `p` là NULL hoặc chuỗi C hợp lệ.
unsafe fn opt_cstr<'a>(p: *const c_char, what: &'static str) -> Result<Option<&'a str>, Error> {
    if p.is_null() {
        Ok(None)
    } else {
        // SAFETY: như trên.
        unsafe { cstr(p, what) }.map(Some)
    }
}

/// # Safety
/// `p` là NULL (khi `len == 0`) hoặc trỏ tới `len` byte đọc được.
unsafe fn bytes<'a>(p: *const u8, len: usize, what: &'static str) -> Result<&'a [u8], Error> {
    if len == 0 {
        return Ok(&[]);
    }
    if p.is_null() {
        return Err(Error::InvalidInput(what));
    }
    // SAFETY: bên gọi bảo đảm `p` trỏ tới `len` byte hợp lệ.
    Ok(unsafe { std::slice::from_raw_parts(p, len) })
}

/// # Safety
/// `h` là NULL hoặc con trỏ do chính thư viện này trả, chưa `_free`.
unsafe fn handle<'a, T>(h: *const T, what: &'static str) -> Result<&'a T, Error> {
    // SAFETY: con trỏ do `Box::into_raw` tạo và còn sống (hợp đồng).
    unsafe { h.as_ref() }.ok_or(Error::InvalidInput(what))
}

/// # Safety
/// `out` là NULL hoặc trỏ tới ô `char*` ghi được.
unsafe fn put_str(out: *mut *mut c_char, s: String) -> Result<(), Error> {
    if out.is_null() {
        return Err(Error::InvalidInput("con trỏ kết quả"));
    }
    let c = CString::new(s).map_err(|_| Error::InvalidInput("chuỗi có NUL"))?;
    // SAFETY: `out` ghi được (hợp đồng).
    unsafe { *out = c.into_raw() };
    Ok(())
}

/// # Safety
/// Như [`put_str`]; `None` ghi NULL.
unsafe fn put_opt_str(out: *mut *mut c_char, s: Option<String>) -> Result<(), Error> {
    match s {
        // SAFETY: chuyển tiếp hợp đồng.
        Some(s) => unsafe { put_str(out, s) },
        None if out.is_null() => Err(Error::InvalidInput("con trỏ kết quả")),
        None => {
            // SAFETY: `out` ghi được.
            unsafe { *out = std::ptr::null_mut() };
            Ok(())
        }
    }
}

fn json<T: serde::Serialize>(v: &T) -> Result<String, Error> {
    serde_json::to_string(v).map_err(|_| Error::Protocol("JSON"))
}

/// # Safety
/// `out`/`out_len` là NULL hoặc ghi được.
unsafe fn put_bytes(
    out: *mut *mut u8,
    out_len: *mut usize,
    v: Option<Vec<u8>>,
) -> Result<(), Error> {
    if out.is_null() || out_len.is_null() {
        return Err(Error::InvalidInput("con trỏ kết quả"));
    }
    let (p, n) = match v {
        Some(v) => {
            let b = v.into_boxed_slice();
            let n = b.len();
            (Box::into_raw(b).cast::<u8>(), n)
        }
        None => (std::ptr::null_mut(), 0),
    };
    // SAFETY: hai ô ghi được (hợp đồng).
    unsafe {
        *out = p;
        *out_len = n;
    }
    Ok(())
}

/// # Safety
/// `out` là NULL hoặc ghi được.
unsafe fn put_handle<T>(out: *mut *mut T, v: T) -> Result<(), Error> {
    if out.is_null() {
        return Err(Error::InvalidInput("con trỏ kết quả"));
    }
    // SAFETY: `out` ghi được.
    unsafe { *out = Box::into_raw(Box::new(v)) };
    Ok(())
}

/// # Safety
/// `out` là NULL hoặc ghi được.
unsafe fn put<T: Copy>(out: *mut T, v: T) -> Result<(), Error> {
    if out.is_null() {
        return Err(Error::InvalidInput("con trỏ kết quả"));
    }
    // SAFETY: `out` ghi được.
    unsafe { *out = v };
    Ok(())
}

/// # Safety
/// `h` là NULL hoặc do thư viện trả và chưa giải phóng; sau lần gọi này không dùng lại.
unsafe fn free<T>(h: *mut T) {
    if !h.is_null() {
        // SAFETY: con trỏ do `Box::into_raw` tạo, giải phóng đúng một lần (hợp đồng).
        drop(unsafe { Box::from_raw(h) });
    }
}

/// # Safety
/// `c` là NULL hoặc thẻ huỷ còn sống.
unsafe fn cancel_of(c: *const TsulinkCancel) -> Option<CancelToken> {
    // SAFETY: con trỏ do thư viện cấp (hợp đồng).
    unsafe { c.as_ref() }.map(|c| c.0.clone())
}

fn wanted_of(s: Option<&str>) -> Result<Vec<String>, Error> {
    s.map_or(Ok(Vec::new()), |s| {
        serde_json::from_str(s).map_err(|_| Error::InvalidInput("wanted (mảng JSON BLAKE3)"))
    })
}

/// Callback tiến độ: `(user, BLAKE3 tệp, byte đã có, tổng byte)`.
pub type TsulinkProgressCb =
    Option<unsafe extern "C" fn(user: *mut c_void, hash: *const c_char, done: u64, total: u64)>;

struct UserPtr(*mut c_void);
// SAFETY: con trỏ người dùng chỉ được trao lại nguyên vẹn cho callback của chính họ; bên gọi cam kết callback an toàn
// khi chạy trên luồng nền (hợp đồng ghi ở `tsulink.h`).
unsafe impl Send for UserPtr {}

fn progress_of(cb: TsulinkProgressCb, user: *mut c_void) -> Option<ProgressFn> {
    let cb = cb?;
    let user = UserPtr(user);
    Some(Box::new(move |hash: &str, done, total| {
        let u = &user;
        if let Ok(h) = CString::new(hash) {
            // SAFETY: `cb` là hàm C bên gọi cấp; chuỗi `h` sống tới hết lời gọi.
            unsafe { cb(u.0, h.as_ptr(), done, total) };
        }
    }))
}

fn parse_addr(s: &str) -> Result<SocketAddr, Error> {
    s.parse()
        .map_err(|_| Error::InvalidInput("địa chỉ ip:cổng"))
}

// ---------------------------------------------------------------- kiểu mờ

/// Thiết bị đã mở.
pub struct TsulinkNode(Arc<Node>);
/// Thẻ huỷ.
pub struct TsulinkCancel(CancelToken);
/// Cổng ghép đôi.
pub struct TsulinkPairingHost(PairingHostHandle);
/// Phiên so mã số.
pub struct TsulinkSas(SasHandle);
/// Cổng đồng bộ.
pub struct TsulinkListener(SyncListener);
/// Khám phá.
pub struct TsulinkDiscovery(DiscoveryHandle);

// ---------------------------------------------------------------- chung

/// Phiên bản thư viện (chuỗi tĩnh, KHÔNG giải phóng).
#[unsafe(no_mangle)]
pub extern "C" fn tsulink_version() -> *const c_char {
    concat!(env!("CARGO_PKG_VERSION"), "\0").as_ptr().cast()
}

/// Thông điệp lỗi của lần gọi hỏng gần nhất trên luồng này (chuỗi rỗng nếu thành công). Con trỏ sống tới lần gọi kế
/// tiếp trên cùng luồng; KHÔNG giải phóng.
#[unsafe(no_mangle)]
pub extern "C" fn tsulink_last_error() -> *const c_char {
    LAST_ERROR.with(|l| l.borrow().as_ptr())
}

/// Giải phóng chuỗi do thư viện trả.
///
/// # Safety
/// `s` là NULL hoặc chuỗi do thư viện trả, chưa giải phóng.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn tsulink_string_free(s: *mut c_char) {
    if !s.is_null() {
        // SAFETY: chuỗi do `CString::into_raw` tạo (hợp đồng).
        drop(unsafe { CString::from_raw(s) });
    }
}

/// Giải phóng mảng byte do thư viện trả.
///
/// # Safety
/// `p`/`len` đúng như thư viện đã trả, chưa giải phóng.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn tsulink_bytes_free(p: *mut u8, len: usize) {
    if !p.is_null() {
        // SAFETY: mảng do `Box<[u8]>` tạo với đúng độ dài `len` (hợp đồng).
        drop(unsafe { Box::from_raw(std::ptr::slice_from_raw_parts_mut(p, len)) });
    }
}

/// Tạo danh tính thiết bị mới (chứng thư DER + khoá PKCS#8 DER). App lưu khoá trong kho bí mật của hệ điều hành.
///
/// # Safety
/// Bốn con trỏ ra ghi được.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn tsulink_identity_generate(
    cert: *mut *mut u8,
    cert_len: *mut usize,
    key: *mut *mut u8,
    key_len: *mut usize,
) -> i32 {
    guard(|| {
        let id = DeviceIdentity::generate()?;
        // SAFETY: chuyển tiếp hợp đồng.
        unsafe {
            put_bytes(cert, cert_len, Some(id.cert_der().to_vec()))?;
            put_bytes(key, key_len, Some(id.key_pkcs8_der().to_vec()))
        }
    })
}

/// Địa chỉ mạng nội bộ của máy này, mảng JSON chuỗi.
///
/// # Safety
/// `out` ghi được.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn tsulink_local_ips(out: *mut *mut c_char) -> i32 {
    // SAFETY: chuyển tiếp hợp đồng.
    guard(|| unsafe { put_str(out, json(&node::local_ips())?) })
}

/// Tạo thẻ huỷ.
#[unsafe(no_mangle)]
pub extern "C" fn tsulink_cancel_new() -> *mut TsulinkCancel {
    Box::into_raw(Box::new(TsulinkCancel(CancelToken::new())))
}

/// Huỷ mọi thao tác đang chờ trên thẻ (gọi được từ luồng bất kỳ).
///
/// # Safety
/// `c` là NULL hoặc thẻ còn sống.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn tsulink_cancel_trigger(c: *const TsulinkCancel) {
    // SAFETY: hợp đồng.
    if let Some(c) = unsafe { c.as_ref() } {
        c.0.cancel();
    }
}

/// Giải phóng thẻ huỷ.
///
/// # Safety
/// `c` là NULL hoặc thẻ chưa giải phóng.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn tsulink_cancel_free(c: *mut TsulinkCancel) {
    // SAFETY: hợp đồng.
    unsafe { free(c) }
}

// ---------------------------------------------------------------- thiết bị

#[derive(serde::Deserialize)]
struct ConfigIn {
    data_dir: PathBuf,
    app: String,
    alias: String,
    schema_version: u32,
}

/// Mở thiết bị. `config_json` = `{"data_dir","app","alias","schema_version"}`.
///
/// # Safety
/// Chuỗi/mảng vào hợp lệ; `out` ghi được.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn tsulink_node_open(
    config_json: *const c_char,
    cert: *const u8,
    cert_len: usize,
    key: *const u8,
    key_len: usize,
    out: *mut *mut TsulinkNode,
) -> i32 {
    guard(|| {
        // SAFETY: hợp đồng.
        let (cfg, cert, key) = unsafe {
            (
                cstr(config_json, "config")?,
                bytes(cert, cert_len, "cert")?,
                bytes(key, key_len, "key")?,
            )
        };
        let c: ConfigIn =
            serde_json::from_str(cfg).map_err(|_| Error::InvalidInput("config JSON"))?;
        let n = Node::open(
            NodeConfig {
                data_dir: c.data_dir,
                app: c.app,
                alias: c.alias,
                schema_version: c.schema_version,
            },
            cert,
            key,
        )?;
        // SAFETY: hợp đồng.
        unsafe { put_handle(out, TsulinkNode(n)) }
    })
}

/// Đóng thiết bị.
///
/// # Safety
/// `n` là NULL hoặc chưa giải phóng.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn tsulink_node_free(n: *mut TsulinkNode) {
    // SAFETY: hợp đồng.
    unsafe { free(n) }
}

/// Vân tay của máy này.
///
/// # Safety
/// `n` còn sống; `out` ghi được.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn tsulink_node_fingerprint(
    n: *const TsulinkNode,
    out: *mut *mut c_char,
) -> i32 {
    guard(|| {
        // SAFETY: hợp đồng.
        let n = unsafe { handle(n, "node")? };
        // SAFETY: hợp đồng.
        unsafe { put_str(out, n.0.fingerprint().to_owned()) }
    })
}

/// Ghi bản ghi; `value_json` là JSON bất kỳ.
///
/// # Safety
/// Con trỏ vào hợp lệ.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn tsulink_node_write(
    n: *const TsulinkNode,
    table: *const c_char,
    key: *const c_char,
    value_json: *const c_char,
) -> i32 {
    guard(|| {
        // SAFETY: hợp đồng.
        let (n, t, k, v) = unsafe {
            (
                handle(n, "node")?,
                cstr(table, "table")?,
                cstr(key, "key")?,
                cstr(value_json, "value")?,
            )
        };
        let v = serde_json::from_str(v).map_err(|_| Error::InvalidInput("value JSON"))?;
        n.0.write(t, k, v).map(|_| ())
    })
}

/// Xoá bản ghi.
///
/// # Safety
/// Con trỏ vào hợp lệ.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn tsulink_node_delete(
    n: *const TsulinkNode,
    table: *const c_char,
    key: *const c_char,
) -> i32 {
    guard(|| {
        // SAFETY: hợp đồng.
        let (n, t, k) = unsafe { (handle(n, "node")?, cstr(table, "table")?, cstr(key, "key")?) };
        n.0.delete(t, k).map(|_| ())
    })
}

/// Đọc bản ghi; `*out` = JSON, hoặc NULL nếu chưa có/đã xoá.
///
/// # Safety
/// Con trỏ vào hợp lệ; `out` ghi được.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn tsulink_node_read(
    n: *const TsulinkNode,
    table: *const c_char,
    key: *const c_char,
    out: *mut *mut c_char,
) -> i32 {
    guard(|| {
        // SAFETY: hợp đồng.
        let (n, t, k) = unsafe { (handle(n, "node")?, cstr(table, "table")?, cstr(key, "key")?) };
        let v = n.0.read(t, k).map(|v| v.to_string());
        // SAFETY: hợp đồng.
        unsafe { put_opt_str(out, v) }
    })
}

/// Nhật ký máy này sau `after`: mảng JSON `{seq,table,key,value,hlc}`.
///
/// # Safety
/// `n` còn sống; `out` ghi được.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn tsulink_node_changes_after(
    n: *const TsulinkNode,
    after: u64,
    limit: u32,
    out: *mut *mut c_char,
) -> i32 {
    guard(|| {
        // SAFETY: hợp đồng.
        let n = unsafe { handle(n, "node")? };
        let v = n.0.changes_after(after, limit as usize);
        // SAFETY: hợp đồng.
        unsafe { put_str(out, json(&v)?) }
    })
}

/// Xoá hẳn bia mộ quá 180 ngày.
///
/// # Safety
/// `n` còn sống; `out` ghi được.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn tsulink_node_purge_tombstones(
    n: *const TsulinkNode,
    out: *mut u64,
) -> i32 {
    guard(|| {
        // SAFETY: hợp đồng.
        let n = unsafe { handle(n, "node")? };
        let c = n.0.purge_tombstones()? as u64;
        // SAFETY: hợp đồng.
        unsafe { put(out, c) }
    })
}

/// Mã các tài liệu Automerge, mảng JSON.
///
/// # Safety
/// `n` còn sống; `out` ghi được.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn tsulink_node_doc_ids(n: *const TsulinkNode, out: *mut *mut c_char) -> i32 {
    guard(|| {
        // SAFETY: hợp đồng.
        let n = unsafe { handle(n, "node")? }.0.clone();
        let ids = node::block_on(async move { Ok(n.doc_ids().await) })?;
        // SAFETY: hợp đồng.
        unsafe { put_str(out, json(&ids)?) }
    })
}

/// Bản lưu Automerge của tài liệu `id`; `*out` = NULL nếu chưa có.
///
/// # Safety
/// Con trỏ vào hợp lệ; `out`, `out_len` ghi được.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn tsulink_node_doc_save(
    n: *const TsulinkNode,
    id: *const c_char,
    out: *mut *mut u8,
    out_len: *mut usize,
) -> i32 {
    guard(|| {
        // SAFETY: hợp đồng.
        let (n, id) = unsafe { (handle(n, "node")?.0.clone(), cstr(id, "id")?.to_owned()) };
        let v = node::block_on(async move { Ok(n.doc_save(&id).await) })?;
        // SAFETY: hợp đồng.
        unsafe { put_bytes(out, out_len, v) }
    })
}

/// Gộp bản lưu/thay đổi Automerge vào tài liệu `id`.
///
/// # Safety
/// Con trỏ vào hợp lệ.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn tsulink_node_doc_merge(
    n: *const TsulinkNode,
    id: *const c_char,
    data: *const u8,
    len: usize,
) -> i32 {
    guard(|| {
        // SAFETY: hợp đồng.
        let (n, id, data) = unsafe {
            (
                handle(n, "node")?.0.clone(),
                cstr(id, "id")?.to_owned(),
                bytes(data, len, "data")?.to_vec(),
            )
        };
        node::block_on(async move { n.doc_merge(&id, &data).await })
    })
}

/// Chép tệp `path` vào kho tệp; `*out` = BLAKE3.
///
/// # Safety
/// Con trỏ vào hợp lệ; `out` ghi được.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn tsulink_node_file_import(
    n: *const TsulinkNode,
    path: *const c_char,
    out: *mut *mut c_char,
) -> i32 {
    guard(|| {
        // SAFETY: hợp đồng.
        let (n, p) = unsafe {
            (
                handle(n, "node")?.0.clone(),
                PathBuf::from(cstr(path, "path")?),
            )
        };
        let h = node::block_on(async move { n.file_import(&p).await })?;
        // SAFETY: hợp đồng.
        unsafe { put_str(out, h) }
    })
}

/// Đường dẫn tệp BLAKE3 `hash` trong kho; `*out` = NULL nếu chưa có.
///
/// # Safety
/// Con trỏ vào hợp lệ; `out` ghi được.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn tsulink_node_file_path(
    n: *const TsulinkNode,
    hash: *const c_char,
    out: *mut *mut c_char,
) -> i32 {
    guard(|| {
        // SAFETY: hợp đồng.
        let (n, h) = unsafe { (handle(n, "node")?, cstr(hash, "hash")?) };
        let p = n.0.file_path(h).map(|p| p.to_string_lossy().into_owned());
        // SAFETY: hợp đồng.
        unsafe { put_opt_str(out, p) }
    })
}

/// Thiết bị đã ghép đôi, mảng JSON `{fingerprint,alias,paired_at,last_sync_at}`.
///
/// # Safety
/// `n` còn sống; `out` ghi được.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn tsulink_node_devices(n: *const TsulinkNode, out: *mut *mut c_char) -> i32 {
    guard(|| {
        // SAFETY: hợp đồng.
        let n = unsafe { handle(n, "node")? };
        // SAFETY: hợp đồng.
        unsafe { put_str(out, json(&n.0.devices())?) }
    })
}

/// Gỡ thiết bị; `*removed` = 1 nếu có.
///
/// # Safety
/// Con trỏ vào hợp lệ; `removed` ghi được.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn tsulink_node_remove_device(
    n: *const TsulinkNode,
    fingerprint: *const c_char,
    removed: *mut i32,
) -> i32 {
    guard(|| {
        // SAFETY: hợp đồng.
        let (n, fp) = unsafe { (handle(n, "node")?, cstr(fingerprint, "fingerprint")?) };
        let r = i32::from(n.0.remove_device(fp)?);
        // SAFETY: hợp đồng.
        unsafe { put(removed, r) }
    })
}

/// Gỡ thiết bị không đồng bộ quá 180 ngày.
///
/// # Safety
/// `n` còn sống; `out` ghi được.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn tsulink_node_prune_stale_devices(
    n: *const TsulinkNode,
    out: *mut u64,
) -> i32 {
    guard(|| {
        // SAFETY: hợp đồng.
        let n = unsafe { handle(n, "node")? };
        let c = n.0.prune_stale_devices()? as u64;
        // SAFETY: hợp đồng.
        unsafe { put(out, c) }
    })
}

// ---------------------------------------------------------------- ghép đôi

/// Mở cổng ghép đôi tạm (`port` 0 = hệ điều hành chọn).
///
/// # Safety
/// `n` còn sống; `out` ghi được.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn tsulink_pairing_host_open(
    n: *const TsulinkNode,
    port: u16,
    out: *mut *mut TsulinkPairingHost,
) -> i32 {
    guard(|| {
        // SAFETY: hợp đồng.
        let n = unsafe { handle(n, "node")? }.0.clone();
        let h = node::block_on(async move { n.pairing_host(port).await })?;
        // SAFETY: hợp đồng.
        unsafe { put_handle(out, TsulinkPairingHost(h)) }
    })
}

/// Đóng cổng ghép đôi.
///
/// # Safety
/// `h` là NULL hoặc chưa giải phóng.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn tsulink_pairing_host_free(h: *mut TsulinkPairingHost) {
    // SAFETY: hợp đồng.
    unsafe { free(h) }
}

/// Cổng đang nghe.
///
/// # Safety
/// `h` còn sống; `out` ghi được.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn tsulink_pairing_host_port(
    h: *const TsulinkPairingHost,
    out: *mut u16,
) -> i32 {
    guard(|| {
        // SAFETY: hợp đồng.
        let h = unsafe { handle(h, "host")? }.0.clone();
        let p = node::block_on(async move { h.port().await })?;
        // SAFETY: hợp đồng.
        unsafe { put(out, p) }
    })
}

/// URI mã QR mới (hạn 120 giây). `ips_json` = mảng JSON địa chỉ IP, hoặc NULL để tự chọn địa chỉ nội bộ.
///
/// # Safety
/// Con trỏ vào hợp lệ; `out` ghi được.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn tsulink_pairing_host_qr_uri(
    h: *const TsulinkPairingHost,
    ips_json: *const c_char,
    out: *mut *mut c_char,
) -> i32 {
    guard(|| {
        // SAFETY: hợp đồng.
        let (h, ips) = unsafe { (handle(h, "host")?.0.clone(), opt_cstr(ips_json, "ips")?) };
        let ips: Vec<IpAddr> = match ips {
            Some(s) => serde_json::from_str(s).map_err(|_| Error::InvalidInput("ips JSON"))?,
            None => Vec::new(),
        };
        let uri = node::block_on(async move { h.qr_uri(ips).await })?;
        // SAFETY: hợp đồng.
        unsafe { put_str(out, uri) }
    })
}

/// Chờ máy kia quét QR vừa tạo; `*out` = thiết bị JSON.
///
/// # Safety
/// Con trỏ vào hợp lệ; `out` ghi được.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn tsulink_pairing_host_accept_qr(
    h: *const TsulinkPairingHost,
    cancel: *const TsulinkCancel,
    out: *mut *mut c_char,
) -> i32 {
    guard(|| {
        // SAFETY: hợp đồng.
        let (h, c) = unsafe { (handle(h, "host")?.0.clone(), cancel_of(cancel)) };
        let d = node::block_on(async move { h.accept_qr(c).await })?;
        // SAFETY: hợp đồng.
        unsafe { put_str(out, json(&d)?) }
    })
}

/// Chờ máy kia nối để so mã số (tối đa `wait_secs`, trần 600).
///
/// # Safety
/// Con trỏ vào hợp lệ; `out` ghi được.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn tsulink_pairing_host_accept_sas(
    h: *const TsulinkPairingHost,
    wait_secs: u64,
    cancel: *const TsulinkCancel,
    out: *mut *mut TsulinkSas,
) -> i32 {
    guard(|| {
        // SAFETY: hợp đồng.
        let (h, c) = unsafe { (handle(h, "host")?.0.clone(), cancel_of(cancel)) };
        let s = node::block_on(async move { h.accept_sas(wait_secs, c).await })?;
        // SAFETY: hợp đồng.
        unsafe { put_handle(out, TsulinkSas(s)) }
    })
}

/// Quét QR của máy kia và ghép đôi; `*out` = thiết bị JSON.
///
/// # Safety
/// Con trỏ vào hợp lệ; `out` ghi được.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn tsulink_join_qr(
    n: *const TsulinkNode,
    uri: *const c_char,
    cancel: *const TsulinkCancel,
    out: *mut *mut c_char,
) -> i32 {
    guard(|| {
        // SAFETY: hợp đồng.
        let (n, uri, c) = unsafe {
            (
                handle(n, "node")?.0.clone(),
                cstr(uri, "uri")?.to_owned(),
                cancel_of(cancel),
            )
        };
        let d = node::block_on(async move { n.join_qr(uri, c).await })?;
        // SAFETY: hợp đồng.
        unsafe { put_str(out, json(&d)?) }
    })
}

/// Nối tới cổng ghép đôi `addr` (`"ip:cổng"`) để so mã số.
///
/// # Safety
/// Con trỏ vào hợp lệ; `out` ghi được.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn tsulink_join_sas(
    n: *const TsulinkNode,
    addr: *const c_char,
    cancel: *const TsulinkCancel,
    out: *mut *mut TsulinkSas,
) -> i32 {
    guard(|| {
        // SAFETY: hợp đồng.
        let (n, a, c) = unsafe {
            (
                handle(n, "node")?.0.clone(),
                cstr(addr, "addr")?,
                cancel_of(cancel),
            )
        };
        let a = parse_addr(a)?;
        let s = node::block_on(async move { n.join_sas(a, c).await })?;
        // SAFETY: hợp đồng.
        unsafe { put_handle(out, TsulinkSas(s)) }
    })
}

#[derive(serde::Serialize)]
struct SasInfo<'a> {
    code: &'a str,
    peer_alias: &'a str,
    peer_fingerprint: &'a str,
}

/// `{"code","peer_alias","peer_fingerprint"}` của phiên so mã số.
///
/// # Safety
/// `s` còn sống; `out` ghi được.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn tsulink_sas_info(s: *const TsulinkSas, out: *mut *mut c_char) -> i32 {
    guard(|| {
        // SAFETY: hợp đồng.
        let s = unsafe { handle(s, "sas")? };
        let i = SasInfo {
            code: s.0.code(),
            peer_alias: s.0.peer_alias(),
            peer_fingerprint: s.0.peer_fingerprint(),
        };
        // SAFETY: hợp đồng.
        unsafe { put_str(out, json(&i)?) }
    })
}

/// Người dùng xác nhận mã khớp (`confirmed` ≠ 0) hay không; `*out` = thiết bị JSON. Chỉ gọi được một lần.
///
/// # Safety
/// `s` còn sống; `out` ghi được.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn tsulink_sas_finish(
    s: *const TsulinkSas,
    confirmed: i32,
    out: *mut *mut c_char,
) -> i32 {
    guard(|| {
        // SAFETY: hợp đồng.
        let s = unsafe { handle(s, "sas")? }.0.clone();
        let d = node::block_on(async move { s.finish(confirmed != 0).await })?;
        // SAFETY: hợp đồng.
        unsafe { put_str(out, json(&d)?) }
    })
}

/// Giải phóng phiên so mã số.
///
/// # Safety
/// `s` là NULL hoặc chưa giải phóng.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn tsulink_sas_free(s: *mut TsulinkSas) {
    // SAFETY: hợp đồng.
    unsafe { free(s) }
}

// ---------------------------------------------------------------- đồng bộ

/// Đồng bộ (bên gọi) với thiết bị đã ghép đôi `peer` ở `addr` (`"ip:cổng"`). `wanted_json` = mảng JSON BLAKE3 tệp
/// cần xin, hoặc NULL. `*out` = `{"rows","docs","files","missing"}`.
///
/// # Safety
/// Con trỏ vào hợp lệ; `out` ghi được; `progress` (có thể NULL) an toàn khi gọi từ luồng nền.
#[unsafe(no_mangle)]
#[allow(clippy::too_many_arguments)]
pub unsafe extern "C" fn tsulink_sync_with(
    n: *const TsulinkNode,
    peer: *const c_char,
    addr: *const c_char,
    wanted_json: *const c_char,
    progress: TsulinkProgressCb,
    user: *mut c_void,
    cancel: *const TsulinkCancel,
    out: *mut *mut c_char,
) -> i32 {
    guard(|| {
        // SAFETY: hợp đồng.
        let (n, peer, addr, wanted, c) = unsafe {
            (
                handle(n, "node")?.0.clone(),
                cstr(peer, "peer")?.to_owned(),
                cstr(addr, "addr")?,
                opt_cstr(wanted_json, "wanted")?,
                cancel_of(cancel),
            )
        };
        let (addr, wanted, p) = (
            parse_addr(addr)?,
            wanted_of(wanted)?,
            progress_of(progress, user),
        );
        let r = node::block_on(async move { n.sync_with(peer, addr, wanted, p, c).await })?;
        // SAFETY: hợp đồng.
        unsafe { put_str(out, json(&r)?) }
    })
}

/// Mở cổng đồng bộ (`port` 0 = hệ điều hành chọn); tự hết hạn sau 10 phút không có kết nối.
///
/// # Safety
/// `n` còn sống; `out` ghi được.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn tsulink_listen(
    n: *const TsulinkNode,
    port: u16,
    out: *mut *mut TsulinkListener,
) -> i32 {
    guard(|| {
        // SAFETY: hợp đồng.
        let n = unsafe { handle(n, "node")? }.0.clone();
        let l = node::block_on(async move { n.listen(port).await })?;
        // SAFETY: hợp đồng.
        unsafe { put_handle(out, TsulinkListener(l)) }
    })
}

/// Cổng đồng bộ đang nghe.
///
/// # Safety
/// `l` còn sống; `out` ghi được.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn tsulink_listener_port(l: *const TsulinkListener, out: *mut u16) -> i32 {
    guard(|| {
        // SAFETY: hợp đồng.
        let l = unsafe { handle(l, "listener")? }.0.clone();
        let p = node::block_on(async move { l.port().await })?;
        // SAFETY: hợp đồng.
        unsafe { put(out, p) }
    })
}

/// Chờ một thiết bị đã ghép đôi nối tới rồi đồng bộ trọn một phiên. `*out` = `{"peer","report":{...}}`.
///
/// # Safety
/// Như [`tsulink_sync_with`].
#[unsafe(no_mangle)]
pub unsafe extern "C" fn tsulink_listener_serve_one(
    l: *const TsulinkListener,
    wanted_json: *const c_char,
    progress: TsulinkProgressCb,
    user: *mut c_void,
    cancel: *const TsulinkCancel,
    out: *mut *mut c_char,
) -> i32 {
    guard(|| {
        // SAFETY: hợp đồng.
        let (l, wanted, c) = unsafe {
            (
                handle(l, "listener")?.0.clone(),
                opt_cstr(wanted_json, "wanted")?,
                cancel_of(cancel),
            )
        };
        let (wanted, p) = (wanted_of(wanted)?, progress_of(progress, user));
        let r = node::block_on(async move { l.serve_one(wanted, p, c).await })?;
        // SAFETY: hợp đồng.
        unsafe { put_str(out, json(&r)?) }
    })
}

/// Đóng cổng đồng bộ.
///
/// # Safety
/// `l` là NULL hoặc chưa giải phóng.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn tsulink_listener_free(l: *mut TsulinkListener) {
    // SAFETY: hợp đồng.
    unsafe { free(l) }
}

// ---------------------------------------------------------------- khám phá

/// Bắt đầu khám phá thiết bị cùng app.
///
/// # Safety
/// `n` còn sống; `out` ghi được.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn tsulink_discovery_start(
    n: *const TsulinkNode,
    out: *mut *mut TsulinkDiscovery,
) -> i32 {
    guard(|| {
        // SAFETY: hợp đồng.
        let n = unsafe { handle(n, "node")? };
        let d = n.0.discovery()?;
        // SAFETY: hợp đồng.
        unsafe { put_handle(out, TsulinkDiscovery(d)) }
    })
}

/// Rao máy này (cổng đồng bộ `port`); `*sent` = số giao diện gửi được.
///
/// # Safety
/// `d` còn sống; `sent` ghi được.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn tsulink_discovery_announce(
    d: *const TsulinkDiscovery,
    port: u16,
    sent: *mut u32,
) -> i32 {
    guard(|| {
        // SAFETY: hợp đồng.
        let d = unsafe { handle(d, "discovery")? }.0.clone();
        let k = node::block_on(async move { d.announce(port).await })?;
        // SAFETY: hợp đồng.
        unsafe { put(sent, u32::try_from(k).unwrap_or(u32::MAX)) }
    })
}

/// Thiết bị kế tiếp nghe thấy (chờ tối đa `wait_ms`); `*out` = `{"fingerprint","alias","addr","paired"}` hoặc NULL.
///
/// # Safety
/// Con trỏ vào hợp lệ; `out` ghi được.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn tsulink_discovery_next(
    d: *const TsulinkDiscovery,
    wait_ms: u64,
    cancel: *const TsulinkCancel,
    out: *mut *mut c_char,
) -> i32 {
    guard(|| {
        // SAFETY: hợp đồng.
        let (d, c) = unsafe { (handle(d, "discovery")?.0.clone(), cancel_of(cancel)) };
        let p = node::block_on(async move { d.next(wait_ms, c).await })?;
        let p = p.map(|p| json(&p)).transpose()?;
        // SAFETY: hợp đồng.
        unsafe { put_opt_str(out, p) }
    })
}

/// Dừng khám phá.
///
/// # Safety
/// `d` là NULL hoặc chưa giải phóng.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn tsulink_discovery_free(d: *mut TsulinkDiscovery) {
    // SAFETY: hợp đồng.
    unsafe { free(d) }
}
