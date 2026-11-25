//! Sao lưu `.tsubak` (`LOCAL_SYNC.md` mục 9): dữ liệu định dạng mở (CSV/JSON + tệp gốc) đóng trong MỘT tệp zip do
//! người dùng chọn nơi lưu; mã hoá tuỳ chọn (mặc định BẬT cho dữ liệu D2+) bằng bộ mật mã `TS 01` của TsuDEV Sync cũ
//! (libsodium secretstream XChaCha20-Poly1305, Argon2id ≥ 64 MiB / 3 lượt, mật khẩu NFKC).
//!
//! Khuôn (ADR-0002):
//!
//! - **Không mã hoá**: zip gồm `tsubak.json` (bản kê) + các tệp dữ liệu ở đúng đường dẫn của chúng - mở được bằng mọi
//!   trình giải nén.
//! - **Có mã hoá**: zip ngoài gồm `tsubak.json` (chỉ phần công khai: định dạng, app, `encrypted`, tham số KDF) +
//!   `payload.ts01` = `TS 01` (loại `file`, không gian tên = app, id `tsubak`) của zip trong (khuôn không mã hoá ở trên).
//!
//! Bản kê ghi SHA-256 + kích thước từng tệp; nhập lại kiểm từng tệp ⇒ khớp từng byte hoặc lỗi rõ ràng.
//! Nhập chống zip bom và đường dẫn thoát thư mục; sai mật khẩu ⇒ [`Error::WrongPassword`], không trả dữ liệu dở.

// Chép nguyên từ tsusync để giữ vector: vài mục (bản ghi `rec`, hằng ngữ cảnh) chỉ dùng trong test vector.
#[allow(dead_code)]
mod crypto;
#[cfg(test)]
mod crypto_vectors;

use crate::Error;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
use std::io::{Cursor, Read, Write};
use zeroize::Zeroizing;
use zip::write::SimpleFileOptions;
use zip::{CompressionMethod, ZipArchive, ZipWriter};

/// Giá trị trường `format` của bản kê.
pub const FORMAT: &str = "tsubak";
/// Phiên bản khuôn `.tsubak`.
pub const VERSION: u32 = 1;
/// Tên bản kê trong zip.
pub const MANIFEST: &str = "tsubak.json";
/// Tên phần bản mã trong zip ngoài khi có mã hoá.
pub const PAYLOAD: &str = "payload.ts01";
/// Trần số tệp khi nhập (chống zip bom).
pub const MAX_ENTRIES: usize = 100_000;
/// Trần tổng dung lượng sau giải nén khi nhập: 2 GiB (bản 1 xử lý trong bộ nhớ).
pub const MAX_TOTAL_BYTES: u64 = 2 * 1024 * 1024 * 1024;
/// Độ dài tối thiểu của mật khẩu sao lưu (ký tự sau NFKC).
pub const MIN_PASSWORD_LENGTH: usize = crypto::MIN_PASSWORD_LENGTH;

/// Một tệp trong bản sao lưu.
#[derive(Clone, PartialEq, Eq)]
pub struct Entry {
    /// Đường dẫn tương đối, phân cách `/` (vd `data/thu-chi.csv`, `files/hoa-don/1.jpg`).
    pub path: String,
    /// Nội dung.
    pub data: Vec<u8>,
}

impl std::fmt::Debug for Entry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Không in nội dung người dùng.
        f.debug_struct("Entry")
            .field("path", &self.path)
            .field("len", &self.data.len())
            .finish()
    }
}

/// Mô tả một tệp trong bản kê.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EntryInfo {
    /// Đường dẫn.
    pub path: String,
    /// Kích thước (byte).
    pub size: u64,
    /// SHA-256 hex chữ thường.
    pub sha256: String,
}

/// Bản kê đầy đủ (trong zip không mã hoá, hoặc trong zip bên trong bản mã).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Manifest {
    /// Luôn [`FORMAT`].
    pub format: String,
    /// Luôn [`VERSION`].
    pub v: u32,
    /// Mã sản phẩm.
    pub app: String,
    /// Phiên bản lược đồ dữ liệu của app (L5: khác ⇒ app quyết chuyển đổi hay từ chối).
    pub schema_version: u32,
    /// Thời điểm tạo (giây Unix).
    pub created_at: u64,
    /// `false` ở bản kê trong.
    pub encrypted: bool,
    /// Danh sách tệp.
    pub entries: Vec<EntryInfo>,
}

/// Bản kê công khai của zip ngoài khi có mã hoá (không lộ tên/số tệp).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
struct OuterManifest {
    format: String,
    v: u32,
    app: String,
    encrypted: bool,
    kdf: serde_json::Value,
}

/// Thông tin đọc được TRƯỚC khi hỏi mật khẩu.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Info {
    /// Mã sản phẩm đã tạo bản sao lưu.
    pub app: String,
    /// Có cần mật khẩu không.
    pub encrypted: bool,
}

/// Bản sao lưu đã mở.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Backup {
    /// Bản kê.
    pub manifest: Manifest,
    /// Các tệp (đã kiểm SHA-256 + kích thước).
    pub entries: Vec<Entry>,
}

/// Các tệp của một zip: (tên, nội dung).
type Files = Vec<(String, Vec<u8>)>;

fn bad(m: &'static str) -> Error {
    Error::Backup(m)
}

fn sha256_hex(data: &[u8]) -> String {
    use std::fmt::Write as _;
    Sha256::digest(data)
        .iter()
        .fold(String::with_capacity(64), |mut s, b| {
            let _ = write!(s, "{b:02x}");
            s
        })
}

/// Đường dẫn an toàn: tương đối, `/`, không `..`/`.`/rỗng, không `\`, không ký tự điều khiển, không trùng tên
/// dành riêng, ≤ 512 byte.
fn valid_path(p: &str) -> bool {
    !p.is_empty()
        && p.len() <= 512
        && p != MANIFEST
        && p != PAYLOAD
        && !p.starts_with('/')
        && !p.contains('\\')
        && !p.chars().any(char::is_control)
        && !(p.len() >= 2 && p.as_bytes()[1] == b':')
        && p.split('/').all(|s| !s.is_empty() && s != "." && s != "..")
}

fn valid_app(app: &str) -> bool {
    (1..=64).contains(&app.len())
        && app
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
}

fn zip_err(_: zip::result::ZipError) -> Error {
    bad("tệp sao lưu hỏng hoặc không phải .tsubak")
}

fn io_err(e: std::io::Error) -> Error {
    Error::Io(e.kind())
}

fn opts() -> SimpleFileOptions {
    SimpleFileOptions::default()
        .compression_method(CompressionMethod::Deflated)
        .unix_permissions(0o600)
        .last_modified_time(zip::DateTime::default())
}

fn write_zip(files: &[(&str, &[u8])]) -> Result<Vec<u8>, Error> {
    let mut w = ZipWriter::new(Cursor::new(Vec::new()));
    for (name, data) in files {
        w.start_file(*name, opts()).map_err(zip_err)?;
        w.write_all(data).map_err(io_err)?;
    }
    Ok(w.finish().map_err(zip_err)?.into_inner())
}

/// Đọc mọi tệp của zip với trần chống zip bom. Trả (tên, nội dung) theo thứ tự trong zip.
fn read_zip(bytes: &[u8]) -> Result<Files, Error> {
    let mut z = ZipArchive::new(Cursor::new(bytes)).map_err(zip_err)?;
    if z.len() > MAX_ENTRIES + 1 {
        return Err(bad("quá nhiều tệp"));
    }
    let mut total = 0u64;
    let mut out = Vec::with_capacity(z.len());
    let mut seen = BTreeSet::new();
    for i in 0..z.len() {
        let f = z.by_index(i).map_err(zip_err)?;
        if f.is_dir() {
            continue;
        }
        let name = f.name().map_err(zip_err)?.into_owned();
        if f.enclosed_name().is_none()
            || (name != MANIFEST && name != PAYLOAD && !valid_path(&name))
        {
            return Err(bad("đường dẫn trong tệp sao lưu không an toàn"));
        }
        if !seen.insert(name.clone()) {
            return Err(bad("tệp trùng tên"));
        }
        let mut data = Vec::new();
        // Đọc tối đa phần còn lại của trần + 1 byte: không tin kích thước khai trong zip.
        let limit = MAX_TOTAL_BYTES - total + 1;
        f.take(limit).read_to_end(&mut data).map_err(io_err)?;
        total += data.len() as u64;
        if total > MAX_TOTAL_BYTES {
            return Err(bad("tệp sao lưu quá lớn"));
        }
        out.push((name, data));
    }
    Ok(out)
}

fn take(files: &mut Files, name: &str) -> Option<Vec<u8>> {
    let i = files.iter().position(|(n, _)| n == name)?;
    Some(files.remove(i).1)
}

fn plain_zip(manifest: &Manifest, entries: &[Entry]) -> Result<Vec<u8>, Error> {
    let m = serde_json::to_vec_pretty(manifest).map_err(|_| bad("bản kê"))?;
    let mut files: Vec<(&str, &[u8])> = vec![(MANIFEST, &m)];
    files.extend(entries.iter().map(|e| (e.path.as_str(), e.data.as_slice())));
    write_zip(&files)
}

/// Tạo `.tsubak`. `password` = `None` ⇒ không mã hoá (chỉ dùng khi người dùng chủ động tắt, hoặc dữ liệu D1).
pub fn export(
    app: &str,
    schema_version: u32,
    entries: &[Entry],
    password: Option<&str>,
    now: u64,
) -> Result<Vec<u8>, Error> {
    export_with_cost(
        app,
        schema_version,
        entries,
        password,
        now,
        crypto::KDF_DEFAULT,
    )
}

fn export_with_cost(
    app: &str,
    schema_version: u32,
    entries: &[Entry],
    password: Option<&str>,
    now: u64,
    cost: crypto::KdfCost,
) -> Result<Vec<u8>, Error> {
    if !valid_app(app) {
        return Err(Error::Malformed("app"));
    }
    if entries.len() > MAX_ENTRIES {
        return Err(bad("quá nhiều tệp"));
    }
    let mut seen = BTreeSet::new();
    let mut total = 0u64;
    for e in entries {
        if !valid_path(&e.path) {
            return Err(bad("đường dẫn tệp không hợp lệ"));
        }
        if !seen.insert(e.path.as_str()) {
            return Err(bad("tệp trùng tên"));
        }
        total += e.data.len() as u64;
    }
    if total > MAX_TOTAL_BYTES {
        return Err(bad("tệp sao lưu quá lớn"));
    }
    let manifest = Manifest {
        format: FORMAT.into(),
        v: VERSION,
        app: app.into(),
        schema_version,
        created_at: now,
        encrypted: false,
        entries: entries
            .iter()
            .map(|e| EntryInfo {
                path: e.path.clone(),
                size: e.data.len() as u64,
                sha256: sha256_hex(&e.data),
            })
            .collect(),
    };
    let inner = Zeroizing::new(plain_zip(&manifest, entries)?);
    let Some(pw) = password else {
        return Ok(inner.to_vec());
    };
    let keys = crypto::create_keys(pw, Some(cost)).map_err(map_crypto)?;
    let ct = crypto::encrypt(&keys.data_key, &payload_ctx(app), &inner).map_err(map_crypto)?;
    let outer = OuterManifest {
        format: FORMAT.into(),
        v: VERSION,
        app: app.into(),
        encrypted: true,
        kdf: keys.params.to_json(),
    };
    let m = serde_json::to_vec_pretty(&outer).map_err(|_| bad("bản kê"))?;
    write_zip(&[(MANIFEST, &m), (PAYLOAD, &ct)])
}

fn payload_ctx(app: &str) -> crypto::CipherContext {
    crypto::CipherContext::new(app, crypto::Kind::File, "tsubak")
}

fn map_crypto(e: crypto::Error) -> Error {
    match e {
        crypto::Error::WeakPassword => Error::WeakPassword,
        crypto::Error::WrongPassword => Error::WrongPassword,
        crypto::Error::Crypto(_) => bad("không mở được dữ liệu mã hoá (tệp hỏng hoặc bị sửa)"),
    }
}

fn read_outer(bytes: &[u8]) -> Result<(Files, serde_json::Value), Error> {
    let mut files = read_zip(bytes)?;
    let m = take(&mut files, MANIFEST).ok_or(bad("thiếu bản kê tsubak.json"))?;
    let v: serde_json::Value = serde_json::from_slice(&m).map_err(|_| bad("bản kê hỏng"))?;
    if v["format"] != FORMAT || v["v"] != VERSION {
        return Err(bad("không phải .tsubak bản 1"));
    }
    Ok((files, v))
}

/// Đọc phần công khai (app, có mã hoá không) để biết có cần hỏi mật khẩu.
pub fn inspect(bytes: &[u8]) -> Result<Info, Error> {
    let (_, v) = read_outer(bytes)?;
    Ok(Info {
        app: v["app"].as_str().unwrap_or_default().to_owned(),
        encrypted: v["encrypted"] == true,
    })
}

/// Mở `.tsubak` của đúng `app`. Có mã hoá mà `password` = `None` ⇒ [`Error::WrongPassword`].
pub fn import(bytes: &[u8], app: &str, password: Option<&str>) -> Result<Backup, Error> {
    let (files, v) = read_outer(bytes)?;
    if v["app"] != app {
        return Err(bad("bản sao lưu của ứng dụng khác"));
    }
    if v["encrypted"] == true {
        let outer: OuterManifest = serde_json::from_value(v).map_err(|_| bad("bản kê hỏng"))?;
        let mut files = files;
        let ct = take(&mut files, PAYLOAD).ok_or(bad("thiếu payload.ts01"))?;
        if !files.is_empty() {
            return Err(bad("tệp lạ cạnh bản mã"));
        }
        let pw = password.ok_or(Error::WrongPassword)?;
        let keys = crypto::unlock_keys(pw, &outer.kdf).map_err(map_crypto)?;
        let inner = Zeroizing::new(
            crypto::decrypt(&keys.data_key, &payload_ctx(app), &ct).map_err(map_crypto)?,
        );
        let backup = open_plain(&inner, app)?;
        return Ok(backup);
    }
    open_plain_files(files, v, app)
}

fn open_plain(bytes: &[u8], app: &str) -> Result<Backup, Error> {
    let (files, v) = read_outer(bytes)?;
    if v["encrypted"] == true {
        return Err(bad("bản kê trong không hợp lệ"));
    }
    open_plain_files(files, v, app)
}

fn open_plain_files(mut files: Files, v: serde_json::Value, app: &str) -> Result<Backup, Error> {
    let manifest: Manifest = serde_json::from_value(v).map_err(|_| bad("bản kê hỏng"))?;
    if manifest.app != app || manifest.encrypted {
        return Err(bad("bản kê không khớp"));
    }
    if files.iter().any(|(n, _)| n == PAYLOAD) || files.len() != manifest.entries.len() {
        return Err(bad("danh sách tệp không khớp bản kê"));
    }
    let mut entries = Vec::with_capacity(files.len());
    for info in &manifest.entries {
        let data = take(&mut files, &info.path).ok_or(bad("thiếu tệp ghi trong bản kê"))?;
        if data.len() as u64 != info.size || sha256_hex(&data) != info.sha256 {
            return Err(bad("tệp bị hỏng hoặc bị sửa"));
        }
        entries.push(Entry {
            path: info.path.clone(),
            data,
        });
    }
    Ok(Backup { manifest, entries })
}

/// Ghi tệp an toàn: ghi ra tệp tạm cùng thư mục, `fsync`, rồi đổi tên nguyên tử (`LOCAL_SYNC.md` mục 4).
pub fn write_atomic(path: &std::path::Path, bytes: &[u8]) -> Result<(), Error> {
    let dir = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(std::path::Path::new("."));
    let name = path
        .file_name()
        .ok_or(bad("đường dẫn lưu không hợp lệ"))?
        .to_string_lossy();
    let mut rnd = [0u8; 8];
    getrandom::fill(&mut rnd).map_err(|_| Error::Rng)?;
    let tmp = dir.join(format!(".{name}.{:016x}.tmp", u64::from_le_bytes(rnd)));
    let res = (|| {
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&tmp)?;
        f.write_all(bytes)?;
        f.sync_all()?;
        std::fs::rename(&tmp, path)
    })();
    if res.is_err() {
        let _ = std::fs::remove_file(&tmp);
    }
    res.map_err(io_err)
}

#[cfg(test)]
mod tests;
