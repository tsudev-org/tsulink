//! Kho bền vững trên đĩa cho app không tự cấp kho (ràng buộc Flutter/C ABI dùng, ADR-0005).
//!
//! - [`FileRowStore`]: nhật ký nối đuôi `rows.jsonl` (một dòng một phiên bản, `fsync` trước khi trả về - xem
//!   [`RowStore::put`]) + `rows-meta.json` (mã nhật ký, con trỏ từng thiết bị; ghi nguyên tử). Mở lại thì phát lại
//!   nhật ký; dòng cuối dở dang (mất điện giữa lúc ghi) bị cắt bỏ; dòng hỏng ở giữa ⇒ [`Error::Corrupt`]. Nhật ký dài
//!   quá gấp đôi số bản ghi sống thì được viết gọn lại khi mở và khi xoá bia mộ.
//! - [`FileDeviceStore`]: `devices.json`, ghi nguyên tử mỗi lần đổi.
//!
//! Ghi nguyên tử = ghi tệp tạm, `fsync`, đổi tên, `fsync` thư mục (Unix).

use crate::Error;
use crate::devices::{DeviceStore, PairedDevice};
use crate::sync::hlc::Hlc;
use crate::sync::table::{Cursor, Row, RowStore};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fs::{self, File, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::sync::Mutex;

fn io(e: std::io::Error) -> Error {
    Error::Io(e.kind())
}

/// Ghi `bytes` vào `path` nguyên tử: tệp tạm cùng thư mục, `fsync`, đổi tên, `fsync` thư mục.
pub fn write_atomic(path: &Path, bytes: &[u8]) -> Result<(), Error> {
    let dir = path
        .parent()
        .ok_or(Error::Io(std::io::ErrorKind::InvalidInput))?;
    let mut tmp = path.as_os_str().to_owned();
    tmp.push(".tmp");
    let tmp = PathBuf::from(tmp);
    {
        let mut f = File::create(&tmp).map_err(io)?;
        f.write_all(bytes).map_err(io)?;
        f.sync_all().map_err(io)?;
    }
    fs::rename(&tmp, path).map_err(io)?;
    sync_dir(dir);
    Ok(())
}

/// `fsync` thư mục để phép đổi tên bền vững (Unix). Windows không mở được thư mục như tệp - bỏ qua.
pub(crate) fn sync_dir(dir: &Path) {
    #[cfg(unix)]
    if let Ok(d) = File::open(dir) {
        let _ = d.sync_all();
    }
    #[cfg(not(unix))]
    let _ = dir;
}

fn random_hex16() -> Result<String, Error> {
    let mut rnd = [0u8; 16];
    getrandom::fill(&mut rnd).map_err(|_| Error::Rng)?;
    Ok(rnd.iter().map(|b| format!("{b:02x}")).collect())
}

#[derive(Serialize, Deserialize)]
struct Line {
    seq: u64,
    row: Row,
}

#[derive(Serialize, Deserialize, Default)]
struct Meta {
    log: String,
    #[serde(default)]
    cursors: BTreeMap<String, Cursor>,
}

#[derive(Debug)]
struct State {
    rows: BTreeMap<(String, String), (u64, Row)>,
    log: BTreeMap<u64, (String, String)>,
    next: u64,
    lines: u64,
    cursors: BTreeMap<String, Cursor>,
    file: File,
}

/// Kho bản ghi trên đĩa (xem tài liệu module).
#[derive(Debug)]
pub struct FileRowStore {
    dir: PathBuf,
    id: String,
    st: Mutex<State>,
}

const ROWS: &str = "rows.jsonl";
const META: &str = "rows-meta.json";

impl FileRowStore {
    /// Mở (hoặc tạo) kho trong thư mục `dir`.
    pub fn open(dir: &Path) -> Result<Self, Error> {
        fs::create_dir_all(dir).map_err(io)?;
        let meta_path = dir.join(META);
        let meta: Meta = match fs::read(&meta_path) {
            Ok(b) => serde_json::from_slice(&b).map_err(|_| Error::Corrupt("rows-meta.json"))?,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                let m = Meta {
                    log: random_hex16()?,
                    cursors: BTreeMap::new(),
                };
                write_atomic(&meta_path, &serde_json::to_vec(&m).map_err(|_| Error::Rng)?)?;
                m
            }
            Err(e) => return Err(io(e)),
        };
        let rows_path = dir.join(ROWS);
        let mut rows = BTreeMap::new();
        let mut log = BTreeMap::new();
        let (mut next, mut lines, mut good_len) = (0u64, 0u64, 0u64);
        let mut torn = false;
        if let Ok(f) = File::open(&rows_path) {
            let mut rd = BufReader::new(f);
            let mut buf = Vec::new();
            loop {
                buf.clear();
                let n = rd.read_until(b'\n', &mut buf).map_err(io)?;
                if n == 0 {
                    break;
                }
                let complete = buf.last() == Some(&b'\n');
                match serde_json::from_slice::<Line>(&buf) {
                    Ok(l) if complete => {
                        let k = (l.row.table.clone(), l.row.key.clone());
                        if let Some((old, _)) = rows.insert(k.clone(), (l.seq, l.row)) {
                            log.remove(&old);
                        }
                        log.insert(l.seq, k);
                        next = next.max(l.seq);
                        lines += 1;
                        good_len += n as u64;
                    }
                    // Dòng cuối chưa ghi xong (mất điện) - cắt bỏ.
                    _ if !complete => {
                        torn = true;
                        break;
                    }
                    _ => return Err(Error::Corrupt("rows.jsonl")),
                }
            }
        }
        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&rows_path)
            .map_err(io)?;
        if torn {
            file.set_len(good_len).map_err(io)?;
            file.sync_all().map_err(io)?;
        }
        let me = Self {
            dir: dir.to_owned(),
            id: meta.log,
            st: Mutex::new(State {
                rows,
                log,
                next,
                lines,
                cursors: meta.cursors,
                file,
            }),
        };
        {
            let mut st = me.lock();
            if st.lines > 2 * st.rows.len() as u64 + 1024 {
                me.compact(&mut st)?;
            }
        }
        Ok(me)
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, State> {
        self.st.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Viết lại nhật ký chỉ còn phiên bản sống (giữ nguyên `seq`).
    fn compact(&self, st: &mut State) -> Result<(), Error> {
        let mut out = Vec::new();
        for (seq, k) in &st.log {
            let row = st.rows[k].1.clone();
            serde_json::to_writer(&mut out, &Line { seq: *seq, row })
                .map_err(|_| Error::Corrupt("ghi nhật ký"))?;
            out.push(b'\n');
        }
        let path = self.dir.join(ROWS);
        write_atomic(&path, &out)?;
        st.file = OpenOptions::new().append(true).open(&path).map_err(io)?;
        st.lines = st.log.len() as u64;
        Ok(())
    }

    fn save_meta(&self, st: &State) -> Result<(), Error> {
        let m = Meta {
            log: self.id.clone(),
            cursors: st.cursors.clone(),
        };
        let b = serde_json::to_vec(&m).map_err(|_| Error::Corrupt("rows-meta.json"))?;
        write_atomic(&self.dir.join(META), &b)
    }
}

impl RowStore for FileRowStore {
    fn log_id(&self) -> String {
        self.id.clone()
    }

    fn get(&self, table: &str, key: &str) -> Option<Row> {
        self.lock()
            .rows
            .get(&(table.to_owned(), key.to_owned()))
            .map(|(_, r)| r.clone())
    }

    fn put(&self, row: Row) -> Result<u64, Error> {
        let mut st = self.lock();
        let seq = st.next + 1;
        let mut line = serde_json::to_vec(&Line {
            seq,
            row: row.clone(),
        })
        .map_err(|_| Error::Corrupt("ghi nhật ký"))?;
        line.push(b'\n');
        st.file.write_all(&line).map_err(io)?;
        st.file.sync_data().map_err(io)?;
        st.next = seq;
        st.lines += 1;
        let k = (row.table.clone(), row.key.clone());
        if let Some((old, _)) = st.rows.insert(k.clone(), (seq, row)) {
            st.log.remove(&old);
        }
        st.log.insert(seq, k);
        Ok(seq)
    }

    fn changes_after(&self, after: u64, limit: usize) -> Vec<(u64, Row)> {
        let st = self.lock();
        st.log
            .range(after.saturating_add(1)..)
            .take(limit)
            .map(|(s, k)| (*s, st.rows[k].1.clone()))
            .collect()
    }

    fn max_hlc(&self) -> Option<Hlc> {
        self.lock().rows.values().map(|(_, r)| r.hlc.clone()).max()
    }

    fn cursor(&self, peer: &str) -> Option<Cursor> {
        self.lock().cursors.get(peer).cloned()
    }

    fn set_cursor(&self, peer: &str, cursor: Cursor) -> Result<(), Error> {
        let mut st = self.lock();
        st.cursors.insert(peer.to_owned(), cursor);
        self.save_meta(&st)
    }

    fn purge_tombstones(&self, before_ms: u64) -> Result<usize, Error> {
        let mut st = self.lock();
        let dead: Vec<_> = st
            .rows
            .iter()
            .filter(|(_, (_, r))| r.value.is_none() && r.hlc.ms < before_ms)
            .map(|(k, (s, _))| (k.clone(), *s))
            .collect();
        if dead.is_empty() {
            return Ok(0);
        }
        for (k, s) in &dead {
            st.rows.remove(k);
            st.log.remove(s);
        }
        // Bia mộ đã xoá phải biến mất khỏi đĩa ⇒ viết gọn ngay.
        self.compact(&mut st)?;
        Ok(dead.len())
    }
}

/// Kho thiết bị đã ghép đôi trên đĩa (`devices.json`).
#[derive(Debug)]
pub struct FileDeviceStore {
    path: PathBuf,
    mem: Mutex<BTreeMap<String, PairedDevice>>,
}

impl FileDeviceStore {
    /// Mở (hoặc tạo) kho trong thư mục `dir`.
    pub fn open(dir: &Path) -> Result<Self, Error> {
        fs::create_dir_all(dir).map_err(io)?;
        let path = dir.join("devices.json");
        let list: Vec<PairedDevice> = match fs::read(&path) {
            Ok(b) => serde_json::from_slice(&b).map_err(|_| Error::Corrupt("devices.json"))?,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Vec::new(),
            Err(e) => return Err(io(e)),
        };
        Ok(Self {
            path,
            mem: Mutex::new(
                list.into_iter()
                    .map(|d| (d.fingerprint.clone(), d))
                    .collect(),
            ),
        })
    }

    fn save(&self, m: &BTreeMap<String, PairedDevice>) -> Result<(), Error> {
        let list: Vec<_> = m.values().collect();
        let b = serde_json::to_vec_pretty(&list).map_err(|_| Error::Corrupt("devices.json"))?;
        write_atomic(&self.path, &b)
    }
}

impl DeviceStore for FileDeviceStore {
    fn list(&self) -> Vec<PairedDevice> {
        let m = self.mem.lock().unwrap_or_else(|e| e.into_inner());
        m.values().cloned().collect()
    }

    fn upsert(&self, device: PairedDevice) -> Result<(), Error> {
        let mut m = self.mem.lock().unwrap_or_else(|e| e.into_inner());
        let mut next = m.clone();
        next.insert(device.fingerprint.clone(), device);
        self.save(&next)?;
        *m = next;
        Ok(())
    }

    fn remove(&self, fingerprint: &str) -> Result<bool, Error> {
        let mut m = self.mem.lock().unwrap_or_else(|e| e.into_inner());
        if !m.contains_key(fingerprint) {
            return Ok(false);
        }
        let mut next = m.clone();
        next.remove(fingerprint);
        self.save(&next)?;
        *m = next;
        Ok(true)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sync::table::Replica;
    use serde_json::json;

    fn tmp(name: &str) -> PathBuf {
        let d =
            std::env::temp_dir().join(format!("tsulink-store-{name}-{}", random_hex16().unwrap()));
        fs::create_dir_all(&d).unwrap();
        d
    }

    #[test]
    fn mo_lai_giu_ban_ghi_seq_con_tro_va_ma_nhat_ky() {
        let d = tmp("mo-lai");
        let (id, hlc) = {
            let r = Replica::new("A", FileRowStore::open(&d).unwrap());
            r.write("chi", "1", json!({"so_tien": 1}), 1000).unwrap();
            r.write("chi", "2", json!(2), 1001).unwrap();
            let h = r.write("chi", "1", json!({"so_tien": 5}), 1002).unwrap();
            r.delete("chi", "2", 1003).unwrap();
            r.store()
                .set_cursor(
                    "B",
                    Cursor {
                        log: "x".into(),
                        seq: 7,
                    },
                )
                .unwrap();
            (r.store().log_id(), h)
        };
        let s = FileRowStore::open(&d).unwrap();
        assert_eq!(s.log_id(), id);
        assert_eq!(
            s.cursor("B"),
            Some(Cursor {
                log: "x".into(),
                seq: 7
            })
        );
        let ch = s.changes_after(0, 100);
        assert_eq!(ch.iter().map(|(q, _)| *q).collect::<Vec<_>>(), vec![3, 4]);
        let r = Replica::new("A", s);
        assert_eq!(r.read("chi", "1"), Some(json!({"so_tien": 5})));
        assert_eq!(r.read("chi", "2"), None);
        // Đồng hồ tiếp nối mốc lớn nhất trên đĩa.
        let h2 = r.write("chi", "3", json!(3), 0).unwrap();
        assert!(h2 > hlc);
        assert_eq!(
            r.store().changes_after(4, 10)[0].0,
            5,
            "seq không bị dùng lại"
        );
        fs::remove_dir_all(d).unwrap();
    }

    #[test]
    fn dong_cuoi_do_dang_bi_cat_dong_hong_giua_bi_tu_choi() {
        let d = tmp("do-dang");
        {
            let r = Replica::new("A", FileRowStore::open(&d).unwrap());
            r.write("t", "a", json!(1), 10).unwrap();
            r.write("t", "b", json!(2), 11).unwrap();
        }
        let p = d.join(ROWS);
        let mut f = OpenOptions::new().append(true).open(&p).unwrap();
        f.write_all(b"{\"seq\":3,\"row\":{\"tab").unwrap();
        drop(f);
        let s = FileRowStore::open(&d).unwrap();
        assert_eq!(s.changes_after(0, 10).len(), 2);
        let r = Replica::new("A", s);
        r.write("t", "c", json!(3), 12).unwrap();
        drop(r);
        assert_eq!(
            FileRowStore::open(&d).unwrap().changes_after(0, 10).len(),
            3
        );

        let txt = fs::read_to_string(&p).unwrap();
        fs::write(&p, txt.replacen("\"seq\":1", "\"seq\":x", 1)).unwrap();
        assert_eq!(
            FileRowStore::open(&d).unwrap_err(),
            Error::Corrupt("rows.jsonl")
        );
        fs::remove_dir_all(d).unwrap();
    }

    #[test]
    fn viet_gon_va_xoa_bia_mo_tren_dia() {
        let d = tmp("gon");
        {
            let r = Replica::new("A", FileRowStore::open(&d).unwrap());
            for i in 0..1200u64 {
                r.write("t", "k", json!(i), 10 + i).unwrap();
            }
            r.delete("t", "x", 5).unwrap();
            // HLC đơn điệu ⇒ bia mộ mang mốc ~1210 ms dù ghi "lúc 5".
            let now = crate::sync::table::TOMBSTONE_TTL_MS + 5_000;
            assert_eq!(r.purge_tombstones(now).unwrap(), 1);
        }
        let txt = fs::read_to_string(d.join(ROWS)).unwrap();
        assert_eq!(txt.lines().count(), 1, "chỉ còn phiên bản sống");
        let s = FileRowStore::open(&d).unwrap();
        assert!(s.get("t", "x").is_none());
        assert_eq!(s.get("t", "k").unwrap().value, Some(json!(1199)));
        fs::remove_dir_all(d).unwrap();
    }

    #[test]
    fn kho_thiet_bi_mo_lai_giu_danh_sach() {
        let d = tmp("tb");
        let dev = PairedDevice {
            fingerprint: "A".repeat(64),
            alias: "Máy A".into(),
            paired_at: 1,
            last_sync_at: 1,
        };
        {
            let s = FileDeviceStore::open(&d).unwrap();
            s.upsert(dev.clone()).unwrap();
            s.touch(&dev.fingerprint, 9).unwrap();
        }
        let s = FileDeviceStore::open(&d).unwrap();
        assert_eq!(s.get(&dev.fingerprint).unwrap().last_sync_at, 9);
        assert!(s.remove(&dev.fingerprint).unwrap());
        assert!(!s.remove(&dev.fingerprint).unwrap());
        assert!(FileDeviceStore::open(&d).unwrap().list().is_empty());
        fs::remove_dir_all(d).unwrap();
    }
}
