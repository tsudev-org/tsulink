//! Bảng bản ghi LWW theo HLC + bia mộ (`LOCAL_SYNC.md` mục 4, ADR-0004).
//!
//! - Mỗi bản ghi `(bảng, khoá)` giữ đúng một phiên bản: phiên bản có [`Hlc`] lớn hơn thắng. Xoá = ghi bia mộ
//!   (`value: None`) với mốc mới, nên "xoá + sửa đồng thời" cũng theo LWW: bên có mốc sau thắng.
//! - Gộp lặp lại cùng phiên bản không đổi gì (idempotent) và không làm tăng nhật ký.
//! - Mỗi lần kho nhận một phiên bản mới (sửa tại máy hoặc gộp từ máy khác), phiên bản đó nhận số thứ tự `seq` tăng dần
//!   của nhật ký máy này. Máy kia nhớ [`Cursor`] = (mã nhật ký, `seq` lớn nhất đã nhận) - đây là "mốc cao nhất đã thấy"
//!   của chuẩn, tính theo nhật ký của bên gửi để không sót phiên bản đến muộn qua máy thứ ba.

use super::hlc::{Clock, Hlc};
use crate::Error;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::sync::{Mutex, RwLock};

/// Bia mộ cũ hơn bấy nhiêu thì xoá hẳn được (180 ngày - bằng hạn tự gỡ thiết bị không đồng bộ, nên mọi thiết bị còn
/// trong danh sách đều đã nhận bia mộ).
pub const TOMBSTONE_TTL_MS: u64 = 180 * 24 * 3600 * 1000;

/// Một phiên bản bản ghi.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Row {
    /// Tên bảng.
    pub table: String,
    /// Khoá chính (chuỗi do app chọn, thường là UUID).
    pub key: String,
    /// Mốc của lần sửa.
    pub hlc: Hlc,
    /// Nội dung; `None` = bia mộ (đã xoá).
    pub value: Option<serde_json::Value>,
}

/// Vị trí đã đọc tới trong nhật ký của một máy khác.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Cursor {
    /// Mã nhật ký của máy kia (đổi khi máy kia làm lại kho ⇒ đọc lại từ đầu).
    pub log: String,
    /// `seq` lớn nhất đã nhận và gộp xong.
    pub seq: u64,
}

/// Kho bản ghi do app cấp (SQLite, tệp...). Cài đặt phải an toàn luồng và ghi bền vững trước khi trả về.
pub trait RowStore: Send + Sync + std::fmt::Debug {
    /// Mã nhật ký ngẫu nhiên, cố định suốt đời kho.
    fn log_id(&self) -> String;
    /// Phiên bản hiện tại của `(table, key)`, gồm cả bia mộ.
    fn get(&self, table: &str, key: &str) -> Option<Row>;
    /// Ghi đè phiên bản của `(row.table, row.key)` và gán `seq` mới (lớn hơn mọi `seq` cũ); trả `seq` đó.
    fn put(&self, row: Row) -> u64;
    /// Tối đa `limit` phiên bản có `seq > after`, theo `seq` tăng dần.
    fn changes_after(&self, after: u64, limit: usize) -> Vec<(u64, Row)>;
    /// Mốc HLC lớn nhất trong kho (để [`Clock::resume`]).
    fn max_hlc(&self) -> Option<Hlc>;
    /// Vị trí đã đọc tới trong nhật ký của thiết bị `peer` (vân tay).
    fn cursor(&self, peer: &str) -> Option<Cursor>;
    /// Lưu vị trí đọc của thiết bị `peer`.
    fn set_cursor(&self, peer: &str, cursor: Cursor);
    /// Xoá hẳn bia mộ có mốc nhỏ hơn `before_ms`; trả số bản ghi đã xoá.
    fn purge_tombstones(&self, before_ms: u64) -> usize;
}

#[derive(Debug, Default)]
struct Mem {
    rows: BTreeMap<(String, String), (u64, Row)>,
    log: BTreeMap<u64, (String, String)>,
    next: u64,
    cursors: BTreeMap<String, Cursor>,
}

/// Kho trong bộ nhớ (test, hoặc app tự chép ra kho thật).
#[derive(Debug)]
pub struct InMemoryRowStore {
    id: String,
    mem: RwLock<Mem>,
}

impl InMemoryRowStore {
    /// Kho rỗng với mã nhật ký ngẫu nhiên.
    pub fn new() -> Result<Self, Error> {
        let mut rnd = [0u8; 16];
        getrandom::fill(&mut rnd).map_err(|_| Error::Rng)?;
        let id = rnd.iter().map(|b| format!("{b:02x}")).collect();
        Ok(Self {
            id,
            mem: RwLock::default(),
        })
    }
}

impl RowStore for InMemoryRowStore {
    fn log_id(&self) -> String {
        self.id.clone()
    }

    fn get(&self, table: &str, key: &str) -> Option<Row> {
        let m = self.mem.read().unwrap_or_else(|e| e.into_inner());
        m.rows
            .get(&(table.to_owned(), key.to_owned()))
            .map(|(_, r)| r.clone())
    }

    fn put(&self, row: Row) -> u64 {
        let mut m = self.mem.write().unwrap_or_else(|e| e.into_inner());
        m.next += 1;
        let seq = m.next;
        let k = (row.table.clone(), row.key.clone());
        if let Some((old, _)) = m.rows.insert(k.clone(), (seq, row)) {
            m.log.remove(&old);
        }
        m.log.insert(seq, k);
        seq
    }

    fn changes_after(&self, after: u64, limit: usize) -> Vec<(u64, Row)> {
        let m = self.mem.read().unwrap_or_else(|e| e.into_inner());
        m.log
            .range(after + 1..)
            .take(limit)
            .map(|(s, k)| (*s, m.rows[k].1.clone()))
            .collect()
    }

    fn max_hlc(&self) -> Option<Hlc> {
        let m = self.mem.read().unwrap_or_else(|e| e.into_inner());
        m.rows.values().map(|(_, r)| r.hlc.clone()).max()
    }

    fn cursor(&self, peer: &str) -> Option<Cursor> {
        let m = self.mem.read().unwrap_or_else(|e| e.into_inner());
        m.cursors.get(peer).cloned()
    }

    fn set_cursor(&self, peer: &str, cursor: Cursor) {
        let mut m = self.mem.write().unwrap_or_else(|e| e.into_inner());
        m.cursors.insert(peer.to_owned(), cursor);
    }

    fn purge_tombstones(&self, before_ms: u64) -> usize {
        let mut m = self.mem.write().unwrap_or_else(|e| e.into_inner());
        let dead: Vec<_> = m
            .rows
            .iter()
            .filter(|(_, (_, r))| r.value.is_none() && r.hlc.ms < before_ms)
            .map(|(k, (s, _))| (k.clone(), *s))
            .collect();
        for (k, s) in &dead {
            m.rows.remove(k);
            m.log.remove(s);
        }
        dead.len()
    }
}

/// Bản sao dữ liệu bảng của một thiết bị: kho + đồng hồ HLC.
#[derive(Debug)]
pub struct Replica<S: RowStore> {
    store: S,
    clock: Mutex<Clock>,
}

impl<S: RowStore> Replica<S> {
    /// Mở bản sao cho thiết bị `node` (vân tay của chính máy này); đồng hồ tiếp nối mốc lớn nhất trong kho.
    pub fn new(node: impl Into<String>, store: S) -> Self {
        let clock = Clock::resume(node, store.max_hlc().as_ref());
        Self {
            store,
            clock: Mutex::new(clock),
        }
    }

    /// Kho bên dưới.
    pub fn store(&self) -> &S {
        &self.store
    }

    fn clock(&self) -> std::sync::MutexGuard<'_, Clock> {
        self.clock.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Ghi `value` vào `(table, key)` tại máy này; trả mốc của lần sửa.
    pub fn write(&self, table: &str, key: &str, value: serde_json::Value, now_ms: u64) -> Hlc {
        self.local(table, key, Some(value), now_ms)
    }

    /// Xoá `(table, key)` tại máy này (ghi bia mộ); trả mốc.
    pub fn delete(&self, table: &str, key: &str, now_ms: u64) -> Hlc {
        self.local(table, key, None, now_ms)
    }

    fn local(&self, table: &str, key: &str, value: Option<serde_json::Value>, now_ms: u64) -> Hlc {
        let hlc = self.clock().tick(now_ms);
        self.store.put(Row {
            table: table.to_owned(),
            key: key.to_owned(),
            hlc: hlc.clone(),
            value,
        });
        hlc
    }

    /// Nội dung hiện tại (`None` nếu chưa có hoặc đã xoá).
    pub fn read(&self, table: &str, key: &str) -> Option<serde_json::Value> {
        self.store.get(table, key).and_then(|r| r.value)
    }

    /// Gộp một phiên bản từ máy khác. Trả `true` nếu phiên bản này thắng và được ghi; `false` nếu đã có phiên bản
    /// bằng hoặc mới hơn (gộp lặp lại không đổi gì). `Err(ClockSkew)` nếu mốc nhanh quá [`super::hlc::MAX_DRIFT_MS`].
    pub fn merge(&self, row: Row, now_ms: u64) -> Result<bool, Error> {
        self.clock().observe(&row.hlc, now_ms)?;
        match self.store.get(&row.table, &row.key) {
            Some(cur) if cur.hlc >= row.hlc => Ok(false),
            _ => {
                self.store.put(row);
                Ok(true)
            }
        }
    }

    /// Xoá hẳn bia mộ quá [`TOMBSTONE_TTL_MS`]; trả số bản ghi đã xoá.
    pub fn purge_tombstones(&self, now_ms: u64) -> usize {
        self.store
            .purge_tombstones(now_ms.saturating_sub(TOMBSTONE_TTL_MS))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn replica(node: &str) -> Replica<InMemoryRowStore> {
        Replica::new(node, InMemoryRowStore::new().unwrap())
    }

    fn copy_all(from: &Replica<InMemoryRowStore>, to: &Replica<InMemoryRowStore>, now: u64) {
        for (_, r) in from.store().changes_after(0, usize::MAX) {
            to.merge(r, now).unwrap();
        }
    }

    #[test]
    fn hai_may_sua_cung_ban_ghi_ngoai_tuyen_ben_sau_thang_o_ca_hai() {
        let a = replica("A");
        let b = replica("B");
        a.write("chi", "1", json!({"so_tien": 100}), 1000);
        b.write("chi", "1", json!({"so_tien": 200}), 2000);
        copy_all(&a, &b, 3000);
        copy_all(&b, &a, 3000);
        assert_eq!(a.read("chi", "1"), Some(json!({"so_tien": 200})));
        assert_eq!(b.read("chi", "1"), a.read("chi", "1"));
    }

    #[test]
    fn xoa_va_sua_dong_thoi_theo_lww() {
        // Xoá sau ⇒ xoá thắng.
        let a = replica("A");
        let b = replica("B");
        a.write("chi", "1", json!(1), 1000);
        copy_all(&a, &b, 1000);
        b.write("chi", "1", json!(2), 2000);
        a.delete("chi", "1", 3000);
        copy_all(&a, &b, 4000);
        copy_all(&b, &a, 4000);
        assert_eq!(a.read("chi", "1"), None);
        assert_eq!(b.read("chi", "1"), None);
        // Sửa sau ⇒ bản ghi sống lại ở cả hai máy.
        b.write("chi", "1", json!(3), 5000);
        copy_all(&b, &a, 6000);
        assert_eq!(a.read("chi", "1"), Some(json!(3)));
    }

    #[test]
    fn gop_lap_lai_khong_doi_va_khong_tang_nhat_ky() {
        let a = replica("A");
        let b = replica("B");
        a.write("t", "k", json!("x"), 10);
        copy_all(&a, &b, 10);
        let before = b.store().changes_after(0, usize::MAX);
        copy_all(&a, &b, 10);
        assert_eq!(b.store().changes_after(0, usize::MAX), before);
    }

    #[test]
    fn nhat_ky_chi_giu_phien_ban_moi_nhat_va_seq_tang() {
        let a = replica("A");
        a.write("t", "k", json!(1), 10);
        a.write("t", "j", json!(1), 10);
        a.write("t", "k", json!(2), 10);
        let log = a.store().changes_after(0, 10);
        assert_eq!(log.len(), 2);
        assert_eq!(log[1].1.key, "k");
        assert!(log[0].0 < log[1].0);
        assert_eq!(a.store().changes_after(log[0].0, 10).len(), 1);
    }

    #[test]
    fn mo_lai_kho_dong_ho_tiep_noi() {
        let store = InMemoryRowStore::new().unwrap();
        store.put(Row {
            table: "t".into(),
            key: "k".into(),
            hlc: Hlc {
                ms: 9_000,
                c: 4,
                node: "B".into(),
            },
            value: None,
        });
        let r = Replica::new("A", store);
        let h = r.write("t", "k", json!(1), 1);
        assert_eq!((h.ms, h.c), (9_000, 5));
        assert_eq!(r.read("t", "k"), Some(json!(1)));
    }

    #[test]
    fn bia_mo_qua_180_ngay_bi_xoa_han() {
        let a = replica("A");
        a.delete("t", "cu", 1);
        a.write("t", "song", json!(1), 2);
        let now = TOMBSTONE_TTL_MS + 10;
        a.delete("t", "moi", now);
        assert_eq!(a.purge_tombstones(now), 1);
        assert!(a.store().get("t", "cu").is_none());
        assert!(a.store().get("t", "moi").is_some());
        assert_eq!(a.read("t", "song"), Some(json!(1)));
    }

    #[test]
    fn tu_choi_moc_lech_gio_qua_xa() {
        let a = replica("A");
        let r = Row {
            table: "t".into(),
            key: "k".into(),
            hlc: Hlc {
                ms: u64::MAX / 2,
                c: 0,
                node: "B".into(),
            },
            value: Some(json!(1)),
        };
        assert_eq!(a.merge(r, 1000), Err(Error::ClockSkew));
        assert_eq!(a.read("t", "k"), None);
    }
}
