//! Danh sách thiết bị đã ghép đôi (`LOCAL_SYNC.md` mục 3): app cấp kho lưu (trait [`DeviceStore`]), xem/xoá được
//! trong Cài đặt; thiết bị không đồng bộ quá [`STALE_AFTER_SECS`] tự bị gỡ. [`PinsFromStore`] nối kho vào bộ ghim
//! mTLS ([`crate::tls::PeerPins`]) nên gỡ thiết bị có hiệu lực ngay ở kết nối kế tiếp.

use crate::tls::PeerPins;
use std::collections::BTreeMap;
use std::sync::{Arc, RwLock};

/// 180 ngày không đồng bộ ⇒ tự gỡ.
pub const STALE_AFTER_SECS: u64 = 180 * 24 * 3600;

/// Một thiết bị đã ghép đôi.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PairedDevice {
    /// Vân tay chứng thư (hex HOA).
    pub fingerprint: String,
    /// Tên hiển thị bên kia tự khai (≤ 64 ký tự) - chỉ để hiện, không dùng để xác thực.
    pub alias: String,
    /// Thời điểm ghép đôi (giây Unix).
    pub paired_at: u64,
    /// Lần đồng bộ gần nhất (giây Unix); bằng `paired_at` khi chưa đồng bộ lần nào.
    pub last_sync_at: u64,
}

/// Kho thiết bị đã ghép đôi do app cấp (mỗi app một kho). Cài đặt phải an toàn luồng.
pub trait DeviceStore: Send + Sync + std::fmt::Debug {
    /// Toàn bộ thiết bị.
    fn list(&self) -> Vec<PairedDevice>;
    /// Thêm hoặc thay theo vân tay.
    fn upsert(&self, device: PairedDevice);
    /// Gỡ theo vân tay; trả `true` nếu có.
    fn remove(&self, fingerprint: &str) -> bool;

    /// Tìm theo vân tay.
    fn get(&self, fingerprint: &str) -> Option<PairedDevice> {
        self.list()
            .into_iter()
            .find(|d| d.fingerprint == fingerprint)
    }

    /// Ghi nhận vừa đồng bộ xong với thiết bị.
    fn touch(&self, fingerprint: &str, now: u64) {
        if let Some(mut d) = self.get(fingerprint) {
            d.last_sync_at = now;
            self.upsert(d);
        }
    }

    /// Gỡ thiết bị không đồng bộ quá 180 ngày; trả số thiết bị đã gỡ.
    fn prune_stale(&self, now: u64) -> usize {
        let stale: Vec<_> = self
            .list()
            .into_iter()
            .filter(|d| now.saturating_sub(d.last_sync_at) > STALE_AFTER_SECS)
            .collect();
        for d in &stale {
            self.remove(&d.fingerprint);
        }
        stale.len()
    }
}

/// Kho trong bộ nhớ (test, hoặc app tự đồng bộ ra kho thật).
#[derive(Debug, Default)]
pub struct InMemoryDeviceStore(RwLock<BTreeMap<String, PairedDevice>>);

impl DeviceStore for InMemoryDeviceStore {
    fn list(&self) -> Vec<PairedDevice> {
        self.0
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .values()
            .cloned()
            .collect()
    }

    fn upsert(&self, device: PairedDevice) {
        self.0
            .write()
            .unwrap_or_else(|e| e.into_inner())
            .insert(device.fingerprint.clone(), device);
    }

    fn remove(&self, fingerprint: &str) -> bool {
        self.0
            .write()
            .unwrap_or_else(|e| e.into_inner())
            .remove(fingerprint)
            .is_some()
    }
}

/// Bộ ghim mTLS đọc thẳng từ kho thiết bị.
#[derive(Debug, Clone)]
pub struct PinsFromStore(pub Arc<dyn DeviceStore>);

impl PeerPins for PinsFromStore {
    fn is_paired(&self, fingerprint: &str) -> bool {
        self.0.get(fingerprint).is_some()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dev(c: char, t: u64) -> PairedDevice {
        PairedDevice {
            fingerprint: c.to_string().repeat(64),
            alias: c.into(),
            paired_at: t,
            last_sync_at: t,
        }
    }

    #[test]
    fn them_go_va_tu_go_sau_180_ngay() {
        let s = Arc::new(InMemoryDeviceStore::default());
        s.upsert(dev('A', 0));
        s.upsert(dev('B', 0));
        let pins = PinsFromStore(s.clone());
        assert!(pins.is_paired(&"A".repeat(64)));
        s.touch(&"B".repeat(64), STALE_AFTER_SECS);
        assert_eq!(s.prune_stale(STALE_AFTER_SECS + 1), 1);
        assert!(!pins.is_paired(&"A".repeat(64)), "gỡ có hiệu lực ngay");
        assert!(pins.is_paired(&"B".repeat(64)));
        assert!(s.remove(&"B".repeat(64)));
        assert!(s.list().is_empty());
    }
}
