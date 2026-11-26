//! Đồng hồ logic lai (HLC, Kulkarni và cộng sự 2014): mốc = (mili giây vật lý, bộ đếm, vân tay thiết bị).
//!
//! Thứ tự so sánh theo đúng thứ tự trường ⇒ hai mốc của hai thiết bị khác nhau không bao giờ bằng nhau, nên LWW luôn có
//! một bên thắng xác định trên mọi máy.

use crate::Error;
use serde::{Deserialize, Serialize};

/// Đồng hồ thiết bị bên kia được phép chạy nhanh hơn đồng hồ máy này tối đa bấy nhiêu (1 giờ). Hơn nữa ⇒ từ chối mốc,
/// tránh một máy đặt sai giờ (năm 2099) làm mọi lần sửa sau đó trên các máy khác luôn thua.
pub const MAX_DRIFT_MS: u64 = 3_600_000;

/// Một mốc HLC.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct Hlc {
    /// Mili giây Unix (phần vật lý).
    pub ms: u64,
    /// Bộ đếm trong cùng mili giây.
    pub c: u32,
    /// Vân tay thiết bị tạo mốc (phá hoà).
    pub node: String,
}

/// Đồng hồ HLC của một thiết bị.
#[derive(Debug, Clone)]
pub struct Clock {
    node: String,
    ms: u64,
    c: u32,
}

impl Clock {
    /// Đồng hồ mới cho thiết bị `node` (vân tay).
    pub fn new(node: impl Into<String>) -> Self {
        Self {
            node: node.into(),
            ms: 0,
            c: 0,
        }
    }

    /// Đồng hồ tiếp nối mốc lớn nhất đã lưu (sau khi mở lại app).
    pub fn resume(node: impl Into<String>, last: Option<&Hlc>) -> Self {
        let mut clock = Self::new(node);
        if let Some(h) = last {
            clock.ms = h.ms;
            clock.c = h.c;
        }
        clock
    }

    /// Vân tay thiết bị.
    pub fn node(&self) -> &str {
        &self.node
    }

    /// Mốc mới cho một lần sửa tại máy này; luôn lớn hơn mọi mốc đã phát hoặc đã thấy.
    pub fn tick(&mut self, now_ms: u64) -> Hlc {
        if now_ms > self.ms {
            self.ms = now_ms;
            self.c = 0;
        } else if self.c == u32::MAX {
            self.ms += 1;
            self.c = 0;
        } else {
            self.c += 1;
        }
        Hlc {
            ms: self.ms,
            c: self.c,
            node: self.node.clone(),
        }
    }

    /// Ghi nhận mốc từ thiết bị khác để lần [`Clock::tick`] sau lớn hơn nó.
    ///
    /// `Err(ClockSkew)` nếu mốc nhanh hơn `now_ms` quá [`MAX_DRIFT_MS`].
    pub fn observe(&mut self, remote: &Hlc, now_ms: u64) -> Result<(), Error> {
        if remote.ms > now_ms.saturating_add(MAX_DRIFT_MS) {
            return Err(Error::ClockSkew);
        }
        if (remote.ms, remote.c) > (self.ms, self.c) {
            self.ms = remote.ms;
            self.c = remote.c;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tick_luon_tang_ke_ca_khi_dong_ho_lui() {
        let mut c = Clock::new("A");
        let a = c.tick(1000);
        let b = c.tick(1000);
        let d = c.tick(900);
        assert!(a < b && b < d);
        assert_eq!((d.ms, d.c), (1000, 2));
        assert_eq!(c.tick(2000).c, 0);
    }

    #[test]
    fn observe_day_dong_ho_len_va_tu_choi_lech_qua_1_gio() {
        let mut a = Clock::new("A");
        let remote = Hlc {
            ms: 5000,
            c: 3,
            node: "B".into(),
        };
        a.observe(&remote, 1000).unwrap();
        assert!(a.tick(1000) > remote);
        let far = Hlc {
            ms: 1000 + MAX_DRIFT_MS + 1,
            c: 0,
            node: "B".into(),
        };
        assert_eq!(a.observe(&far, 1000), Err(Error::ClockSkew));
    }

    #[test]
    fn hai_may_cung_mili_giay_van_co_thu_tu() {
        let x = Clock::new("A").tick(7);
        let y = Clock::new("B").tick(7);
        assert_ne!(x, y);
        assert!(x < y);
    }

    #[test]
    fn bo_dem_tran_thi_sang_mili_giay_ke() {
        let mut c = Clock::resume(
            "A",
            Some(&Hlc {
                ms: 10,
                c: u32::MAX,
                node: "A".into(),
            }),
        );
        let h = c.tick(10);
        assert_eq!((h.ms, h.c), (11, 0));
    }
}
