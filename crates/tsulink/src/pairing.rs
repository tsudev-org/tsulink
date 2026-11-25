//! URI mã QR ghép đôi (`LOCAL_SYNC.md` mục 3):
//!
//! `tsulink:1?app=<ma>&fp=<vân tay>&a=<IP:cổng>[,<IP:cổng>]&t=<mã 128 bit base64url>&exp=<unix>`
//!
//! IPv6 viết `[addr]:port`; `%` của scope id viết `%25`. Mã `t` dùng một lần, hạn tối đa [`MAX_TTL_SECS`].

use crate::{Error, addr::require_local, is_valid_fingerprint};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use percent_encoding::{AsciiSet, CONTROLS, percent_decode_str, utf8_percent_encode};
use std::net::SocketAddr;

/// Hạn tối đa của một mã QR ghép đôi.
pub const MAX_TTL_SECS: u64 = 120;

const PREFIX: &str = "tsulink:1?";
const ENC: &AsciiSet = &CONTROLS
    .add(b'%')
    .add(b'&')
    .add(b'=')
    .add(b'?')
    .add(b'#')
    .add(b' ')
    .add(b'+');

/// Nội dung mã QR ghép đôi.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PairingOffer {
    /// Mã sản phẩm (vd `qulythuchi`) - chỉ `a-z`, `0-9`, `-`.
    pub app: String,
    /// Vân tay chứng thư của thiết bị hiện QR.
    pub fingerprint: String,
    /// Địa chỉ mạng nội bộ của thiết bị hiện QR (≥ 1).
    pub addrs: Vec<SocketAddr>,
    /// Mã ghép đôi một lần, 16 byte ngẫu nhiên.
    pub token: [u8; 16],
    /// Hết hạn (giây Unix).
    pub expires_at: u64,
}

impl PairingOffer {
    /// Tạo lời mời mới với mã ngẫu nhiên, hạn [`MAX_TTL_SECS`] kể từ `now`.
    pub fn new(
        app: &str,
        fingerprint: &str,
        addrs: Vec<SocketAddr>,
        now: u64,
    ) -> Result<Self, Error> {
        let mut token = [0u8; 16];
        getrandom::fill(&mut token).map_err(|_| Error::Rng)?;
        let offer = Self {
            app: app.to_owned(),
            fingerprint: fingerprint.to_owned(),
            addrs,
            token,
            expires_at: now + MAX_TTL_SECS,
        };
        offer.validate(now)?;
        Ok(offer)
    }

    /// Kiểm mọi ràng buộc tại thời điểm `now`.
    pub fn validate(&self, now: u64) -> Result<(), Error> {
        if self.app.is_empty()
            || self.app.len() > 64
            || !self
                .app
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        {
            return Err(Error::Malformed("app"));
        }
        if !is_valid_fingerprint(&self.fingerprint) {
            return Err(Error::BadFingerprint);
        }
        if self.addrs.is_empty() || self.addrs.len() > 8 {
            return Err(Error::Malformed("a"));
        }
        for a in &self.addrs {
            require_local(*a)?;
        }
        if self.expires_at <= now || self.expires_at > now + MAX_TTL_SECS {
            return Err(Error::Expired);
        }
        Ok(())
    }

    /// Chuỗi đưa vào mã QR.
    pub fn to_uri(&self) -> String {
        let addrs: Vec<String> = self
            .addrs
            .iter()
            .map(|a| utf8_percent_encode(&a.to_string(), ENC).to_string())
            .collect();
        format!(
            "{PREFIX}app={}&fp={}&a={}&t={}&exp={}",
            self.app,
            self.fingerprint,
            addrs.join(","),
            URL_SAFE_NO_PAD.encode(self.token),
            self.expires_at
        )
    }

    /// Đọc và kiểm chuỗi quét được từ mã QR tại thời điểm `now`.
    pub fn parse(uri: &str, now: u64) -> Result<Self, Error> {
        let query = uri
            .strip_prefix(PREFIX)
            .ok_or(Error::Malformed("tiền tố"))?;
        let (mut app, mut fp, mut a, mut t, mut exp) = (None, None, None, None, None);
        for pair in query.split('&') {
            let (k, v) = pair
                .split_once('=')
                .ok_or(Error::Malformed("cặp khoá=giá trị"))?;
            let slot = match k {
                "app" => &mut app,
                "fp" => &mut fp,
                "a" => &mut a,
                "t" => &mut t,
                "exp" => &mut exp,
                _ => return Err(Error::Malformed("khoá lạ")),
            };
            if slot.replace(v).is_some() {
                return Err(Error::Malformed("khoá lặp"));
            }
        }
        let addrs = a
            .ok_or(Error::Malformed("a"))?
            .split(',')
            .map(|s| {
                let s = percent_decode_str(s)
                    .decode_utf8()
                    .map_err(|_| Error::Malformed("a"))?;
                s.parse::<SocketAddr>().map_err(|_| Error::Malformed("a"))
            })
            .collect::<Result<Vec<_>, _>>()?;
        let raw = URL_SAFE_NO_PAD
            .decode(t.ok_or(Error::Malformed("t"))?)
            .map_err(|_| Error::Malformed("t"))?;
        let token: [u8; 16] = raw.try_into().map_err(|_| Error::Malformed("t"))?;
        let offer = Self {
            app: app.ok_or(Error::Malformed("app"))?.to_owned(),
            fingerprint: fp.ok_or(Error::Malformed("fp"))?.to_owned(),
            addrs,
            token,
            expires_at: exp
                .ok_or(Error::Malformed("exp"))?
                .parse()
                .map_err(|_| Error::Malformed("exp"))?,
        };
        offer.validate(now)?;
        Ok(offer)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const FP: &str = "0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF";

    fn offer(now: u64) -> PairingOffer {
        PairingOffer::new(
            "qulythuchi",
            FP,
            vec![
                "192.168.1.20:41234".parse().unwrap(),
                "[fe80::1]:41234".parse().unwrap(),
            ],
            now,
        )
        .unwrap()
    }

    #[test]
    fn khu_hoi_uri() {
        let o = offer(1_000);
        let uri = o.to_uri();
        assert!(uri.starts_with("tsulink:1?app=qulythuchi&fp="));
        assert_eq!(PairingOffer::parse(&uri, 1_050).unwrap(), o);
    }

    #[test]
    fn het_han_sau_120_giay() {
        let uri = offer(1_000).to_uri();
        assert_eq!(PairingOffer::parse(&uri, 1_120), Err(Error::Expired));
    }

    #[test]
    fn han_qua_xa_bi_tu_choi() {
        let mut o = offer(1_000);
        o.expires_at = 1_000 + MAX_TTL_SECS + 1;
        assert_eq!(o.validate(1_000), Err(Error::Expired));
    }

    #[test]
    fn dia_chi_cong_cong_bi_tu_choi() {
        let e = PairingOffer::new("qulythuchi", FP, vec!["8.8.8.8:443".parse().unwrap()], 0);
        assert!(matches!(e, Err(Error::PublicAddress(_))));
        let mut uri = offer(0).to_uri();
        uri = uri.replace("192.168.1.20", "203.0.113.7");
        assert!(matches!(
            PairingOffer::parse(&uri, 1),
            Err(Error::PublicAddress(_))
        ));
    }

    #[test]
    fn van_tay_sai_khuon() {
        let lower = FP.to_lowercase();
        assert_eq!(
            PairingOffer::new("x", &lower, vec!["10.0.0.2:1".parse().unwrap()], 0),
            Err(Error::BadFingerprint)
        );
    }

    #[test]
    fn khoa_lap_va_khoa_la() {
        let uri = offer(0).to_uri();
        assert_eq!(
            PairingOffer::parse(&format!("{uri}&app=x"), 1),
            Err(Error::Malformed("khoá lặp"))
        );
        assert_eq!(
            PairingOffer::parse(&format!("{uri}&relay=1"), 1),
            Err(Error::Malformed("khoá lạ"))
        );
    }

    #[test]
    fn ma_moi_lan_khac_nhau() {
        assert_ne!(offer(0).token, offer(0).token);
    }
}
