//! Luật L1: Tsu Link chỉ nói chuyện với địa chỉ mạng nội bộ.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

/// `true` nếu địa chỉ thuộc mạng nội bộ: IPv4 RFC 1918 hoặc link-local (169.254/16); IPv6 ULA (fc00::/7) hoặc
/// link-local (fe80::/10); IPv4 ánh xạ trong IPv6 xét theo IPv4. Loopback, địa chỉ công cộng, multicast,
/// unspecified ⇒ `false`.
pub fn is_local_network(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => is_local_v4(v4),
        IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
            Some(v4) => is_local_v4(v4),
            None => is_local_v6(v6),
        },
    }
}

fn is_local_v4(ip: Ipv4Addr) -> bool {
    ip.is_private() || ip.is_link_local()
}

fn is_local_v6(ip: Ipv6Addr) -> bool {
    let first = ip.segments()[0];
    (first & 0xfe00) == 0xfc00 || (first & 0xffc0) == 0xfe80
}

/// Kiểm một địa chỉ socket; trả lỗi [`crate::Error::PublicAddress`] nếu ngoài mạng nội bộ.
pub fn require_local(addr: SocketAddr) -> Result<SocketAddr, crate::Error> {
    if is_local_network(addr.ip()) {
        Ok(addr)
    } else {
        Err(crate::Error::PublicAddress(addr.to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    #[test]
    fn nhan_mang_noi_bo() {
        for s in [
            "10.0.0.5",
            "172.16.3.4",
            "172.31.255.1",
            "192.168.1.20",
            "169.254.10.1",
            "fd12:3456::1",
            "fe80::1",
            "::ffff:192.168.0.9",
        ] {
            assert!(is_local_network(ip(s)), "{s}");
        }
    }

    #[test]
    fn tu_choi_cong_cong_va_dac_biet() {
        for s in [
            "8.8.8.8",
            "172.32.0.1",
            "1.1.1.1",
            "127.0.0.1",
            "0.0.0.0",
            "224.0.0.168",
            "2001:4860::8888",
            "::1",
            "::",
            "ff12::1075:5ea0",
            "::ffff:8.8.8.8",
        ] {
            assert!(!is_local_network(ip(s)), "{s}");
        }
    }
}
