//! Khám phá thiết bị qua multicast, dùng chung kênh Lotus v2 (`LOCAL_SYNC.md` mục 2):
//! `224.0.0.168:53420` và `ff12::1075:5ea0`, socket mở với `SO_REUSEADDR`/`SO_REUSEPORT` để chạy cạnh Lotus Share.
//!
//! Lời rao giữ khuôn JSON `MulticastMessageV2` của Lotus v2 và thêm trường `tsulink: {"app", "v"}`; cổng TCP trong
//! trường `port` là cổng của [`crate::transport::Listener`] (không chiếm 53420). Bên nhận chỉ giữ lời rao:
//! có `tsulink.v == 1` và đúng `app`, `protocol == "https"`, vân tay hợp lệ, nguồn thuộc mạng nội bộ (L1).
//! Thiết bị chưa ghép đôi vẫn được báo (để ghép đôi bằng so mã số) với `paired == false` - lớp đồng bộ MUST bỏ qua
//! chúng (L2). Mạng chặn multicast ⇒ dùng địa chỉ trong mã QR.

use crate::addr::is_local_network;
use crate::tls::PeerPins;
use crate::{Error, is_valid_fingerprint};
use serde::{Deserialize, Serialize};
use socket2::{Domain, Protocol, Socket, Type};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6};
use std::sync::Arc;
use tokio::net::UdpSocket;
use tokio::sync::mpsc;

/// Nhóm multicast IPv4 của Lotus v2.
pub const GROUP_V4: Ipv4Addr = Ipv4Addr::new(224, 0, 0, 168);
/// Nhóm multicast IPv6 (link-local) của Lotus v2.
pub const GROUP_V6: Ipv6Addr = Ipv6Addr::new(0xff12, 0, 0, 0, 0, 0, 0x1075, 0x5ea0);
/// Cổng UDP khám phá của Lotus v2.
pub const PORT: u16 = 53420;
/// Phiên bản trường `tsulink`.
pub const TSULINK_VERSION: u32 = 1;
/// Kích thước tối đa một lời rao.
const MAX_DATAGRAM: usize = 2048;

/// Trường riêng của Tsu Link trong lời rao.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TsulinkField {
    /// Mã sản phẩm (vd `qulythuchi`).
    pub app: String,
    /// Phiên bản giao thức Tsu Link.
    pub v: u32,
}

/// Lời rao multicast (khuôn Lotus v2 `MulticastMessageV2` + trường `tsulink`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Announcement {
    /// Tên hiển thị của thiết bị.
    pub alias: String,
    /// Phiên bản Lotus v2 (`2.2`).
    pub version: String,
    /// Kiểu máy (tuỳ chọn).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub device_model: Option<String>,
    /// `mobile`/`desktop`/... (tuỳ chọn).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub device_type: Option<String>,
    /// Vân tay chứng thư.
    pub fingerprint: String,
    /// Cổng TCP mTLS của app.
    pub port: u16,
    /// Luôn `https` (L3).
    pub protocol: String,
    /// Lotus Share: API tải xuống - Tsu Link luôn `false`.
    #[serde(default)]
    pub download: bool,
    /// Trường Tsu Link; thiếu ⇒ không phải Tsu Link (vd Lotus Share) ⇒ bỏ qua.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tsulink: Option<TsulinkField>,
}

impl Announcement {
    /// Lời rao của thiết bị này.
    pub fn new(app: &str, alias: &str, fingerprint: &str, port: u16) -> Self {
        Self {
            alias: alias.chars().take(64).collect(),
            version: "2.2".into(),
            device_model: None,
            device_type: None,
            fingerprint: fingerprint.to_owned(),
            port,
            protocol: "https".into(),
            download: false,
            tsulink: Some(TsulinkField {
                app: app.to_owned(),
                v: TSULINK_VERSION,
            }),
        }
    }

    /// Mã hoá JSON để gửi.
    pub fn to_bytes(&self) -> Vec<u8> {
        serde_json::to_vec(self).unwrap_or_default()
    }
}

/// Một thiết bị Tsu Link vừa thấy trên mạng.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DiscoveredPeer {
    /// Vân tay chứng thư (chưa xác thực - chỉ xác thực khi bắt tay mTLS).
    pub fingerprint: String,
    /// Tên hiển thị.
    pub alias: String,
    /// Địa chỉ mTLS (IP nguồn của lời rao + cổng khai báo).
    pub addr: SocketAddr,
    /// Đã ghép đôi chưa (theo [`PeerPins`]); `false` ⇒ lớp đồng bộ MUST bỏ qua.
    pub paired: bool,
}

/// Đọc một lời rao nhận từ `src`. Trả `None` nếu không phải lời rao Tsu Link hợp lệ cho `app`, là của chính mình
/// (`own_fp`) hoặc đến từ địa chỉ không thuộc mạng nội bộ.
pub fn parse(
    datagram: &[u8],
    src: SocketAddr,
    app: &str,
    own_fp: &str,
    pins: &dyn PeerPins,
) -> Option<DiscoveredPeer> {
    if datagram.len() > MAX_DATAGRAM || !is_local_network(src.ip()) {
        return None;
    }
    let msg: Announcement = serde_json::from_slice(datagram).ok()?;
    let field = msg.tsulink.as_ref()?;
    if field.v != TSULINK_VERSION
        || field.app != app
        || msg.protocol != "https"
        || msg.port == 0
        || !is_valid_fingerprint(&msg.fingerprint)
        || msg.fingerprint == own_fp
    {
        return None;
    }
    let ip = match src.ip() {
        IpAddr::V6(v6) => v6
            .to_ipv4_mapped()
            .map(IpAddr::V4)
            .unwrap_or(IpAddr::V6(v6)),
        v4 => v4,
    };
    let addr = match (ip, src) {
        (IpAddr::V6(v6), SocketAddr::V6(s)) => {
            SocketAddr::V6(SocketAddrV6::new(v6, msg.port, 0, s.scope_id()))
        }
        (ip, _) => SocketAddr::new(ip, msg.port),
    };
    Some(DiscoveredPeer {
        paired: pins.is_paired(&msg.fingerprint),
        fingerprint: msg.fingerprint,
        alias: msg.alias.chars().take(64).collect(),
        addr,
    })
}

struct McastSocket {
    target: SocketAddr,
    socket: Arc<UdpSocket>,
}

/// Bộ khám phá: mở socket multicast trên mọi giao diện mạng nội bộ, rao và nghe.
pub struct Discovery {
    sockets: Vec<McastSocket>,
    rx: mpsc::Receiver<(Vec<u8>, SocketAddr)>,
    tasks: Vec<tokio::task::JoinHandle<()>>,
    app: String,
    own_fp: String,
    pins: Arc<dyn PeerPins>,
}

impl std::fmt::Debug for Discovery {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Discovery")
            .field("sockets", &self.sockets.len())
            .field("app", &self.app)
            .finish_non_exhaustive()
    }
}

impl Drop for Discovery {
    fn drop(&mut self) {
        for t in &self.tasks {
            t.abort();
        }
    }
}

impl Discovery {
    /// Mở khám phá cho `app`. Giao diện không mở được bị bỏ qua; không còn giao diện nào ⇒ [`Error::Io`].
    pub fn start(app: &str, own_fp: &str, pins: Arc<dyn PeerPins>) -> Result<Self, Error> {
        let mut sockets = Vec::new();
        let ifaces = if_addrs::get_if_addrs().map_err(|e| Error::Io(e.kind()))?;
        let mut v6_done = Vec::new();
        for iface in ifaces.iter().filter(|i| !i.is_loopback()) {
            match &iface.addr {
                if_addrs::IfAddr::V4(a) if is_local_network(IpAddr::V4(a.ip)) => {
                    if let Ok(s) = bind_v4(a.ip) {
                        sockets.push(McastSocket {
                            target: SocketAddr::V4(SocketAddrV4::new(GROUP_V4, PORT)),
                            socket: Arc::new(s),
                        });
                    }
                }
                if_addrs::IfAddr::V6(a) if is_local_network(IpAddr::V6(a.ip)) => {
                    let Some(idx) = iface.index else { continue };
                    if v6_done.contains(&idx) {
                        continue;
                    }
                    if let Ok(s) = bind_v6(idx) {
                        v6_done.push(idx);
                        sockets.push(McastSocket {
                            target: SocketAddr::V6(SocketAddrV6::new(GROUP_V6, PORT, 0, idx)),
                            socket: Arc::new(s),
                        });
                    }
                }
                _ => {}
            }
        }
        if sockets.is_empty() {
            return Err(Error::Io(std::io::ErrorKind::AddrNotAvailable));
        }
        let (tx, rx) = mpsc::channel(64);
        let tasks = sockets
            .iter()
            .map(|s| {
                let sock = s.socket.clone();
                let tx = tx.clone();
                tokio::spawn(async move {
                    let mut buf = vec![0u8; MAX_DATAGRAM + 1];
                    while let Ok((n, src)) = sock.recv_from(&mut buf).await {
                        if tx.send((buf[..n].to_vec(), src)).await.is_err() {
                            break;
                        }
                    }
                })
            })
            .collect();
        Ok(Self {
            sockets,
            rx,
            tasks,
            app: app.to_owned(),
            own_fp: own_fp.to_owned(),
            pins,
        })
    }

    /// Số socket đang mở (mỗi giao diện một socket).
    pub fn socket_count(&self) -> usize {
        self.sockets.len()
    }

    /// Rao lời rao trên mọi giao diện. Trả số giao diện gửi thành công.
    pub async fn announce(&self, msg: &Announcement) -> usize {
        let bytes = msg.to_bytes();
        let mut ok = 0;
        for s in &self.sockets {
            if s.socket.send_to(&bytes, s.target).await.is_ok() {
                ok += 1;
            }
        }
        ok
    }

    /// Chờ thiết bị Tsu Link kế tiếp (đã lọc theo [`parse`]).
    pub async fn next(&mut self) -> Option<DiscoveredPeer> {
        loop {
            let (data, src) = self.rx.recv().await?;
            if let Some(p) = parse(&data, src, &self.app, &self.own_fp, self.pins.as_ref()) {
                return Some(p);
            }
        }
    }
}

fn bind_v4(iface: Ipv4Addr) -> std::io::Result<UdpSocket> {
    let s = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP))?;
    // Chung cổng với Lotus Share và app Tsu Link khác. Windows không có SO_REUSEPORT.
    s.set_reuse_address(true)?;
    #[cfg(all(unix, not(any(target_os = "solaris", target_os = "illumos"))))]
    s.set_reuse_port(true)?;
    s.bind(&SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, PORT)).into())?;
    s.join_multicast_v4(&GROUP_V4, &iface)?;
    s.set_multicast_if_v4(&iface)?;
    s.set_multicast_loop_v4(true)?;
    s.set_multicast_ttl_v4(1)?; // chỉ trong mạng con
    s.set_nonblocking(true)?;
    UdpSocket::from_std(s.into())
}

fn bind_v6(iface: u32) -> std::io::Result<UdpSocket> {
    let s = Socket::new(Domain::IPV6, Type::DGRAM, Some(Protocol::UDP))?;
    s.set_only_v6(true)?;
    s.set_reuse_address(true)?;
    #[cfg(all(unix, not(any(target_os = "solaris", target_os = "illumos"))))]
    s.set_reuse_port(true)?;
    s.bind(&SocketAddr::V6(SocketAddrV6::new(Ipv6Addr::UNSPECIFIED, PORT, 0, 0)).into())?;
    s.join_multicast_v6(&GROUP_V6, iface)?;
    s.set_multicast_if_v6(iface)?;
    s.set_multicast_loop_v6(true)?;
    s.set_multicast_hops_v6(1)?;
    s.set_nonblocking(true)?;
    UdpSocket::from_std(s.into())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tls::PinSet;

    fn fp(c: char) -> String {
        c.to_string().repeat(64)
    }

    fn src() -> SocketAddr {
        "192.168.1.20:53420".parse().unwrap()
    }

    #[test]
    fn loi_rao_giu_khuon_lotus_v2_va_them_tsulink() {
        let a = Announcement::new("qulythuchi", "Máy A", &fp('A'), 40123);
        let v: serde_json::Value = serde_json::from_slice(&a.to_bytes()).unwrap();
        assert_eq!(v["version"], "2.2");
        assert_eq!(v["protocol"], "https");
        assert_eq!(v["port"], 40123);
        assert_eq!(v["download"], false);
        assert_eq!(v["tsulink"]["app"], "qulythuchi");
        assert_eq!(v["tsulink"]["v"], 1);
    }

    #[test]
    fn nhan_loi_rao_hop_le_va_danh_dau_ghep_doi() {
        let pins = PinSet::new([fp('B')]);
        let a = Announcement::new("qulythuchi", "Máy B", &fp('B'), 40123).to_bytes();
        let p = parse(&a, src(), "qulythuchi", &fp('A'), &pins).unwrap();
        assert_eq!(p.addr, "192.168.1.20:40123".parse().unwrap());
        assert!(p.paired);
        let c = Announcement::new("qulythuchi", "Máy C", &fp('C'), 1).to_bytes();
        assert!(
            !parse(&c, src(), "qulythuchi", &fp('A'), &pins)
                .unwrap()
                .paired
        );
    }

    #[test]
    fn bo_qua_loi_rao_khong_hop_le() {
        let pins = PinSet::default();
        let ok = |m: &Announcement, s: SocketAddr| {
            parse(&m.to_bytes(), s, "qulythuchi", &fp('A'), &pins).is_some()
        };
        let base = Announcement::new("qulythuchi", "B", &fp('B'), 40123);
        assert!(ok(&base, src()));
        // Lotus Share (không có trường tsulink).
        let mut m = base.clone();
        m.tsulink = None;
        assert!(!ok(&m, src()));
        // Khác app, khác phiên bản, http, cổng 0, vân tay sai, của chính mình.
        let mut m = base.clone();
        m.tsulink.as_mut().unwrap().app = "sound-db".into();
        assert!(!ok(&m, src()));
        let mut m = base.clone();
        m.tsulink.as_mut().unwrap().v = 2;
        assert!(!ok(&m, src()));
        let mut m = base.clone();
        m.protocol = "http".into();
        assert!(!ok(&m, src()));
        let mut m = base.clone();
        m.port = 0;
        assert!(!ok(&m, src()));
        let mut m = base.clone();
        m.fingerprint = "abc".into();
        assert!(!ok(&m, src()));
        let m = Announcement::new("qulythuchi", "A", &fp('A'), 1);
        assert!(!ok(&m, src()));
        // L1: nguồn công cộng hoặc loopback.
        assert!(!ok(&base, "8.8.8.8:53420".parse().unwrap()));
        assert!(!ok(&base, "127.0.0.1:53420".parse().unwrap()));
        // Rác, quá dài.
        assert!(parse(b"{", src(), "qulythuchi", &fp('A'), &pins).is_none());
        assert!(parse(&[b' '; 4096], src(), "qulythuchi", &fp('A'), &pins).is_none());
    }

    #[test]
    fn ipv6_link_local_giu_scope() {
        let pins = PinSet::default();
        let s = SocketAddr::V6(SocketAddrV6::new("fe80::1".parse().unwrap(), PORT, 0, 3));
        let a = Announcement::new("qulythuchi", "B", &fp('B'), 40123).to_bytes();
        let p = parse(&a, s, "qulythuchi", &fp('A'), &pins).unwrap();
        assert_eq!(
            p.addr,
            SocketAddr::V6(SocketAddrV6::new("fe80::1".parse().unwrap(), 40123, 0, 3))
        );
    }

    #[test]
    fn doc_duoc_loi_rao_lotus_v2_co_truong_la() {
        let pins = PinSet::default();
        let json = format!(
            r#"{{"alias":"B","version":"2.2","deviceModel":"Windows","deviceType":"desktop","fingerprint":"{}","port":40123,"protocol":"https","download":false,"tsulink":{{"app":"qulythuchi","v":1}},"moi":1}}"#,
            fp('B')
        );
        assert!(parse(json.as_bytes(), src(), "qulythuchi", &fp('A'), &pins).is_some());
    }
}
