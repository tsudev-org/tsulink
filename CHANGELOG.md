# Nhật ký thay đổi

Theo [Keep a Changelog](https://keepachangelog.com/vi/1.1.0/) và SemVer.

## [Chưa phát hành]

## [0.2.0] - 26/11/2026

### Thêm

- `identity::DeviceIdentity`: khoá ECDSA P-256 + chứng thư tự ký, vân tay SHA-256 HOA, nạp lại từ DER (kiểm khoá khớp).
- `tls`: cấu hình rustls chỉ TLS 1.3, ALPN `tsulink/1`, mTLS bắt buộc, ghim vân tay hai chiều (`PeerPins`, `PinSet`),
  tắt nối lại phiên và 0-RTT.
- `transport::connect` / `Listener`: chỉ địa chỉ mạng nội bộ (L1), cổng nghe tự hết hạn sau 10 phút (L4), bỏ qua máy
  chưa ghép đôi (L2), không có đường `http` (L3).
- `discovery`: multicast chung kênh Lotus v2 (IPv4 + IPv6), lời rao thêm trường `tsulink`, lọc nguồn/app/vân tay.
- ADR-0001: dựng lại khám phá + mTLS theo lõi Lotus v2 thay vì phụ thuộc crate `localsend`.

## [0.1.0] - 25/11/2026

### Thêm

- `addr::is_local_network` / `require_local`: chỉ nhận IPv4 RFC 1918 + link-local, IPv6 ULA + link-local (luật L1).
- `pairing::PairingOffer`: URI mã QR `tsulink:1?app=&fp=&a=&t=&exp=`, mã ghép đôi 128 bit ngẫu nhiên, hạn ≤ 120 giây,
  từ chối địa chỉ công cộng, khoá lạ/lặp, vân tay sai khuôn.
- `sas::code`: mã 6 chữ số = (4 byte đầu SHA-256, big-endian) mod 1 000 000, thứ tự theo vân tay; vector
  `conformance/sas-vector-1.txt` tính độc lập bằng Python.
- Vector `.tsubak` (`conformance/tsubak-vectors-v1.json`) chuyển từ tsusync.
