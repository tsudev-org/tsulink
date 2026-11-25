# Nhật ký thay đổi

Theo [Keep a Changelog](https://keepachangelog.com/vi/1.1.0/) và SemVer.

## [Chưa phát hành]

## [0.1.0] - 25/11/2026

### Thêm

- `addr::is_local_network` / `require_local`: chỉ nhận IPv4 RFC 1918 + link-local, IPv6 ULA + link-local (luật L1).
- `pairing::PairingOffer`: URI mã QR `tsulink:1?app=&fp=&a=&t=&exp=`, mã ghép đôi 128 bit ngẫu nhiên, hạn ≤ 120 giây,
  từ chối địa chỉ công cộng, khoá lạ/lặp, vân tay sai khuôn.
- `sas::code`: mã 6 chữ số = (4 byte đầu SHA-256, big-endian) mod 1 000 000, thứ tự theo vân tay; vector
  `conformance/sas-vector-1.txt` tính độc lập bằng Python.
- Vector `.tsubak` (`conformance/tsubak-vectors-v1.json`) chuyển từ tsusync.
