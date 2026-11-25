# Tsu Link (`tsulink`)

Đồng bộ dữ liệu **trực tiếp giữa hai thiết bị** của hệ TsuDEV qua cùng mạng Wi-Fi/Ethernet, ghép đôi bằng mã QR, so
mã 6 chữ số hoặc Bluetooth - **không đi qua internet**, không máy chủ trung gian, không tài khoản đám mây của bên thứ ba.
Miễn phí, mã nguồn mở (Apache-2.0).

Chuẩn: tsudev-standards [`docs/LOCAL_SYNC.md`](https://github.com/tsudev-org/tsudev-standards/blob/main/docs/LOCAL_SYNC.md)
(bản sao chỉ-đọc ở `.standards/docs/LOCAL_SYNC.md`). Nền kỹ thuật: giao thức Lotus v2 của
[Lotus Share](https://github.com/tsudev-org/lotus-share) (khám phá multicast, TLS hai chiều, ghim vân tay chứng thư).

## Trạng thái

| Phần | Trạng thái |
| --- | --- |
| `addr` - chỉ nhận địa chỉ mạng nội bộ (luật L1) | ✅ 0.1.0 |
| `pairing` - URI mã QR `tsulink:1?...`, mã một lần hạn 120 giây | ✅ 0.1.0 |
| `sas` - mã 6 chữ số so trên hai máy, vector đối chiếu chéo | ✅ 0.1.0 |
| Khám phá + mTLS 1.3 ghim vân tay (tách từ lõi Lotus v2) | ⬜ |
| Khung đồng bộ CRDT (Automerge, HLC), truyền tệp khối BLAKE3 | ⬜ |
| Sao lưu `.tsubak` (vector ở `conformance/tsubak-vectors-v1.json`) | ⬜ |
| Ràng buộc Flutter / C ABI (.NET) / Tauri; gói TS `@tsudev/link` | ⬜ |

Lộ trình: [`logs/handover/20261125-TL1_khoi-tao-tsulink.md`](logs/handover/20261125-TL1_khoi-tao-tsulink.md).

## Phát triển

```bash
cargo fmt --all --check
cargo clippy --all-targets -- -D warnings
cargo test
python3 conformance/check_sas_vector.py   # vector mã 6 chữ số tính độc lập
```

## Bảo mật

Báo lỗ hổng: [`SECURITY.md`](SECURITY.md) - không mở issue công khai.

## English summary

`tsulink` lets two TsuDEV apps sync user data **directly between devices on the same local network** (QR / 6-digit
comparison / Bluetooth pairing, mutual TLS 1.3 with pinned certificate fingerprints) - never over the internet, no relay,
no third-party cloud account. Spec: tsudev-standards `docs/LOCAL_SYNC.md`. Built on the Lotus v2 protocol of Lotus Share.
Version 0.1.0 ships local-address checks, QR pairing URIs and the 6-digit SAS code. Apache-2.0.
