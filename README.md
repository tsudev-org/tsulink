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
| `identity`, `tls`, `transport`, `discovery` - danh tính P-256, mTLS 1.3 ghim vân tay, khám phá multicast (theo lõi Lotus v2, ADR-0001) | ✅ 0.2.0 |
| `session`, `devices`, `frame` - phiên ghép đôi QR/so mã số (cam kết nonce), khoá 10 phút, kho thiết bị (ADR-0003) | ✅ 0.4.0 |
| `sync` - khung đồng bộ: bắt tay `schema_version`, bảng LWW theo HLC + bia mộ, Automerge, tệp khối 1 MiB BLAKE3 nối lại (ADR-0004) | ✅ 0.5.0 |
| `tsubak` - sao lưu `.tsubak`: zip mở, mã hoá tuỳ chọn `TS 01` (Argon2id + secretstream), vector chéo (ADR-0002) | ✅ 0.3.0 |
| `node` + `store` - mặt tiền cho ràng buộc: kho bền vững trên đĩa, runtime riêng, huỷ được, mã lỗi ổn định (ADR-0005) | ✅ 0.6.0 |
| C ABI `crates/tsulink-capi` (`include/tsulink.h`) + .NET `bindings/dotnet/Tsudev.Link` | ✅ 0.6.0 |
| Flutter `bindings/dart` (flutter_rust_bridge 2.13.0, gói Dart `tsulink`) | ✅ 0.6.0 |
| Tauri: dùng thẳng crate `tsulink` (`node`) | ✅ 0.6.0 |
| Gói TS `@tsudev/link` (WebRTC host-only) | ⬜ thử nghiệm riêng |

Lộ trình: [`logs/handover/20261125-TL1_khoi-tao-tsulink.md`](logs/handover/20261125-TL1_khoi-tao-tsulink.md).

## Phát triển

```bash
cargo fmt --all --check
cargo clippy --all-targets -- -D warnings
cargo test
python3 conformance/check_sas_vector.py   # vector mã 6 chữ số tính độc lập

# Ràng buộc
./scripts/gen-dart-bridge.sh                                   # sinh lại cầu Dart (flutter_rust_bridge 2.13.0)
cargo build -p tsulink-dart && (cd bindings/dart && flutter test)
cargo build --release -p tsulink-capi && (cd bindings/dotnet/Tsudev.Link.Smoke && \
  TSULINK_NATIVE_DIR=$PWD/../../../target/release dotnet run -c Release)
```

## Dùng trong app

- **Flutter**: `tsulink: {git: {url: https://github.com/tsudev-org/tsulink, path: bindings/dart, ref: v0.6.0}}`;
  `await RustLib.init()`, rồi `LinkNode.open(...)`. Cần Rust trên máy dựng (cargokit dựng lõi theo đích).
- **.NET**: tham chiếu `bindings/dotnet/Tsudev.Link`, đặt `tsulink.dll`/`libtsulink.so` (dựng từ `tsulink-capi`) cạnh
  tệp chạy; `TsulinkNode.Open(...)`.
- **C**: `crates/tsulink-capi/include/tsulink.h`.

Danh tính (`generate_identity`) giữ khoá riêng trong kho bí mật của hệ điều hành; `data_dir` chỉ chứa dữ liệu đồng bộ.

## Bảo mật

Báo lỗ hổng: [`SECURITY.md`](SECURITY.md) - không mở issue công khai.

## English summary

`tsulink` lets two TsuDEV apps sync user data **directly between devices on the same local network** (QR / 6-digit
comparison / Bluetooth pairing, mutual TLS 1.3 with pinned certificate fingerprints) - never over the internet, no relay,
no third-party cloud account. Spec: tsudev-standards `docs/LOCAL_SYNC.md`. Built on the Lotus v2 protocol of Lotus Share.
Version 0.5.0 added the sync framework (`schema_version` handshake, HLC last-writer-wins tables with tombstones,
Automerge, resumable BLAKE3-chunked files); 0.6.0 adds bindings: a C ABI (`include/tsulink.h`) with a .NET wrapper and
a Flutter plugin (flutter_rust_bridge), both over one safe `node` facade with durable on-disk stores. Apache-2.0.
