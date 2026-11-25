# PHIẾU TL1 - Khởi tạo tsulink và lộ trình tới bản dùng được cho qulythuchi (pilot SYN1)

- **Mã phiếu**: 20261125-TL1 - **Từ**: điều phối `projects-05`, 25/11/2026 - **Trạng thái**: MỞ - **Cho**: phiên tsulink
- **Chuẩn**: tsudev-standards v7.0.1 `docs/LOCAL_SYNC.md` (đọc HẾT), phiếu toàn hệ `20261125-SYN1` (bản sao ở đây).
- **Đã có (0.1.0)**: `addr` (L1), `pairing` (URI QR, mã một lần 120 giây), `sas` (mã 6 chữ số + vector), vector `.tsubak`.

## Việc theo thứ tự (mỗi bước một PR, CI xanh, bản MINOR)

1. **Tách lõi Lotus v2**: từ `~/projects/lotus-share/packages/core` lấy khám phá multicast (`224.0.0.168:53420`,
   `ff12::1075:5ea0`, `SO_REUSEADDR`/`SO_REUSEPORT`) + mTLS ghim (`v2_tls_pinning.rs`). Đổi chứng thư sang ECDSA P-256 (rcgen),
   rustls TLS 1.3 only, ALPN `tsulink/1`, không có đường `http`; thêm trường `tsulink: {app, v}`; chỉ nhận thiết bị đã
   ghép đôi. lotus-share có phiên riêng ⇒ chỉ ĐỌC repo đó; cần đổi gì bên đó ⇒ phiếu + SendMessage.
2. **Phiên ghép đôi**: máy hiện QR mở cổng tạm, nhận mTLS từ máy quét + mã `t` (một lần), lưu vân tay hai chiều; so mã số
   qua `sas::code`; khoá 10 phút sau 5 lần sai; danh sách thiết bị đã ghép đôi (lưu do app cấp kho - trait).
3. **Đồng bộ**: khung CRDT (Automerge 2 cho tài liệu, HLC + LWW + bia mộ cho bảng), trao delta, idempotent; tệp chia khối
   1 MiB BLAKE3, nối lại khi đứt; bắt tay `schema_version`.
4. **`.tsubak`**: zip định dạng mở + libsodium secretstream XChaCha20-Poly1305, Argon2id ≥ 64 MiB/3 lượt, NFKC - khớp
   `conformance/tsubak-vectors-v1.json` (chạy `verify_libsodium.py`).
5. **Ràng buộc**: `flutter_rust_bridge` (gói Dart cho `tsudev_ui` dựng màn "Đồng bộ thiết bị"), C ABI cho .NET, crate cho
   Tauri; gói TS `@tsudev/link` (WebRTC host-only, `iceServers: []`) - thử thật Safari iOS trước khi hứa.
6. **Test mục 10 LOCAL_SYNC** + thử thật Android ↔ Windows cùng Wi-Fi (👤 cầm máy) ⇒ báo điều phối, qulythuchi bắt đầu pilot.

## Kết quả xử lý

- 25/11/2026 - projects-05: tạo repo (chủ dự án cho phép), 0.1.0, CI.
