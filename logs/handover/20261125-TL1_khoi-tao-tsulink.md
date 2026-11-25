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

## Phase (mỗi phase = một phiên agent, một PR, một bản MINOR)

| Phase | Nội dung | Phụ thuộc | Ước lượng |
| --- | --- | --- | --- |
| TL1-P1 ✅ | Bước 1 - danh tính, mTLS, khám phá (0.2.0) | - | xong 26/11 |
| TL1-P2 | Bước 2 - phiên ghép đôi: cổng chế độ ghép đôi nhận mọi chứng thư nhưng chỉ đổi lấy mã `t` một lần; SAS qua `sas::code`; khoá 10 phút sau 5 lần sai; trait kho thiết bị đã ghép đôi + tự gỡ 180 ngày (0.4.0) | P1 | 1 phiên |
| TL1-P3 ✅ | Bước 4 - `.tsubak` (độc lập P2, làm song song được): zip + secretstream + Argon2id, khớp `tsubak-vectors-v1.json` (làm thành 0.3.0) | - | xong 26/11 |
| TL1-P4 | Bước 3 - khung đồng bộ: khung tin có độ dài, bắt tay `schema_version`, HLC + LWW + bia mộ, Automerge sync, tệp khối 1 MiB BLAKE3 nối lại (0.5.0) | P2 | 1-2 phiên |
| TL1-P5 | Bước 5 - ràng buộc `flutter_rust_bridge` + C ABI (.NET) (0.6.0); `@tsudev/link` WebRTC host-only là thử nghiệm riêng | P4 | 1-2 phiên |
| TL1-P6 | Bước 6 - test mục 10 LOCAL_SYNC đầy đủ + thử thật Android ↔ Windows (👤) ⇒ báo điều phối, qulythuchi pilot | P5 | 1 phiên + 👤 |

Lệnh khởi động phiên: "Đọc AGENTS.md, logs/STATE.md, phiếu `logs/handover/20261125-TL1_*` rồi làm phase TL1-P<n>".

## Kết quả xử lý

- 25/11/2026 - projects-05: tạo repo (chủ dự án cho phép), 0.1.0, CI.
- 26/11/2026 - projects-82 (điều phối): bước 1 xong - 0.2.0 (`identity`, `tls`, `transport`, `discovery`, ADR-0001, 29 test); thêm Dependabot + sửa miễn gitleaks (PR #1).
- 26/11/2026 - projects-82: TL1-P3 xong - 0.3.0 `.tsubak` (ADR-0002, 49 test, libsodium C khớp 36 ca). P2 (ghép đôi) là phase kế tiếp.
