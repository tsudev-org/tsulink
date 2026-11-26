# AGENTS.md - tsulink

> **ĐỌC FILE NÀY ĐẦU TIÊN trong mọi phiên làm việc mới.**

## Phần A - Quy ước chung của hệ sinh thái (KHÔNG SỬA Ở ĐÂY)

Toàn bộ quy ước chung nằm trong bản sao chỉ-đọc tại
[`.standards/AGENTS.md`](.standards/AGENTS.md). `MUST` đọc file đó trước.

Bản quy ước repo này đang dùng: xem [`.standards-version`](.standards-version).

| Cần gì | Đọc file nào |
| --- | --- |
| Điểm vào, nguyên tắc chung | `.standards/AGENTS.md` |
| Quy trình phiên, khóa file, bàn giao | `.standards/docs/AGENT_PROTOCOL.md` |
| Bảo mật bắt buộc | `.standards/docs/SECURITY_BASELINE.md` |
| Quy tắc `.gitignore` | `.standards/docs/GITIGNORE_POLICY.md` |
| Nhánh, commit, PR, phát hành | `.standards/docs/GIT_WORKFLOW.md` |
| Đăng nhập, đăng ký, xác minh tài khoản | `.standards/docs/AUTH_AND_ACCOUNT.md` |
| Giao diện và token | `.standards/docs/DESIGN_SYSTEM.md` |
| Bảng bản ghi, bộ chọn số bản ghi | `.standards/docs/DATA_TABLE.md` |
| Logo, favicon, icon ứng dụng | `.standards/docs/BRAND_ASSETS.md` |
| tsudev.com, ảnh đại diện, trang hồ sơ | `.standards/docs/ECOSYSTEM_IDENTITY.md` |
| Cấu trúc thư mục | `.standards/docs/PROJECT_STRUCTURE.md` |
| Chọn ngôn ngữ, framework | `.standards/docs/LANGUAGE_SELECTION.md` |
| Hạ tầng 0 đồng | `.standards/docs/FREE_TIER_STACK.md` |
| Trình soạn thảo nội dung | `.standards/docs/RICH_TEXT_EDITOR.md` |
| Tìm kiếm và lọc tiếng Việt | `.standards/docs/SEARCH_AND_FILTER.md` |
| Kiểm thử và chất lượng mã | `.standards/docs/TESTING_QUALITY.md` |
| Khả năng truy cập | `.standards/docs/ACCESSIBILITY.md` |

`MUST NOT` sửa bất kỳ file nào trong `.standards/`. Cần đổi quy ước thì mở đề
xuất tại repo `tsudev-standards` theo `.standards/docs/SYNC.md` mục 1.

## Phần B - Riêng của repo này

> Phần này KHÔNG thuộc bộ quy ước chung. Điền theo thực tế của repo.

### B.1. Repo này là gì

- **Loại**: thư viện (crate Rust `tsulink` + C ABI `crates/tsulink-capi` + .NET `bindings/dotnet` + plugin Flutter `bindings/dart`; gói TS `@tsudev/link` chưa làm)
- **Stack**: Rust 1.97 (`rust-toolchain.toml`), edition 2024, lõi `#![forbid(unsafe_code)]` (`unsafe` chỉ ở `tsulink-capi` và mã sinh `frb_generated.rs`); flutter_rust_bridge 2.13.0 + Flutter 3.47.8; .NET 8
- **Mức phân loại dữ liệu cao nhất**: D3 đi qua (dữ liệu người dùng giữa hai thiết bị) - không lưu, không gửi ra internet
- **Người liên hệ khi có sự cố**: chủ dự án (qua `SECURITY.md`)

### B.2. Chạy trong 5 phút

```bash
cargo test
cargo clippy --all-targets -- -D warnings && cargo fmt --all --check
python3 conformance/check_sas_vector.py
```

### B.3. Ranh giới sở hữu file

| Vùng | Chủ sở hữu |
| --- | --- |
| `crates/tsulink/src/*` | phiên tsulink |
| `conformance/*` | phiên tsulink - vector chỉ THÊM, không đổi vector đã phát hành |
| `crates/tsulink-capi/*`, `bindings/*` | phiên tsulink - `bindings/dart/lib/src/rust`, `bindings/dart/rust/src/frb_generated.rs` là mã SINH (`scripts/gen-dart-bridge.sh`) |

### B.4. Điểm lệch chuẩn đã biết

| Lệch ở đâu | Vì sao | Kế hoạch |
| --- | --- | --- |
| | | |

### B.5. Việc riêng của repo cần biết trước khi sửa

- Chuẩn là `.standards/docs/LOCAL_SYNC.md` - đổi giao thức ⇒ sửa chuẩn ở tsudev-standards TRƯỚC.
- Tách code từ `lotus-share/packages/core` ⇒ giữ ghi chú bản quyền LocalSend (Apache-2.0) và cập nhật `NOTICE`.
- Không thêm phụ thuộc gọi mạng ra ngoài (luật L1); mọi phụ thuộc ghim trong `Cargo.lock`.
- Lộ trình: `logs/handover/20261125-TL1_khoi-tao-tsulink.md`.
- Ràng buộc (ADR-0005): đổi API trong `node` ⇒ sửa CẢ `crates/tsulink-capi/src/lib.rs` + `include/tsulink.h` (test
  `header_khop_ham_xuat` bắt), `bindings/dotnet/Tsudev.Link`, `bindings/dart/rust/src/api` rồi `scripts/gen-dart-bridge.sh`
  (CI so `git diff`). Mã lỗi `Error::code()` chỉ THÊM. flutter_rust_bridge ghim `=2.13.0` ở crate + pubspec + CI.
- Test mạng (node, C ABI, .NET, Dart) nối qua địa chỉ mạng nội bộ của máy chạy - KHÔNG nới luật L1 cho loopback.
