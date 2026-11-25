# ADR-0002 - Khuôn tệp sao lưu `.tsubak` bản 1

- **Trạng thái**: Chấp nhận - 26/11/2026
- **Bối cảnh**: `LOCAL_SYNC.md` mục 9: xuất dữ liệu định dạng mở (CSV/JSON + tệp gốc) trong một tệp `.tsubak` (zip);
  mã hoá tuỳ chọn bằng libsodium secretstream XChaCha20-Poly1305 + Argon2id ≥ 64 MiB/3 lượt, NFKC; giữ bộ mật mã và
  vector chéo của TsuDEV Sync cũ để không viết lại.

## Quyết định

1. **Không mã hoá**: zip thường = `tsubak.json` + các tệp ở đúng đường dẫn. Bản kê: `format = "tsubak"`, `v = 1`, `app`,
   `schema_version`, `created_at`, `encrypted = false`, `entries[] = {path, size, sha256}`. Mở được bằng mọi trình giải
   nén - người dùng không bị khoá vào TsuDEV.
2. **Có mã hoá**: zip ngoài = `tsubak.json` công khai (`format`, `v`, `app`, `encrypted = true`, `kdf` = tham số
   `{"v":1,"alg":"argon2id13","salt","ops","mem","check"}`) + `payload.ts01` = bản mã `TS 01` (loại `file`, không gian
   tên = `app`, id `tsubak`) của zip trong ở khuôn mục 1. Tên/số tệp không lộ; bản mã gắn với app qua AAD.
3. **Mật mã**: chép NGUYÊN `tsusync/clients/rust` (dryoc thuần Rust, =2.0.1) - qua `conformance/tsubak-vectors-v1.json`
   (36 ca) trong test và `verify_libsodium.py` (libsodium C). Mặc định 3 lượt / 64 MiB; mật khẩu ≥ 10 ký tự sau NFKC;
   mã `check` báo sai mật khẩu mà không cần giải mã thử.
4. **Nhập an toàn**: trần 100 000 tệp và 2 GiB sau giải nén (đọc có giới hạn, không tin kích thước khai trong zip); từ
   chối đường dẫn tuyệt đối, `..`, `\`, ổ đĩa Windows, ký tự điều khiển, tên trùng, tệp lạ ngoài bản kê; kiểm SHA-256 +
   kích thước từng tệp. Sai mật khẩu ⇒ `WrongPassword`, không trả dữ liệu dở.
5. **Ghi tệp**: `write_atomic` - tệp tạm cùng thư mục, `fsync`, đổi tên nguyên tử.

## Hệ quả

- Bản 1 xử lý trong bộ nhớ (trần 2 GiB). App có kho tệp lớn hơn ⇒ bản 2 dùng secretstream theo luồng (khuôn `TS 01`
  vốn đã chia khối 64 KiB), cần ADR mới.
- Đổi bất kỳ điểm nào ở mục 1-3 ⇒ `v = 2` + ADR + vector mới; bản 1 vẫn phải mở được.
