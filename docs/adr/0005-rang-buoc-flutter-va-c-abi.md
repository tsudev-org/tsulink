# ADR-0005 - Ràng buộc Flutter (flutter_rust_bridge) và C ABI (.NET) qua mặt tiền `node`

- **Trạng thái**: Chấp nhận - 26/11/2026
- **Bối cảnh**: phiếu TL1 bước 5 / phase P5. App Flutter (qulythuchi pilot, tsudev_ui màn "Đồng bộ thiết bị") và app
  .NET (Windows) cần gọi lõi Rust: ghép đôi, đồng bộ (`sync::run` + `Replica`), khám phá. ADR-0004 để `RowStore`/
  `DeviceStore` cho app tự cấp, nhưng flutter_rust_bridge không gọi ngược Dart ĐỒNG BỘ được (callback Dart là `async`)
  trong khi trait kho là đồng bộ và nằm giữa vòng lặp đồng bộ.

## Quyết định

1. **Một mặt tiền an toàn trong lõi** (`tsulink::node`, vẫn `forbid(unsafe_code)`): `Node` = một thiết bị trong một app.
   Mọi ràng buộc chỉ gọi `node` - không ràng buộc nào tự ghép `session`/`transport`/`sync`, nên luật L1-L5 nằm một chỗ.
   Tauri dùng thẳng crate `tsulink` (mặt tiền này), không cần lớp riêng.
2. **Kho do lõi giữ trên đĩa** trong `data_dir` của app (`store`): `rows.jsonl` nối đuôi, `fsync` từng phiên bản TRƯỚC
   khi trả về (phiên bản đã gửi cho máy khác mà mất sau mất điện thì `seq` bị dùng lại và máy kia bỏ sót phiên bản mới
   mang `seq` đó); dòng cuối dở dang bị cắt, dòng hỏng giữa ⇒ `Corrupt`; viết gọn khi nhật ký > 2 lần số bản ghi sống
   và khi xoá bia mộ. `rows-meta.json`, `devices.json` ghi nguyên tử (tạm + `fsync` + đổi tên + `fsync` thư mục).
   Tài liệu Automerge `docs/<hex mã>.automerge`; tệp `blobs/<BLAKE3>` (định danh theo nội dung - tệp nhận về vào thẳng
   đây, `FileProvider` chỉ phục vụ tệp trong kho). App chép dữ liệu ra kho/giao diện của mình bằng `changes_after(seq)`
   (nhật ký máy này gồm cả thay đổi nhận về) - không cần callback.
3. **Trait kho thành có lỗi** (`put`/`set_cursor`/`purge`/`upsert`/`remove` trả `Result`): kho thật (đĩa, SQLite) hỏng
   được; trước đây chỉ có cách `panic` (bản phát hành `panic = "abort"` ⇒ app chết).
4. **Khoá riêng không nằm trong `data_dir`**: app tạo danh tính một lần (`generate_identity`/`tsulink_identity_generate`),
   giữ khoá trong kho bí mật của hệ điều hành (Keystore/Keychain/DPAPI) và truyền vào `open`.
5. **Runtime**: một tokio đa luồng (2 luồng) dùng chung; hàm `async` của `node` `spawn` phần mạng lên đó nên chạy được từ
   executor của flutter_rust_bridge; C ABI chặn luồng gọi (`block_on`), .NET bọc bằng `Task.Run`. **Huỷ**: `CancelToken`
   (cờ + `Notify`) ⇒ `Error::Cancelled`; Dart truyền thẻ THAM CHIẾU (truyền giá trị thì Dart mất đối tượng).
6. **Mã lỗi ổn định** `Error::code()` 1-22 (+ `-1` panic ở C) dùng chung C/.NET/Dart; chỉ THÊM mã. Lỗi mới:
   `Cancelled` (20), `InvalidInput` (21), `Closed` (22).
7. **C ABI** (`crates/tsulink-capi`, thư viện `tsulink`): 45 hàm `tsulink_*`, đối tượng mờ + `_free`, chuỗi UTF-8,
   kết quả có cấu trúc là JSON, thông điệp lỗi theo luồng (`tsulink_last_error`), callback tiến độ có con trỏ `user`.
   `include/tsulink.h` viết tay; test `header_khop_ham_xuat` so tên hàm + bảng mã lỗi, CI biên dịch header C99/C++.
   `unsafe` chỉ ở crate này, mỗi khối có chú thích SAFETY. .NET: `bindings/dotnet/Tsudev.Link` (LibraryImport, JSON
   sinh nguồn, tương thích AOT, không gói NuGet) + bài kiểm thử console chạy qua thư viện thật.
8. **Flutter**: plugin `bindings/dart` (gói Dart `tsulink`, cargokit dựng `bindings/dart/rust` = thư viện
   `tsulink_dart` - khác tên thư viện C để không đè nhau trong `target/`). flutter_rust_bridge ghim `=2.13.0` ở ba nơi
   (crate, pubspec, codegen); mã sinh được commit, CI sinh lại và so `git diff`. Kiểu `Link*` là đối tượng mờ; số 64 bit
   đi qua `i64` (Dart `int`).
9. **Test trên mạng thật**: hai thiết bị trong một tiến trình nối qua địa chỉ mạng nội bộ của máy chạy test - KHÔNG nới
   luật L1 cho loopback trong ràng buộc; máy không có địa chỉ nội bộ thì test mạng tự bỏ qua.

## Hệ quả

- App không còn tự cấp `RowStore`; app cần SQLite thì chép từ `changes_after` (một chiều) và ghi qua `write`/`delete`.
- `fsync` mỗi phiên bản: lô 512 bản ghi tốn cỡ 512 lần `fsync` (đo trên máy dev: không đáng kể; điện thoại cũ có thể
  vài trăm ms/lô). Gộp `fsync` theo lô cần thêm hàm vào trait - để khi đo thấy chậm ở P6.
- Bộ đếm sai ghép đôi (`AttemptLimiter`) sống trong bộ nhớ của `Node`: khởi động lại app thì đếm lại từ 0.
- Chưa dựng thật gói Flutter cho Android/iOS/macOS/Windows (chỉ Linux qua `flutter test`); P6 thử Android ↔ Windows.
- `@tsudev/link` (WebRTC) KHÔNG thuộc phase này.
