# ADR-0004 - Khung đồng bộ: bắt tay lược đồ, bảng LWW theo HLC, Automerge, tệp khối BLAKE3

- **Trạng thái**: Chấp nhận - 26/11/2026
- **Bối cảnh**: `LOCAL_SYNC.md` mục 4 (v1.0.2): CRDT để hai máy sửa ngoại tuyến rồi gộp không mất dữ liệu - Automerge
  cho tài liệu, LWW theo HLC + bia mộ cho bảng; trao delta, idempotent; tệp khối 1 MiB BLAKE3 nối lại, thay tệp nguyên
  tử; bắt tay `schema_version`, khác ⇒ dừng (L5). Mục 10: test sửa đồng thời, xoá + sửa, đứt giữa chừng, lược đồ khác.

## Quyết định

1. **Kênh**: chạy trên kết nối mTLS `tsulink/1` đã ghép đôi (ADR-0001), khung 4 byte độ dài; tin điều khiển JSON gắn
   thẻ `t`; khối tệp và tin Automerge là khung nhị phân. Trần mọi khung 32 MiB (chặn thiết bị đã ghép đôi làm cạn bộ
   nhớ), khối tệp ≤ 1 MiB, lô bản ghi ≤ 1 MiB/512 bản ghi. Mỗi tin chờ tối đa 60 giây.
2. **Bắt tay**: hai bên gửi `{"t":"hello","proto":1,"app","schema"}` rồi đọc của bên kia. Khác `proto`/`app` ⇒ lỗi
   giao thức; khác `schema` ⇒ `Error::SchemaMismatch { local, remote }`, không trao dữ liệu nào - app nhắc cập nhật.
3. **HLC**: mốc = (mili giây, bộ đếm u32, vân tay thiết bị), so theo thứ tự đó ⇒ không bao giờ hoà giữa hai máy.
   Mốc nhanh hơn đồng hồ máy nhận quá **1 giờ** ⇒ `ClockSkew`, không gộp (một máy đặt sai năm 2099 không được làm mọi
   lần sửa sau đó của máy khác luôn thua).
4. **Bảng LWW + bia mộ**: mỗi `(bảng, khoá)` giữ một phiên bản; mốc lớn hơn thắng; xoá = phiên bản `value: null` với
   mốc mới, nên **xoá + sửa đồng thời: bên có mốc sau thắng** (sửa sau ⇒ bản ghi sống lại; xoá sau ⇒ mất). Gộp phiên
   bản bằng hoặc cũ hơn không đổi gì và không ghi nhật ký (idempotent). Bia mộ giữ 180 ngày (= hạn tự gỡ thiết bị) rồi
   mới xoá hẳn. Quy tắc gộp theo trường (thay vì cả bản ghi) là việc của từng app - ghi trong ADR của app đó.
5. **Con trỏ theo nhật ký bên gửi** (cách hiện thực "HLC cao nhất đã thấy" của chuẩn): mỗi lần kho nhận phiên bản mới
   (sửa tại chỗ hoặc gộp về), phiên bản đó nhận `seq` tăng dần trong nhật ký máy này. Bên kéo nhớ
   `Cursor { log, seq }` cho từng thiết bị và lưu sau mỗi lô đã gộp. Chọn `seq` thay vì so HLC vì với ≥ 3 máy, một
   phiên bản mốc cũ có thể đến B qua C SAU KHI A đã đọc qua mốc đó của B - so HLC sẽ bỏ sót, `seq` thì không (test
   `ba_may_khong_sot_phien_ban_den_muon`). `log` là mã ngẫu nhiên của kho; khác mã (cài lại app) ⇒ gửi lại từ đầu.
6. **Tài liệu**: giao thức đồng bộ của `automerge` 0.12 (MIT), lần lượt từng mã tài liệu trong hợp hai danh sách (tài
   liệu chỉ một bên có được tạo ở bên kia), bên gọi gửi trước, hai bên luân phiên tới khi một vòng cả hai đều rỗng
   (tối đa 64 vòng). Trạng thái đồng bộ Automerge không lưu giữa các phiên (bloom filter vẫn tránh gửi lại phần đã có).
7. **Tệp**: định danh bằng BLAKE3 toàn tệp; bảng khối = BLAKE3 từng khối 1 MiB. Bên nhận ghi `<đích>.tsulink-part`;
   mở lại thì kiểm từng khối đã có, cắt từ khối hỏng đầu tiên, xin tiếp `from = khối kế`. Đủ khối và khớp BLAKE3 toàn tệp
   ⇒ `fsync` + đổi tên nguyên tử; sai ⇒ xoá tệp dở. Bên gửi chỉ phục vụ tệp app chỉ ra (`FileProvider`) và kiểm lại
   băm trước khi gửi.
8. **Thứ tự phiên** (`run`): bắt tay → bên gọi kéo bảng, bên nghe kéo bảng → tài liệu → bên gọi xin tệp, bên nghe xin
   tệp. Mọi hàm `async`, huỷ bằng cách bỏ future; dữ liệu cục bộ không hỏng vì bản ghi gộp từng cái và tệp chỉ thay khi
   đủ.

## Hệ quả

- App cấp `RowStore` thật (SQLite...) và phải ghi bền vững trong `put`/`set_cursor`; `InMemoryRowStore` chỉ để test.
- Tệp cần xin thường suy ra từ bản ghi vừa gộp ⇒ app gọi `fetch_file` sau `run`, hoặc `run` lần hai.
- Ràng buộc Flutter/C ABI (P5) bọc `run` + `Replica`; tiến độ qua callback `Progress`.
- Đề xuất ghi mục 5 (con trỏ `seq`) và ngưỡng lệch giờ 1 giờ vào `LOCAL_SYNC.md` bản sau.
