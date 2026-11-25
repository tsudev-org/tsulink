# ADR-0003 - Giao thức phiên ghép đôi (QR và so mã số)

- **Trạng thái**: Chấp nhận - 26/11/2026
- **Bối cảnh**: `LOCAL_SYNC.md` mục 3 (v1.0.1): ghép đôi bằng mã QR (mã `t` 128 bit, một lần, 120 giây) hoặc so 6 chữ số;
  5 lần sai/10 phút ⇒ khoá 10 phút; danh sách thiết bị xem/xoá được, 180 ngày không đồng bộ ⇒ tự gỡ.

## Quyết định

1. **Kênh**: mTLS 1.3 như kết nối đồng bộ nhưng ALPN riêng `tsulink-pair/1`; máy chủ nhận mọi chứng thư máy khách
   (vẫn kiểm chữ ký bắt tay) và ghi vân tay; chỉ địa chỉ mạng nội bộ. Kết nối đồng bộ (`tsulink/1`) không bắt tay được
   với cổng ghép đôi và ngược lại.
2. **Khung tin**: 4 byte độ dài big-endian + JSON, ≤ 64 KiB (`frame`), đọc có thời hạn 30 giây.
3. **QR**: B ghim vân tay A trong QR, gửi `{"alias","t"}`; A so `t` thời gian hằng, kiểm hạn, rồi lưu B và trả
   `{"ok":true,"alias"}`; B lưu A. `accept_qr` nhận lời mời theo giá trị ⇒ mã chỉ dùng một lần. Mã sai ⇒ `{"ok":false}`
   + đếm lần sai.
4. **So mã số có cam kết** (bổ sung so với văn bản LOCAL_SYNC, không đổi công thức mã): A (bên được gọi) gửi
   `commit = SHA-256("tsulink-sas-commit|" ‖ nonce A)` trước; B gửi nonce B; A mở nonce A; B kiểm cam kết. Không có bước
   này, kẻ đứng giữa (trình chứng thư riêng cho mỗi bên) có thể thử ~10⁶ nonce sau khi thấy nonce thật cho hai mã trùng
   nhau. Mã = `sas::code` (vector `conformance/sas-vector-1.txt`). Cả hai người dùng xác nhận ⇒ mỗi bên gửi
   `{"confirm":true}`; một bên `false`/hết 2 phút ⇒ không ai lưu, tính một lần sai.
5. **Kho thiết bị**: trait `DeviceStore` (app cấp, mỗi app một kho), `PinsFromStore` nối thẳng vào bộ ghim mTLS nên gỡ
   thiết bị có hiệu lực ở kết nối kế tiếp; `prune_stale` gỡ thiết bị > 180 ngày.

## Hệ quả

- Đề xuất ghi bước cam kết vào `LOCAL_SYNC.md` bản sau (tsudev-standards) để các cài đặt khác làm giống.
- `AttemptLimiter` nằm trong bộ nhớ của màn ghép đôi; app muốn khoá qua lần mở lại màn thì giữ đối tượng ở tầng trên.
