# ADR-0001 - Khám phá multicast và mTLS ghim vân tay dựng lại theo lõi Lotus v2

- **Trạng thái**: Chấp nhận - 26/11/2026
- **Bối cảnh**: `LOCAL_SYNC.md` mục 2 và phiếu TL1 bước 1 yêu cầu tách khám phá + mTLS ghim từ
  `lotus-share/packages/core` (crate `localsend`). Crate đó gắn chặt HTTP/hyper, RSA 2048, TLS 1.2, chế độ `http`,
  WebRTC và có phiên riêng đang làm; Tsu Link cấm `http` (L3), dùng P-256 và chỉ TLS 1.3.

## Quyết định

1. **Dựng lại phần nhỏ cần dùng** trong `tsulink`, theo đúng hành vi đã kiểm thật của Lotus v2, thay vì phụ thuộc crate
   `localsend`: lotus-share không phải sửa gì (chỉ ĐỌC), cây phụ thuộc nhỏ (không hyper/reqwest/RSA/WebRTC).
2. **Danh tính**: ECDSA P-256 (`rcgen` + `ring`), chứng thư tự ký CN `Tsu Link`, vân tay SHA-256 DER hex HOA.
   App cất khoá PKCS#8 trong kho khoá nền tảng; thư viện không ghi khoá ra đĩa; bộ nhớ khoá xoá khi huỷ (`zeroize`).
3. **TLS**: rustls 0.23 + `ring`, chỉ TLS 1.3, ALPN `tsulink/1` (kiểm lại sau bắt tay), mTLS bắt buộc; máy chủ nhận
   máy khách có vân tay trong `PeerPins`, máy khách nhận đúng một vân tay ghim; chữ ký bắt tay vẫn kiểm bằng khoá trong
   chứng thư (ECDSA P-256/Ed25519). **Tắt nối lại phiên và 0-RTT** để mỗi kết nối qua kiểm ghim (gỡ ghim có hiệu lực ngay).
4. **Vận chuyển**: chỉ địa chỉ mạng nội bộ (L1) cho cả gọi đi, cổng nghe và nguồn kết nối đến; cổng nghe trả
   `IdleTimeout` sau 10 phút không có kết nối hợp lệ (L4); bắt tay ≤ 10 giây.
5. **Khám phá**: chung kênh Lotus v2 (`224.0.0.168:53420`, `ff12::1075:5ea0`, `SO_REUSEADDR`/`SO_REUSEPORT`, TTL/hops 1,
   một socket mỗi giao diện mạng nội bộ), khuôn JSON `MulticastMessageV2` + trường `tsulink: {app, v}`. Thiết bị chưa
   ghép đôi được báo với `paired = false` (cần cho ghép đôi so mã số); lớp đồng bộ bỏ qua chúng (L2).

## Hệ quả

- Lotus Share 2.x nhìn thấy lời rao Tsu Link như một thiết bị `https`; nó sẽ thử đăng ký HTTPS và thất bại ở mTLS (không
  có chứng thư ghim) - không lộ dữ liệu. Nếu cần ẩn khỏi danh sách Lotus ⇒ phiếu cho lotus-share lọc theo trường `tsulink`.
- Bắt tay chạy tuần tự trong `accept` (≤ 10 giây/kết nối): máy trong LAN có thể làm chậm ghép đôi; chấp nhận cho cổng mở
  ngắn hạn, xem lại khi có phiên đồng bộ dài (bước 3).
- Sửa lỗi khám phá phát hiện ở lotus-share cần đối chiếu và chép tay sang đây.
