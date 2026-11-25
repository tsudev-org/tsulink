# Chính sách bảo mật - tsulink

## Báo lỗ hổng

**KHÔNG mở issue công khai.** Dùng [Báo cáo lỗ hổng riêng tư của GitHub](https://github.com/tsudev-org/tsulink/security/advisories/new).
Gửi kèm: thành phần, phiên bản (tag), cách tái hiện, tác động. Phản hồi trong 7 ngày, bản sửa lỗi nghiêm trọng trong
30 ngày. Quy trình chung: [`.standards/SECURITY.md`](.standards/SECURITY.md).

## Cam kết (tsudev-standards `LOCAL_SYNC.md` mục 1)

- **Không internet**: chỉ địa chỉ mạng nội bộ; không relay, không STUN/TURN công cộng, không API lưu trữ đám mây.
- **Ghép đôi bắt buộc**: mã QR dùng một lần, hạn 120 giây, hoặc so 6 chữ số trên cả hai máy; thiết bị lạ bị bỏ qua.
- **TLS 1.3 hai chiều**, cả hai bên ghim vân tay chứng thư đã ghép đôi; không có chế độ không mã hoá.
- **Chỉ nghe khi người dùng mở màn đồng bộ**; tự đóng sau 10 phút không hoạt động.
- `#![forbid(unsafe_code)]`; không tự cài đặt mật mã - chỉ thư viện chuẩn (sha2, rustls, libsodium).

## English summary

Report vulnerabilities privately via GitHub Security Advisories, not public issues. Commitments: local network only, no
relay or cloud; mandatory one-time pairing; mutual TLS 1.3 with pinned fingerprints; listen only while the sync screen
is open; no unsafe code, no home-made cryptography.
