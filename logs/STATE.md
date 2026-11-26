# STATE.md - Trạng thái project

> Agent đọc file này ở đầu mỗi phiên và cập nhật ở cuối mỗi phiên.
> Quy trình: `.standards/docs/AGENT_PROTOCOL.md`.

## Hàng đợi task (làm từ trên xuống)

- [ ] TL1 phase P5-P6 (bước 5, 6) (`logs/handover/20261125-TL1_khoi-tao-tsulink.md`) - kế hoạch phase ở mục "Phase" của phiếu

## Đang thực hiện

| Task | Agent | Bắt đầu |
| --- | --- | --- |

## Đã hoàn thành (mới nhất trên cùng)

- 26/11/2026 - TL1-P4, 0.5.0: khung đồng bộ (bắt tay lược đồ, HLC + LWW + bia mộ, Automerge, tệp khối BLAKE3 nối lại), 87 test; `.standards` v7.1.1

- 26/11/2026 - TL1-P2, 0.4.0: phiên ghép đôi QR + so mã số có cam kết, khoá 10 phút, kho thiết bị (62 test)

- 26/11/2026 - TL1-P3, 0.3.0: `.tsubak` (ADR-0002), 49 test, `verify_libsodium.py` 36 ca khớp libsodium 1.0.18

- 26/11/2026 - TL1 bước 1, 0.2.0: danh tính P-256, mTLS 1.3 ghim, cổng nghe L1/L4, khám phá multicast Lotus v2 (29 test)

- 25/11/2026 - Khởi tạo repo, 0.1.0: `addr`, `pairing`, `sas` + vector, CI

## Quyết định quan trọng

> Quyết định kiến trúc lớn thì viết ADR riêng theo `docs/templates/ADR.md` và chỉ
> ghi một dòng tham chiếu ở đây.

- 26/11/2026 - Khung đồng bộ: LWW/HLC, con trỏ theo nhật ký bên gửi, Automerge, tệp khối - `docs/adr/0004-khung-dong-bo.md`
- 26/11/2026 - Giao thức ghép đôi + cam kết nonce khi so mã số - `docs/adr/0003-phien-ghep-doi.md`
- 26/11/2026 - Khuôn `.tsubak` bản 1 - `docs/adr/0002-dinh-dang-tsubak.md`
- 26/11/2026 - Khám phá + mTLS dựng lại theo Lotus v2, không phụ thuộc crate `localsend` - `docs/adr/0001-kham-pha-va-mtls-tu-loi-lotus-v2.md`

## Sự cố bảo mật

> Ghi theo `.standards/docs/SECURITY_BASELINE.md` mục 9. Để trống nếu chưa có.

- (chưa có)
