# STATE.md - Trạng thái project

> Agent đọc file này ở đầu mỗi phiên và cập nhật ở cuối mỗi phiên.
> Quy trình: `.standards/docs/AGENT_PROTOCOL.md`.

## Hàng đợi task (làm từ trên xuống)

- [ ] TL1 bước 2-6 (`logs/handover/20261125-TL1_khoi-tao-tsulink.md`) - kế hoạch phase ở mục "Phase" của phiếu

## Đang thực hiện

| Task | Agent | Bắt đầu |
| --- | --- | --- |

## Đã hoàn thành (mới nhất trên cùng)

- 26/11/2026 - TL1 bước 1, 0.2.0: danh tính P-256, mTLS 1.3 ghim, cổng nghe L1/L4, khám phá multicast Lotus v2 (29 test)

- 25/11/2026 - Khởi tạo repo, 0.1.0: `addr`, `pairing`, `sas` + vector, CI

## Quyết định quan trọng

> Quyết định kiến trúc lớn thì viết ADR riêng theo `docs/templates/ADR.md` và chỉ
> ghi một dòng tham chiếu ở đây.

- 26/11/2026 - Khám phá + mTLS dựng lại theo Lotus v2, không phụ thuộc crate `localsend` - `docs/adr/0001-kham-pha-va-mtls-tu-loi-lotus-v2.md`

## Sự cố bảo mật

> Ghi theo `.standards/docs/SECURITY_BASELINE.md` mục 9. Để trống nếu chưa có.

- (chưa có)
