# Nhật ký thay đổi

Theo [Keep a Changelog](https://keepachangelog.com/vi/1.1.0/) và SemVer.

## [Chưa phát hành]

## [0.6.0] - 26/11/2026

### Thêm

- Ràng buộc (TL1 bước 5 / phase P5, ADR-0005):
  - `node`: mặt tiền một thiết bị/một app - `Node::open` (danh tính do app giữ), bảng (`write`/`delete`/`read`/
    `changes_after`), tài liệu Automerge (`doc_merge`/`doc_save`), kho tệp theo BLAKE3 (`file_import`/`file_path`),
    ghép đôi (`pairing_host` → `qr_uri`/`accept_qr`/`accept_sas`, `join_qr`, `join_sas`, `SasHandle::finish`), đồng bộ
    (`sync_with`, `listen` → `serve_one`), khám phá, `CancelToken`, runtime tokio dùng chung, `local_ips`.
  - `store`: `FileRowStore` (nhật ký nối đuôi `fsync`, cắt dòng dở, viết gọn), `FileDeviceStore`, `write_atomic`.
  - `crates/tsulink-capi`: C ABI 45 hàm + `include/tsulink.h` (test khớp tên hàm và bảng mã lỗi).
  - `bindings/dotnet/Tsudev.Link` (net8.0, LibraryImport, tương thích AOT) + kiểm thử trọn đường.
  - `bindings/dart`: plugin Flutter `tsulink` (flutter_rust_bridge 2.13.0, cargokit) + test trọn đường.
- `Error::code()` mã ổn định; lỗi mới `Cancelled`, `InvalidInput`, `Closed`.
- CI: job `.NET` và `Dart/Flutter` (mã sinh phải khớp, analyze, test); biên dịch header C99/C++.

### Đổi

- **Phá vỡ**: `RowStore::put`/`set_cursor`/`purge_tombstones`, `Replica::write`/`delete`/`purge_tombstones`,
  `DeviceStore::upsert`/`remove`/`touch`/`prune_stale` trả `Result` (kho thật hỏng được thay vì `panic`).
- `PairedDevice`, `SyncReport`, `DiscoveredPeer` có `Serialize`.
- `.standards` v7.1.1 → v7.2.0 (thêm `CONTROL_PLANE.md`); phụ thuộc: base64 0.23, sha2 0.11, getrandom (Dependabot #3).

### Sửa

- `sync::file::Receiver::push` không `flush` tệp tokio: đứt kết nối ngay sau một khối có thể làm mất khối đã đếm là
  nhận (nối lại phải tải lại; test nối lại chập chờn khi máy bận).
- (trong bản) `SyncListener::port`/`PairingHostHandle::port`/`qr_uri` không còn qua khoá mà `serve_one`/`accept_*` giữ
  suốt lúc chờ (hỏi cổng sau khi bắt đầu chờ treo tới hết 10 phút - bắt ở CI .NET).

## [0.5.0] - 26/11/2026

### Thêm

- `sync` (TL1 bước 3 / phase P4, ADR-0004): `handshake` (trao `proto`/`app`/`schema_version`, khác lược đồ ⇒ dừng),
  `pull_rows`/`serve_rows`, `sync_docs` (giao thức đồng bộ Automerge 0.12), `fetch_file`/`serve_files`/`finish_files`,
  `run` (trọn một phiên) + `SyncReport`.
- `sync::hlc`: `Hlc`, `Clock` (từ chối mốc nhanh hơn quá 1 giờ).
- `sync::table`: `Row`, `Cursor`, trait `RowStore` + `InMemoryRowStore`, `Replica` (LWW theo HLC, bia mộ, gộp
  idempotent, con trỏ theo nhật ký bên gửi nên không sót phiên bản đến muộn qua máy thứ ba, xoá bia mộ sau 180 ngày).
- `sync::file`: `Manifest`, `Receiver` - khối 1 MiB BLAKE3, nối lại từ khối thiếu/hỏng đầu tiên, `fsync` + đổi tên
  nguyên tử khi đủ và khớp BLAKE3 toàn tệp.
- `frame`: khung nhị phân/JSON lớn có giới hạn (`write_bytes`, `read_bytes`, `write_json_max`, `read_json_max`,
  trần `MAX_BLOB` 32 MiB).
- Lỗi mới `SchemaMismatch`, `ClockSkew`, `Corrupt`. Phụ thuộc mới: `automerge` 0.12.0 (MIT), `blake3` 1.8.7.

### Đổi

- `.standards` v7.0.0 → v7.1.1.

## [0.4.0] - 26/11/2026

### Thêm

- `session` (TL1 bước 2 / phase P2, ADR-0003): `PairingHost` (`qr_offer`, `accept_qr`, `accept_sas`), `join_qr`,
  `join_sas`, `SasSession::finish`; ALPN riêng `tsulink-pair/1`; so mã số có cam kết nonce (chống thử nonce của kẻ
  đứng giữa); `AttemptLimiter` 5 lần sai/10 phút ⇒ khoá 10 phút.
- `devices`: `DeviceStore`, `InMemoryDeviceStore`, `PinsFromStore` (ghim mTLS đọc thẳng kho), tự gỡ sau 180 ngày.
- `frame`: khung tin 4 byte độ dài + JSON (≤ 64 KiB).
- Lỗi mới `Locked`, `PairingRejected`.

## [0.3.0] - 26/11/2026

### Thêm

- `tsubak` (TL1 bước 4 / phase P3, ADR-0002): `export`, `inspect`, `import`, `write_atomic`. Zip định dạng mở +
  `tsubak.json` (SHA-256 từng tệp); mã hoá tuỳ chọn = `TS 01` của TsuDEV Sync (libsodium secretstream
  XChaCha20-Poly1305, Argon2id 64 MiB/3 lượt, NFKC) - qua 36 ca `conformance/tsubak-vectors-v1.json` và libsodium C.
  Chống zip bom, đường dẫn thoát thư mục, tệp lạ; sai mật khẩu ⇒ lỗi rõ.
- Lỗi mới `Backup`, `WrongPassword`, `WeakPassword`.

## [0.2.0] - 26/11/2026

### Thêm

- `identity::DeviceIdentity`: khoá ECDSA P-256 + chứng thư tự ký, vân tay SHA-256 HOA, nạp lại từ DER (kiểm khoá khớp).
- `tls`: cấu hình rustls chỉ TLS 1.3, ALPN `tsulink/1`, mTLS bắt buộc, ghim vân tay hai chiều (`PeerPins`, `PinSet`),
  tắt nối lại phiên và 0-RTT.
- `transport::connect` / `Listener`: chỉ địa chỉ mạng nội bộ (L1), cổng nghe tự hết hạn sau 10 phút (L4), bỏ qua máy
  chưa ghép đôi (L2), không có đường `http` (L3).
- `discovery`: multicast chung kênh Lotus v2 (IPv4 + IPv6), lời rao thêm trường `tsulink`, lọc nguồn/app/vân tay.
- ADR-0001: dựng lại khám phá + mTLS theo lõi Lotus v2 thay vì phụ thuộc crate `localsend`.

## [0.1.0] - 25/11/2026

### Thêm

- `addr::is_local_network` / `require_local`: chỉ nhận IPv4 RFC 1918 + link-local, IPv6 ULA + link-local (luật L1).
- `pairing::PairingOffer`: URI mã QR `tsulink:1?app=&fp=&a=&t=&exp=`, mã ghép đôi 128 bit ngẫu nhiên, hạn ≤ 120 giây,
  từ chối địa chỉ công cộng, khoá lạ/lặp, vân tay sai khuôn.
- `sas::code`: mã 6 chữ số = (4 byte đầu SHA-256, big-endian) mod 1 000 000, thứ tự theo vân tay; vector
  `conformance/sas-vector-1.txt` tính độc lập bằng Python.
- Vector `.tsubak` (`conformance/tsubak-vectors-v1.json`) chuyển từ tsusync.
