/// Tsu Link - đồng bộ trực tiếp giữa thiết bị qua mạng nội bộ, không internet (tsudev-standards LOCAL_SYNC.md).
///
/// Gọi `await RustLib.init()` một lần lúc khởi động app, rồi dùng [LinkNode]. Mã lỗi trong [LinkError.code] khớp C ABI
/// (`crates/tsulink-capi/include/tsulink.h`); xem [LinkErrorCode].
library;

export 'src/rust/api.dart';
export 'src/rust/frb_generated.dart' show RustLib;

/// Mã lỗi ổn định hay dùng ở giao diện.
abstract final class LinkErrorCode {
  /// Mã ghép đôi hết hạn.
  static const expired = 4;

  /// Quá thời hạn.
  static const timeout = 9;

  /// Cổng nghe hết 10 phút chờ (L4) - đóng màn đồng bộ.
  static const idleTimeout = 10;

  /// Tạm khoá ghép đôi (5 lần sai/10 phút).
  static const locked = 14;

  /// Ghép đôi bị từ chối / thiết bị chưa ghép đôi.
  static const pairingRejected = 15;

  /// Khác phiên bản dữ liệu - nhắc cập nhật app (L5).
  static const schemaMismatch = 17;

  /// Đồng hồ hai máy lệch quá 1 giờ.
  static const clockSkew = 18;

  /// Đã huỷ.
  static const cancelled = 20;

  /// Tham số không hợp lệ.
  static const invalidInput = 21;
}
