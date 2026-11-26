// Test trọn đường qua thư viện Rust thật (target/<profile>/libtsulink_dart.*): hai thiết bị trong một tiến trình, nối
// qua địa chỉ mạng nội bộ (loopback bị luật L1 chặn). Chạy: cargo build -p tsulink-dart && flutter test
import 'dart:io';

import 'package:flutter_rust_bridge/flutter_rust_bridge_for_generated_io.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:tsulink/tsulink.dart';

String _libPath() {
  final profile = Platform.environment['TSULINK_PROFILE'] ?? 'debug';
  final name = Platform.isWindows
      ? 'tsulink_dart.dll'
      : Platform.isMacOS
      ? 'libtsulink_dart.dylib'
      : 'libtsulink_dart.so';
  return '${Directory.current.path}/../../target/$profile/$name';
}

void main() {
  late Directory root;

  setUpAll(() async {
    await RustLib.init(externalLibrary: ExternalLibrary.open(_libPath()));
    root = await Directory.systemTemp.createTemp('tsulink-dart-');
  });

  tearDownAll(() => root.delete(recursive: true));

  Future<LinkNode> open(String name, int schema) async => LinkNode.open(
    dataDir: '${root.path}/$name',
    app: 'qulythuchi',
    alias: 'Máy $name',
    schemaVersion: schema,
    identity: await generateIdentity(),
  );

  test('phiên bản lõi', () {
    expect(tsulinkVersion(), '0.6.0');
  });

  test('lỗi mang mã ổn định, huỷ được lệnh đang chờ', () async {
    final a = await open('loi', 1);
    await expectLater(
      a.write(table: '', key: 'k', valueJson: '1'),
      throwsA(isA<LinkError>().having((e) => e.code, 'code', LinkErrorCode.invalidInput)),
    );
    final l = await a.listen(port: 0);
    final c = LinkCancel();
    final f = l.serveOne(wanted: [], onProgress: (_, _, _) {}, cancel: c);
    await Future<void>.delayed(const Duration(milliseconds: 100));
    c.cancel();
    await expectLater(f, throwsA(isA<LinkError>().having((e) => e.code, 'code', LinkErrorCode.cancelled)));
  });

  test('ghép đôi QR rồi đồng bộ bản ghi + tệp', () async {
    final ip = localIps().where((i) => !i.contains(':')).firstOrNull;
    if (ip == null) {
      markTestSkipped('máy không có địa chỉ IPv4 mạng nội bộ');
      return;
    }
    final a = await open('a', 2);
    final b = await open('b', 2);
    final host = await a.openPairingHost(port: 0);
    final uri = await host.qrUri(ips: [ip]);
    expect(uri, startsWith('tsulink:1?'));
    final accepted = host.acceptQr(cancel: LinkCancel());
    final joined = await b.joinQr(uri: uri, cancel: LinkCancel());
    expect(joined.fingerprint, a.fingerprint);
    expect((await accepted).alias, 'Máy b');

    await b.write(table: 'chi', key: '1', valueJson: '{"so_tien":99}');
    final src = File('${root.path}/anh.bin')..writeAsBytesSync(List.filled(1200000, 5));
    final hash = await b.fileImport(path: src.path);

    final l = await b.listen(port: 0);
    final port = await l.port();
    final served = l.serveOne(wanted: [], onProgress: (_, _, _) {}, cancel: LinkCancel());
    var seen = 0;
    final rep = await a.syncWith(
      peer: b.fingerprint,
      addr: '$ip:$port',
      wanted: [hash],
      onProgress: (h, done, total) => seen = done,
      cancel: LinkCancel(),
    );
    expect((await served).peer, a.fingerprint);
    expect(rep.rows, 1);
    expect(rep.files, hasLength(1));
    expect(await a.read(table: 'chi', key: '1'), '{"so_tien":99}');
    expect(File((await a.filePath(hash: hash))!).lengthSync(), 1200000);
    final changes = await a.changesAfter(after: 0, limit: 100);
    expect(changes.single.key, '1');
    expect((await a.devices()).single.fingerprint, b.fingerprint);
    // Tiến độ gửi không chờ Dart ⇒ cho vòng sự kiện chạy nốt.
    await Future<void>.delayed(const Duration(milliseconds: 50));
    expect(seen, 1200000);
  });
}
