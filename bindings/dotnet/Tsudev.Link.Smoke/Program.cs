// Kiểm thử trọn đường Tsudev.Link qua thư viện native thật: hai thiết bị trong một tiến trình, nối qua địa chỉ mạng
// nội bộ (loopback bị luật L1 chặn). Thoát mã khác 0 nếu sai. Chạy: TSULINK_NATIVE_DIR=<thư mục libtsulink> dotnet run
using System.Runtime.InteropServices;
using Tsudev.Link;

var nativeDir = Environment.GetEnvironmentVariable("TSULINK_NATIVE_DIR");
if (nativeDir is not null)
{
    NativeLibrary.SetDllImportResolver(typeof(TsulinkNode).Assembly, (name, _, _) =>
        name == "tsulink"
            ? NativeLibrary.Load(Path.Combine(nativeDir, OperatingSystem.IsWindows() ? "tsulink.dll"
                : OperatingSystem.IsMacOS() ? "libtsulink.dylib" : "libtsulink.so"))
            : 0);
}

var failures = 0;
void Check(bool ok, string what)
{
    Console.WriteLine($"{(ok ? "ĐẠT " : "SAI ")} {what}");
    if (!ok) failures++;
}

Console.WriteLine($"tsulink {Tsulink.Version}");
Check(Tsulink.Version == "0.6.0", "phiên bản native = 0.6.0");
var ip = Tsulink.LocalIps().FirstOrDefault(i => !i.Contains(':'));
var root = Path.Combine(Path.GetTempPath(), "tsulink-dotnet-" + Guid.NewGuid().ToString("N"));

using (var a = TsulinkNode.Open(Path.Combine(root, "a"), "qulythuchi", "Máy A", 2, DeviceIdentity.Generate()))
using (var b = TsulinkNode.Open(Path.Combine(root, "b"), "qulythuchi", "Máy B", 2, DeviceIdentity.Generate()))
{
    // Lỗi có mã ổn định.
    try { a.Write("", "k", "1"); Check(false, "bảng rỗng bị từ chối"); }
    catch (TsulinkException e) { Check(e.Code == TsulinkError.InvalidInput, $"bảng rỗng ⇒ InvalidInput ({e.Message})"); }

    // Huỷ bằng CancellationToken.
    using (var l = a.Listen())
    using (var cts = new CancellationTokenSource(TimeSpan.FromMilliseconds(200)))
    {
        try { await l.ServeOneAsync(ct: cts.Token); Check(false, "huỷ chờ"); }
        catch (OperationCanceledException) { Check(true, "CancellationToken huỷ được lệnh đang chặn"); }
    }

    if (ip is null)
    {
        Console.WriteLine("bỏ qua phần mạng: máy không có địa chỉ IPv4 mạng nội bộ");
    }
    else
    {
        // Ghép đôi bằng so mã số.
        using var host = a.OpenPairingHost();
        var accept = host.AcceptSasAsync(TimeSpan.FromSeconds(30));
        using var sb = await b.JoinSasAsync($"{ip}:{host.Port}");
        using var sa = await accept;
        Check(sa.Code == sb.Code && sa.Code.Length == 6, $"hai máy cùng mã {sa.Code}");
        var fa = sa.FinishAsync(true);
        var devB = await sb.FinishAsync(true);
        await fa;
        Check(devB.Fingerprint == a.Fingerprint && a.Devices().Length == 1, "ghép đôi lưu hai chiều");

        b.Write("chi", "1", """{"so_tien":250}""");
        var file = Path.Combine(root, "anh.bin");
        File.WriteAllBytes(file, new byte[1_300_000]);
        var hash = b.FileImport(file);

        using var listener = b.Listen();
        var served = listener.ServeOneAsync();
        ulong seen = 0;
        var progress = new SyncProgress(p => seen = p.Done);
        var rep = await a.SyncWithAsync(b.Fingerprint, $"{ip}:{listener.Port}", [hash], progress);
        var srv = await served;
        Check(rep.Rows == 1 && rep.Files.Length == 1, $"đồng bộ: {rep.Rows} bản ghi, {rep.Files.Length} tệp");
        Check(srv.Peer == a.Fingerprint, "bên nghe biết máy gọi");
        Check(seen == 1_300_000, $"tiến độ tới {seen}");
        Check(a.Read("chi", "1") == """{"so_tien":250}""", "đọc bản ghi nhận về");
        Check(a.FilePath(hash) is { } p && new FileInfo(p).Length == 1_300_000, "tệp nhận đủ");
        Check(a.ChangesAfter(0).Single().Value?.GetProperty("so_tien").GetInt32() == 250, "nhật ký thay đổi");
    }
}
Directory.Delete(root, true);
Console.WriteLine(failures == 0 ? "TẤT CẢ ĐẠT" : $"{failures} SAI");
return failures == 0 ? 0 : 1;

/// <summary>IProgress gọi ngay trên luồng báo (Progress&lt;T&gt; đẩy qua SynchronizationContext - chậm/khó kiểm).</summary>
sealed class SyncProgress(Action<TransferProgress> f) : IProgress<TransferProgress>
{
    public void Report(TransferProgress value) => f(value);
}
