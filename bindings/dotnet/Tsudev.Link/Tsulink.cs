// API .NET của Tsu Link (ADR-0005). Mọi hàm chờ là async: chạy C ABI chặn trong Task.Run, CancellationToken nối vào
// TsulinkCancel của thư viện. Kiểu dữ liệu khớp JSON của C ABI (snake_case).
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace Tsudev.Link;

/// <summary>Mã lỗi ổn định (khớp TSULINK_E_* trong tsulink.h).</summary>
public enum TsulinkError
{
    /// <summary>Lỗi nội bộ.</summary>
    Panic = -1,
    /// <summary>URI ghép đôi sai khuôn.</summary>
    Malformed = 1,
    /// <summary>Vân tay không hợp lệ.</summary>
    BadFingerprint = 2,
    /// <summary>Địa chỉ không thuộc mạng nội bộ (L1).</summary>
    PublicAddress = 3,
    /// <summary>Mã ghép đôi hết hạn.</summary>
    Expired = 4,
    /// <summary>Không lấy được số ngẫu nhiên.</summary>
    Rng = 5,
    /// <summary>Danh tính thiết bị không hợp lệ.</summary>
    Identity = 6,
    /// <summary>Lỗi TLS (gồm vân tay không khớp).</summary>
    Tls = 7,
    /// <summary>Lỗi mạng/đĩa.</summary>
    Io = 8,
    /// <summary>Quá thời hạn.</summary>
    Timeout = 9,
    /// <summary>Cổng nghe hết 10 phút chờ (L4).</summary>
    IdleTimeout = 10,
    /// <summary>Tệp sao lưu hỏng.</summary>
    Backup = 11,
    /// <summary>Sai mật khẩu sao lưu.</summary>
    WrongPassword = 12,
    /// <summary>Mật khẩu sao lưu quá ngắn.</summary>
    WeakPassword = 13,
    /// <summary>Tạm khoá ghép đôi (5 lần sai/10 phút).</summary>
    Locked = 14,
    /// <summary>Ghép đôi bị từ chối / thiết bị chưa ghép đôi.</summary>
    PairingRejected = 15,
    /// <summary>Sai giao thức.</summary>
    Protocol = 16,
    /// <summary>Khác phiên bản lược đồ - nhắc cập nhật app (L5).</summary>
    SchemaMismatch = 17,
    /// <summary>Đồng hồ hai máy lệch quá 1 giờ.</summary>
    ClockSkew = 18,
    /// <summary>Dữ liệu hỏng.</summary>
    Corrupt = 19,
    /// <summary>Đã huỷ.</summary>
    Cancelled = 20,
    /// <summary>Tham số không hợp lệ.</summary>
    InvalidInput = 21,
    /// <summary>Đối tượng đã đóng.</summary>
    Closed = 22,
}

/// <summary>Lỗi từ thư viện Tsu Link.</summary>
public sealed class TsulinkException(TsulinkError code, string message) : Exception(message)
{
    /// <summary>Mã lỗi ổn định.</summary>
    public TsulinkError Code { get; } = code;
}

/// <summary>Thiết bị đã ghép đôi.</summary>
public sealed record PairedDevice(string Fingerprint, string Alias, ulong PairedAt, ulong LastSyncAt);

/// <summary>Mốc HLC.</summary>
public sealed record Hlc(ulong Ms, uint C, string Node);

/// <summary>Một thay đổi trong nhật ký máy này.</summary>
public sealed record Change(ulong Seq, string Table, string Key, JsonElement? Value, Hlc Hlc);

/// <summary>Kết quả một phiên đồng bộ.</summary>
public sealed record SyncReport(int Rows, int Docs, string[] Files, string[] Missing);

/// <summary>Kết quả phiên phía bên nghe.</summary>
public sealed record ServedSync(string Peer, SyncReport Report);

/// <summary>Thiết bị nghe thấy qua khám phá.</summary>
public sealed record DiscoveredPeer(string Fingerprint, string Alias, string Addr, bool Paired);

/// <summary>Tiến độ truyền tệp.</summary>
public readonly record struct TransferProgress(string Hash, ulong Done, ulong Total);

internal sealed record SasInfo(string Code, string PeerAlias, string PeerFingerprint);

internal sealed record NodeConfigJson(string DataDir, string App, string Alias, uint SchemaVersion);

[JsonSourceGenerationOptions(PropertyNamingPolicy = JsonKnownNamingPolicy.SnakeCaseLower)]
[JsonSerializable(typeof(PairedDevice))]
[JsonSerializable(typeof(PairedDevice[]))]
[JsonSerializable(typeof(Change[]))]
[JsonSerializable(typeof(SyncReport))]
[JsonSerializable(typeof(ServedSync))]
[JsonSerializable(typeof(DiscoveredPeer))]
[JsonSerializable(typeof(SasInfo))]
[JsonSerializable(typeof(NodeConfigJson))]
[JsonSerializable(typeof(string[]))]
internal sealed partial class Json : JsonSerializerContext;

/// <summary>Danh tính thiết bị: chứng thư + khoá riêng (app lưu khoá trong kho bí mật của hệ điều hành, vd. DPAPI).</summary>
public sealed record DeviceIdentity(byte[] CertDer, byte[] KeyPkcs8Der)
{
    /// <summary>Tạo danh tính mới (ECDSA P-256).</summary>
    public static DeviceIdentity Generate()
    {
        Native.Check(Native.tsulink_identity_generate(out var c, out var cl, out var k, out var kl));
        return new DeviceIdentity(Native.TakeBytes(c, cl)!, Native.TakeBytes(k, kl)!);
    }
}

/// <summary>Hàm chung của thư viện.</summary>
public static class Tsulink
{
    /// <summary>Phiên bản thư viện native.</summary>
    public static string Version => Marshal.PtrToStringUTF8(Native.tsulink_version()) ?? "";

    /// <summary>Địa chỉ mạng nội bộ của máy này (để đưa vào QR).</summary>
    public static string[] LocalIps()
    {
        Native.Check(Native.tsulink_local_ips(out var j));
        return JsonSerializer.Deserialize(Native.Take(j)!, Json.Default.StringArray)!;
    }

    /// <summary>Chạy lệnh C ABI chặn trên luồng nền, nối huỷ.</summary>
    internal static Task<T> Run<T>(Func<nint, T> f, CancellationToken ct) => Task.Run(() =>
    {
        var c = Native.tsulink_cancel_new();
        try
        {
            using var reg = ct.Register(() => Native.tsulink_cancel_trigger(c));
            try { return f(c); }
            catch (TsulinkException e) when (e.Code == TsulinkError.Cancelled)
            {
                throw new OperationCanceledException(e.Message, e, ct);
            }
        }
        finally { Native.tsulink_cancel_free(c); }
    }, CancellationToken.None);
}

/// <summary>Giữ handle native, giải phóng đúng một lần.</summary>
public abstract class NativeObject : IDisposable
{
    private nint _h;
    private readonly Action<nint> _free;

    private protected NativeObject(nint h, Action<nint> free)
    {
        _h = h;
        _free = free;
    }

    private protected nint H => _h != 0 ? _h : throw new ObjectDisposedException(GetType().Name);

    /// <inheritdoc/>
    public void Dispose()
    {
        var h = Interlocked.Exchange(ref _h, 0);
        if (h != 0) _free(h);
        GC.SuppressFinalize(this);
    }

    /// <summary>Giải phóng nếu app quên Dispose.</summary>
    ~NativeObject()
    {
        var h = Interlocked.Exchange(ref _h, 0);
        if (h != 0) _free(h);
    }
}

/// <summary>Một thiết bị trong một app.</summary>
public sealed class TsulinkNode : NativeObject
{
    private TsulinkNode(nint h) : base(h, Native.tsulink_node_free) { }

    /// <summary>Mở thiết bị; dữ liệu Tsu Link nằm trong <paramref name="dataDir"/>.</summary>
    public static unsafe TsulinkNode Open(string dataDir, string app, string alias, uint schemaVersion, DeviceIdentity id)
    {
        var cfg = JsonSerializer.Serialize(new NodeConfigJson(dataDir, app, alias, schemaVersion), Json.Default.NodeConfigJson);
        fixed (byte* c = id.CertDer)
        fixed (byte* k = id.KeyPkcs8Der)
        {
            Native.Check(Native.tsulink_node_open(cfg, c, (nuint)id.CertDer.Length, k, (nuint)id.KeyPkcs8Der.Length, out var h));
            return new TsulinkNode(h);
        }
    }

    /// <summary>Vân tay máy này.</summary>
    public string Fingerprint
    {
        get
        {
            Native.Check(Native.tsulink_node_fingerprint(H, out var s));
            return Native.Take(s)!;
        }
    }

    /// <summary>Ghi bản ghi (JSON).</summary>
    public void Write(string table, string key, string valueJson) => Native.Check(Native.tsulink_node_write(H, table, key, valueJson));

    /// <summary>Xoá bản ghi.</summary>
    public void Delete(string table, string key) => Native.Check(Native.tsulink_node_delete(H, table, key));

    /// <summary>Đọc bản ghi (JSON), null nếu chưa có/đã xoá.</summary>
    public string? Read(string table, string key)
    {
        Native.Check(Native.tsulink_node_read(H, table, key, out var s));
        return Native.Take(s);
    }

    /// <summary>Nhật ký máy này sau <paramref name="after"/>.</summary>
    public Change[] ChangesAfter(ulong after, uint limit = 512)
    {
        Native.Check(Native.tsulink_node_changes_after(H, after, limit, out var s));
        return JsonSerializer.Deserialize(Native.Take(s)!, Json.Default.ChangeArray)!;
    }

    /// <summary>Xoá hẳn bia mộ quá 180 ngày.</summary>
    public ulong PurgeTombstones()
    {
        Native.Check(Native.tsulink_node_purge_tombstones(H, out var n));
        return n;
    }

    /// <summary>Mã các tài liệu Automerge.</summary>
    public string[] DocIds()
    {
        Native.Check(Native.tsulink_node_doc_ids(H, out var s));
        return JsonSerializer.Deserialize(Native.Take(s)!, Json.Default.StringArray)!;
    }

    /// <summary>Bản lưu Automerge của tài liệu, null nếu chưa có.</summary>
    public byte[]? DocSave(string id)
    {
        Native.Check(Native.tsulink_node_doc_save(H, id, out var p, out var n));
        return Native.TakeBytes(p, n);
    }

    /// <summary>Gộp bản lưu Automerge vào tài liệu.</summary>
    public unsafe void DocMerge(string id, byte[] data)
    {
        fixed (byte* d = data) Native.Check(Native.tsulink_node_doc_merge(H, id, d, (nuint)data.Length));
    }

    /// <summary>Chép tệp vào kho tệp; trả BLAKE3.</summary>
    public string FileImport(string path)
    {
        Native.Check(Native.tsulink_node_file_import(H, path, out var s));
        return Native.Take(s)!;
    }

    /// <summary>Đường dẫn tệp trong kho, null nếu chưa có.</summary>
    public string? FilePath(string hash)
    {
        Native.Check(Native.tsulink_node_file_path(H, hash, out var s));
        return Native.Take(s);
    }

    /// <summary>Thiết bị đã ghép đôi.</summary>
    public PairedDevice[] Devices()
    {
        Native.Check(Native.tsulink_node_devices(H, out var s));
        return JsonSerializer.Deserialize(Native.Take(s)!, Json.Default.PairedDeviceArray)!;
    }

    /// <summary>Gỡ thiết bị.</summary>
    public bool RemoveDevice(string fingerprint)
    {
        Native.Check(Native.tsulink_node_remove_device(H, fingerprint, out var r));
        return r != 0;
    }

    /// <summary>Gỡ thiết bị không đồng bộ quá 180 ngày.</summary>
    public ulong PruneStaleDevices()
    {
        Native.Check(Native.tsulink_node_prune_stale_devices(H, out var n));
        return n;
    }

    /// <summary>Mở cổng ghép đôi tạm.</summary>
    public PairingHost OpenPairingHost(ushort port = 0)
    {
        Native.Check(Native.tsulink_pairing_host_open(H, port, out var h));
        return new PairingHost(h);
    }

    /// <summary>Quét QR của máy kia và ghép đôi.</summary>
    public Task<PairedDevice> JoinQrAsync(string uri, CancellationToken ct = default) => Tsulink.Run(c =>
    {
        Native.Check(Native.tsulink_join_qr(H, uri, c, out var s));
        return JsonSerializer.Deserialize(Native.Take(s)!, Json.Default.PairedDevice)!;
    }, ct);

    /// <summary>Nối tới cổng ghép đôi <paramref name="addr"/> ("ip:cổng") để so mã số.</summary>
    public Task<SasSession> JoinSasAsync(string addr, CancellationToken ct = default) => Tsulink.Run(c =>
    {
        Native.Check(Native.tsulink_join_sas(H, addr, c, out var s));
        return new SasSession(s);
    }, ct);

    /// <summary>Đồng bộ (bên gọi) với thiết bị đã ghép đôi.</summary>
    public unsafe Task<SyncReport> SyncWithAsync(string peer, string addr, IEnumerable<string>? wanted = null,
        IProgress<TransferProgress>? progress = null, CancellationToken ct = default)
    {
        var w = wanted is null ? null : JsonSerializer.Serialize(wanted.ToArray(), Json.Default.StringArray);
        return Tsulink.Run(c => ProgressBridge.With(progress, (cb, user) =>
        {
            Native.Check(Native.tsulink_sync_with(H, peer, addr, w,
                (delegate* unmanaged[Cdecl]<nint, nint, ulong, ulong, void>)cb, user, c, out var s));
            return JsonSerializer.Deserialize(Native.Take(s)!, Json.Default.SyncReport)!;
        }), ct);
    }

    /// <summary>Mở cổng đồng bộ (tự hết hạn sau 10 phút không có kết nối).</summary>
    public SyncListener Listen(ushort port = 0)
    {
        Native.Check(Native.tsulink_listen(H, port, out var l));
        return new SyncListener(l);
    }

    /// <summary>Bắt đầu khám phá thiết bị cùng app.</summary>
    public Discovery StartDiscovery()
    {
        Native.Check(Native.tsulink_discovery_start(H, out var d));
        return new Discovery(d);
    }
}

internal static unsafe class ProgressBridge
{
    [UnmanagedCallersOnly(CallConvs = [typeof(CallConvCdecl)])]
    private static void OnProgress(nint user, nint hash, ulong done, ulong total)
    {
        try
        {
            var p = (IProgress<TransferProgress>)GCHandle.FromIntPtr(user).Target!;
            p.Report(new TransferProgress(Marshal.PtrToStringUTF8(hash) ?? "", done, total));
        }
        catch
        {
            // Ngoại lệ không được vượt biên native.
        }
    }

    internal static T With<T>(IProgress<TransferProgress>? progress,
        Func<nint, nint, T> f)
    {
        if (progress is null) return f(0, 0);
        var h = GCHandle.Alloc(progress);
        try { return f((nint)(delegate* unmanaged[Cdecl]<nint, nint, ulong, ulong, void>)&OnProgress, GCHandle.ToIntPtr(h)); }
        finally { h.Free(); }
    }
}

/// <summary>Cổng ghép đôi đang mở.</summary>
public sealed class PairingHost : NativeObject
{
    internal PairingHost(nint h) : base(h, Native.tsulink_pairing_host_free) { }

    /// <summary>Cổng đang nghe.</summary>
    public ushort Port
    {
        get
        {
            Native.Check(Native.tsulink_pairing_host_port(H, out var p));
            return p;
        }
    }

    /// <summary>URI mã QR mới (hạn 120 giây); <paramref name="ips"/> null ⇒ tự chọn địa chỉ nội bộ.</summary>
    public string QrUri(IEnumerable<string>? ips = null)
    {
        var j = ips is null ? null : JsonSerializer.Serialize(ips.ToArray(), Json.Default.StringArray);
        Native.Check(Native.tsulink_pairing_host_qr_uri(H, j, out var s));
        return Native.Take(s)!;
    }

    /// <summary>Chờ máy kia quét QR vừa tạo.</summary>
    public Task<PairedDevice> AcceptQrAsync(CancellationToken ct = default) => Tsulink.Run(c =>
    {
        Native.Check(Native.tsulink_pairing_host_accept_qr(H, c, out var s));
        return JsonSerializer.Deserialize(Native.Take(s)!, Json.Default.PairedDevice)!;
    }, ct);

    /// <summary>Chờ máy kia nối để so mã số.</summary>
    public Task<SasSession> AcceptSasAsync(TimeSpan wait, CancellationToken ct = default) => Tsulink.Run(c =>
    {
        Native.Check(Native.tsulink_pairing_host_accept_sas(H, (ulong)wait.TotalSeconds, c, out var s));
        return new SasSession(s);
    }, ct);
}

/// <summary>Phiên so mã số 6 chữ số.</summary>
public sealed class SasSession : NativeObject
{
    private readonly SasInfo _info;

    internal SasSession(nint h) : base(h, Native.tsulink_sas_free)
    {
        Native.Check(Native.tsulink_sas_info(h, out var s));
        _info = JsonSerializer.Deserialize(Native.Take(s)!, Json.Default.SasInfo)!;
    }

    /// <summary>Mã để hai người so.</summary>
    public string Code => _info.Code;
    /// <summary>Tên máy kia.</summary>
    public string PeerAlias => _info.PeerAlias;
    /// <summary>Vân tay máy kia.</summary>
    public string PeerFingerprint => _info.PeerFingerprint;

    /// <summary>Người dùng xác nhận mã khớp hay không (gọi một lần).</summary>
    public Task<PairedDevice> FinishAsync(bool confirmed) => Tsulink.Run(_ =>
    {
        Native.Check(Native.tsulink_sas_finish(H, confirmed ? 1 : 0, out var s));
        return JsonSerializer.Deserialize(Native.Take(s)!, Json.Default.PairedDevice)!;
    }, CancellationToken.None);
}

/// <summary>Cổng đồng bộ đang mở.</summary>
public sealed class SyncListener : NativeObject
{
    internal SyncListener(nint h) : base(h, Native.tsulink_listener_free) { }

    /// <summary>Cổng đang nghe.</summary>
    public ushort Port
    {
        get
        {
            Native.Check(Native.tsulink_listener_port(H, out var p));
            return p;
        }
    }

    /// <summary>Chờ một thiết bị đã ghép đôi rồi đồng bộ trọn một phiên.</summary>
    public unsafe Task<ServedSync> ServeOneAsync(IEnumerable<string>? wanted = null,
        IProgress<TransferProgress>? progress = null, CancellationToken ct = default)
    {
        var w = wanted is null ? null : JsonSerializer.Serialize(wanted.ToArray(), Json.Default.StringArray);
        return Tsulink.Run(c => ProgressBridge.With(progress, (cb, user) =>
        {
            Native.Check(Native.tsulink_listener_serve_one(H, w,
                (delegate* unmanaged[Cdecl]<nint, nint, ulong, ulong, void>)cb, user, c, out var s));
            return JsonSerializer.Deserialize(Native.Take(s)!, Json.Default.ServedSync)!;
        }), ct);
    }
}

/// <summary>Khám phá thiết bị cùng app trên mạng nội bộ.</summary>
public sealed class Discovery : NativeObject
{
    internal Discovery(nint h) : base(h, Native.tsulink_discovery_free) { }

    /// <summary>Rao máy này; trả số giao diện gửi được.</summary>
    public Task<uint> AnnounceAsync(ushort port) => Tsulink.Run(_ =>
    {
        Native.Check(Native.tsulink_discovery_announce(H, port, out var n));
        return n;
    }, CancellationToken.None);

    /// <summary>Thiết bị kế tiếp nghe thấy, null nếu hết <paramref name="wait"/>.</summary>
    public Task<DiscoveredPeer?> NextAsync(TimeSpan wait, CancellationToken ct = default) => Tsulink.Run(c =>
    {
        Native.Check(Native.tsulink_discovery_next(H, (ulong)wait.TotalMilliseconds, c, out var s));
        var j = Native.Take(s);
        return j is null ? null : JsonSerializer.Deserialize(j, Json.Default.DiscoveredPeer);
    }, ct);
}
