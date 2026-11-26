// P/Invoke khớp include/tsulink.h (crates/tsulink-capi). Tên thư viện "tsulink" ⇒ tsulink.dll / libtsulink.so /
// libtsulink.dylib; app đặt tệp native cạnh tệp chạy (runtimes/<rid>/native khi đóng gói).
using System.Runtime.InteropServices;

namespace Tsudev.Link;

internal static unsafe partial class Native
{
    private const string Lib = "tsulink";

    [LibraryImport(Lib)] internal static partial nint tsulink_version();
    [LibraryImport(Lib)] internal static partial nint tsulink_last_error();
    [LibraryImport(Lib)] internal static partial void tsulink_string_free(nint s);
    [LibraryImport(Lib)] internal static partial void tsulink_bytes_free(nint p, nuint len);
    [LibraryImport(Lib)] internal static partial int tsulink_identity_generate(out nint cert, out nuint certLen, out nint key, out nuint keyLen);
    [LibraryImport(Lib)] internal static partial int tsulink_local_ips(out nint json);
    [LibraryImport(Lib)] internal static partial nint tsulink_cancel_new();
    [LibraryImport(Lib)] internal static partial void tsulink_cancel_trigger(nint c);
    [LibraryImport(Lib)] internal static partial void tsulink_cancel_free(nint c);

    [LibraryImport(Lib, StringMarshalling = StringMarshalling.Utf8)]
    internal static partial int tsulink_node_open(string config, byte* cert, nuint certLen, byte* key, nuint keyLen, out nint node);
    [LibraryImport(Lib)] internal static partial void tsulink_node_free(nint n);
    [LibraryImport(Lib)] internal static partial int tsulink_node_fingerprint(nint n, out nint s);
    [LibraryImport(Lib, StringMarshalling = StringMarshalling.Utf8)]
    internal static partial int tsulink_node_write(nint n, string table, string key, string valueJson);
    [LibraryImport(Lib, StringMarshalling = StringMarshalling.Utf8)]
    internal static partial int tsulink_node_delete(nint n, string table, string key);
    [LibraryImport(Lib, StringMarshalling = StringMarshalling.Utf8)]
    internal static partial int tsulink_node_read(nint n, string table, string key, out nint json);
    [LibraryImport(Lib)] internal static partial int tsulink_node_changes_after(nint n, ulong after, uint limit, out nint json);
    [LibraryImport(Lib)] internal static partial int tsulink_node_purge_tombstones(nint n, out ulong count);
    [LibraryImport(Lib)] internal static partial int tsulink_node_doc_ids(nint n, out nint json);
    [LibraryImport(Lib, StringMarshalling = StringMarshalling.Utf8)]
    internal static partial int tsulink_node_doc_save(nint n, string id, out nint data, out nuint len);
    [LibraryImport(Lib, StringMarshalling = StringMarshalling.Utf8)]
    internal static partial int tsulink_node_doc_merge(nint n, string id, byte* data, nuint len);
    [LibraryImport(Lib, StringMarshalling = StringMarshalling.Utf8)]
    internal static partial int tsulink_node_file_import(nint n, string path, out nint hash);
    [LibraryImport(Lib, StringMarshalling = StringMarshalling.Utf8)]
    internal static partial int tsulink_node_file_path(nint n, string hash, out nint path);
    [LibraryImport(Lib)] internal static partial int tsulink_node_devices(nint n, out nint json);
    [LibraryImport(Lib, StringMarshalling = StringMarshalling.Utf8)]
    internal static partial int tsulink_node_remove_device(nint n, string fingerprint, out int removed);
    [LibraryImport(Lib)] internal static partial int tsulink_node_prune_stale_devices(nint n, out ulong count);

    [LibraryImport(Lib)] internal static partial int tsulink_pairing_host_open(nint n, ushort port, out nint host);
    [LibraryImport(Lib)] internal static partial void tsulink_pairing_host_free(nint h);
    [LibraryImport(Lib)] internal static partial int tsulink_pairing_host_port(nint h, out ushort port);
    [LibraryImport(Lib, StringMarshalling = StringMarshalling.Utf8)]
    internal static partial int tsulink_pairing_host_qr_uri(nint h, string? ipsJson, out nint uri);
    [LibraryImport(Lib)] internal static partial int tsulink_pairing_host_accept_qr(nint h, nint cancel, out nint json);
    [LibraryImport(Lib)] internal static partial int tsulink_pairing_host_accept_sas(nint h, ulong waitSecs, nint cancel, out nint sas);
    [LibraryImport(Lib, StringMarshalling = StringMarshalling.Utf8)]
    internal static partial int tsulink_join_qr(nint n, string uri, nint cancel, out nint json);
    [LibraryImport(Lib, StringMarshalling = StringMarshalling.Utf8)]
    internal static partial int tsulink_join_sas(nint n, string addr, nint cancel, out nint sas);
    [LibraryImport(Lib)] internal static partial int tsulink_sas_info(nint s, out nint json);
    [LibraryImport(Lib)] internal static partial int tsulink_sas_finish(nint s, int confirmed, out nint json);
    [LibraryImport(Lib)] internal static partial void tsulink_sas_free(nint s);

    [LibraryImport(Lib, StringMarshalling = StringMarshalling.Utf8)]
    internal static partial int tsulink_sync_with(nint n, string peer, string addr, string? wantedJson,
        delegate* unmanaged[Cdecl]<nint, nint, ulong, ulong, void> progress, nint user, nint cancel, out nint json);
    [LibraryImport(Lib)] internal static partial int tsulink_listen(nint n, ushort port, out nint listener);
    [LibraryImport(Lib)] internal static partial int tsulink_listener_port(nint l, out ushort port);
    [LibraryImport(Lib, StringMarshalling = StringMarshalling.Utf8)]
    internal static partial int tsulink_listener_serve_one(nint l, string? wantedJson,
        delegate* unmanaged[Cdecl]<nint, nint, ulong, ulong, void> progress, nint user, nint cancel, out nint json);
    [LibraryImport(Lib)] internal static partial void tsulink_listener_free(nint l);

    [LibraryImport(Lib)] internal static partial int tsulink_discovery_start(nint n, out nint d);
    [LibraryImport(Lib)] internal static partial int tsulink_discovery_announce(nint d, ushort port, out uint sent);
    [LibraryImport(Lib)] internal static partial int tsulink_discovery_next(nint d, ulong waitMs, nint cancel, out nint json);
    [LibraryImport(Lib)] internal static partial void tsulink_discovery_free(nint d);

    /// <summary>Đọc rồi giải phóng chuỗi do thư viện trả (NULL ⇒ null).</summary>
    internal static string? Take(nint p)
    {
        if (p == 0) return null;
        try { return Marshal.PtrToStringUTF8(p); }
        finally { tsulink_string_free(p); }
    }

    /// <summary>Đọc rồi giải phóng mảng byte do thư viện trả.</summary>
    internal static byte[]? TakeBytes(nint p, nuint len)
    {
        if (p == 0) return null;
        try
        {
            var b = new byte[(int)len];
            Marshal.Copy(p, b, 0, b.Length);
            return b;
        }
        finally { tsulink_bytes_free(p, len); }
    }

    /// <summary>Ném <see cref="TsulinkException"/> nếu mã khác 0.</summary>
    internal static void Check(int rc)
    {
        if (rc == 0) return;
        var msg = Marshal.PtrToStringUTF8(tsulink_last_error()) ?? "";
        throw new TsulinkException((TsulinkError)rc, msg);
    }
}
