"""Tính độc lập vector mã 6 chữ số (LOCAL_SYNC.md mục 3) và so với conformance/sas-vector-1.txt."""
import hashlib
import pathlib
import sys

A = "AAAA456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF"
B = "BBBB456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF"
lo, hi = sorted([A, B])
h = hashlib.sha256(b"tsulink-sas|" + lo.encode() + hi.encode() + bytes([1] * 16) + bytes([2] * 16)).digest()
want = f"{int.from_bytes(h[:4], 'big') % 1_000_000:06}"
got = (pathlib.Path(__file__).parent / "sas-vector-1.txt").read_text()
print(f"python={want} tệp={got}")
sys.exit(0 if want == got else 1)
