"""inspect one zip archive: members, encryption, and what the app's
analyzer (cryptoparse) reports - usage: python inspect_zip.py <path>"""
import sys
import zipfile

from zippass import cryptoparse

path = sys.argv[1]
try:
    zf = zipfile.ZipFile(path)
except Exception as e:
    print(f"not a readable zip: {e!r}")
    sys.exit(1)

names = zf.namelist()
print(f"archive: {path}")
print(f"members: {len(names)}")
for info in zf.infolist():
    enc = bool(info.flag_bits & 0x1)
    # AES-encrypted members carry an extra field with header id 0x9901
    aes = any(e.header_id == 0x9901 for e in getattr(info, "extra", b"") and [])
    extra_ids = []
    raw = info.extra
    i = 0
    while i + 4 <= len(raw):
        hid, sz = int.from_bytes(raw[i:i + 2], "little"), \
            int.from_bytes(raw[i + 2:i + 4], "little")
        extra_ids.append(hex(hid))
        i += 4 + sz
    print(f"  {info.filename!r} size={info.file_size} encrypted={enc} "
          f"compress={info.compress_type} extras={extra_ids}")

try:
    members = cryptoparse.parse_members(path)
    print(f"\ncryptoparse: {len(members)} attackable member(s)")
    for m in members:
        print(f"  {m}")
except Exception as e:
    print(f"\ncryptoparse failed: {e!r}")
