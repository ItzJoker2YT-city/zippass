"""shared fixture builders for the live test archives (also usable standalone)."""
import os
import struct
import zlib

import pyzipper

HERE = os.path.dirname(os.path.abspath(__file__))
TESTS = os.path.join(HERE, "tests")
os.makedirs(TESTS, exist_ok=True)

_CRC = []
for _i in range(256):
    _c = _i
    for _ in range(8):
        _c = (_c >> 1) ^ (0xEDB88320 if _c & 1 else 0)
    _CRC.append(_c)


class PkCrypt:
    """pkware stream cipher, encryption side - keys advance on plaintext bytes."""

    def __init__(self, pwd):
        self.k0, self.k1, self.k2 = 0x12345678, 0x23456789, 0x34567890
        for c in pwd:
            self._upd(c)

    def _upd(self, c):
        t = self.k0
        self.k0 = (t >> 8) ^ _CRC[(t ^ c) & 0xFF]
        k1 = self.k1 + (self.k0 & 0xFF)
        self.k1 = (k1 * 134775813 + 1) & 0xFFFFFFFF
        t2 = self.k2
        self.k2 = (t2 >> 8) ^ _CRC[(t2 ^ (self.k1 >> 24)) & 0xFF]

    def enc(self, data):
        out = bytearray()
        for c in data:
            k = self.k2 | 2
            out.append(c ^ (((k * (k ^ 1)) >> 8) & 0xFF))
            self._upd(c)
        return bytes(out)


def _deflate(data: bytes) -> bytes:
    comp = zlib.compressobj(9, zlib.DEFLATED, -15)
    return comp.compress(data) + comp.flush()


def _eocd(cd_size: int, cd_off: int) -> bytes:
    return struct.pack("<4sHHHHIIH", b"PK\x05\x06", 0, 0, 1, 1, cd_size, cd_off, 0)


def make_zipcrypto(path: str, pwd: bytes, content: str, name: str = "secret.txt") -> None:
    """build a traditional zipcrypto archive by hand (stdlib cannot write these)."""
    data = content.encode("utf-8")
    crc = zlib.crc32(data) & 0xFFFFFFFF
    cdata = _deflate(data)
    crypt = PkCrypt(pwd)
    # 11 junk bytes + check byte = crc>>24 (no data-descriptor flag)
    hdr = b"\x7a\x21\x9c\x44\x11\xde\x03\x88\x5f\x2a\xc3" + bytes([(crc >> 24) & 0xFF])
    payload = crypt.enc(hdr) + crypt.enc(cdata)
    csize = len(payload)
    lname = name.encode()
    lho = 0
    local = struct.pack("<4sHHHHHIIIHH", b"PK\x03\x04", 20, 0x0001, 8, 0x6C40, 0x5D2E,
                        crc, csize, len(data), len(lname), 0) + lname
    central = struct.pack("<4sHHHHHHIIIHHHHHII", b"PK\x01\x02", 20, 20, 0x0001, 8,
                          0x6C40, 0x5D2E, crc, csize, len(data), len(lname), 0,
                          0, 0, 0, 0, lho) + lname
    with open(path, "wb") as f:
        f.write(local + payload + central + _eocd(len(central), len(local) + len(payload)))


def make_dd_zip(path: str, pwd: bytes, content: str, name: str = "dd.txt") -> None:
    """zipcrypto with the data-descriptor flag (bit 3): check byte comes from
    dos time, crc/csize/usize in the local header are zeroed."""
    data = content.encode("utf-8")
    crc = zlib.crc32(data) & 0xFFFFFFFF
    cdata = _deflate(data)
    crypt = PkCrypt(pwd)
    mtime = 0x6C40
    hdr = b"\x11\x22\x33\x44\x55\x66\x77\x88\x99\xaa\xbb" + bytes([(mtime >> 8) & 0xFF])
    payload = crypt.enc(hdr) + crypt.enc(cdata)
    csize = len(payload)
    lname = name.encode()
    desc = struct.pack("<III", crc, csize, len(data))
    local = struct.pack("<4sHHHHHIIIHH", b"PK\x03\x04", 20, 0x0009, 8, mtime, 0x5D2E,
                        0, 0, 0, len(lname), 0) + lname
    central = struct.pack("<4sHHHHHHIIIHHHHHII", b"PK\x01\x02", 20, 20, 0x0009, 8,
                          mtime, 0x5D2E, crc, csize, len(data), len(lname), 0,
                          0, 0, 0, 0, 0) + lname
    with open(path, "wb") as f:
        f.write(local + payload + desc + central + _eocd(len(central), len(local) + len(payload) + len(desc)))


def make_aes_zip(path: str, pwd: bytes, content: str = "top secret payload",
                 name: str = "vault.txt") -> None:
    """winzip AES-256 archive via pyzipper (the official writer path)."""
    with pyzipper.AESZipFile(path, "w", compression=pyzipper.ZIP_DEFLATED,
                             encryption=pyzipper.WZ_AES) as zf:
        zf.setpassword(pwd)
        zf.writestr(name, content)


def build_test_wordlist(path: str, target: str, junk_count: int = 280000) -> int:
    """wordlist with the target buried near the end; returns line count."""
    lines = [f"{i:06d}" for i in range(junk_count)]
    lines.append(target)
    lines += [f"zz{j}" for j in range(19999)]
    with open(path, "w") as f:
        f.write("\n".join(lines) + "\n")
    return len(lines)


def main() -> None:
    pw_zc = b"l3gacy"
    zc = os.path.join(TESTS, "zc.zip")
    make_zipcrypto(zc, pw_zc, "attack at dawn. the quick brown fox jumps over the lazy dog." * 8)
    import zipfile
    with zipfile.ZipFile(zc) as zf:
        assert zf.read("secret.txt", pwd=pw_zc).startswith(b"attack at dawn.")
    print(f"[+] {zc} - zipcrypto, password {pw_zc.decode()}, stdlib read-back OK")

    pw_aes = b"31337"
    aes = os.path.join(TESTS, "aes.zip")
    make_aes_zip(aes, pw_aes)
    with pyzipper.AESZipFile(aes) as zf:
        assert zf.read("vault.txt", pwd=pw_aes) == b"top secret payload"
    print(f"[+] {aes} - winzip aes-256, password {pw_aes.decode()}, pyzipper read-back OK")

    wl = os.path.join(TESTS, "wl.txt")
    n = build_test_wordlist(wl, "l3gacy")
    print(f"[+] {wl} - {n} lines, target at line 280001")


if __name__ == "__main__":
    main()
