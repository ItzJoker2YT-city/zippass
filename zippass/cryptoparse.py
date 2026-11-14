"""zip archive structure parsing - per-member crypto metadata extraction."""
import struct
import zipfile

AES_EXTRA_ID = 0x9901
_SALT_BY_STRENGTH = {1: 8, 2: 12, 3: 16}    # aes-128/192/256
_KEYLEN_BY_STRENGTH = {1: 16, 2: 24, 3: 32}
_BITS_BY_STRENGTH = {1: 128, 2: 192, 3: 256}
_PREFILTER_BYTES = 512                      # encrypted data head kept in meta


def parse_members(path: str) -> list:
    """walk the central + local headers; one meta dict per file member.

    kind: 'plain' (unencrypted), 'zipcrypto' (raw12/check), 'aes' (salt/pv per
    winzip AE spec: dkLen = 2*key_length + 2, verifier = last 2 bytes).
    """
    out = []
    with zipfile.ZipFile(path) as zf:
        infos = zf.infolist()
    with open(path, "rb") as f:
        for idx, info in enumerate(infos):
            if info.is_dir():
                continue
            m = _parse_member(f, path, info, idx)
            if m is not None:
                out.append(m)
    return out


def _parse_member(f, path: str, info, idx: int):
    flag = info.flag_bits
    method = info.compress_type
    csize = info.compress_size   # central value - zip64-safe
    crc = info.CRC
    f.seek(info.header_offset)
    lh = f.read(30)
    if len(lh) < 30 or lh[:4] != b"PK\x03\x04":
        raise ValueError(f"bad local header for member {info.filename!r}")
    (_sig, _ver, _lflag, _lmethod, mtime, _mdate, _lcrc, _lcs, _lus,
     fnlen, exlen) = struct.unpack("<4s5H3I2H", lh)
    f.read(fnlen)
    extra = f.read(exlen)
    data_off = info.header_offset + 30 + fnlen + exlen

    m = {"index": idx, "name": info.filename, "csize": csize,
         "usize": info.file_size, "crc": crc, "method": method,
         "data_off": data_off, "encrypted": bool(flag & 0x1),
         "kind": "plain", "path": path}

    if not m["encrypted"]:
        return m

    aes_strength = _aes_strength(extra) if method == 99 else None
    if aes_strength:
        return _aes_meta(m, f, data_off, aes_strength)
    return _zipcrypto_meta(m, f, data_off, mtime, flag, crc, method)


def _aes_strength(extra: bytes):
    j = 0
    while j + 4 <= len(extra):
        hid, sz = struct.unpack("<HH", extra[j:j + 4])
        if j + 4 + sz > len(extra):
            break
        if hid == AES_EXTRA_ID and sz >= 7 and extra[j + 4 + 4] in (1, 2, 3):
            return extra[j + 4 + 4]
        j += 4 + sz
    return None


def _aes_meta(m, f, data_off: int, strength: int):
    salt_len = _SALT_BY_STRENGTH[strength]
    key_len = _KEYLEN_BY_STRENGTH[strength]
    m["kind"] = "aes"
    m["strength"] = _BITS_BY_STRENGTH[strength]
    m["salt_len"] = salt_len
    m["dklen"] = 2 * key_len + 2   # winzip AE: verifier = last 2 bytes of derived data
    f.seek(data_off)
    head = f.read(salt_len + 2)
    if len(head) < salt_len + 2:
        raise ValueError(f"member {m['name']!r}: too short for aes salt")
    m["salt"] = head[:salt_len].hex()
    m["pv"] = head[salt_len:].hex()
    m["payload_len"] = m["csize"] - salt_len - 2
    return m


def _zipcrypto_meta(m, f, data_off: int, mtime: int, flag: int, crc: int,
                    method: int):
    m["kind"] = "zipcrypto"
    f.seek(data_off)
    raw12 = f.read(12)
    if len(raw12) < 12:
        raise ValueError(f"member {m['name']!r}: too short for zipcrypto header")
    m["raw12"] = raw12.hex()
    # zipfile rule: descriptor-flagged members check against the dos time
    m["check"] = ((mtime >> 8) & 0xFF) if (flag & 0x8) else ((crc >> 24) & 0xFF)
    # big deflate members carry the encrypted head of their compressed
    # data: the worker decrypts it and requires the raw deflate stream to
    # stay decodable - a writer-independent prefilter that keeps the vast
    # majority of wrong passwords away from the full CRC-verified read
    # (which can take seconds on a multi-MB member)
    if method == 8 and m["csize"] - 12 >= _PREFILTER_BYTES:
        f.seek(data_off + 12)
        m["cdata"] = f.read(_PREFILTER_BYTES).hex()
    return m


def pick_member(members: list, idx=None) -> dict:
    """crack target: user pick, else the encrypted member with the smallest
    payload (aes confirm reads the whole member - smallest wins)."""
    enc = [m for m in members if m["encrypted"]]
    if idx is not None:
        for m in enc:
            if m["index"] == idx:
                return m
        raise ValueError("that member is not encrypted")
    if not enc:
        raise ValueError("no encrypted members in this archive")

    def eff(m):
        return m.get("payload_len") or (m["csize"] - 12 if m["kind"] == "zipcrypto" else m["csize"])
    return min(enc, key=eff)
