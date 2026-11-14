"""numba-jit pkware kernels - the jit layer under the vector fast path.

fastfilter reduces millions of candidates to a handful of filter
passers; these kernels make every other step cheap too: the per-row
key schedule + header check behind fastfilter.zc_pass1 (a scalar pass
per row, each ending at its own length - no freezing machinery), the
candidate matrix fills for dict/hybrid scans, the 512-byte cdata
prefilter decrypt, and the full-member decrypt that backs the
CRC-verified confirm (a pure-python zipfile read of a multi-MB member
costs seconds; the jit decrypt of the same bytes costs milliseconds).

arithmetic runs in int64 with explicit masks - products stay under
2**63 (the decrypt byte uses the 16-bit identity: bits 8..15 of
(k|2)*((k|2)^1) depend only on bits 0..15 of k|2), and the test suite
anchors every kernel against the scalar reference in zippass.pkware.
when numba is missing the module degrades to plain-python kernels of
the same name - correct, just slower; matbuild then sends every task
to the scalar scanners instead (HAS_NUMBA).
"""
import zlib

import numpy as np

try:
    from numba import njit
    HAS_NUMBA = True
except ImportError:          # pragma: no cover - numba is optional
    def njit(*a, **k):
        def wrap(fn):
            return fn
        return wrap
    HAS_NUMBA = False

_T = np.zeros(256, dtype=np.int64)
for _i in range(256):
    _c = _i
    for _ in range(8):
        _c = (_c >> 1) ^ (0xEDB88320 if _c & 1 else 0)
    _T[_i] = _c


@njit(cache=True)
def pwd_keys(pwd):
    """pkware keys after consuming the password bytes; int64 in, int64 out."""
    k0, k1, k2 = np.int64(0x12345678), np.int64(0x23456789), np.int64(0x34567890)
    for i in range(pwd.shape[0]):
        c = np.int64(pwd[i])
        k0 = (k0 >> np.int64(8)) ^ _T[(k0 ^ c) & np.int64(0xFF)]
        k1 = ((k1 + (k0 & np.int64(0xFF))) * np.int64(134775813)
              + np.int64(1)) & np.int64(0xFFFFFFFF)
        k2 = (k2 >> np.int64(8)) ^ _T[(k2 ^ (k1 >> np.int64(24))) & np.int64(0xFF)]
    return k0, k1, k2


@njit(cache=True)
def schedule_batch(mat, lens, raw12, check):
    """pkware key schedule + header check for a whole candidate batch.

    one scalar pass per row: the password bytes, then the 12-byte
    header, each row ending at its own length. returns
    (passers, k0s, k1s, k2s): row indices whose decrypted 12th header
    byte equals the check byte (1/256 of wrong passwords), plus every
    row's post-header keys positioned to decrypt the compressed data -
    key arrays are indexed by row, passers select into them. mirrors
    the column-wise numpy version it replaced bit-exactly (tests pin it
    against the scalar reference in testers).
    """
    n = mat.shape[0]
    passers = np.empty(n, np.int64)
    k0s = np.empty(n, np.int64)
    k1s = np.empty(n, np.int64)
    k2s = np.empty(n, np.int64)
    cnt = 0
    for r in range(n):
        k0, k1, k2 = np.int64(0x12345678), np.int64(0x23456789), np.int64(0x34567890)
        for t in range(lens[r]):
            d = np.int64(mat[r, t])
            k0 = (k0 >> np.int64(8)) ^ _T[(k0 ^ d) & np.int64(0xFF)]
            k1 = ((k1 + (k0 & np.int64(0xFF))) * np.int64(134775813)
                  + np.int64(1)) & np.int64(0xFFFFFFFF)
            k2 = (k2 >> np.int64(8)) ^ _T[(k2 ^ (k1 >> np.int64(24))) & np.int64(0xFF)]
        d = np.int64(0)
        for j in range(12):
            k = (k2 | np.int64(2)) & np.int64(0xFFFF)
            t = (k * (k ^ np.int64(1))) & np.int64(0xFFFF)
            d = np.int64(raw12[j]) ^ ((t >> np.int64(8)) & np.int64(0xFF))
            k0 = (k0 >> np.int64(8)) ^ _T[(k0 ^ d) & np.int64(0xFF)]
            k1 = ((k1 + (k0 & np.int64(0xFF))) * np.int64(134775813)
                  + np.int64(1)) & np.int64(0xFFFFFFFF)
            k2 = (k2 >> np.int64(8)) ^ _T[(k2 ^ (k1 >> np.int64(24))) & np.int64(0xFF)]
        k0s[r], k1s[r], k2s[r] = k0, k1, k2
        if d == check:
            passers[cnt] = r
            cnt += 1
    return passers[:cnt], k0s, k1s, k2s


@njit(cache=True)
def dict_fill(mat, buf, starts, lens, idx):
    """fill candidate rows from usable-line indices (any order); rows
    shorter than the block width keep their zero padding."""
    for k in range(idx.shape[0]):
        r = idx[k]
        s = starts[r]
        w = lens[r]
        for t in range(w):
            mat[k, t] = buf[s + t]


@njit(cache=True)
def hybrid_fill(mat, buf, starts, lens_line, idx, pre, suf_tab, P, Ls, S):
    """fill hybrid rows: prefix + word + suffix, lines x suffix combos
    line-major (the scalar product order); idx carries original line
    positions, suf_tab the (S, Ls) suffix odometer table."""
    for k in range(idx.shape[0]):
        r = idx[k]
        s = starts[r]
        w = lens_line[r]
        base = k * S
        for c in range(S):
            row = base + c
            for t in range(P):
                mat[row, t] = pre[t]
            for t in range(w):
                mat[row, P + t] = buf[s + t]
            for p in range(Ls):
                mat[row, P + w + p] = suf_tab[c, p]


@njit(cache=True)
def decrypt(cipher, k0, k1, k2, out):
    """decrypt cipher[0:] into out[0:], keys advancing on plaintext bytes."""
    for i in range(cipher.shape[0]):
        k = (k2 | np.int64(2)) & np.int64(0xFFFF)
        t = (k * (k ^ np.int64(1))) & np.int64(0xFFFF)
        d = np.int64(cipher[i]) ^ ((t >> np.int64(8)) & np.int64(0xFF))
        out[i] = d
        k0 = (k0 >> np.int64(8)) ^ _T[(k0 ^ d) & np.int64(0xFF)]
        k1 = ((k1 + (k0 & np.int64(0xFF))) * np.int64(134775813)
              + np.int64(1)) & np.int64(0xFFFFFFFF)
        k2 = (k2 >> np.int64(8)) ^ _T[(k2 ^ (k1 >> np.int64(24))) & np.int64(0xFF)]


@njit(cache=True)
def decrypt_rows(k0s, k1s, k2s, cipher, out):
    """decrypt one cipher stream per row, each row starting from its own keys."""
    for r in range(k0s.shape[0]):
        k0, k1, k2 = k0s[r], k1s[r], k2s[r]
        for j in range(cipher.shape[0]):
            k = (k2 | np.int64(2)) & np.int64(0xFFFF)
            t = (k * (k ^ np.int64(1))) & np.int64(0xFFFF)
            d = np.int64(cipher[j]) ^ ((t >> np.int64(8)) & np.int64(0xFF))
            out[r, j] = d
            k0 = (k0 >> np.int64(8)) ^ _T[(k0 ^ d) & np.int64(0xFF)]
            k1 = ((k1 + (k0 & np.int64(0xFF))) * np.int64(134775813)
                  + np.int64(1)) & np.int64(0xFFFFFFFF)
            k2 = (k2 >> np.int64(8)) ^ _T[(k2 ^ (k1 >> np.int64(24))) & np.int64(0xFF)]


def confirm_zc(meta: dict, pwd: bytes):
    """ground-truth verdict: full-member decrypt + inflate + crc + size.

    returns True/False, or None when the fast path does not apply (caller
    falls back to the zipfile read in testers). matches zipfile's rule:
    a wrong password fails inflate or crc - there is no shortcut.
    """
    need = ("data_off", "csize", "crc", "usize")
    if any(meta.get(k) is None for k in need) or meta.get("method") != 8:
        return None
    path, off, n = meta["path"], meta["data_off"], meta["csize"]
    if n < 12:
        return None
    try:
        cipher = _payload(path, off, n)
        if len(cipher) != n:
            return False
        keys = pwd_keys(np.frombuffer(pwd, np.uint8))
        out = np.empty(n, np.uint8)
        decrypt(np.frombuffer(cipher, np.uint8),
                np.int64(keys[0]), np.int64(keys[1]), np.int64(keys[2]), out)
        data = zlib.decompressobj(-15).decompress(out[12:].tobytes())
        return (zlib.crc32(data) & 0xFFFFFFFF) == meta["crc"] \
            and len(data) == meta["usize"]
    except (zlib.error, OSError, ValueError):
        return False


_PAYLOAD_CACHE = {}   # (path, data_off, csize) -> encrypted bytes


def _payload(path: str, off: int, n: int) -> bytes:
    """encrypted member payload, cached - small deflate members have no
    cdata prefilter, so every 1/256 check-byte passer confirms, and a
    fresh open+seek+read per confirm dominates the batch time."""
    key = (path, off, n)
    data = _PAYLOAD_CACHE.get(key)
    if data is None:
        with open(path, "rb") as f:
            f.seek(off)
            data = f.read(n)
        if n <= 4_000_000:           # never cache huge members
            if len(_PAYLOAD_CACHE) > 8:
                _PAYLOAD_CACHE.clear()
            _PAYLOAD_CACHE[key] = data
    return data
