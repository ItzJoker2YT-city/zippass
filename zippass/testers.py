"""candidate testing - inline zipcrypto filter, jit AES verifier, and the
chunk/range scanners the worker pool runs.

zipcrypto scans run the numpy vector path (fastfilter/matbuild) when
available; AES verification runs the folded last-block pbkdf2 in jit
(aesfast) with openssl's full derivation as the fallback. the scalar
paths below are the reference implementations and the fallbacks - tests
pin jit and scalar to identical results.
"""
import functools
import hashlib
import itertools
import sys
import zipfile
import zlib

try:
    import pyzipper
except ImportError:
    pyzipper = None

from . import candidates as cand
from . import config
from . import rustfast
from .pkware import CRC_TABLE

try:
    from . import pkfast
    from . import matbuild
    from . import aesfast
except ImportError:              # numpy missing - scalar paths carry on
    pkfast = None
    matbuild = None
    aesfast = None

_TESTER_CACHE = {}   # (path, index) -> tester closure, per process
_ZIP_CACHE = {}      # (kind, path) -> (open archive, infolist) - persists in pool workers


def tester_for(meta: dict):
    """build (or fetch) a fast password tester for one archive member."""
    key = (meta["path"], meta["index"])
    t = _TESTER_CACHE.get(key)
    if t is None:
        t = _make_aes_tester(meta) if meta["kind"] == "aes" else _make_zc_tester(meta)
        _TESTER_CACHE[key] = t
    return t


def _make_zc_tester(meta: dict):
    raw12 = bytes.fromhex(meta["raw12"])
    check, path, idx = meta["check"], meta["path"], meta["index"]
    cdata = meta.get("cdata")       # encrypted head of a big deflate member
    cdata = bytes.fromhex(cdata) if cdata else None

    def tester(pwd: bytes) -> bool:
        d, k0, k1, k2 = _zc_schedule(pwd, raw12)
        if d != check:
            return False            # 1-byte check filter (1/256)
        if cdata is not None and not _deflate_decodable(k0, k1, k2, cdata):
            return False            # data decodes to deflate garbage
        return _confirm_zipcrypto(path, idx, pwd)  # CRC-verified truth
    return tester


def _make_aes_tester(meta: dict):
    salt = bytes.fromhex(meta["salt"])
    pv = bytes.fromhex(meta["pv"])
    dklen, path, idx = meta["dklen"], meta["path"], meta["index"]

    verifier = (aesfast.make_verifier(salt, dklen, pv)
                if aesfast is not None else None)
    if verifier is not None:
        def tester(pwd: bytes) -> bool:
            # jit folded last-block pbkdf2 - 2002 sha1 compressions per
            # candidate instead of openssl's full-dkLen count (AES-256:
            # 0.47 ms vs 3.1 ms measured). ~1/65536 pass to the confirm.
            if not verifier(pwd):
                return False
            return _confirm_aes(path, idx, pwd)
        return tester

    def tester(pwd: bytes) -> bool:
        # openssl full derivation - the fallback when numba is missing.
        # computing only the last block via a python hmac chain measured
        # SLOWER than this (hashlib per-op overhead eats the 8x block
        # saving), so there is no python middle path.
        d = hashlib.pbkdf2_hmac("sha1", pwd, salt, 1000, dklen)
        if d[-2:] != pv:
            return False            # ~1/65536 pass on to the full confirm
        return _confirm_aes(path, idx, pwd)
    return tester


def prewarm_aes() -> None:
    """compile the jit aes verifier and load the rust batch dll once per
    worker process - the pool prewarm barrier calls this so the first
    aes job starts at full speed."""
    if aesfast is not None and aesfast.HAS_NUMBA:
        ver = aesfast.make_verifier(bytes(16), 66, b"\x00\x00")
        if ver is not None:
            ver(b"prewarm")
    rustfast.warm()


def _zc_schedule(pwd: bytes, raw12: bytes) -> tuple:
    """pkware key schedule over pwd + the 12-byte header; returns
    (last_plain_byte, k0, k1, k2): the byte is the check-byte filter and
    the keys are positioned to continue decrypting the compressed data."""
    T = CRC_TABLE
    k0, k1, k2 = 0x12345678, 0x23456789, 0x34567890
    for c in pwd:
        k0 = (k0 >> 8) ^ T[(k0 ^ c) & 0xFF]
        k1 = ((k1 + (k0 & 0xFF)) * 134775813 + 1) & 0xFFFFFFFF
        k2 = (k2 >> 8) ^ T[(k2 ^ (k1 >> 24)) & 0xFF]
    d = -1
    for c in raw12:
        k = k2 | 2
        d = c ^ (((k * (k ^ 1)) >> 8) & 0xFF)
        k0 = (k0 >> 8) ^ T[(k0 ^ d) & 0xFF]
        k1 = ((k1 + (k0 & 0xFF)) * 134775813 + 1) & 0xFFFFFFFF
        k2 = (k2 >> 8) ^ T[(k2 ^ (k1 >> 24)) & 0xFF]
    return d, k0, k1, k2


def _deflate_decodable(k0: int, k1: int, k2: int, cdata: bytes) -> bool:
    """decrypt cdata continuing the pkware keystream and require the raw
    deflate stream to stay decodable. real data always decodes; a wrong
    password almost always dies inside the first block - so this is a
    cheap writer-independent filter ahead of the full CRC-verified read
    (which can take seconds on a multi-MB member)."""
    T = CRC_TABLE
    out = bytearray()
    for c in cdata:
        k = k2 | 2
        d = c ^ (((k * (k ^ 1)) >> 8) & 0xFF)
        k0 = (k0 >> 8) ^ T[(k0 ^ d) & 0xFF]
        k1 = ((k1 + (k0 & 0xFF)) * 134775813 + 1) & 0xFFFFFFFF
        k2 = (k2 >> 8) ^ T[(k2 ^ (k1 >> 24)) & 0xFF]
        out.append(d)
    try:
        zlib.decompressobj(-15).decompress(bytes(out))
    except zlib.error:
        return False
    return True


def _open_zip(kind: str, path: str):
    entry = _ZIP_CACHE.get((kind, path))
    if entry is None:
        z = zipfile.ZipFile(path) if kind == "zc" else pyzipper.AESZipFile(path)
        entry = (z, z.infolist())
        _ZIP_CACHE[(kind, path)] = entry
    return entry


def _evict(kind: str, path: str) -> None:
    _ZIP_CACHE.pop((kind, path), None)


def _confirm_zipcrypto(path: str, idx: int, pwd: bytes) -> bool:
    """definitive check-byte/crc verdict for one filter-passing candidate.

    a wrong password fails the read deterministically (bad check byte ->
    RuntimeError, colliding check byte -> BadZipFile/zlib.error), but a
    transient failure (io hiccup, memory pressure) raises the same way -
    and this confirm runs on the true candidate too, so a transient may
    never read as "wrong password". non-crypto errors get one retry on a
    freshly opened archive before the False verdict.
    """
    try:
        zf, infos = _open_zip("zc", path)
        zf.read(infos[idx], pwd=pwd)  # full stream + crc check
        return True
    except (RuntimeError, zipfile.BadZipFile, zlib.error):
        _evict("zc", path)  # wrong pwd or vanished file - reopen next time
        return False
    except Exception:
        _evict("zc", path)
        try:
            zf, infos = _open_zip("zc", path)
            zf.read(infos[idx], pwd=pwd)
            return True
        except Exception:
            return False


def _confirm_aes(path: str, idx: int, pwd: bytes) -> bool:
    """definitive hmac verdict for one pv-passing candidate - same rule
    as _confirm_zipcrypto: crypto failures (pyzipper's bad-password
    RuntimeError, its BadZipFile bad-HMAC/bad-CRC, zlib) are definitive,
    everything else retries once so a transient load error cannot
    silently drop the true password."""
    if pyzipper is None:
        return False
    try:
        zf, infos = _open_zip("aes", path)
        zf.read(infos[idx], pwd=pwd)  # full stream, HMAC verified
        return True
    except (RuntimeError, zipfile.BadZipFile, zlib.error):
        _evict("aes", path)  # wrong pwd or vanished file - reopen next time
        return False
    except Exception:
        _evict("aes", path)
        try:
            zf, infos = _open_zip("aes", path)
            zf.read(infos[idx], pwd=pwd)
            return True
        except Exception:
            return False


def _confirm_fast(meta: dict, pwd: bytes) -> bool:
    """truth verdict for the vector path: jit full-member decrypt+inflate+crc
    when the meta carries the fields it needs, else the zipfile read."""
    if pkfast is not None:
        r = pkfast.confirm_zc(meta, pwd)
        if r is not None:
            return r
    return _confirm_zipcrypto(meta["path"], meta["index"], pwd)


def _vector_ok(meta: dict) -> bool:
    return (matbuild is not None and config.VECTOR
            and meta["kind"] == "zipcrypto")


def _bound_confirm(meta: dict):
    """the adapters take confirm(pwd); bind the member meta here at the
    dispatch boundary - one shape everywhere, tests pin the contract."""
    return functools.partial(_confirm_fast, meta)


def _fallback(where: str, e: Exception) -> None:
    print(f"zippass: vector {where} scan failed ({e!r}) - scalar fallback",
          file=sys.stderr)


# ---------------------------------------------------------------- scanners

def _run_aes(words, meta: dict):
    """batched rust verifier path for aes members - same verdicts and
    (tried, hit, sample) semantics as the per-candidate loop: candidates
    before the confirmed hit count as tried, the hit counts, candidates
    after it do not (the batch verifier checked them, but the scalar loop
    would have broken out before them). candidate-stream errors propagate
    (fail loud); verifier ffi failures degrade this stream to the scalar
    tester from the batch boundary on."""
    try:
        bv = rustfast.make_batch_verifier(bytes.fromhex(meta["salt"]),
                                          meta["dklen"],
                                          bytes.fromhex(meta["pv"]))
    except Exception:
        bv = None
    if bv is None:
        return None
    confirm = functools.partial(_confirm_aes, meta["path"], meta["index"])
    tester = None

    def flush(batch):
        """first confirmed verifier pass in the batch, or -1"""
        for i in bv(batch):
            if confirm(batch[i]):
                return i
        return -1

    def flush_scalar(batch):
        for i, pwd in enumerate(batch):
            if tester(pwd):
                return i
        return -1

    def take(batch):
        """flush one batch; once the ffi path fails, degrade this whole
        stream to the scalar tester (re-testing the batch keeps the
        tried-count exact)."""
        nonlocal tester
        if tester is not None:
            return flush_scalar(batch)
        try:
            return flush(batch)
        except Exception:
            tester = tester_for(meta)
            return flush_scalar(batch)

    tried, sample = 0, b""
    batch = []
    for pwd in words:
        batch.append(pwd)
        if len(batch) < rustfast.BATCH:
            continue
        h = take(batch)
        if h >= 0:
            return tried + h + 1, batch[h], batch[h]
        tried += len(batch)
        sample = batch[-1]
        batch = []
    if batch:
        h = take(batch)
        if h >= 0:
            return tried + h + 1, batch[h], batch[h]
        tried += len(batch)
        sample = batch[-1]
    return tried, None, sample


def _run(words, meta: dict):
    """test a candidate stream; returns (tried, hit, last_candidate)."""
    tried, hit, sample = 0, None, b""
    if meta["kind"] == "zipcrypto":
        raw = tuple(bytes.fromhex(meta["raw12"]))
        check, path, idx = meta["check"], meta["path"], meta["index"]
        cdata = meta.get("cdata")       # encrypted head of a big deflate
        cdata = bytes.fromhex(cdata) if cdata else None
        T = CRC_TABLE
        for pwd in words:
            tried += 1
            sample = pwd
            # pkware key schedule, fully inlined - a function call per
            # candidate measured ~15% on the hot path
            k0, k1, k2 = 0x12345678, 0x23456789, 0x34567890
            for c in pwd:
                k0 = (k0 >> 8) ^ T[(k0 ^ c) & 0xFF]
                k1 = ((k1 + (k0 & 0xFF)) * 134775813 + 1) & 0xFFFFFFFF
                k2 = (k2 >> 8) ^ T[(k2 ^ (k1 >> 24)) & 0xFF]
            d = -1
            for c in raw:
                k = k2 | 2
                d = c ^ (((k * (k ^ 1)) >> 8) & 0xFF)
                k0 = (k0 >> 8) ^ T[(k0 ^ d) & 0xFF]
                k1 = ((k1 + (k0 & 0xFF)) * 134775813 + 1) & 0xFFFFFFFF
                k2 = (k2 >> 8) ^ T[(k2 ^ (k1 >> 24)) & 0xFF]
            # the 1-byte check plus the deflate prefilter keep wrong
            # passwords from _confirm_zipcrypto - a full read of the
            # member, seconds for a multi-MB file
            if (d == check
                    and (cdata is None
                         or _deflate_decodable(k0, k1, k2, cdata))
                    and _confirm_zipcrypto(path, idx, pwd)):
                hit = pwd
                break
    else:
        if meta["kind"] == "aes":
            r = _run_aes(words, meta)
            if r is not None:
                return r
        tester = tester_for(meta)
        for pwd in words:
            tried += 1
            sample = pwd
            if tester(pwd):
                hit = pwd
                break
    return tried, hit, sample


def _chunk_words(path: str, a: int, b: int):
    """whole-line candidates from one seekable byte range. files written in
    text mode carry \\r\\n - strip the \\r exactly like the old line reader."""
    with open(path, "rb") as f:
        f.seek(a)
        data = f.read(b - a)
    for line in data.split(b"\n"):
        line = line.rstrip(b"\r")
        if line and len(line) <= config.MAX_WORD_LEN:
            yield line


def scan_dict(task):
    """(meta, path, start, end) -> test every usable line in that range."""
    meta, path, a, b = task
    if _vector_ok(meta):
        try:
            with open(path, "rb") as f:
                f.seek(a)
                data = f.read(b - a)
            return matbuild.scan_dict_chunk(meta, data, _bound_confirm(meta))
        except Exception as e:   # noqa: BLE001 - a scan never dies to the fast path
            _fallback("dict", e)
    return _run(_chunk_words(path, a, b), meta)


def scan_hybrid(task):
    """(meta, path, start, end, prefix, suffix_sets) -> words x mask suffixes."""
    meta, path, a, b, prefix, suffix_sets = task
    if _vector_ok(meta):
        try:
            with open(path, "rb") as f:
                f.seek(a)
                data = f.read(b - a)
            r = matbuild.scan_hybrid_chunk(meta, data, prefix, suffix_sets,
                                           _bound_confirm(meta))
            if r is not None:
                return r
        except Exception as e:   # noqa: BLE001
            _fallback("hybrid", e)

    def words():
        for line in _chunk_words(path, a, b):
            if suffix_sets:
                for combo in itertools.product(*suffix_sets):
                    yield prefix + line + b"".join(combo)
            else:
                yield prefix + line
    return _run(words(), meta)


def scan_brute(task):
    """(meta, charset, min_len, max_len, start, count) -> index-range brute."""
    meta, charset, min_len, max_len, start, count = task
    if _vector_ok(meta):
        try:
            r = matbuild.scan_brute_task(meta, charset, min_len, max_len,
                                         start, count, _bound_confirm(meta))
            if r is not None:
                return r
        except Exception as e:   # noqa: BLE001
            _fallback("brute", e)
    return _run(cand.brute_iter(charset, min_len, max_len, start, count), meta)


def scan_mask(task):
    """(meta, sets, start, count) -> index-range mask."""
    meta, sets, start, count = task
    if _vector_ok(meta):
        try:
            r = matbuild.scan_mask_task(meta, sets, start, count, _bound_confirm(meta))
            if r is not None:
                return r
        except Exception as e:   # noqa: BLE001
            _fallback("mask", e)
    return _run(cand.mask_iter(sets, start, count), meta)
