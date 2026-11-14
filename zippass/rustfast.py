"""ctypes bridge to the rust folded last-block pbkdf2 verifier
(rust/aesfast_rs, built as zippass/_native/aesfast_rs.dll).

the batch contract keeps the scanner semantics exact: zpv_batch returns
the indices of every verifier-passing candidate in order, and the caller
runs the same pyzipper confirm on each pass that the per-candidate tester
would. any load/ffi failure just returns HAS_RUST False and the numba /
openssl paths carry on.
"""
import ctypes
import os

_DLL_CANDIDATES = (
    os.environ.get("ZIPPASS_AESFAST_LIB"),                # explicit override
    os.path.join(os.path.dirname(os.path.abspath(__file__)), "_native",
                 "aesfast_rs.dll"),                       # windows build
    os.path.join(os.path.dirname(os.path.abspath(__file__)), "_native",
                 "libaesfast_rs.so"),                     # linux build
)

_dll = None
for _path in _DLL_CANDIDATES:
    if not _path:
        continue
    try:
        _dll = ctypes.CDLL(_path)
        _loaded_from = _path
        break
    except OSError:
        continue
_zpv = None
if _dll is not None:
    _zpv = _dll.zpv_batch
    _zpv.restype = ctypes.c_int32
    _zpv.argtypes = [
        ctypes.c_char_p,                    # flat password bytes
        ctypes.POINTER(ctypes.c_uint32),    # per-password lengths
        ctypes.c_size_t,                    # password count
        ctypes.c_char_p,                    # salt
        ctypes.c_size_t,                    # salt length
        ctypes.c_uint32,                    # dklen
        ctypes.c_uint16,                    # pv as big-endian int
        ctypes.POINTER(ctypes.c_uint32),    # hit indices out
        ctypes.c_uint32,                    # hit capacity
    ]
    HAS_RUST = True
else:                               # pragma: no cover - dll is optional
    HAS_RUST = False

BATCH = 256                         # candidates per ffi call


def params_ok(salt: bytes, dklen: int) -> bool:
    """the shapes the rust kernel implements (mirrors aesfast) - salt
    beyond 48 bytes would need a second u1 message block."""
    return (bool(salt) and len(salt) <= 48 and len(salt) % 4 == 0
            and dklen >= 2)


def make_batch_verifier(salt: bytes, dklen: int, pv: bytes):
    """callable(pwds: list[bytes]) -> list[int] of verifier-passing
    indices, or None when the dll is missing / params are off-spec."""
    if not HAS_RUST or _zpv is None or not params_ok(salt, dklen):
        return None
    if not pv or len(pv) != 2:
        return None
    nb = (dklen + 19) // 20
    if nb > 0xFFFFFFFF or dklen - 20 * (nb - 1) < 2:
        return None
    zpv, salt_len = _zpv, len(salt)
    pv16 = int.from_bytes(pv, "big")

    def verifier(pwds: list) -> list:
        flat = b"".join(pwds)
        n = len(pwds)
        lens = (ctypes.c_uint32 * n)(*[len(p) for p in pwds])
        hits = (ctypes.c_uint32 * n)()
        rc = zpv(flat, lens, n, salt, salt_len, dklen, pv16, hits, n)
        if rc < 0:
            raise RuntimeError(f"rustfast zpv_batch rc={rc}")
        return [hits[i] for i in range(rc)]

    return verifier


def warm() -> None:
    """load the dll and run one batch - called from the pool prewarm so
    the first aes job pays no loader cost."""
    if not HAS_RUST:
        return
    bv = make_batch_verifier(bytes(16), 66, b"\x00\x00")
    if bv is not None:
        bv([b"prewarm", b"warm", b"up", b"now"])
