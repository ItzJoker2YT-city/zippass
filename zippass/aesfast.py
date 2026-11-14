"""numba-jit winzip AES verifier - folded pbkdf2, last block only.

the AE spec's verifier is the last 2 bytes of PBKDF2-HMAC-SHA1(pw, salt,
1000, dkLen). openssl's full derivation hashes every output block (AES-256:
dkLen 66 -> 4 blocks x 1000 iterations x 4 sha1 compressions = 16000
blocks); only the LAST block's tail is ever compared, and each block
T_i = U_1 ^ ... ^ U_1000 is independent - so compute just T_last:

  U_1     = HMAC(pw, salt || INT_be(last_index))
  U_k     = HMAC(pw, U_(k-1))                  (k = 2..1000)
  T_last  = U_1 ^ ... ^ U_1000, verifier = bytes [r-2, r-1]

the hmac loop is state-folded: the ipad/opad sha1 states depend only on
the password, and every post-key message is exactly 20 bytes, so each
iteration is two compressions over a fixed 16-word template with the
message words swapped in place - no byte packing anywhere (a sha1 digest
IS its state words big-endian). 2002 compressions per candidate instead
of openssl's full-dkLen count, each at jit speed instead of through the
EVP pbkdf2 layer. measured on the reference box (AES-256, dkLen 66):
~0.4 ms vs 3.1 ms per candidate.

arithmetic is uint32 with explicit rotation masks; numba wraps fixed-width
ints, matching the spec's mod-2**32. bit-exactness is pinned by
tests/test_aes.py against hashlib.pbkdf2_hmac across every strength, salt
and password shape (including keys > 64 bytes, which hash down first).
when numba is missing make_verifier returns None and testers falls back
to the openssl derivation.
"""
import struct

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

_U32 = np.uint32
_INIT = (0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0)


@njit(cache=True)
def _compress(w, a, b, c, d, e):
    """one sha1 compression: block words w[0:16] -> updated state.

    w is a uint32[80] scratch; the caller fills w[0:16] with the block's
    big-endian message words, the schedule expands in place. arithmetic
    runs in int64 masked back to 32 bits - numba promotes uint32+uint32
    to a wider type without wrapping, so every place the spec relies on
    mod-2**32 gets an explicit mask (schedule rotate, round sum, the bb
    rotate, the state additions).
    """
    for i in range(16, 80):
        x = w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16]
        w[i] = ((x << _U32(1)) | (x >> _U32(31))) & _U32(0xFFFFFFFF)
    aa, bb, cc, dd, ee = a, b, c, d, e
    for i in range(80):
        if i < 20:
            f = (bb & cc) | ((~bb) & dd)
            k = _U32(0x5A827999)
        elif i < 40:
            f = bb ^ cc ^ dd
            k = _U32(0x6ED9EBA1)
        elif i < 60:
            f = (bb & cc) | (bb & dd) | (cc & dd)
            k = _U32(0x8F1BBCDC)
        else:
            f = bb ^ cc ^ dd
            k = _U32(0xCA62C1D6)
        t = (((aa << _U32(5)) | (aa >> _U32(27))) + f + ee + k
             + w[i]) & _U32(0xFFFFFFFF)
        ee = dd
        dd = cc
        cc = ((bb << _U32(30)) | (bb >> _U32(2))) & _U32(0xFFFFFFFF)
        bb = aa
        aa = t
    return ((a + aa) & _U32(0xFFFFFFFF), (b + bb) & _U32(0xFFFFFFFF),
            (c + cc) & _U32(0xFFFFFFFF), (d + dd) & _U32(0xFFFFFFFF),
            (e + ee) & _U32(0xFFFFFFFF))


@njit(cache=True)
def _load_be(buf, pos, n):
    """big-endian word from buf[pos:pos+4]; bytes past n are zeros."""
    v = _U32(0)
    for t in range(4):
        p = pos + t
        v = (v << _U32(8)) | _U32(buf[p] if p < n else 0)
    return v


@njit(cache=True)
def _pick_word(j, w0, w1, w2, w3, w4):
    if j == 0:
        return w0
    if j == 1:
        return w1
    if j == 2:
        return w2
    if j == 3:
        return w3
    return w4


@njit(cache=True)
def _sha1_words(buf, n, w):
    """sha1(buf[:n]) as its 5 state words (the digest, unpacked)."""
    a, b, c, d, e = (_U32(_INIT[0]), _U32(_INIT[1]), _U32(_INIT[2]),
                     _U32(_INIT[3]), _U32(_INIT[4]))
    nblk = (n + 9 + 63) // 64
    for bi in range(nblk):
        off = bi * 64
        for j in range(16):
            w[j] = _load_be(buf, off + 4 * j, n)
        if bi == nblk - 1:            # 8-byte length field in the final block
            w[14] = _U32(0)
            w[15] = _U32(n * 8)
        if off <= n < off + 64:       # 0x80 pad byte lives where message
            pos = n - off             # byte n would be - that block may be
            w[pos >> 2] ^= _U32(0x80 << (8 * (3 - (pos & 3))))  # nblk-2
        a, b, c, d, e = _compress(w, a, b, c, d, e)
    return a, b, c, d, e


@njit(cache=True)
def verify_pv(pwd, salt_words, salt_len, nb, r, pv32, w):
    """last-block pbkdf2 verifier: True when bytes [r-2, r-1] of T_nb
    equal pv32.

    pwd is a uint8 array (any length; hmac keys > 64 bytes hash down
    first), salt_words the salt as pre-converted big-endian uint32 words,
    nb/r the last pbkdf2 block index and its used byte count, w the
    uint32[80] scratch.
    """
    n = pwd.shape[0]
    if n > 64:
        k0, k1, k2, k3, k4 = _sha1_words(pwd, n, w)
    else:
        k0 = k1 = k2 = k3 = k4 = _U32(0)
    # ipad / opad states over the zero-padded key block
    for j in range(16):
        if n <= 64:
            w[j] = _load_be(pwd, 4 * j, n)
        elif j < 5:
            w[j] = _pick_word(j, k0, k1, k2, k3, k4)
        else:
            w[j] = _U32(0)            # key is 5 words - pad the block out
        w[j] ^= _U32(0x36363636)
    ia, ib, ic, id_, ie = _compress(w, _U32(_INIT[0]), _U32(_INIT[1]),
                                    _U32(_INIT[2]), _U32(_INIT[3]),
                                    _U32(_INIT[4]))
    for j in range(16):
        w[j] ^= _U32(0x36363636) ^ _U32(0x5C5C5C5C)
    oa, ob, oc, od, oe = _compress(w, _U32(_INIT[0]), _U32(_INIT[1]),
                                   _U32(_INIT[2]), _U32(_INIT[3]),
                                   _U32(_INIT[4]))

    # U1 = HMAC(pw, salt || INT_be(nb)) - inner over the ipad state
    m = salt_len + 4                  # salt bytes + the 4-byte block index
    for j in range(16):
        v = _U32(0)
        for t in range(4):
            idx = 4 * j + t
            if idx < salt_len:        # salt bytes, big-endian words
                v = (v << _U32(8)) | ((salt_words[idx >> 2] >>
                                       _U32(8 * (3 - (idx & 3)))) &
                                      _U32(0xFF))
            elif idx < m:             # INT_be(nb)
                v = (v << _U32(8)) | _U32((nb >> (8 * (3 - (idx - salt_len))))
                                          & 0xFF)
            elif idx == m:            # pad byte
                v = (v << _U32(8)) | _U32(0x80)
            else:
                v = v << _U32(8)
        w[j] = v
    w[14] = _U32(0)
    w[15] = _U32((64 + m) * 8)
    a, b, c, d, e = _compress(w, ia, ib, ic, id_, ie)

    # all later messages are exactly 20 bytes: one shared template
    w[0], w[1], w[2], w[3], w[4] = a, b, c, d, e
    w[5] = _U32(0x80000000)
    for j in range(6, 14):
        w[j] = _U32(0)
    w[14] = _U32(0)
    w[15] = _U32(672)                 # (64 + 20) * 8
    a, b, c, d, e = _compress(w, oa, ob, oc, od, oe)

    u0, u1_, u2, u3, u4 = a, b, c, d, e
    acc0, acc1, acc2, acc3, acc4 = u0, u1_, u2, u3, u4
    for _ in range(999):
        w[0], w[1], w[2], w[3], w[4] = u0, u1_, u2, u3, u4
        a, b, c, d, e = _compress(w, ia, ib, ic, id_, ie)
        w[0], w[1], w[2], w[3], w[4] = a, b, c, d, e
        u0, u1_, u2, u3, u4 = _compress(w, oa, ob, oc, od, oe)
        acc0 ^= u0
        acc1 ^= u1_
        acc2 ^= u2
        acc3 ^= u3
        acc4 ^= u4

    # verifier = bytes [r-2, r-1] of T_nb = the accumulated state
    bi = r - 2
    wj = bi >> 2
    off = bi & 3
    hw = _pick_word(wj, acc0, acc1, acc2, acc3, acc4)
    hi = (hw >> _U32(8 * (3 - off))) & _U32(0xFF)
    if off == 3:
        lo = (_pick_word(wj + 1, acc0, acc1, acc2, acc3, acc4) >>
              _U32(24)) & _U32(0xFF)
    else:
        lo = (hw >> _U32(8 * (2 - off))) & _U32(0xFF)
    return ((hi << _U32(8)) | lo) == pv32


def make_verifier(salt: bytes, dklen: int, pv: bytes):
    """bind one member's constants; callable(pwd: bytes) -> bool, or None
    when the jit layer is missing (openssl fallback in testers) or the
    parameters fall outside the spec's shapes."""
    if not HAS_NUMBA or not pv or len(pv) != 2 or dklen < 2:
        return None
    if len(salt) == 0 or len(salt) % 4 or len(salt) > 48:
        # salt + 4 index bytes must fit one sha1 block with padding
        # (message <= 55 bytes); beyond that the u1 template would need
        # a second block, which this kernel does not implement. real
        # AE archives carry salt 8/12/16 - larger salts fall back to
        # openssl rather than risk a wrong verdict.
        return None
    nb = (dklen + 19) // 20
    r = dklen - 20 * (nb - 1)         # bytes of T_nb the data actually uses
    if nb > 0xFFFFFFFF or r < 2:
        return None
    salt_words = np.array(struct.unpack(">" + "I" * (len(salt) // 4), salt),
                          np.uint32)
    w = np.zeros(80, np.uint32)       # one scratch, shared across calls
    pv32 = np.uint32(int.from_bytes(pv, "big"))
    slen, iterations = len(salt), nb

    def verifier(pwd: bytes) -> bool:
        return verify_pv(np.frombuffer(pwd, np.uint8), salt_words, slen,
                         iterations, r, pv32, w)

    return verifier
