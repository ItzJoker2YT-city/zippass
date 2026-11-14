"""rust folded-pbkdf2 verifier: bit exactness vs hashlib and the batched
_run path's exact (tried, hit, sample) semantics vs the scalar loop."""
import hashlib

import numpy as np
import pytest

from make_tests import make_aes_zip
from zippass import candidates, cryptoparse, rustfast, testers

pytestmark = pytest.mark.skipif(not rustfast.HAS_RUST,
                                reason="rust dll not built")

SALTS = (8, 12, 16, 20, 48)     # 48 is the last single-u1-block shape
DKLENS = (34, 50, 66)
PWDS = (b"", b"m", b"mana", b"x" * 63, b"x" * 64, b"x" * 65, b"p" * 100,
        b"q" * 200, b"k" * 512)


def _bv(salt, dklen, pv):
    return rustfast.make_batch_verifier(salt, dklen, pv)


def test_verifier_matches_hashlib_per_lane():
    """same password in all simd lanes must verify everywhere the
    reference does - an 8-copy batch pins the avx2 lanes 0..7, a 4-copy
    batch pins the sse2/remainder path."""
    rng = np.random.default_rng(11)
    checked = 0
    for salt_len in SALTS:
        for dklen in DKLENS:
            salt = bytes(rng.integers(0, 256, salt_len, dtype=np.uint8))
            for p in PWDS:
                pv = hashlib.pbkdf2_hmac("sha1", p, salt, 1000, dklen)[-2:]
                got8 = _bv(salt, dklen, pv)([p] * 8)
                assert got8 == list(range(8)), (salt_len, dklen, len(p))
                got4 = _bv(salt, dklen, pv)([p] * 4)
                assert got4 == [0, 1, 2, 3], (salt_len, dklen, len(p))
                assert _bv(salt, dklen, bytes(2))([p] * 8) == []
                checked += 1
    assert checked == len(SALTS) * len(DKLENS) * len(PWDS)


def test_mixed_batch_lane_independence():
    """different passwords per lane: only the matching one passes,
    whichever lane holds it."""
    rng = np.random.default_rng(3)
    salt = bytes(rng.integers(0, 256, 16, dtype=np.uint8))
    pwds = [b"wr%06d" % i for i in range(7)] + [b"x" * 64] \
        + [b"aa%06d" % i for i in range(8)] + [b"x" * 65]
    for k, p in enumerate(pwds):
        pv = hashlib.pbkdf2_hmac("sha1", p, salt, 1000, 66)[-2:]
        assert _bv(salt, 66, pv)(pwds) == [k], k


def test_batch_edge_sizes():
    rng = np.random.default_rng(5)
    salt = bytes(rng.integers(0, 256, 12, dtype=np.uint8))
    for size in (0, 1, 2, 3, 4, 5, 7, 8, 255, 256):
        pwds = [b"z%06d" % i for i in range(size)]
        assert _bv(salt, 66, b"ab")(pwds) == [], size
    assert _bv(salt, 66, b"ab")([]) == []


def test_offspec_params_fall_back():
    """salt beyond 48 bytes needs a second u1 block - the kernel must
    refuse, not guess."""
    assert rustfast.make_batch_verifier(bytes(52), 66, b"ab") is None
    assert rustfast.make_batch_verifier(bytes(12), 1, b"ab") is None
    assert rustfast.make_batch_verifier(bytes(12), 66, b"abc") is None
    assert _bv(bytes(16), 66, b"ab") is not None


def _meta_for(path):
    return cryptoparse.pick_member(cryptoparse.parse_members(path))


def test_run_batched_matches_scalar_triples(tmp_path, monkeypatch):
    """the batched path must return the exact same (tried, hit, sample)
    triples as the per-candidate scalar loop, hit or no hit."""
    path = str(tmp_path / "aes.zip")
    make_aes_zip(path, b"zz7q")
    meta = _meta_for(path)
    stream = [b"aa%03d" % i for i in range(600)] + [b"zz7q"] \
        + [b"bb%03d" % i for i in range(50)]
    batched = testers._run(list(stream), meta)
    monkeypatch.setattr(rustfast, "make_batch_verifier",
                        lambda *a, **k: None)
    scalar = testers._run(list(stream), meta)
    assert batched[0] == 601               # stops right at the hit
    assert batched[1] == b"zz7q"
    assert batched == scalar

    miss = [b"aa%03d" % i for i in range(9)]
    b2 = testers._run(list(miss), meta)
    s2 = testers._run(list(miss), meta)
    assert b2 == (9, None, miss[-1]) == s2


def test_scan_brute_finds_through_rust_path(tmp_path):
    path = str(tmp_path / "aes.zip")
    make_aes_zip(path, b"q9z")
    meta = _meta_for(path)
    charset = tuple(bytes([c]) for c in
                    b"abcdefghijklmnopqrstuvwxyz0123456789")
    space = sum(len(charset) ** k for k in (1, 2, 3))
    r = testers.scan_brute((meta, charset, 1, 3, 0, space))
    assert r[1] == b"q9z"


def test_run_propagates_candidate_stream_errors(tmp_path):
    """bad candidates are a caller bug - the batched path must fail loud,
    not silently report an empty scan."""
    path = str(tmp_path / "aes.zip")
    make_aes_zip(path, b"zz7q")
    meta = _meta_for(path)
    with pytest.raises(ValueError):
        # brute_iter raises on an empty charset - a stream error, not an
        # ffi error, so _run_aes must not swallow it
        testers._run(candidates.brute_iter((), 1, 3, 0, 10), meta)
