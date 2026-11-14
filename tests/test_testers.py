"""password testers on real archives (in-process, no pool)."""
from make_tests import make_dd_zip, make_zipcrypto
from zippass import candidates, cryptoparse, testers


def _tester_for(path):
    members = cryptoparse.parse_members(path)
    return testers.tester_for(cryptoparse.pick_member(members))


def _pick_meta(path):
    members = cryptoparse.parse_members(path)
    return cryptoparse.pick_member(members)


def test_zipcrypto_tester(tmp_path):
    from make_tests import make_zipcrypto
    path = str(tmp_path / "zc.zip")
    make_zipcrypto(path, b"pkware42", "some payload")
    tester = _tester_for(path)
    assert tester(b"pkware42") is True
    assert tester(b"pkware43") is False
    assert tester(b"") is False


def test_data_descriptor_tester(tmp_path):
    from make_tests import make_dd_zip
    path = str(tmp_path / "dd.zip")
    make_dd_zip(path, b"descript", "descriptor flag archive")
    tester = _tester_for(path)
    assert tester(b"descript") is True
    assert tester(b"descript2") is False


def test_zc_deflate_prefilter_meta(tmp_path):
    """big deflate members carry an encrypted data head for the prefilter;
    small and store members do not (the full confirm is cheap there)."""
    import random
    import string
    from make_tests import make_zipcrypto
    path = str(tmp_path / "big.zip")
    body = "".join(random.Random(7).choices(
        string.ascii_letters + string.digits, k=4096))  # ~incompressible
    make_zipcrypto(path, b"pkware42", body)
    meta = _pick_meta(path)
    assert len(bytes.fromhex(meta["cdata"])) == 512

    path = str(tmp_path / "small.zip")
    make_zipcrypto(path, b"pkware42", "small payload")
    assert "cdata" not in _pick_meta(path)


def test_zc_deflate_prefilter(tmp_path):
    """real data always decodes; wrong passwords that survive the 1-byte
    check-byte filter are rejected by the deflate prefilter - the guard
    that keeps a multi-MB member's full read off the hot path."""
    import random
    import string
    from make_tests import make_zipcrypto
    path = str(tmp_path / "big.zip")
    body = "".join(random.Random(7).choices(
        string.ascii_letters + string.digits, k=4096))
    make_zipcrypto(path, b"pkware42", body)
    meta = _pick_meta(path)
    raw12 = bytes.fromhex(meta["raw12"])
    cdata = bytes.fromhex(meta["cdata"])

    d, k0, k1, k2 = testers._zc_schedule(b"pkware42", raw12)
    assert d == meta["check"]
    assert testers._deflate_decodable(k0, k1, k2, cdata) is True

    rng = random.Random(42)
    checked, rejected = 0, 0
    while checked < 256:                # 1-byte check-byte survivors
        pwd = "".join(rng.choices(string.ascii_lowercase, k=6)).encode()
        d, k0, k1, k2 = testers._zc_schedule(pwd, raw12)
        if d != meta["check"]:
            continue
        checked += 1
        if not testers._deflate_decodable(k0, k1, k2, cdata):
            rejected += 1
    assert rejected >= 224              # <12.5% of survivors may pass on


def test_aes_tester(tmp_path):
    from make_tests import make_aes_zip
    path = str(tmp_path / "aes.zip")
    make_aes_zip(path, b"aeS-9zz")
    tester = _tester_for(path)
    assert tester(b"aeS-9zz") is True
    assert tester(b"aeS-9za") is False


def test_aes_tester_long_password(tmp_path):
    """hmac keys > 64 bytes hash down first - exercises the jit sha1 path."""
    from make_tests import make_aes_zip
    path = str(tmp_path / "aes.zip")
    make_aes_zip(path, b"k" * 100)
    tester = _tester_for(path)
    assert tester(b"k" * 100) is True
    assert tester(b"k" * 99) is False


def test_aes_confirm_retries_transient(tmp_path, monkeypatch):
    """a transient io/memory failure during the confirm must not read as
    'wrong password' - the retry reopens the archive and still confirms."""
    from make_tests import make_aes_zip
    path = str(tmp_path / "aes.zip")
    make_aes_zip(path, b"aeS-9zz")
    real_open = testers._open_zip
    calls = {"n": 0}

    def flaky(kind, p):
        calls["n"] += 1
        if calls["n"] == 1:
            raise MemoryError("transient under load")
        return real_open(kind, p)

    monkeypatch.setattr(testers, "_open_zip", flaky)
    testers._TESTER_CACHE.clear()
    tester = _tester_for(path)
    assert tester(b"aeS-9zz") is True
    assert calls["n"] == 2
    testers._TESTER_CACHE.clear()


def test_zipcrypto_confirm_retries_transient(tmp_path, monkeypatch):
    from make_tests import make_zipcrypto
    path = str(tmp_path / "zc.zip")
    make_zipcrypto(path, b"pkware42", "some payload")
    real_open = testers._open_zip
    calls = {"n": 0}

    def flaky(kind, p):
        calls["n"] += 1
        if calls["n"] == 1:
            raise OSError("transient read failure")
        return real_open(kind, p)

    monkeypatch.setattr(testers, "_open_zip", flaky)
    testers._TESTER_CACHE.clear()
    tester = _tester_for(path)
    assert tester(b"pkware42") is True
    assert calls["n"] == 2
    testers._TESTER_CACHE.clear()


def test_aes_tester_openssl_fallback(tmp_path, monkeypatch):
    """without the jit layer the tester must still be exact (openssl full
    derivation) - same verdicts, different implementation."""
    from make_tests import make_aes_zip
    path = str(tmp_path / "aes.zip")
    make_aes_zip(path, b"aeS-9zz")
    monkeypatch.setattr(testers, "aesfast", None)
    testers._TESTER_CACHE.clear()
    tester = _tester_for(path)
    assert tester(b"aeS-9zz") is True
    assert tester(b"aeS-9za") is False
    testers._TESTER_CACHE.clear()


def test_aes_verifier_matches_openssl():
    """the jit folded last-block chain must agree with openssl's full
    derivation on the verifier bytes for every spec shape."""
    import hashlib
    import numpy as np
    from zippass import aesfast

    rng = np.random.default_rng(7)
    pwds = [bytes(rng.integers(1, 256, L, dtype=np.uint8)) for L in
            (0, 1, 16, 63, 64, 65, 200)] + [b"mana", b"aeS-9zz"]
    checked = 0
    for salt_len in (8, 12, 16):
        for dklen in (34, 50, 66):
            salt = bytes(rng.integers(0, 256, salt_len, dtype=np.uint8))
            for p in pwds:
                ref = hashlib.pbkdf2_hmac("sha1", p, salt, 1000, dklen)[-2:]
                ver = aesfast.make_verifier(salt, dklen, ref)
                assert ver is not None
                assert ver(p) is True
                assert ver(p + b"x") is False   # neighbouring pwds differ
                checked += 1
    assert checked == 9 * len(pwds)


def test_scan_dict_finds_and_counts(tmp_path):
    path = str(tmp_path / "zc.zip")
    make_zipcrypto(path, b"ok2", "dict scan payload")
    wl = tmp_path / "w.txt"
    wl.write_bytes(b"nope1\n\n" + b"x" * 600 + b"\nok1\nok2\nno-newline")
    meta = _pick_meta(path)
    tried, hit, _ = testers.scan_dict((meta, str(wl), 0, wl.stat().st_size))
    assert hit == b"ok2"
    assert tried == 3          # nope1, ok1, ok2 - stop right at the hit


def test_scan_dict_crlf_wordlist(tmp_path):
    """text-mode-written wordlists (windows) carry \\r\\n - the candidates
    must be stripped or the real password never matches."""
    path = str(tmp_path / "zc.zip")
    make_zipcrypto(path, b"pkware42", "crlf regression payload")
    wl = tmp_path / "w.txt"
    wl.write_bytes(b"aaa\r\nbbb\r\npkware42\r\nccc\r\n")
    meta = _pick_meta(path)
    tried, hit, sample = testers.scan_dict((meta, str(wl), 0, wl.stat().st_size))
    assert hit == b"pkware42" and tried == 3 and sample == b"pkware42"


def test_scan_dict_chunk_union(tmp_path):
    """scanning every line_chunk must find the password exactly like one pass."""
    path = str(tmp_path / "zc.zip")
    make_zipcrypto(path, b"zz-target-zz", "chunk union payload")
    wl = tmp_path / "w.txt"
    wl.write_bytes(b"a\n" * 50 + b"zz-target-zz\n" + b"b\n" * 50)
    meta = _pick_meta(path)
    hits = []
    for a, b in candidates.line_chunks(str(wl), 32):
        _, hit, _ = testers.scan_dict((meta, str(wl), a, b))
        if hit:
            hits.append(hit)
    assert hits == [b"zz-target-zz"]


def test_scan_brute_hit_and_miss(tmp_path):
    path = str(tmp_path / "zc.zip")
    make_zipcrypto(path, b"0101", "brute scan payload")
    meta = _pick_meta(path)
    tried, hit, sample = testers.scan_brute((meta, _cb("01"), 4, 4, 0, 16))
    assert hit == b"0101"
    assert tried == 6          # product order: 0000,0001,0010,0011,0100,0101
    assert sample == b"0101"
    # starting past the hit finds nothing and tests exactly the remainder
    tried2, hit2, _ = testers.scan_brute((meta, _cb("01"), 4, 4, 6, 10))
    assert hit2 is None and tried2 == 10


def test_scan_mask_hit(tmp_path):
    path = str(tmp_path / "zc.zip")
    make_zipcrypto(path, b"a3", "mask scan payload")
    meta = _pick_meta(path)
    sets = (_cb("a"), _cb("0123456789"))
    tried, hit, _ = testers.scan_mask((meta, sets, 0, 10))
    assert hit == b"a3" and tried == 4   # a0,a1,a2,a3


def test_scan_hybrid_prefix_suffix(tmp_path):
    path = str(tmp_path / "zc.zip")
    make_zipcrypto(path, b"xone5", "hybrid scan payload")
    wl = tmp_path / "w.txt"
    wl.write_bytes(b"one\n\ntwo\n")
    meta = _pick_meta(path)
    task = (meta, str(wl), 0, wl.stat().st_size, b"x", (_cb("0123456789"),))
    tried, hit, _ = testers.scan_hybrid(task)
    assert hit == b"xone5" and tried == 6  # blank line skipped: one0..one5


def _cb(s):
    return tuple(c.encode() for c in s)
