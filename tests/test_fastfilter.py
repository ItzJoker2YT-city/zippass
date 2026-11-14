"""fast path (numpy vector filter + jit decrypt) vs the scalar reference.

the vector path must be bit-exact and order-exact with testers' scalar
scans - a filter that ever drops the true password is a catastrophic
failure mode, so these tests pin: the key schedule math, the candidate
matrix order, the wordlist parsing rules, full scan triples across all
four modes on real archives (big member with prefilter data, small
member, data-descriptor flag), the confirm-truth verdicts, and the
fallbacks for spaces the vector path deliberately does not touch.
"""
import random
import string

import numpy as np
import pytest

from make_tests import make_dd_zip, make_zipcrypto
from zippass import candidates as cand
from zippass import config, cryptoparse, fastfilter, matbuild, pkfast, testers


def _pick_meta(path):
    return cryptoparse.pick_member(cryptoparse.parse_members(path))


def _big_body(seed=3, k=4096):
    return "".join(random.Random(seed).choices(
        string.ascii_letters + string.digits, k=k))     # ~incompressible


def _both(monkeypatch, task, scan):
    """run one task through the vector path and the scalar path; the
    (tried, hit, sample) triples must be identical. returns the scalar."""
    monkeypatch.setattr(config, "VECTOR", False)
    scalar = scan(task)
    monkeypatch.setattr(config, "VECTOR", True)
    assert scan(task) == scalar
    return scalar


# ------------------------------------------------------------- kernel level

def test_schedule_matches_scalar(tmp_path):
    """vector finals + check-byte passers == _zc_schedule on every row,
    including empty rows and rows shorter than the block width."""
    path = str(tmp_path / "zc.zip")
    make_zipcrypto(path, b"pkware42", "schedule payload")
    meta = _pick_meta(path)
    raw12 = bytes.fromhex(meta["raw12"])
    rng = random.Random(11)
    lens = np.array([rng.randint(0, 40) for _ in range(300)], np.int64)
    mat = np.array([[rng.randint(0, 255) for _ in range(40)]
                    for _ in range(300)], np.uint8)
    passers, k0, k1, k2 = fastfilter.zc_pass1(mat, lens, raw12, meta["check"])
    pset = set(int(p) for p in passers)
    for i in range(300):
        pwd = bytes(mat[i, :lens[i]])
        d, e0, e1, e2 = testers._zc_schedule(pwd, raw12)
        assert (d == meta["check"]) == (i in pset), i
        assert (e0, e1, e2) == (int(k0[i]), int(k1[i]), int(k2[i])), i


def test_brute_matrix_order():
    """odometer blocks reproduce brute_iter's exact product order,
    across a whole multi-length space."""
    charset = tuple(c.encode() for c in "ab3!")
    base = len(charset)
    arr = matbuild._charset_bytes(charset)
    segs = cand._segments(base, 0, 3)
    expect = list(cand.brute_iter(charset, 0, 3, 0, segs[-1][2]))
    got = []
    for L, lo, hi in segs:
        blk = matbuild._brute_block(arr, base, L, 0, hi - lo)
        got.extend(blk[r].tobytes() for r in range(blk.shape[0]))
    assert got == expect


def test_mask_matrix_order():
    sets = tuple(tuple(c.encode() for c in s) for s in ("abcde", "0123456789", "xy"))
    radices = [len(s) for s in sets]
    expect = list(cand.mask_iter(sets, 0, 100))
    arrs = [np.frombuffer(b"".join(s), np.uint8) for s in sets]
    blk = matbuild._mask_block(arrs, radices, 0, 100)
    assert [blk[r].tobytes() for r in range(100)] == expect


def test_dict_spans_matches_chunk_words(tmp_path):
    """same parse rules as _chunk_words: strip \\r repeatedly, skip empty
    and oversized lines, keep the no-trailing-newline last line."""
    wl = tmp_path / "w.txt"
    wl.write_bytes(b"one\r\n\r\n" + b"x" * 600 + b"\r\n"
                   + b"two\rthree\r\r\nlast-no-nl")
    buf, starts, lens = matbuild.dict_spans(wl.read_bytes(), config.MAX_WORD_LEN)
    expect = list(testers._chunk_words(str(wl), 0, wl.stat().st_size))
    got = [buf[starts[i]:starts[i] + lens[i]].tobytes()
           for i in range(lens.size)]
    assert got == expect == [b"one", b"two\rthree", b"last-no-nl"]


# ------------------------------------------------------- scan equivalence

def _brute_case(tmp_path, body, idx, start, count, dd=False):
    """zip whose password is the brute candidate at odometer index idx."""
    charset = tuple(c.encode() for c in "abc123")
    pwd = list(cand.brute_iter(charset, 1, 3, idx, 1))[0]
    path = str(tmp_path / "zc.zip")
    (make_dd_zip if dd else make_zipcrypto)(path, pwd, body)
    meta = _pick_meta(path)
    return meta, charset, 1, 3, start, count, pwd


@pytest.mark.parametrize("body", [_big_body(), "small payload"])
@pytest.mark.parametrize("off", [0, 37, -1])
def test_brute_equivalence(tmp_path, monkeypatch, body, off):
    idx, count = 150, 120
    start = max(0, idx - off) if off >= 0 else idx - (count - 1)
    meta, charset, lo, hi, start, count, pwd = _brute_case(
        tmp_path, body, idx, start, count)
    task = (meta, charset, lo, hi, start, count)
    tried, hit, sample = _both(monkeypatch, task, testers.scan_brute)
    if off == -1 or off == 0 or off == 37:
        assert hit == pwd and tried == idx - start + 1
        assert sample == pwd


def test_brute_equivalence_absent(tmp_path, monkeypatch):
    meta, charset, lo, hi, start, count, pwd = _brute_case(
        tmp_path, _big_body(), 150, 170, 88)
    tried, hit, sample = _both(monkeypatch, (meta, charset, lo, hi, start, count),
                               testers.scan_brute)
    assert hit is None and tried == 88 and sample is not None


def test_brute_equivalence_dd_flag(tmp_path, monkeypatch):
    """data-descriptor member: check byte comes from the dos time."""
    meta, charset, lo, hi, start, count, pwd = _brute_case(
        tmp_path, _big_body(5), 100, 100, 150, dd=True)
    tried, hit, sample = _both(
        monkeypatch, (meta, charset, lo, hi, start, count), testers.scan_brute)
    assert hit == pwd and tried == 1


def _mask_case(tmp_path, body, idx, start, count):
    sets = tuple(tuple(c.encode() for c in s)
                 for s in ("abc123!?-", "xyzXY", "0123456789"))
    pwd = list(cand.mask_iter(sets, idx, 1))[0]
    path = str(tmp_path / "zc.zip")
    make_zipcrypto(path, pwd, body)
    meta = _pick_meta(path)
    return (meta, sets, start, count), pwd


@pytest.mark.parametrize("body", [_big_body(9), "tiny"])
@pytest.mark.parametrize("off", [0, 41, -1])
def test_mask_equivalence(tmp_path, monkeypatch, body, off):
    idx, count = 200, 120
    start = idx - off if off >= 0 else idx - (count - 1)
    task, pwd = _mask_case(tmp_path, body, idx, start, count)
    tried, hit, sample = _both(monkeypatch, task, testers.scan_mask)
    assert hit == pwd and tried == idx - start + 1 and sample == pwd


def _dict_lines(tmp_path, pwd, place):
    """wordlist with pwd at a chosen usable position plus parse-stress noise."""
    rng = random.Random(77)
    noise = ["".join(rng.choices(string.ascii_lowercase, k=6))
             for _ in range(2000)]
    if place == "first":
        lines = [pwd] + noise
    elif place == "mid":
        lines = noise[:1000] + [pwd] + noise[1000:]
    elif place == "end":
        lines = noise + [pwd]           # no trailing newline
    else:
        lines = noise
    body = []
    for i, line in enumerate(lines):
        body.append(line + ("\r\n" if i % 3 == 0 else "\n"))
        if i % 500 == 250:
            body.append("\n")                        # empty line
        if i % 700 == 350:
            body.append("x" * 600 + "\n")            # oversized line
    wl = tmp_path / "w.txt"
    wl.write_text("".join(body), encoding="utf-8", newline="")
    return str(wl)


@pytest.mark.parametrize("place", ["first", "mid", "end", "absent"])
def test_dict_equivalence(tmp_path, monkeypatch, place):
    path = str(tmp_path / "zc.zip")
    pwd = b"tgt42q"
    make_zipcrypto(path, pwd, _big_body(13))
    meta = _pick_meta(path)
    wl = _dict_lines(tmp_path, "tgt42q", place)
    size = __import__("os").path.getsize(wl)
    task = (meta, wl, 0, size)
    tried, hit, sample = _both(monkeypatch, task, testers.scan_dict)
    usable = sum(1 for _ in testers._chunk_words(wl, 0, size))
    if place == "absent":
        assert hit is None and tried == usable
    else:
        assert hit == pwd and sample == pwd
        assert tried == usable if place == "end" else tried > 0


def test_hybrid_equivalence(tmp_path, monkeypatch):
    path = str(tmp_path / "zc.zip")
    pwd = b"pre-hello1"
    make_zipcrypto(path, pwd, _big_body(17))
    meta = _pick_meta(path)
    suffix = (tuple(c.encode() for c in "01"),)
    rng = random.Random(19)
    words = ["".join(rng.choices(string.ascii_lowercase, k=6))
             for _ in range(500)] + ["hello", "world"]
    wl = tmp_path / "w.txt"
    wl.write_text("\n".join(words) + "\n", encoding="utf-8", newline="")
    import os
    size = os.path.getsize(str(wl))
    task = (meta, str(wl), 0, size, b"pre-", suffix)
    tried, hit, sample = _both(monkeypatch, task, testers.scan_hybrid)
    # hello is usable-line 500, suffix index 1 -> candidate ordinal 500*2+1
    assert hit == pwd and tried == 500 * 2 + 2 and sample == pwd


def test_passer_continue(tmp_path, monkeypatch):
    """a filter passer that fails the confirm must be counted and the scan
    must continue to the real hit - forced here by rejecting confirms."""
    path = str(tmp_path / "zc.zip")
    make_zipcrypto(path, b"tgt42q", _big_body(23))
    meta = _pick_meta(path)
    wl = _dict_lines(tmp_path, "tgt42q", "mid")
    import os
    size = os.path.getsize(wl)
    real = testers._confirm_fast
    monkeypatch.setattr(testers, "_confirm_fast",
                        lambda m, p: p == b"tgt42q" and real(m, p))
    monkeypatch.setattr(config, "VECTOR", False)
    scalar = testers.scan_dict((meta, wl, 0, size))
    monkeypatch.setattr(config, "VECTOR", True)
    vec = testers.scan_dict((meta, wl, 0, size))
    assert vec == scalar == (1001, b"tgt42q", b"tgt42q")


# ------------------------------------------------------------ fast confirm

def test_confirm_zc_truth(tmp_path):
    path = str(tmp_path / "zc.zip")
    make_zipcrypto(path, b"jokwe", _big_body(29))
    meta = _pick_meta(path)
    assert pkfast.confirm_zc(meta, b"jokwe") is True
    assert pkfast.confirm_zc(meta, b"jokwf") is False
    assert pkfast.confirm_zc(meta, b"") is False
    m2 = dict(meta)
    m2.pop("data_off")
    assert pkfast.confirm_zc(m2, b"jokwe") is None      # falls back to zipfile
    assert pkfast.confirm_zc({"path": "x"}, b"jokwe") is None


def test_confirm_zc_dd(tmp_path):
    path = str(tmp_path / "dd.zip")
    make_dd_zip(path, b"descript", _big_body(31))
    meta = _pick_meta(path)
    assert pkfast.confirm_zc(meta, b"descript") is True
    assert pkfast.confirm_zc(meta, b"descripT") is False


# ---------------------------------------------------------------- fallbacks

def test_multibyte_charset_falls_back(tmp_path, monkeypatch):
    """entries wider than one byte (utf-8) keep the scalar scanner."""
    path = str(tmp_path / "zc.zip")
    make_zipcrypto(path, "é".encode(), "payload")
    meta = _pick_meta(path)
    charset = (b"a", "é".encode())
    assert matbuild._charset_bytes(charset) is None
    task = (meta, charset, 1, 1, 0, 2)
    tried, hit, sample = _both(monkeypatch, task, testers.scan_brute)
    assert hit == "é".encode() and tried == 2


def test_huge_space_falls_back():
    """odometer spaces beyond uint64 indexing return None, not garbage."""
    meta = {"kind": "zipcrypto", "raw12": "00" * 12, "check": 0}
    charset = tuple(bytes([i]) for i in range(100))
    r = matbuild.scan_brute_task(meta, charset, 10, 10, 0, 4, lambda p: False)
    assert r is None
    sets = tuple(tuple(bytes([c]) for c in b"0123456789") for _ in range(20))
    r = matbuild.scan_mask_task(meta, sets, 0, 4, lambda p: False)
    assert r is None


def test_hybrid_multibyte_suffix_falls_back(tmp_path, monkeypatch):
    """entries wider than one byte in the suffix keep the scalar scanner,
    and the scalar result is correct."""
    path = str(tmp_path / "zc.zip")
    make_zipcrypto(path, "wrdö".encode(), "payload")
    meta = _pick_meta(path)
    suffix = (("ö".encode(),),)           # multi-byte suffix entry
    wl = tmp_path / "w.txt"
    wl.write_text("wrd\n", encoding="utf-8", newline="")
    import os
    task = (meta, str(wl), 0, os.path.getsize(str(wl)), b"", suffix)
    tried, hit, sample = _both(monkeypatch, task, testers.scan_hybrid)
    assert hit == "wrdö".encode() and tried == 1
