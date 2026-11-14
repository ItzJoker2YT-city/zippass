"""candidate generation: index math must match itertools.product exactly,
wordlist chunking must tile the file at line boundaries."""
import itertools
import os

import pytest

from zippass import candidates

LOWER = "abcdefghijklmnopqrstuvwxyz"
DIGITS = "0123456789"
CB_AB = tuple(c.encode() for c in "ab")


def _cb(s: str) -> tuple:
    return tuple(c.encode() for c in s)


def test_mask_tokens():
    assert candidates.mask_sets("?l?d?1", {"c1": "ab"}) == [LOWER, DIGITS, "ab"]
    assert candidates.mask_sets("ab?d", {}) == ["a", "b", DIGITS]
    assert candidates.mask_sets("??", {}) == ["?"]


def test_mask_rejects_bad_tokens():
    with pytest.raises(ValueError):
        candidates.mask_sets("?9", {})
    with pytest.raises(ValueError):
        candidates.mask_sets("?1", {})          # custom set not provided
    big = {"c2": "x" * 300}
    with pytest.raises(ValueError):
        candidates.mask_sets("?2", big)


def test_mask_space():
    assert candidates.mask_space(["ab", "cde"]) == 6
    assert candidates.mask_space([b"a", b"b"]) == 1


def test_brute_total():
    assert candidates.brute_total("01", 2, 3) == 12
    with pytest.raises(ValueError):
        candidates.brute_total("", 1, 1)


def test_brute_iter_matches_product():
    ref = ["".join(t).encode() for L in (2, 3) for t in itertools.product("ab", repeat=L)]
    assert list(candidates.brute_iter(CB_AB, 2, 3, 0, len(ref))) == ref


def test_brute_iter_slices():
    ref = ["".join(t).encode() for L in (2, 3) for t in itertools.product("ab", repeat=L)]
    assert list(candidates.brute_iter(CB_AB, 2, 3, 4, 3)) == ref[4:7]
    assert list(candidates.brute_iter(CB_AB, 2, 3, 10, 99)) == ref[10:]
    assert list(candidates.brute_iter(CB_AB, 2, 3, 9999, 5)) == []


def test_mask_iter_matches_product():
    sets = (_cb("ab"), _cb("01"))
    ref = ["".join(t).encode() for t in itertools.product("ab", "01")]
    assert list(candidates.mask_iter(sets, 0, len(ref))) == ref
    assert list(candidates.mask_iter(sets, 3, 4)) == ref[3:7]
    assert list(candidates.mask_iter(sets, 999, 5)) == []


def test_mask_iter_multibyte_chars():
    sets = (_cb("éx"), _cb("01"))
    ref = ["".join(t).encode() for t in itertools.product("éx", "01")]
    assert list(candidates.mask_iter(sets, 0, 4)) == ref


def test_mask_iter_rejects_empty():
    with pytest.raises(ValueError):
        list(candidates.mask_iter((), 0, 1))


def test_wordlist_iter_rules(tmp_path):
    wl = tmp_path / "w.txt"
    wl.write_bytes(b"ok\n\n" + b"x" * 600 + b"\nsecond\n")
    assert list(candidates.wordlist_iter(str(wl))) == [b"ok", b"second"]


def test_count_words_cached(tmp_path):
    wl = tmp_path / "w.txt"
    wl.write_bytes(b"a\nb\nc\n")
    assert candidates.count_words(str(wl)) == 3
    assert candidates.count_words(str(wl)) == 3   # second call served from cache


def test_line_chunks_tile_the_file(tmp_path):
    p = tmp_path / "w.bin"
    p.write_bytes(b"one\n\nthree\nno-newline-tail")
    size = os.path.getsize(str(p))
    chunks = candidates.line_chunks(str(p), 4)   # tiny target -> multiple chunks
    assert chunks[0][0] == 0
    assert chunks[-1][1] == size
    for (_, end), (start, _) in zip(chunks, chunks[1:]):
        assert start == end                       # contiguous
    parts = []
    with open(str(p), "rb") as f:
        for s, e in chunks:
            f.seek(s)
            parts.append(f.read(e - s))
    assert b"".join(parts) == p.read_bytes()      # chunks reproduce the file byte-for-byte
    for s, e in chunks[:-1]:                      # interior chunk ends just past a newline
        with open(str(p), "rb") as f:
            f.seek(e - 1)
            assert f.read(1) == b"\n"


def test_line_chunks_empty_file(tmp_path):
    p = tmp_path / "empty.txt"
    p.write_bytes(b"")
    assert candidates.line_chunks(str(p), 1024) == []


def test_estimate_total(tmp_path):
    wl = tmp_path / "w.txt"
    wl.write_bytes(b"a\nb\nc\n")
    assert candidates.estimate_total({"mode": "dict", "wordlist": str(wl)}) == 3
    assert candidates.estimate_total(
        {"mode": "brute", "charset": "01", "min_len": 2, "max_len": 2}) == 4
    assert candidates.estimate_total({"mode": "mask", "mask": "?d?d", "custom": {}}) == 100
