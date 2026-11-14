"""candidate space math - index-addressable generation + wordlist chunking.

brute/mask spaces are addressed by integer index (workers generate candidates
locally from a range, so no candidate is ever pickled); wordlists are shipped
as whole-line byte ranges read straight from the file.
"""
import os

from . import config


def mask_sets(mask: str, custom=None) -> list:
    """hashcat-style mask -> per-position charset list; literal chars stay literal."""
    custom = custom or {}
    sets = []
    i = 0
    while i < len(mask):
        if mask[i] == "?" and i + 1 < len(mask):
            sets.append(_mask_token(mask[i + 1], custom))
            i += 2
        else:
            sets.append(mask[i])
            i += 1
        if len(sets) > config.MAX_MASK_TOKENS:
            raise ValueError(f"mask exceeds {config.MAX_MASK_TOKENS} positions")
    return sets


def _mask_token(tok: str, custom: dict) -> str:
    if tok in ("l", "u", "d", "s", "h", "a"):
        return config.CHARSETS[tok]
    if tok in "1234":
        c = custom.get("c" + tok, "")
        if not c:
            raise ValueError(f"custom set ?{tok} is empty")
        if len(c) > config.MAX_CUSTOM_SET_LEN:
            raise ValueError(f"custom set ?{tok} exceeds {config.MAX_CUSTOM_SET_LEN} chars")
        return c
    if tok == "?":
        return "?"
    raise ValueError(f"unknown mask token ?{tok}")


def wordlist_iter(path: str):
    """stream a wordlist file; blank and oversized lines are skipped."""
    with open(path, "rb") as f:
        for line in f:
            w = line.rstrip(b"\r\n")
            if w and len(w) <= config.MAX_WORD_LEN:
                yield w


_WORD_COUNTS = {}


def count_words(path: str) -> int:
    """count usable lines, cached per (path, size, mtime) - wordlists are
    re-used across jobs and scanning a 14M-line file per start is waste."""
    st = os.stat(path)
    key = (path, st.st_size, st.st_mtime_ns)
    n = _WORD_COUNTS.get(key)
    if n is None:
        n = sum(1 for _ in wordlist_iter(path))
        if len(_WORD_COUNTS) > 32:
            _WORD_COUNTS.clear()
        _WORD_COUNTS[key] = n
    return n


def mask_space(sets) -> int:
    """space size; sets may be charset strings or tuples of char bytes."""
    n = 1
    for s in sets:
        n *= len(s)
    return n


def brute_total(charset: str, min_len: int, max_len: int) -> int:
    if not charset:
        raise ValueError("empty charset")
    base = len(charset)
    return sum(base ** L for L in range(min_len, max_len + 1))


def _segments(base: int, min_len: int, max_len: int) -> list:
    """(length, start_index, end_index) segments of the brute space."""
    segs, acc = [], 0
    for L in range(min_len, max_len + 1):
        sz = base ** L
        segs.append((L, acc, acc + sz))
        acc += sz
    return segs


def brute_iter(charset: tuple, min_len: int, max_len: int, start: int, count: int):
    """candidates [start, start+count) of the brute space, same order as
    itertools.product over ascending lengths (last position varies fastest).

    charset: tuple of per-char bytes, so multibyte characters stay intact.
    """
    if not charset:
        raise ValueError("empty charset")
    base = len(charset)
    segs = _segments(base, min_len, max_len)
    i, produced = start, 0
    while produced < count:
        seg = next(((L, lo, hi) for L, lo, hi in segs if lo <= i < hi), None)
        if seg is None:
            return
        L, lo, hi = seg
        while produced < count and i < hi:
            r = i - lo
            pos = [0] * L
            for p in range(L - 1, -1, -1):
                r, d = divmod(r, base)
                pos[p] = d
            yield b"".join(charset[d] for d in pos)
            produced += 1
            i += 1


def mask_iter(sets: tuple, start: int, count: int):
    """candidates [start, start+count) of a mask space, product order.

    sets: tuple of per-position tuples of per-char bytes.
    """
    if not sets:
        raise ValueError("empty mask")
    radices = [len(s) for s in sets]
    total = 1
    for r_ in radices:
        total *= r_
    L = len(sets)
    i, produced = start, 0
    while produced < count and i < total:
        r = i
        pos = [0] * L
        for p in range(L - 1, -1, -1):
            r, d = divmod(r, radices[p])
            pos[p] = d
        yield b"".join(sets[p][d] for p, d in enumerate(pos))
        produced += 1
        i += 1


def line_chunks(path: str, target: int) -> list:
    """(start, end) byte ranges covering whole lines: every end sits just past
    a newline or at eof, and every start is a line start - so workers can
    seek+read a chunk and own it completely."""
    chunks = []
    with open(path, "rb") as f:
        size = os.fstat(f.fileno()).st_size
        pos = 0
        while pos < size:
            end = min(pos + target, size)
            if end < size:
                f.seek(end)
                probe = f.read(8192)
                nl = probe.find(b"\n")
                end = end + nl + 1 if nl >= 0 else size
            chunks.append((pos, end))
            pos = end
    return chunks


def estimate_total(cfg: dict):
    """total space size, or None when unknown/invalid."""
    mode = cfg["mode"]
    custom = cfg.get("custom") or {}
    try:
        if mode == "dict":
            return count_words(cfg["wordlist"])
        if mode == "mask":
            return mask_space(mask_sets(cfg["mask"], custom))
        if mode == "brute":
            return brute_total(cfg["charset"], cfg["min_len"], cfg["max_len"])
        if mode == "hybrid":
            n = count_words(cfg["wordlist"])
            s = mask_sets(cfg.get("suffix_mask") or "", custom)
            return n * mask_space(s) if s else n
    except Exception:
        return None
    return None
