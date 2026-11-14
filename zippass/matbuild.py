"""candidate matrices + vector task adapters - the feed layer of the fast path.

builders turn task tuples into (rows, lens) byte matrices in exactly the
candidate order the scalar iterators produce (tests pin this order);
the adapters run them through fastfilter and return the same
(tried, hit, sample) triple as testers' scalar scans. brute/mask build
odometer blocks per candidate length; dict/hybrid sort lines into
length bands so every batch's padded width tracks its own rows - a few
long lines in a chunk must not force short rows through dead columns -
with ordinals preserving file order for exact tried/sample accounting.
every adapter falls back to None when the vector path does not apply -
multi-byte charset entries, spaces beyond uint64 odometer indexing -
and callers then run the scalar scan unchanged.
"""
import numpy as np

from . import candidates as cand
from . import config
from . import fastfilter
from . import pkfast

_U8 = np.uint8
_ELEM_CAP = 4_000_000      # max matrix elements per kernel call (~28MB transients)


def _pk(meta):
    """prepack the per-member constants the kernels need; None when the
    jit layer is missing - plain-python kernels would be slower than
    the scalar scans they would replace."""
    if not pkfast.HAS_NUMBA:
        return None
    cdata = meta.get("cdata")
    return (bytes.fromhex(meta["raw12"]), meta["check"],
            bytes.fromhex(cdata) if cdata else None)


# ------------------------------------------------------------- brute / mask

def _charset_bytes(charset):
    """flat byte array for all-1-byte charset entries, else None."""
    if any(len(c) != 1 for c in charset):
        return None
    return np.frombuffer(b"".join(charset), _U8)


def _brute_block(arr, base, L, a, b):
    """rows for local indices [a, b) of the length-L odometer block;
    position 0 is most significant - brute_iter's exact product order."""
    mat = np.empty((b - a, L), _U8)
    r = np.arange(a, b, dtype=np.uint64)
    for p in range(L - 1, -1, -1):
        d = (r % np.uint64(base)).astype(np.int64)
        mat[:, p] = arr[d]
        r //= np.uint64(base)
    return mat


def scan_brute_task(meta, charset, min_len, max_len, start, count, confirm):
    """vector scan_brute; None when the fast path does not apply."""
    arr = _charset_bytes(charset)
    if arr is None:
        return None
    pk = _pk(meta)
    if pk is None:
        return None
    base = len(charset)
    end = start + count
    tried, sample = 0, b""
    for L, lo, hi in cand._segments(base, min_len, max_len):
        if hi <= start or lo >= end:
            continue
        if base ** L >= (1 << 64):    # odometer exceeds uint64 - go scalar
            return None
        blk = _brute_block(arr, base, L, max(start, lo) - lo, min(end, hi) - lo)
        lens = np.full(blk.shape[0], L, np.int64)
        t, hit, sample = fastfilter.scan_rows(blk, lens, *pk, confirm)
        tried += t
        if hit is not None:
            return tried, hit, sample
    return tried, None, sample


def _mask_block(arrs, radices, a, b):
    """rows for mask indices [a, b), product order - mask_iter's exact order."""
    mat = np.empty((b - a, len(radices)), _U8)
    r = np.arange(a, b, dtype=np.uint64)
    for p in range(len(radices) - 1, -1, -1):
        d = (r % np.uint64(radices[p])).astype(np.int64)
        mat[:, p] = arrs[p][d]
        r //= np.uint64(radices[p])
    return mat


def scan_mask_task(meta, sets, start, count, confirm):
    """vector scan_mask; None when the fast path does not apply."""
    if any(len(c) != 1 for s in sets for c in s):
        return None
    pk = _pk(meta)
    if pk is None:
        return None
    arrs = [np.frombuffer(b"".join(s), _U8) for s in sets]
    radices = [len(s) for s in sets]
    total = 1
    for r_ in radices:
        total *= r_
    if total >= (1 << 64):
        return None
    b = min(start + count, total)
    if b <= start:
        return 0, None, b""
    mat = _mask_block(arrs, radices, start, b)
    lens = np.full(mat.shape[0], len(radices), np.int64)
    return fastfilter.scan_rows(mat, lens, *pk, confirm)


# ------------------------------------------------------------ dict / hybrid

def dict_spans(data, max_word):
    """usable wordlist lines from one chunk as (buf, starts, lens).

    mirrors testers._chunk_words exactly: split on \\n, strip trailing
    \\r (repeatedly, like rstrip), skip empty and oversized lines.
    starts are int32 line offsets into buf; lens the usable lengths.
    returns None when the chunk has no usable lines.
    """
    buf = np.frombuffer(data, _U8)
    nl = np.nonzero(buf == 10)[0]
    starts = np.concatenate(([0], nl + 1))
    ends = np.concatenate((nl, [buf.size]))
    lens = ends - starts
    act = np.nonzero(lens > 0)[0]
    while act.size:                      # one \r per pass, re-checking rows
        idx = np.clip(starts[act] + lens[act] - 1, 0, buf.size - 1)
        cr = buf[idx] == 13
        if not cr.any():
            break
        rows = act[cr]
        lens[rows] -= 1
        act = rows
    keep = np.nonzero((lens > 0) & (lens <= max_word))[0]
    if keep.size == 0:
        return None
    return buf, starts[keep].astype(np.int64), lens[keep]


def _dict_block(buf, starts, lens, idx):
    """matrix rows for the given usable-line indices (any order); zero
    padded, rows may be shorter than the block width (lens carries the
    true length). jit scatter of the actual content bytes only - the
    padded width never multiplies the fill traffic."""
    s, l = starts[idx], lens[idx]
    W = int(l.max()) if l.size else 0
    mat = np.zeros((l.size, W), _U8)
    if l.size:
        pkfast.dict_fill(mat, buf, starts, lens, idx)
    return mat


def _band_blocks(buf, starts, lens):
    """length-banded candidate blocks over a chunk's usable lines.

    rows are sorted by length and split so each block's padded width
    tracks its own rows: a few long lines must not force short rows
    through dead columns in the gather or the schedule (both scale with
    the batch's max length). each block carries ordinals - the original
    usable-line positions - so scan_blocks can report scalar-exact
    tried/sample in file order.
    """
    n = lens.size
    order = np.argsort(lens, kind="stable")    # file order within a length
    slens = lens[order]
    blocks = []
    i = 0
    while i < n:
        j = min(n, i + max(1, _ELEM_CAP // max(int(slens[i]), 1)))
        W = int(slens[j - 1])                  # sorted: band max
        if (j - i) * W > _ELEM_CAP:            # lengths rose within the band
            j = i + max(1, _ELEM_CAP // W)
            W = int(slens[j - 1])
        idx = order[i:j]
        blocks.append((_dict_block(buf, starts, lens, idx), lens[idx], idx))
        i = j
    return blocks


def scan_dict_chunk(meta, data, confirm):
    """vector scan_dict for one whole-line chunk; (tried, hit, sample)
    or None when the fast path does not apply."""
    pk = _pk(meta)
    if pk is None:
        return None
    spans = dict_spans(data, config.MAX_WORD_LEN)
    if spans is None:
        return 0, None, b""
    blocks = _band_blocks(spans[0], spans[1], spans[2])
    return fastfilter.scan_blocks(blocks, *pk, confirm)


def _hybrid_block(buf, starts, lens_line, idx, pre, arrs, radices, P, Ls, S):
    """one band's candidate rows: lines x suffix combos, line-major -
    exactly the scalar product order (prefix + word + suffix per row).
    returns (mat, lens, ordinals); ordinals = line position x S + combo."""
    maxw = int(lens_line[idx].max())
    W = P + maxw + Ls
    rows = idx.size * S
    mat = np.zeros((rows, W), _U8)
    j = np.arange(S, dtype=np.int64)
    suf_tab = np.zeros((max(S, 1), Ls), _U8)
    for p in range(Ls - 1, -1, -1):            # suffix odometer table
        suf_tab[:, p] = arrs[p][j % radices[p]]
        j //= radices[p]
    pkfast.hybrid_fill(mat, buf, starts, lens_line, idx, pre, suf_tab, P, Ls, S)
    ords = idx[:, None] * np.int64(S) + np.arange(S, dtype=np.int64)
    lens = P + lens_line[np.repeat(idx, S)] + Ls
    return mat, lens, ords.ravel()


def _hybrid_blocks(buf, starts, lens_line, pre, arrs, radices, P, Ls, S):
    """length-banded hybrid blocks: lines sorted by length, each line
    expanding to the S suffix combos line-major; ordinals carry the
    (line x S + combo) candidate positions in file order."""
    n = lens_line.size
    order = np.argsort(lens_line, kind="stable")
    slens = lens_line[order]
    blocks = []
    i = 0
    while i < n:
        W0 = P + int(slens[i]) + Ls
        j = min(n, i + max(1, _ELEM_CAP // max(1, S * W0)))
        W = P + int(slens[j - 1]) + Ls
        if (j - i) * S * W > _ELEM_CAP:        # lengths rose within the band
            j = i + max(1, _ELEM_CAP // (S * W))
            W = P + int(slens[j - 1]) + Ls
        idx = order[i:j]
        blocks.append(_hybrid_block(buf, starts, lens_line, idx, pre,
                                    arrs, radices, P, Ls, S))
        i = j
    return blocks


def scan_hybrid_chunk(meta, data, prefix, suffix_sets, confirm):
    """vector scan_hybrid: rows enumerate word-major, suffix-minor, exactly
    the scalar product order (prefix + line + suffix per row); lines are
    length-banded so padded widths track the chunk's own rows. None when
    the fast path does not apply."""
    if any(len(c) != 1 for s in suffix_sets for c in s):
        return None                      # multi-byte entries - scalar handles
    pk = _pk(meta)
    if pk is None:
        return None
    spans = dict_spans(data, config.MAX_WORD_LEN)
    if spans is None:
        return 0, None, b""
    buf, starts, lens_line = spans
    arrs = [np.frombuffer(b"".join(s), _U8) for s in suffix_sets]
    radices = [len(s) for s in suffix_sets]
    S = 1
    for r_ in radices:
        S *= r_
    if S >= (1 << 64):
        return None
    blocks = _hybrid_blocks(buf, starts, lens_line, np.frombuffer(prefix, _U8),
                            arrs, radices, len(prefix), len(radices), S)
    return fastfilter.scan_blocks(blocks, *pk, confirm)
