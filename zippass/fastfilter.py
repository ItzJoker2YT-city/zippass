"""numpy + numba vectorized pkware batch filter - the core of the fast path.

runs the whole candidate pipeline for a batch of thousands as array
ops: candidate matrices come in from matbuild, the key schedule and
12-byte header check run as one jit pass per row (pkfast.schedule_batch,
per-row lengths - no freezing machinery needed), and survivors' keys
drive the 512-byte deflate prefilter on the batched numba decrypt.
survivors of that (~1/2**40) go to the CRC-verified confirm owned by
testers.

bit-exactness is anchored by tests/test_fastfilter.py against the
scalar reference in testers.py. the identities it relies on:
  - bits 8..15 of (k|2)*((k|2)^1) depend only on bits 0..15 of k|2, so
    the decrypt byte needs no 2**64 wrap
  - uint32/uint64 array arithmetic wraps mod 2**32/2**64, matching the
    scalar "& 0xFFFFFFFF" masks exactly
"""
import zlib

import numpy as np

from . import pkfast


def zc_pass1(mat, lens, raw12, check):
    """key schedule + header decrypt for a whole batch.

    mat: (n, W) uint8 candidate bytes; lens: (n,) per-row byte length -
    rows shorter than W ignore the padding columns. returns
    (passers, k0, k1, k2): row indices whose decrypted 12th header byte
    equals the check byte (1/256 of wrong passwords), plus each row's
    post-header keys positioned to decrypt the compressed data.
    """
    return pkfast.schedule_batch(mat, lens,
                                 np.frombuffer(raw12, np.uint8), check)


def cdata_filter(k0s, k1s, k2s, cdata):
    """decrypt the encrypted cdata head per passer; keep rows whose bytes
    stay decodable as a raw deflate stream - the same verdict as the
    scalar _deflate_decodable, batched. real data always decodes; wrong
    passwords almost always die inside the first block."""
    cd = np.frombuffer(cdata, np.uint8)
    out = np.empty((k0s.size, cd.size), np.uint8)
    pkfast.decrypt_rows(k0s.astype(np.int64), k1s.astype(np.int64),
                        k2s.astype(np.int64), cd, out)
    keep = np.empty(k0s.size, bool)
    for r in range(k0s.size):
        try:
            zlib.decompressobj(-15).decompress(out[r].tobytes())
            keep[r] = True
        except zlib.error:
            keep[r] = False
    return np.nonzero(keep)[0]


def scan_blocks(blocks, raw12, check, cdata, confirm):
    """full vector pipeline over one or more candidate matrices.

    blocks: (mat, lens, ordinals) triples - ordinals map local rows to
    global candidate positions (file order). length-banded dict/hybrid
    scans use this so each batch's gather + schedule width tracks its
    own rows, not the chunk's longest line. returns the exact
    (tried, hit, sample) triple of the scalar scan: tried counts every
    candidate up to and including the hit (its ordinal + 1), or the
    whole space; sample is the hit or the max-ordinal candidate. only
    the true password can survive the CRC confirm, but passers are
    still processed in ascending ordinal order to mirror the scalar
    walk exactly.
    """
    total, max_ord, max_sample = 0, -1, b""
    acc = []                     # per block: (ords, k0, k1, k2, block, rows)
    for bi, (mat, lens, ords) in enumerate(blocks):
        n = mat.shape[0]
        total += n
        if n == 0:
            continue
        omax = int(ords.max())
        if omax > max_ord:       # file order: the max-ordinal row is sample
            max_ord = omax
            r = int(ords[-1]) if int(ords[-1]) == omax else int(np.argmax(ords))
            max_sample = mat[r, :lens[r]].tobytes()
        p, k0, k1, k2 = zc_pass1(mat, lens, raw12, check)
        if p.size:
            acc.append((ords[p].astype(np.int64), k0[p], k1[p], k2[p],
                        np.full(p.size, bi, np.int64), p.astype(np.int64)))
    if total == 0:
        return 0, None, b""
    if acc:
        op = np.concatenate([a[0] for a in acc])
        bip = np.concatenate([a[4] for a in acc])
        rp = np.concatenate([a[5] for a in acc])
        if cdata is not None:
            keep = cdata_filter(np.concatenate([a[1] for a in acc]),
                                np.concatenate([a[2] for a in acc]),
                                np.concatenate([a[3] for a in acc]), cdata)
            op, bip, rp = op[keep], bip[keep], rp[keep]
        for q in np.argsort(op, kind="stable"):   # ascending file order
            mat, lens, _ = blocks[int(bip[q])]
            pwd = mat[int(rp[q]), :lens[int(rp[q])]].tobytes()
            if confirm(pwd):
                return int(op[q]) + 1, pwd, pwd
    return total, None, max_sample


def scan_rows(mat, lens, raw12, check, cdata, confirm):
    """single-block convenience over scan_blocks (contiguous ordinals)."""
    return scan_blocks([(mat, lens, np.arange(mat.shape[0], dtype=np.int64))],
                       raw12, check, cdata, confirm)
