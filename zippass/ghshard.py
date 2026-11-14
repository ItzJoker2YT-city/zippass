"""scanner for one shard of an indexable candidate space (brute / mask),
built to run on a github actions runner - and on this box for tests.

reads a json spec (built by zippass.ghcompute), scans candidates
[shard, shards) of the space through the fastest available verifier
(rust .so from ZIPPASS_AESFAST_LIB -> numba -> hashlib), and writes one
json line per verifier pass to --out: {"i": global_index, "p": pwd}.
the app-side collector sorts passes by global index across all shards
and confirms them in order against the real archive, so the verdict
semantics stay identical to a purely local scan (first confirmed pass
in candidate order wins).
"""
import argparse
import hashlib
import json
import os
import sys

from . import candidates as cand

try:
    from . import rustfast
except Exception:                                   # pragma: no cover
    rustfast = None
try:
    from . import aesfast
except Exception:                                   # pragma: no cover
    aesfast = None

BATCH = 256


def verifier_for(salt: bytes, dklen: int, pv: bytes):
    """fastest available batch verifier; falls back to hashlib so a
    runner without the .so still produces correct (if slow) verdicts."""
    if rustfast is not None:
        bv = rustfast.make_batch_verifier(salt, dklen, pv)
        if bv is not None:
            return bv
    if aesfast is not None and aesfast.HAS_NUMBA:
        ver = aesfast.make_verifier(salt, dklen, pv)
        if ver is not None:
            def batched(pwds):
                return [i for i, p in enumerate(pwds) if ver(p)]
            return batched
    pbkdf2 = hashlib.pbkdf2_hmac

    def slow(pwds):
        return [i for i, p in enumerate(pwds)
                if pbkdf2("sha1", p, salt, 1000, dklen)[-2:] == pv]
    return slow


def split_space(total: int, shard: int, shards: int):
    """disjoint [lo, count) covering the space exactly once."""
    base, rem = divmod(total, shards)
    lo = shard * base + min(shard, rem)
    return lo, base + (1 if shard < rem else 0)


def space_of(spec: dict):
    """(total, iterator factory) for the spec's attack - raises on
    unsupported modes so a bad spec fails loud, never scans nothing."""
    if spec["mode"] == "brute":
        charset = spec["charset"]
        total = cand.brute_total(charset, spec["min_len"], spec["max_len"])
        chars = tuple(c.encode("utf-8") for c in charset)

        def it(lo, count):
            return cand.brute_iter(chars, spec["min_len"], spec["max_len"],
                                   lo, count)
        return total, it
    if spec["mode"] == "mask":
        sets = tuple(tuple(c.encode("utf-8") for c in s)
                     for s in cand.mask_sets(spec["mask"],
                                             spec.get("custom") or {}))
        total = cand.mask_space(sets)

        def it(lo, count):
            return cand.mask_iter(sets, lo, count)
        return total, it
    raise SystemExit(f"unsupported mode for cloud shards: {spec['mode']!r}")


def scan_shard(spec: dict, shard: int, shards: int):
    """scan one shard and return (passes, tried) - passes carry the
    password bytes looked up from the stream position of each hit."""
    salt = bytes.fromhex(spec["salt_hex"])
    dklen, pv = spec["dklen"], bytes.fromhex(spec["pv_hex"])
    total, make_iter = space_of(spec)
    lo, count = split_space(total, shard, shards)
    if count <= 0:
        return [], 0
    verify = verifier_for(salt, dklen, pv)
    stream = make_iter(lo, count)
    passes, tried, batch = [], 0, []
    for pwd in stream:
        batch.append(pwd)
        tried += 1
        if len(batch) < BATCH:
            continue
        for j in verify(batch):
            passes.append((lo + tried - len(batch) + j, batch[j]))
        batch = []
    if batch:
        for j in verify(batch):
            passes.append((lo + tried - len(batch) + j, batch[j]))
    return passes, tried


def main() -> None:
    ap = argparse.ArgumentParser(description="scan one cloud shard")
    ap.add_argument("--spec", default=os.environ.get("ZIPPASS_GH_SPEC", ""))
    ap.add_argument("--shard", type=int, default=0)
    ap.add_argument("--shards", type=int, default=1)
    ap.add_argument("--out", default="found.txt")
    args = ap.parse_args()
    if not args.spec:
        raise SystemExit("no spec: pass --spec or set ZIPPASS_GH_SPEC")
    shards = max(1, min(64, args.shards))
    shard = max(0, min(shards - 1, args.shard))
    spec = json.loads(args.spec)
    passes, tried = scan_shard(spec, shard, shards)
    if passes:
        with open(args.out, "w", encoding="utf-8") as fh:
            for i, pwd in passes:
                fh.write(json.dumps({"i": i, "p": pwd.decode("utf-8")}) + "\n")
    print(f"shard {shard}/{shards}: scanned {tried} candidates, "
          f"{len(passes)} verifier pass(es)")


if __name__ == "__main__":
    main()
