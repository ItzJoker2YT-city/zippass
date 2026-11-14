"""cloud boost (github actions offload): shard math must cover the space
exactly, the runner script must find the true password from spec alone
(never the archive), and the boundary validation must reject junk."""
import json
import os
import subprocess
import sys

import pytest

from make_tests import make_aes_zip
from zippass import candidates as cand
from zippass import config, cryptoparse, ghcompute, ghshard, routes, testers

CHARSET = "abcdefghijklmnopqrstuvwxyz0123456789"


# ---------------------------------------------------------------- shard math
@pytest.mark.parametrize("total,shards", [(1, 1), (7, 7), (7, 3), (123, 7),
                                          (47988, 4), (1000, 64)])
def test_split_space_covers_exactly(total, shards):
    slices = [ghshard.split_space(total, s, shards) for s in range(shards)]
    assert sum(c for _, c in slices) == total
    lo_prev = 0
    for lo, count in slices:
        assert lo == lo_prev          # contiguous, no gaps, no overlap
        assert count >= 0
        lo_prev = lo + count


# ---------------------------------------------------------------- spec / artifacts
def test_build_spec_carries_verifier_fields(tmp_path):
    path = str(tmp_path / "aes.zip")
    make_aes_zip(path, b"q9z")
    meta = cryptoparse.pick_member(cryptoparse.parse_members(path))
    cfg = {"mode": "brute", "charset": CHARSET, "min_len": 1, "max_len": 3}
    spec = ghcompute.build_spec(meta, cfg)
    assert spec["salt_hex"] == meta["salt"]
    assert spec["dklen"] == meta["dklen"] == 66
    assert spec["pv_hex"] == meta["pv"]
    assert spec["charset"] == CHARSET
    assert "path" not in spec and "salt" not in spec   # archive never travels


def test_spec_too_large_is_reflected(tmp_path):
    path = str(tmp_path / "aes.zip")
    make_aes_zip(path, b"q9z")
    meta = cryptoparse.pick_member(cryptoparse.parse_members(path))
    cfg = {"mode": "mask", "mask": "?1", "custom": {"1": "x" * 40000},
           "min_len": 0, "max_len": 0}
    with pytest.raises(ghcompute.GHError):
        ghcompute.build_spec(meta, cfg)


def test_parse_found_roundtrip():
    import io
    import zipfile
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("found-3.txt",
                    json.dumps({"i": 22723, "p": "q9z"}) + "\n"
                    + json.dumps({"i": 5, "p": "x"}) + "\n")
    assert ghcompute.parse_found(buf.getvalue()) == [(22723, b"q9z"), (5, b"x")]


# ---------------------------------------------------------------- runner e2e
def _run_shard(spec, shard, shards, out):
    env = dict(os.environ, ZIPPASS_GH_SPEC=json.dumps(spec))
    r = subprocess.run(
        [sys.executable, "-m", "zippass.ghshard", "--spec", json.dumps(spec),
         "--shard", str(shard), "--shards", str(shards), "--out", out],
        cwd=config.APP_ROOT, env=env, capture_output=True, text=True,
        timeout=600)
    assert r.returncode == 0, r.stderr
    return r.stdout


def test_ghshard_finds_true_password_across_shards(tmp_path):
    """four subprocess shards scan the whole 47,988-candidate space; the
    true password must come back with its exact global index and confirm
    locally - the cloud path's verdict chain, end to end."""
    path = str(tmp_path / "aes.zip")
    make_aes_zip(path, b"q9z")
    meta = cryptoparse.pick_member(cryptoparse.parse_members(path))
    cfg = {"mode": "brute", "charset": CHARSET, "min_len": 1, "max_len": 3}
    spec = ghcompute.build_spec(meta, cfg)

    total = cand.brute_total(CHARSET, 1, 3)
    chars = tuple(c.encode() for c in CHARSET)
    expected = next(i for i, p in enumerate(cand.brute_iter(chars, 1, 3, 0, total))
                    if p == b"q9z")

    passes = []
    for shard in range(4):
        out = str(tmp_path / f"found-{shard}.txt")
        _run_shard(spec, shard, 4, out)
        if os.path.isfile(out):
            with open(out, encoding="utf-8") as fh:
                passes += [(rec["i"], rec["p"].encode())
                           for rec in map(json.loads, fh)]
    passes.sort()
    assert (expected, b"q9z") in passes          # the truth is in there

    first = None
    for i, pwd in passes:                        # confirm in candidate order
        if testers._confirm_aes(path, meta["index"], pwd):
            first = pwd
            break
    assert first == b"q9z"


def test_ghshard_rejects_wordlist_modes(tmp_path):
    spec = {"mode": "dict", "salt_hex": "00" * 16, "dklen": 66,
            "pv_hex": "0000", "min_len": 1, "max_len": 3}
    with pytest.raises(SystemExit):
        ghshard.scan_shard(spec, 0, 1)


# ---------------------------------------------------------------- boundary
def test_validate_gh_accepts_and_normalizes():
    g = routes._validate_gh({"repo": " me/zippass ", "shards": "12"})
    assert g == {"repo": "me/zippass", "token": None, "ref": None, "shards": 12}
    assert routes._validate_gh(None) is None
    assert routes._validate_gh({}) is None


def test_validate_gh_rejects_junk():
    for bad in ({"repo": "no-slash"}, {"repo": "a/b", "shards": 0},
                {"repo": "a/b", "shards": 99}, {"repo": "a/b", "token": "x y"},
                "nope"):
        with pytest.raises(ValueError):
            routes._validate_gh(bad)
