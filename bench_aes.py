"""aes per-candidate cost breakdown - where do the 12.4 ms/worker go?

times the ways to get the 2-byte winzip verifier from one password:
  a) openssl full derivation      hashlib.pbkdf2_hmac (fallback)
  b) hmac.new chain, last block   one pbkdf2 block, fresh hmac per iteration
  c) state-copy chain, last block precomputed ipad/opad states + copies
  d) the shipped tester closure   jit verifier + pv check + pyzipper confirm
  e) aesfast verify_pv alone      numba folded last-block kernel
  f) rust batch verifier          scalar (1-pwd batches) and 4-way simd
also verifies b/c produce bit-identical verifier bytes to a, and that the
true password confirms. run: python bench_aes.py [--server] [true_password]
"""
import glob
import hashlib
import hmac
import os
import struct
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
ROOT = os.path.dirname(os.path.abspath(__file__))

from zippass import cryptoparse, testers  # noqa: E402

_flags = [a for a in sys.argv[1:] if not a.startswith("--")]
TRUE_PWD = (_flags[0].encode() if _flags else b"mana")

# ---------------------------------------------------------------- find meta
found = []
for p in sorted(glob.glob(os.path.join(ROOT, "uploads", "*.zip"))):
    try:
        members = cryptoparse.parse_members(p)
    except Exception:
        continue
    for m in members:
        if m["kind"] == "aes":
            found.append((p, m))
if found:
    mp3 = [x for x in found if "alaba" in x[1]["name"].lower()]
    target = (mp3 or found)[0]
    for p, m in found:
        print(f"aes member: {m['name']!r} file={os.path.basename(p)} "
              f"salt_len={m['salt_len']} dklen={m['dklen']} "
              f"csize={m['csize']:,}")
else:
    p = os.path.join(ROOT, "tests", "aes.zip")
    m = cryptoparse.pick_member(cryptoparse.parse_members(p))
    print(f"no aes upload found - using {p}: dklen={m['dklen']}")
    target = (p, m)

path, meta = target
salt = bytes.fromhex(meta["salt"])
pv = bytes.fromhex(meta["pv"])
dklen = meta["dklen"]
NB = (dklen + 19) // 20                     # pbkdf2 output blocks
R = dklen - 20 * (NB - 1)                   # bytes used from the last block
print(f"verifier block: n={NB} used={R} -> chain derives 1 block, "
      f"slice [{R-2}:{R}]")

N = 300
pwds = [b"wrong%04d" % i for i in range(N)]


def timeit(fn):
    t0 = time.perf_counter()
    for p in pwds:
        fn(p)
    return (time.perf_counter() - t0) / N * 1000


def full_pbkdf2(p):
    return hashlib.pbkdf2_hmac("sha1", p, salt, 1000, dklen)[-2:]


def hmac_new_chain(p):
    u = hmac.new(p, salt + struct.pack(">I", NB), hashlib.sha1).digest()
    acc = int.from_bytes(u, "big")          # T_n = U1 ^ U2 ^ ... ^ U1000
    for _ in range(999):
        u = hmac.new(p, u, hashlib.sha1).digest()
        acc ^= int.from_bytes(u, "big")
    return ((acc >> (8 * (20 - R))) & 0xFFFF).to_bytes(2, "big")  # first R bytes' last two


def _key_blocks(p):
    k = hashlib.sha1(p).digest() if len(p) > 64 else p
    k = k + b"\x00" * (64 - len(k))
    return (hashlib.sha1(bytes(b ^ 0x36 for b in k)),
            hashlib.sha1(bytes(b ^ 0x5C for b in k)))


def state_copy_chain(p):
    inner0, outer0 = _key_blocks(p)
    inner = inner0.copy()
    inner.update(salt)
    inner.update(struct.pack(">I", NB))
    u = outer0.copy()
    u.update(inner.digest())
    u = u.digest()
    acc = int.from_bytes(u, "big")
    for _ in range(999):
        inner = inner0.copy()
        inner.update(u)
        outer = outer0.copy()
        outer.update(inner.digest())
        u = outer.digest()
        acc ^= int.from_bytes(u, "big")
    return ((acc >> (8 * (20 - R))) & 0xFFFF).to_bytes(2, "big")


# ------------------------------------------------- bit-exactness vs openssl
ref = [full_pbkdf2(p) for p in pwds]
b = [hmac_new_chain(p) for p in pwds]
c = [state_copy_chain(p) for p in pwds]
assert b == ref, "hmac.new chain diverges from openssl"
assert c == ref, "state-copy chain diverges from openssl"
print("bit-exactness: chains == openssl full derivation on 300 pwds  OK")

# ------------------------------------------------------------------- timing
t_a = timeit(full_pbkdf2)
t_b = timeit(hmac_new_chain)
t_c = timeit(state_copy_chain)
print(f"a) openssl full dklen={dklen}: {t_a:8.3f} ms/candidate")
print(f"b) hmac.new last-block chain : {t_b:8.3f} ms/candidate "
      f"({t_a/t_b:4.2f}x)")
print(f"c) state-copy last-block     : {t_c:8.3f} ms/candidate "
      f"({t_a/t_c:4.2f}x)")

# ------------------------------------------------------------- shipped path
tester = testers.tester_for(meta)
t_d = timeit(tester)
print(f"d) shipped tester (jit verifier) : {t_d:8.3f} ms/candidate "
      f"({t_a/t_d:4.2f}x vs openssl full)")
if testers.aesfast is not None and testers.aesfast.HAS_NUMBA:
    from zippass import aesfast
    ver = aesfast.make_verifier(salt, dklen, pv)
    t_e = timeit(ver)
    print(f"e) aesfast verify_pv alone       : {t_e:8.3f} ms/candidate "
          f"({t_a/t_e:4.2f}x)")

# ---------------------------------------------------------- rust verifier
from zippass import rustfast  # noqa: E402

bv = rustfast.make_batch_verifier(salt, dklen, pv)
if bv is not None:
    big = [b"wrong%06d" % i for i in range(1024)]
    t0 = time.perf_counter()
    for off in range(0, 1024, 256):
        bv(big[off:off + 256])
    t_f = (time.perf_counter() - t0) / 1024 * 1000
    print(f"f) rust simd batch (8-way avx2): {t_f:8.3f} ms/candidate "
          f"({t_a/t_f:5.1f}x vs openssl, {t_e/t_f:4.1f}x vs numba)")
    hits = bv([TRUE_PWD])
    assert hits == [0], f"true pwd not flagged: {hits}"
    print(f"true password {TRUE_PWD!r} flagged by rust verifier OK")

assert tester(TRUE_PWD) is True, "true password does not confirm!"
print(f"true password {TRUE_PWD!r} confirms OK")

# raw sha1 block rate for context
blk = os.urandom(64)
t0 = time.perf_counter()
for _ in range(20000):
    hashlib.sha1(blk).digest()
per = (time.perf_counter() - t0) / 20000
print(f"raw hashlib sha1 (1 block): {per*1e9:7.0f} ns/call "
      f"-> {1/per/1e6:.1f}M calls/s")

# ------------------------------------------------- server-level end-to-end
# the user's real scenario: brute lower+digits 1-4 over the real AES member
# ('mana' sits ~608k candidates in). before the jit verifier this ran at
# 641 tries/s aggregate (8 workers, openssl pbkdf2, found in 5m52s).
if "--server" in sys.argv:
    import json

    from check_refresh import call, upload

    zid = upload(path)["id"]
    cfg = {"mode": "brute", "charset": "abcdefghijklmnopqrstuvwxyz0123456789",
           "min_len": 1, "max_len": 4, "zip_id": zid}
    jid = call("/jobs", data=json.dumps(cfg).encode(),
               headers={"Content-Type": "application/json"})["job_id"]
    print(f"server aes job {jid}: brute lower+digits 1-4 ...")
    t0 = time.monotonic()
    while True:
        time.sleep(0.5)
        s = call(f"/jobs/{jid}")
        if s["state"] in ("found", "exhausted", "stopped", "error"):
            break
    dt = time.monotonic() - t0
    print(f"SERVER: state={s['state']} done={s['done']:,} in {dt:.0f}s "
          f"-> {s['done']/dt:,.0f} tries/s aggregate "
          f"(was 641/s before the jit verifier)")
    if s["found"]:
        print(f"  password: {s['found']}")
