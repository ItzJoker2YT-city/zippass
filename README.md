# zippass

Local web UI for zip password recovery. Upload a locked archive, see exactly how
each member is encrypted, then attack it with a dictionary, a mask, brute force,
a hybrid of wordlist + mask, or verify a pasted list of candidate passwords.

Runs entirely on your machine - all state (uploads, wordlists, jobs, logs) stays
in this directory. No telemetry, no external calls.

## How it works

| Layer | Module | Responsibility |
|---|---|---|
| entry point | `app.py` | wiring only: logging + app factory + serve |
| app factory | `zippass/__init__.py` | create app, register blueprint + error boundary |
| http | `zippass/routes.py` | thin controllers under `/api/v1`, input validation |
| structure | `zippass/cryptoparse.py` | per-member crypto metadata (AES / ZipCrypto / plain) |
| cipher | `zippass/pkware.py` | vendored PKWARE zipcrypto stream cipher |
| testing | `zippass/testers.py` | fast password testers + full-read confirmation |
| candidates | `zippass/candidates.py` | wordlist / mask / brute / hybrid generators |
| execution | `zippass/jobs.py` | job runner thread + worker pool + rate sampling |
| state | `zippass/state.py` | uploads/members/jobs tables + prune helpers |
| bridge | `zippass/bridge.py` | zip2john → john/hashcat command export |
| config | `zippass/config.py` | every tunable, env-driven where deployment varies |
| errors | `zippass/errors.py` | JSON errors to clients, tracebacks to the log only |
| ui | `zippass/templates/index.html` | single-page frontend |

## Engines

- **ZipCrypto (traditional pkzip)** - vendored cipher on the 12-byte encryption
  header. Wrong passwords are kept off the full-read confirmation by two
  writer-independent filters: the header check byte (1/256 survives), then a
  **deflate prefilter** - big deflate members carry an encrypted ~512-byte head
  of their compressed data in the member metadata; a 1/256 survivor's keys
  decrypt it and the raw stream must stay decodable (real data always decodes,
  wrong-password garbage almost always dies inside the first block). Only then
  is the full CRC-verified read run. Note header byte 10 is a *writer
  convention*, not part of the pkware spec, and is deliberately not used as a
  filter (archives written by different tools store junk there and would reject
  the real password).
- **Vector fast path (numpy + numba, ZipCrypto only)** - the filter pipeline
  above runs over *batches*, not one password at a time: `fastfilter` executes
  the key schedule, 12-byte header decrypt and check-byte compare for
  thousands of candidates as uint32 array ops (bit-exact by construction -
  the 16-bit identity for the decrypt byte and mod-2^32 wrap semantics match
  the scalar math); `matbuild` builds the candidate matrices in exactly the
  scalar iterators' order (odometer blocks for brute/mask, length-banded
  line blocks for dict/hybrid - bands keep each batch's padded width
  tracking its own rows so a few long lines cannot poison a chunk), with
  the per-row key schedule, header check and matrix fills themselves JIT'd
  (`pkfast.schedule_batch`, `dict_fill`, `hybrid_fill`). Survivors of the
  batched check-byte pass into a numba-JIT batched 512-byte prefilter
  decrypt (`pkfast.decrypt_rows`), and the final CRC-verified confirm is a
  JIT full-member decrypt + inflate + CRC + size check
  (`pkfast.confirm_zc`) - milliseconds instead of the seconds a pure-python
  zipfile read costs on a multi-MB member. Measured on the reference box
  (4 workers, against a 1.35 MB deflate member): brute ~3.2M tries/s, dict
  ~2.1-2.6M words/s, hybrid ~3.2M candidates/s - roughly 130x the scalar
  scanners. The scalar scanners remain the reference and the fallback:
  `ZIPPASS_VECTOR=0` disables the fast path (numba missing disables it too),
  multi-byte charset entries and odometer spaces beyond uint64 indexing
  fall back per-task, and any fast-path exception degrades to the scalar
  scan with a stderr note. `tests/test_fastfilter.py` pins the two
  implementations to identical `(tried, hit, sample)` triples across all
  four modes, real archives (big/small members, data-descriptor flag), hits
  at start/middle/end/absent, and the exact matrix orders.
- **WinZip AES (AE-1/AE-2)** - PBKDF2-HMAC-SHA1 verifier per the spec (fixed
  1000 iterations, `dkLen = 2*key_length + 2`, verifier = last 2 bytes of the
  derived data), then a full pyzipper MAC confirmation on verifier hits.
  Only the last output block is ever compared and each block is independent,
  so a candidate costs 2·1000+2 sha1 compressions instead of openssl's
  full-`dkLen` chain (AES-256: 2002 vs 16000 blocks). The hot path is
  `rust/aesfast_rs` (built to `zippass/_native/aesfast_rs.dll`, loaded via
  `zippass/rustfast.py`): hand-rolled sha1 with fully unrolled rounds, and
  a multi-buffer chain where the lanes are *different candidates* (one
  candidate's 999-iteration chain is serial, so lanes in flight are what
  count) - 8-way avx2 when the CPU has it (measured 1.6x over 4-way: the
  round chain is latency-bound, not throughput-bound), else 4-way sse2,
  with a scalar tail for batch remainders. `ZIPPASS_RUST_MAXWIDTH=4|1`
  forces the narrower path for a/b timing. Scanner feeds 256-candidate
  batches through one ctypes call; ~0.08 ms/candidate single-thread vs
  ~0.15 on 4-way, ~0.5-0.8 ms for the numba kernel (`zippass/aesfast.py`)
  and 3.1-5.2 ms for `hashlib.pbkdf2_hmac`. Bit exactness against hashlib
  is pinned by tests across every strength/salt/password shape (keys >
  64 bytes hash down first), per simd lane; the batched scanner returns
  the exact (tried, hit, sample) triples of the scalar loop. Fallback
  chain: rust dll missing -> numba -> openssl, same verdicts throughout.
- **Execution** - one persistent worker pool per server process (Windows spawn
  costs ~1-2s + a full interpreter per worker, so pools are never spawned per
  job). Sizing is workload-weighted: AES-bound jobs default to `cpu_count`
  workers, ZipCrypto jobs to `min(4, cpu_count)` (measured: ZipCrypto
  throughput *drops* past 4 concurrent workers; AES scales). An idle
  size-mismatched pool is resized; a pool is discarded only after a job
  died unexpectedly (error). Tasks are fed in finite batches (~2 tasks
  per worker per dispatch, AES tasks capped at 4096 candidates each), so
  the queue never holds more than one batch per job: jobs sharing the
  pool interleave fairly instead of one starving the other, and a
  found/stopped job leaves at most one batch of orphan work that drains
  on its own. Workers generate candidates themselves - brute/mask jobs
  ship integer index ranges, dict/hybrid jobs ship whole-line byte
  ranges of the wordlist file - so no candidate password is ever
  pickled or shipped.
- **GPU export** - when John the Ripper is installed, one click runs `zip2john`
  and emits the hash plus ready-to-run john/hashcat commands (`-m 13600` for
  WinZip AES, `-m 17200/17210/17220` for PKZIP) for GPU-class attacks.

Measured on the dev VM (a throttled 8-LP box - a real desktop runs several
times faster): ZipCrypto ~45-75k guesses/s aggregate at 4 workers; AES
~23k/s aggregate live on a real AES-256 member (641/s with plain openssl
on the same job, ~4.1k/s with the numba kernel) - the 1000-iteration
PBKDF2 is fixed by the format, so no CPU reaches millions/s on AES; that
is the wall, not the code. Hard passwords belong on the GPU export path.

## Goose port (experimental standalone cracker)

`goose/aescrack.goose` is a self-contained winzip-aes verifier + brute
forcer written in [Goose](https://github.com/aardappel/goose) - the same
folded last-block pbkdf2 as the rust kernel, with a 16-word ring sha1
schedule and one worker thread per shard (default 4, one per core).
Selftest is bit-exact against `hashlib.pbkdf2_hmac`; brute results carry
the exact global candidate index, identical to a single-threaded scan.

```
# toolchain: any goose release on PATH, plus a C compiler for native builds
goose build goose/aescrack.goose --cc gcc        # native exe (needed for threads)
goose/aescrack.exe                                # selftest vs hashlib vectors
goose/aescrack.exe <salt_hex> <dklen> <pv_hex> <charset> <min> <max> [threads]
# e.g. goose/aescrack.exe 000102030405060708090a0b0c0d0e0f 66 47a1 abcdefghijklmnopqrstuvwxyz0123456789 1 3
```

Measured on this box: ~4.7k tries/s aggregate at 4 threads (native,
ring schedule) - slower per-core than the rust 8-way avx2 kernel in the
app, but zero python/rust dependencies once built.

## Quickstart

```
pip install -r requirements.txt
python app.py            # NOT `flask run` - windows spawn needs the script entry
```

Open http://127.0.0.1:5000, drop a `.zip`, pick an attack. The page now
guides a first-time user: a 3-step "how to use" card, four one-click
quick-start buttons (1M common passwords ~1 sec · digits 1-6 ~1 sec ·
rockyou 14M ~10 sec · words+2 digits ~5-10 min), a plain-English
explanation under every attack tab, a live candidate-count + time
estimate for mask/brute/hybrid as you type (~2M tries/s assumed - the
progress card shows the real rate once running), and a workers field
that applies to every mode (leave empty = automatic).

- `wordlists/` ships with eight built-in lists: the two top-1M dumps the
  quick-start buttons use (`common-passwords-1m.txt`,
  `common-passwords-1m-b.txt`), `rockyou.txt` (14.3M), the full 10M
  Xato dump (`common-10m-xato.txt`), and curated high-density lists
  (`probable-top12k.txt`, `ncsc-top100k.txt`, `darkweb-10k.txt`,
  `common-10k.txt`). Any other `.txt` dropped there appears in the picker.
- Uploaded wordlists land in the same folder.
- "exhausted" means the attack tried its entire space and the password
  is not that type - move to the next quick-start button.

## API (v1)

| Method | Path | Purpose |
|---|---|---|
| POST | `/api/v1/uploads` | upload a zip (multipart `file`) |
| GET | `/api/v1/uploads` | list uploads held server-side, newest first |
| POST | `/api/v1/wordlists` | upload a wordlist |
| GET | `/api/v1/wordlists` | list server-side wordlists |
| GET | `/api/v1/archives/<id>` | analyze: members + crypto kinds |
| POST | `/api/v1/jobs` | start an attack (`zip_id`, `mode`, config) |
| GET | `/api/v1/jobs` | list all jobs, newest first (refresh reattach) |
| GET | `/api/v1/jobs/<id>` | live status (state, done, rate, eta, found, log) |
| POST | `/api/v1/jobs/<id>/stop` | request stop (idempotent) |
| POST | `/api/v1/archives/<id>/verify` | check pasted passwords |
| GET | `/api/v1/archives/<id>/export` | zip2john hash + john/hashcat commands |

Attack modes and fields:

- `dict` - `wordlist` (path under the app root or an allowed root)
- `mask` - `mask` (`?l ?u ?d ?s ?h ?a ?1..?4`), `custom` (`c1`..`c4`)
- `brute` - `charset`, `min_len`, `max_len` (0..64)
- `hybrid` - `wordlist`, `prefix`, `suffix_mask`

All input is validated at the boundary with field-level 400s; wordlist paths
outside the allowed roots get a 403.

Refreshing the page never stops an attack: jobs run server-side, and on load
the page reattaches to the newest job (preferring a running one) and the
newest upload, restoring the archive card and live progress automatically.
Closing the browser tab is equally safe - only the stop button (or the job
finishing) ends an attack.

## Configuration (environment variables)

| Variable | Default | Meaning |
|---|---|---|
| `ZIPPASS_HOST` | `127.0.0.1` | bind address (keep local - there is no auth) |
| `ZIPPASS_PORT` | `5000` | listen port |
| `ZIPPASS_MAX_UPLOAD_MB` | `2048` | upload size cap |
| `ZIPPASS_TASK_RANGE` | `65536` | max candidates per worker task (brute/mask; auto-scaled down to keep every worker fed) |
| `ZIPPASS_DICT_CHUNK` | `1048576` | wordlist bytes per worker task |
| `ZIPPASS_VECTOR` | `1` | `0` disables the numpy/numba fast path (scalar scans everywhere) |
| `ZIPPASS_MAX_WORD_LEN` | `512` | skip wordlist lines longer than this |
| `ZIPPASS_MAX_WORKERS` | `64` | worker-process cap |
| `ZIPPASS_MAX_UPLOADS_KEPT` | `50` | oldest uploads pruned beyond this |
| `ZIPPASS_MAX_JOBS_KEPT` | `50` | oldest terminal jobs pruned beyond this |
| `ZIPPASS_WORDLIST_ROOTS` | - | extra allowed wordlist roots (`os.pathsep`-separated) |

## Tests

```
python -m pytest tests -q
```

46 tests. Coverage: PKWARE cipher roundtrip, mask/brute index-generation
verified byte-for-byte against `itertools.product`, wordlist chunk tiling,
archive parsing for all three member kinds (including data-descriptor
archives), scanner-level hits with counting semantics, input validation at
the API boundary (bad mask, path traversal 403, non-zip upload), and live
end-to-end dictionary crack + mid-brute stop through the HTTP layer.

## Security notes

- Binds to loopback by default; there is no authentication. Do not expose it.
- Wordlist paths are sandboxed to the app root (plus `ZIPPASS_WORDLIST_ROOTS`).
- Uploads are magic-checked, size-capped, and pruned by age/count.
- Stack traces never leave the server: they go to `zippass.log`; clients get
  short JSON errors.
- Found passwords are written to the job log by design - that is the product.
  Treat `zippass.log` and the uploads directory as sensitive.

## Known limits

- Windows spawn cost (~1-2s) is paid once per server process; a pool is
  discarded only after a job errors, so found/stopped jobs hand it to
  the next attack unchanged.
- Worker defaults: ZipCrypto `min(4, cpu_count)`, AES `cpu_count`; the UI
  `workers` field (or a job's `workers` value) always wins for its job.
- AES confirm reads the whole target member - the backend picks the smallest
  encrypted member for that reason; pin a different one only if you know it is
  small.
- The `tried` counter is approximate while running: results arrive out of
  order from the pool, so it counts candidates from *completed* tasks only
  (same semantics as before; the final count on completion is exact).
- Legacy OEM-encoded passwords display with `\x` escapes; matching is on bytes.
- All state (uploads, jobs) is in-memory plus files on disk: restarting the
  server drops the job table; a refreshed page then shows "gone" for old jobs.
- The `rate` counter reads 0/s for jobs that finish inside one 0.7s sampling
  window; the final rate is filled in on completion.
