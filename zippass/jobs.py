"""attack job lifecycle - persistent worker pool + lean task dispatch.

the pool is spawned once per process and reused for every job (on windows a
worker is a full spawned interpreter, ~1-2s + tens of MB each, so per-job
pools waste both). brute/mask jobs ship index ranges and workers generate
candidates locally; dict/hybrid jobs ship whole-line file ranges. task
feeding is batched: a job submits finite batches (~2 tasks per worker)
and drains each before submitting the next. mp.Pool has a single
task-handler thread that stays inside one task sequence until it ends,
so per-job streams - even windowed ones - would starve a job that joins
the shared pool later; finite batches keep the handler free, the
workers' FIFO queue interleaves concurrent jobs' tasks, and a stopped
job leaves at most one harmless batch of orphan work.
"""
import logging
import multiprocessing as mp
import multiprocessing.pool  # noqa: F401  - mp.pool.TERMINATE in quiesce_pool_for_exit
import os
import threading
import time
from itertools import islice

from . import candidates as cand
from . import config
from . import testers

log = logging.getLogger("zippass.jobs")

TERMINAL = ("found", "exhausted", "stopped", "error")

_SCANNERS = {
    "dict": testers.scan_dict,
    "hybrid": testers.scan_hybrid,
    "brute": testers.scan_brute,
    "mask": testers.scan_mask,
}


class Job:
    """one attack run: config, target member, counters, live log."""

    def __init__(self, jid: str, zip_id: str, member: dict, cfg: dict) -> None:
        self.id = jid
        self.zip_id = zip_id
        self.member = member
        self.cfg = cfg
        self.state = "queued"
        self.done = 0
        self.total = None
        self.rate = 0.0
        self.eta = None
        self.found = None
        self.sample = None
        self.error = None
        self.started = time.time()          # wall clock: display + prune order
        self.started_mono = time.monotonic()  # clock-jump-proof duration math
        self.ended = None
        self.stop = threading.Event()
        self.lock = threading.Lock()
        self.log = []

    def logline(self, msg: str) -> None:
        self.log.append(time.strftime("%H:%M:%S ") + msg)

    def _finalize(self, state: str, note: str) -> None:
        with self.lock:
            if self.state not in TERMINAL:
                self.state = state
                self.ended = time.time()
                elapsed = max(time.monotonic() - self.started_mono, 1e-6)
                self.rate = self.done / elapsed
        if note:
            self.logline(note)


_POOL = None
_POOL_SIZE = 0
_POOL_USERS = 0      # jobs currently holding the pool
_POOL_DIRTY = False  # a job errored mid-run; discard the pool when idle
_POOL_LOCK = threading.Lock()


def get_pool(workers_hint=None, heavy: bool = False):
    """return (pool, size, spawned).

    sizing is workload-dependent when the caller gives no hint: aes-bound
    jobs (3ms of C per candidate - pbkdf2) scale to cpu_count, zipcrypto
    jobs (24us of python per candidate) flatten past ~4 workers, so they
    default to min(4, cpu_count). an explicit hint always wins. the pool
    resizes only while no other job holds it.

    a dirty pool (previous job errored and left tasks of unknown state)
    is retired off-thread and replaced - a fresh job must never queue
    behind a broken pool.
    """
    global _POOL, _POOL_SIZE, _POOL_USERS, _POOL_DIRTY
    cpus = os.cpu_count() or 4
    doomed = None
    with _POOL_LOCK:
        want = int(workers_hint or (cpus if heavy else min(4, cpus)))
        want = max(1, min(want, config.MAX_WORKERS))
        if _POOL is not None and _POOL_USERS == 0 and _POOL_DIRTY:
            doomed, _POOL = _POOL, None            # stale tasks in queue
            _POOL_DIRTY = False
        if _POOL is not None and want != _POOL_SIZE and _POOL_USERS == 0:
            doomed, _POOL = _POOL, None            # wrong width for this job
        if _POOL is None:
            _POOL = mp.Pool(processes=want)
            _POOL_SIZE = want
            _POOL_DIRTY = False
            log.info("worker pool spawned: %d processes", want)
        _POOL_USERS += 1
        pool, size, spawned = _POOL, _POOL_SIZE, _POOL_USERS == 1
    if doomed is not None:
        _retire_async(doomed)
        log.info("worker pool retired for a fresh %d-process pool", want)
    return pool, size, spawned


def _retire_async(pool) -> None:
    """terminate a retired pool on a throwaway thread.

    windows pool.terminate() has been observed to wedge on this box; running
    it here means a wedge can only strand one daemon thread (and idle
    workers), never jam get_pool or a job thread."""
    def retire():
        try:
            pool.terminate()
            pool.join()
            log.info("worker pool retired")
        except Exception as e:  # noqa: BLE001 - best-effort teardown
            log.warning("worker pool retire failed: %s", e)
    threading.Thread(target=retire, daemon=True).start()


def release_pool(early_exit: bool) -> None:
    """drop the job's reservation. only a job that died unexpectedly
    (error) leaves tasks whose state is unknown - mark the pool dirty so
    the next get_pool replaces it. hits/stops strand at most one tiny
    batch, which drains on its own. teardown happens off-thread."""
    global _POOL_USERS, _POOL_DIRTY
    with _POOL_LOCK:
        _POOL_USERS -= 1
        if early_exit:
            _POOL_DIRTY = True


def _warm_worker() -> None:
    """prewarm barrier - one import+result roundtrip, plus the jit aes
    verifier compile so the first AES job skips it."""
    try:
        from . import testers
        testers.prewarm_aes()
    except Exception:                # noqa: BLE001 - prewarm is best-effort
        pass


def prewarm_pool() -> None:
    """spawn and warm the shared worker pool at server startup.

    a windows spawn worker pays ~1-2s of interpreter start plus the
    zippass/numba import chain; prepaying it at boot means the user's
    first job starts at full speed instead of eating the cost. the
    reservation is released immediately so later jobs can still resize
    the pool (e.g. an aes job scaling to cpu_count).
    """
    try:
        pool, size, spawned = get_pool()
    except Exception as e:  # noqa: BLE001 - prewarm is best-effort
        log.warning("pool prewarm skipped: %s", e)
        return
    try:
        if spawned:
            warm = [pool.apply_async(_warm_worker) for _ in range(size)]
            for r in warm:
                r.get(timeout=60)
    except Exception as e:  # noqa: BLE001 - prewarm is best-effort
        log.warning("pool prewarm incomplete: %s", e)
    finally:
        release_pool(False)


def _step_for(total: int, heavy: bool = False) -> int:
    """task size for brute/mask: small enough that every worker stays fed
    (>= ~16 tasks per worker on small spaces), bounded for huge ones.
    aes tasks are capped at 4096 candidates (~2-3s of pbkdf2 each) so a job
    joining the shared pool never queues behind minutes of one task."""
    if heavy:
        return max(256, min(4096, total // max(1, _POOL_SIZE * 16)))
    return max(4096, min(config.TASK_RANGE, total // max(1, _POOL_SIZE * 16)))


def _batches(cfg: dict, meta: dict, size: int):
    """yield finite task batches - one imap_unordered call per batch.

    mp.Pool has a single task-handler thread that stays inside one task
    sequence until it ends. a per-job stream (even a windowed one) keeps
    that thread busy for the whole attack, so a job joining the shared
    pool later never gets its own stream served and starves. finite
    batches end immediately: the handler submits one within microseconds
    and then serves the next job's stream, the workers' FIFO task queue
    interleaves concurrent jobs' tasks, and the queue never holds more
    than one batch (~2 tasks per worker) per job - so a stopped or found
    job strands only seconds of harmless orphan work.
    """
    stream = _task_stream(cfg, meta)
    while True:
        batch = list(islice(stream, size + 2))
        if not batch:
            return
        yield batch


def _task_stream(cfg: dict, meta: dict):
    """worker tasks per mode - tiny tuples, never the candidates themselves."""
    mode = cfg["mode"]
    if mode == "dict":
        for a, b in cand.line_chunks(cfg["wordlist"], config.DICT_CHUNK):
            yield (meta, cfg["wordlist"], a, b)
    elif mode == "hybrid":
        prefix = (cfg.get("prefix") or "").encode("utf-8")
        suffix = tuple(tuple(c.encode("utf-8") for c in s)
                       for s in cand.mask_sets(cfg.get("suffix_mask") or "",
                                               cfg.get("custom") or {}))
        for a, b in cand.line_chunks(cfg["wordlist"], config.DICT_CHUNK):
            yield (meta, cfg["wordlist"], a, b, prefix, suffix)
    elif mode == "brute":
        charset = tuple(c.encode("utf-8") for c in cfg["charset"])
        total = cand.brute_total(cfg["charset"], cfg["min_len"], cfg["max_len"])
        step = _step_for(total, meta["kind"] == "aes")
        for start in range(0, total, step):
            yield (meta, charset, cfg["min_len"], cfg["max_len"],
                   start, min(step, total - start))
    elif mode == "mask":
        sets = tuple(tuple(c.encode("utf-8") for c in s)
                     for s in cand.mask_sets(cfg["mask"], cfg.get("custom") or {}))
        total = cand.mask_space(sets)
        step = _step_for(total, meta["kind"] == "aes")
        for start in range(0, total, step):
            yield (meta, sets, start, min(step, total - start))


def run_job(job: Job) -> None:
    """drive one attack on a background thread using the shared pool."""
    meta = job.member
    early_exit = True
    try:
        with job.lock:
            job.state = "running"
        job.logline(f"attack '{job.cfg['mode']}' started, target "
                    f"{meta['name']} ({meta['kind']})")
        threading.Thread(target=_tick, args=(job,), daemon=True).start()
        pool, size, spawned = get_pool(job.cfg.get("workers"),
                                       heavy=meta["kind"] == "aes")
        job.logline(f"{'spawned' if spawned else 'reusing'} worker pool: "
                    f"{size} processes")
        _total_async(job)      # space size off the hot path: dispatch first,
        # the count fills in when ready (ui shows an indeterminate bar)
        scanner = _SCANNERS[job.cfg["mode"]]
        for batch in _batches(job.cfg, meta, size):
            if job.stop.is_set():
                break              # stop clicked - never feed another batch
            it = pool.imap_unordered(scanner, batch, chunksize=1)
            while True:
                try:
                    tried, hit, sample = it.next(timeout=1.0)
                except mp.TimeoutError:
                    if (job.stop.is_set()
                            or getattr(pool, "_state", "RUN") != "RUN"):
                        break      # stop clicked, or the pool was torn
                        # down underneath us - no more results coming;
                        # bail within ~1s, never wait out a worker task
                        # (AES tasks run seconds)
                    continue       # nothing ready - re-check every second
                except StopIteration:
                    break          # batch fully consumed
                with job.lock:
                    job.done += tried
                    if sample:
                        job.sample = sample.decode("utf-8",
                                                   "backslashreplace")
                if hit:
                    with job.lock:
                        job.found = hit.decode("utf-8", "backslashreplace")
                    job.logline(f"PASSWORD FOUND: {job.found}")
                    job._finalize("found", "")
                    early_exit = False  # one orphan batch drains itself
                    return
            if job.stop.is_set() or getattr(pool, "_state", "RUN") != "RUN":
                break              # nothing left to feed: stopped, or the
                # pool's workers are gone (e.g. torn down underneath us)
        if job.stop.is_set():
            early_exit = False     # orphans (<= 1 tiny batch) drain on
            # their own - the pool stays clean and reusable
            job._finalize("stopped", "stopped by user")
        elif getattr(pool, "_state", "RUN") != "RUN":
            job._finalize("error", "worker pool was torn down mid-attack")
        else:
            early_exit = False     # every batch was consumed - pool clean
            job._finalize("exhausted", "search space exhausted")
    except Exception as e:  # noqa: BLE001 - background thread must never die silently
        with job.lock:
            job.error = str(e)
        job._finalize("error", f"error: {e}")
    finally:
        release_pool(early_exit)


def _total_async(job: Job) -> None:
    """fill job.total in a side thread - counting a 14M-line wordlist
    reads the whole file, and that must not stall the first dispatch."""

    def fill() -> None:
        total = cand.estimate_total(job.cfg)
        if total is not None:
            with job.lock:
                if job.state == "running":     # a fast stop beat the count
                    job.total = total

    threading.Thread(target=fill, daemon=True).start()


def _tick(job: Job) -> None:
    """sample done-counters into rate/eta while the job runs."""
    prev_t, prev_d = time.monotonic(), 0
    while True:
        time.sleep(0.7)
        with job.lock:
            done, state = job.done, job.state
        if state != "running":
            return
        now = time.monotonic()
        dt = now - prev_t
        if dt > 0:
            with job.lock:
                job.rate = (done - prev_d) / dt
                if job.total and job.rate > 0:
                    job.eta = max(0.0, (job.total - done) / job.rate)
        prev_t, prev_d = now, done


def request_stop(job: Job) -> None:
    """idempotent stop request."""
    job.stop.set()
    with job.lock:
        if job.state == "running":
            job.state = "stopping"


def quiesce_pool_for_exit() -> None:
    """silence Pool.__del__ during interpreter finalization.

    short-lived hosts (pytest, CLI checks) exit with the persistent pool
    still alive; by then finalization has already torn down the queues
    __del__ wants to poke ('NoneType' object has no attribute 'dumps').
    marking the pool non-RUN keeps __del__ quiet - the pool's own
    registered finalizer still does the real teardown."""
    pool = _POOL
    if pool is not None:
        try:
            pool._state = mp.pool.TERMINATE
        except Exception:  # noqa: BLE001 - exit path must never raise
            pass
