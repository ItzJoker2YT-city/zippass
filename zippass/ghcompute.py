"""github actions offload - optional cloud boost for big aes attacks.

opt-in per job (ui checkbox / gh config). the flow:
  1. build a small json spec from the member's aes verifier fields +
     the attack config (brute/mask only - deterministic indexable spaces)
  2. dispatch zippass-crack in the user's repo; the workflow matrix fans
     out to `shards` runner vms (default 20 = free concurrency cap,
     4 cores each -> 80 cores on a public repo)
  3. poll the run; when it completes, download every found-shard-N
     artifact, sort verifier passes by global candidate index across
     shards, and confirm each against the real archive locally - first
     confirmed pass wins, exactly like the local scalar loop
the token lives in memory only (explicit paste or `gh auth token`);
it is never logged, written, or sent anywhere but api.github.com.
"""
import io
import json
import re
import subprocess
import time
import urllib.error
import urllib.request
import zipfile

from . import candidates as cand
from . import config

API = "https://api.github.com"
SPEC_MAX = 32000          # workflow_dispatch input sanity cap
GITHUB_URL_RE = re.compile(r"^https://github\.com/")


class GHError(RuntimeError):
    """github api failure with a user-safe message (never the token)."""


def _token(cfg: dict) -> str:
    """explicit token, else the local gh cli's token, else fail loud."""
    tok = cfg.get("token")
    if tok:
        return tok
    try:
        out = subprocess.run(["gh", "auth", "token"], capture_output=True,
                             text=True, timeout=10)
    except (OSError, subprocess.TimeoutExpired) as e:
        raise GHError(f"no gh.token given and gh cli unavailable: {e}") from e
    tok = (out.stdout or "").strip()
    if out.returncode != 0 or not tok:
        raise GHError("no gh.token given and `gh auth token` returned none - "
                      "run `gh auth login` or paste a token in the ui")
    return tok


class _NoAuthRedirect(urllib.request.HTTPRedirectHandler):
    """artifact downloads 302 to a signed azure blob url - that url
    carries its own auth in the query string, and forwarding our Bearer
    header to a foreign host makes storage reject the request (401)."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        new = super().redirect_request(req, fp, code, msg, headers, newurl)
        if new is not None:
            new.headers.pop("Authorization", None)
        return new


_OPENER = urllib.request.build_opener(_NoAuthRedirect)


def _api(method: str, repo: str, token: str, path: str, body=None):
    """one github rest call; returns parsed json (dict/list)."""
    base = f"{API}/repos/{repo}" if repo else API
    url = f"{base}/{path}" if path else base
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(url, data=data, method=method, headers={
        "Authorization": f"Bearer {token}",
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
        "User-Agent": "zippass-local",
        "Content-Type": "application/json",
    })
    try:
        with urllib.request.urlopen(req, timeout=30) as r:
            raw = r.read()
            return json.loads(raw) if raw else None
    except urllib.error.HTTPError as e:
        try:
            msg = json.loads(e.read() or b"{}").get("message", "")
        except Exception:                     # noqa: BLE001 - best effort
            msg = ""
        raise GHError(f"github api {e.code} on {path}: {msg}") from e
    except urllib.error.URLError as e:
        raise GHError(f"github api unreachable: {e.reason}") from e


def default_branch(repo: str, token: str) -> str:
    """repo's default branch - also the earliest token/repo sanity check."""
    return _api("GET", repo, token, "", None)["default_branch"]


def dispatch(repo: str, ref: str, spec: dict, shards: int, token: str) -> None:
    body = {"ref": ref, "inputs": {"spec": json.dumps(spec, separators=(",", ":")),
                                   "shards": str(shards)}}
    _api("POST", repo, token, "actions/workflows/crack.yml/dispatches", body)


def wait_for_run(repo: str, token: str, started: float,
                 timeout: float) -> dict:
    """the run created by our dispatch (newest workflow_dispatch after
    `started`); github returns no id from the dispatch itself."""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        runs = _api("GET", repo, token,
                    "actions/workflows/crack.yml/runs?per_page=5")
        for run in runs.get("workflow_runs", []):
            if (run.get("event") == "workflow_dispatch"
                    and run["created_at"] >= _iso_cutoff(started)):
                return run
        time.sleep(5)
    raise GHError("dispatched but no run appeared within the wait window - "
                  "check the repo's Actions tab and that crack.yml exists")


def _iso_cutoff(started: float) -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ",
                         time.gmtime(started - 120))  # clock-skew margin


def run_progress(repo: str, token: str, run_id: int) -> dict:
    """{status, conclusion, done, total, job_ids} for the run's crack jobs."""
    run = _api("GET", repo, token, f"actions/runs/{run_id}")
    jobs = _api("GET", repo, token, f"actions/runs/{run_id}/jobs?per_page=100")
    crack = [j for j in jobs.get("jobs", [])
             if j.get("name", "").startswith("crack")]
    done = sum(1 for j in crack if j.get("status") == "completed")
    return {"status": run.get("status"), "conclusion": run.get("conclusion"),
            "done": done, "total": len(crack),
            "job_ids": [j["id"] for j in crack]}


_LOG_TRIED = re.compile(r"scanned\s+(\d+)\s+candidates")


def parse_job_tried(log_text: str):
    """the shard's exact tried count from its log's last 'scanned N
    candidates' line (progress prints + the final summary share one
    phrasing); None when the log carries no progress lines."""
    found = _LOG_TRIED.findall(log_text or "")
    return int(found[-1]) if found else None


def job_log(repo: str, token: str, job_id: int) -> str:
    """one crack job's log text (redirects to blob storage - the
    no-auth redirect opener applies there too)."""
    req = urllib.request.Request(
        f"{API}/repos/{repo}/actions/jobs/{job_id}/logs",
        headers={"Authorization": f"Bearer {token}",
                 "User-Agent": "zippass-local"})
    try:
        with _OPENER.open(req, timeout=60) as r:
            return r.read().decode("utf-8", "replace")
    except (urllib.error.URLError, OSError):
        return ""                     # one unreadable log must not fail the job


def cancel(repo: str, token: str, run_id: int) -> None:
    try:
        _api("POST", repo, token, f"actions/runs/{run_id}/cancel", None)
    except GHError:
        pass                       # already finishing - stop proceeds anyway


def collect(repo: str, token: str, run_id: int) -> list:
    """all verifier passes from the run's found-* artifacts, in global
    candidate order: [(index, pwd_bytes)]."""
    arts = _api("GET", repo, token, f"actions/runs/{run_id}/artifacts?per_page=100")
    hits = []
    for a in arts.get("artifacts", []):
        if not a.get("name", "").startswith("found-") or a.get("expired"):
            continue
        req = urllib.request.Request(
            f"{API}/repos/{repo}/actions/artifacts/{a['id']}/zip",
            headers={"Authorization": f"Bearer {token}",
                     "User-Agent": "zippass-local"})
        with _OPENER.open(req, timeout=120) as r:
            hits += parse_found(r.read())
    hits.sort(key=lambda h: h[0])
    return hits


def parse_found(artifact_zip: bytes) -> list:
    """found-shard-N artifact bytes -> [(index, pwd_bytes)] - json lines."""
    out = []
    with zipfile.ZipFile(io.BytesIO(artifact_zip)) as zf:
        for name in zf.namelist():
            for line in zf.read(name).decode("utf-8").splitlines():
                if not line.strip():
                    continue
                rec = json.loads(line)
                out.append((int(rec["i"]), rec["p"].encode("utf-8")))
    return out


def build_spec(meta: dict, cfg: dict) -> dict:
    """the runner's whole world: verifier fields + attack shape."""
    spec = {
        "salt_hex": meta["salt"], "dklen": meta["dklen"],
        "pv_hex": meta["pv"], "mode": cfg["mode"],
        "min_len": cfg["min_len"], "max_len": cfg["max_len"],
    }
    if cfg["mode"] == "brute":
        spec["charset"] = cfg["charset"]
    else:
        spec["mask"] = cfg["mask"]
        spec["custom"] = cfg.get("custom") or {}
    blob = json.dumps(spec, separators=(",", ":"))
    if len(blob) > SPEC_MAX:
        raise GHError(f"attack spec too large for one dispatch ({len(blob)} B)")
    return spec


def run_gh_job(job) -> None:
    """cloud variant of jobs.run_job - drive one offloaded attack on a
    background thread. updates the same Job fields so the ui is identical
    (cloud jobs hold no local pool reservation, so there is no release)."""
    from . import testers
    gh, cfg, meta = job.gh, job.cfg, job.member
    try:
        with job.lock:
            job.state = "running"
        job.logline(f"cloud boost: dispatching {gh['shards']} shard(s) to "
                    f"{gh['repo']} ({cfg['mode']})")
        token = _token(gh)
        ref = gh.get("ref") or default_branch(gh["repo"], token)
        job.logline(f"repo {gh['repo']} ok, ref {ref}")
        spec = build_spec(meta, cfg)
        total = cand.estimate_total(cfg)
        with job.lock:
            job.total = total
        threading_start_tick(job)
        dispatch(gh["repo"], ref, spec, gh["shards"], token)
        job.logline("dispatched - waiting for the run to register")
        run = wait_for_run(gh["repo"], token, job.started,
                           config.GH_DISPATCH_WAIT)
        with job.lock:
            job.gh_run_url = run["html_url"]
        job.logline(f"run #{run['run_number']}: {run['html_url']}")

        prog, concl, last_shards = {}, None, -1
        while True:
            if job.stop.is_set():
                cancel(gh["repo"], token, run["id"])
                job._finalize("stopped", "stopped - run cancelled")
                return
            prog = run_progress(gh["repo"], token, run["id"])
            if total and prog["total"]:
                with job.lock:
                    job.done = int(total * prog["done"] / prog["total"])
            if prog["done"] != last_shards:
                last_shards = prog["done"]
                job.logline(f"cloud shards: {prog['done']}/{prog['total']} "
                            f"finished - live per-shard counts: "
                            f"{run['html_url']}/actions")
            if prog["status"] == "completed":
                concl = prog["conclusion"]
                break
            time.sleep(config.GH_POLL_SECS)

        # exact tried total from the shards' logs (progress prints + final
        # summaries); approximate per-shard math only if a log is unreadable
        exact_total, exact_ok = 0, True
        for jid in prog.get("job_ids", []):
            n = parse_job_tried(job_log(gh["repo"], token, jid))
            if n is None:
                exact_ok = False          # one unreadable log -> keep estimate
                break
            exact_total += n
        if exact_ok and prog.get("job_ids"):
            with job.lock:
                job.done = exact_total
            job.logline(f"exact cloud total: {exact_total:,} candidates tried")

        passes = collect(gh["repo"], token, run["id"])
        job.logline(f"{len(passes)} verifier pass(es) collected - "
                    f"confirming against the real archive")
        for idx, pwd in passes:
            with job.lock:
                job.done = idx + 1
            if testers._confirm_aes(meta["path"], meta["index"], pwd):
                found = pwd.decode("utf-8", "backslashreplace")
                with job.lock:
                    job.found = found
                job.logline(f"PASSWORD FOUND: {found}")
                job._finalize("found", "")
                early = False
                return
        if concl == "success":
            with job.lock:
                job.done = total
            job._finalize("exhausted", "cloud space exhausted")
        else:
            raise GHError(f"run finished as {concl} without a confirmed "
                          f"password - see {run['html_url']}")
    except Exception as e:  # noqa: BLE001 - background thread must never die silently
        with job.lock:
            job.error = str(e)
        job._finalize("error", f"error: {e}")


def threading_start_tick(job) -> None:
    """reuse jobs' rate/eta sampler."""
    from . import jobs
    import threading as _t
    _t.Thread(target=jobs._tick, args=(job,), daemon=True).start()
