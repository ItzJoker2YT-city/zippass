"""http boundary - thin controllers; all logic lives in the service modules."""
import os
import threading
import time
import uuid

from flask import Blueprint, jsonify, render_template, request

from . import bridge, candidates, config, cryptoparse, jobs, state
from .testers import tester_for

bp = Blueprint("api", __name__, url_prefix="/api/v1")
ui = Blueprint("ui", __name__)

_MODES = ("dict", "mask", "brute", "hybrid")


@ui.get("/")
def index():
    """single-page frontend."""
    return render_template("index.html")


# ---------------------------------------------------------------- uploads

@bp.get("/uploads")
def list_uploads():
    """uploads still held server-side, newest first - a refreshed page
    reattaches to these instead of showing an empty state."""
    items = []
    for zid, u in state.UPLOADS.items():
        try:
            mt = os.path.getmtime(u["path"])
        except OSError:
            continue
        items.append((mt, {"id": zid, "name": u["name"], "size": u["size"]}))
    items.sort(key=lambda x: x[0], reverse=True)
    return jsonify(items=[it for _, it in items])


@bp.post("/uploads")
def upload_zip():
    f = request.files.get("file")
    if not f or not f.filename:
        return jsonify(error="no file"), 400
    zid = uuid.uuid4().hex
    path = os.path.join(config.UPLOAD_DIR, zid + ".zip")
    f.save(path)
    with open(path, "rb") as fh:
        magic = fh.read(4)
    if magic[:2] != b"PK":
        os.unlink(path)
        return jsonify(error="not a zip archive"), 400
    size = os.path.getsize(path)
    state.remember_upload(zid, path, f.filename, size)
    state.prune_uploads(config.UPLOAD_DIR, config.MAX_UPLOADS_KEPT)
    return jsonify(id=zid, name=f.filename, size=size), 201


@bp.post("/wordlists")
def upload_wordlist():
    f = request.files.get("file")
    if not f or not f.filename:
        return jsonify(error="no file"), 400
    name = os.path.basename(f.filename)
    if not name or name.startswith("."):
        return jsonify(error="bad wordlist name"), 400
    path = os.path.join(config.WORDLIST_DIR, name)
    f.save(path)
    return jsonify(name=name, path=path, size=os.path.getsize(path)), 201


@bp.get("/wordlists")
def list_wordlists():
    items = []
    for n in sorted(os.listdir(config.WORDLIST_DIR)):
        p = os.path.join(config.WORDLIST_DIR, n)
        if os.path.isfile(p):
            items.append({"name": n, "path": p, "size": os.path.getsize(p)})
    return jsonify(items=items)


# ---------------------------------------------------------------- analyze / attack

@bp.get("/archives/<zid>")
def analyze(zid):
    u = state.UPLOADS.get(zid)
    if not u:
        return jsonify(error="unknown upload"), 404
    try:
        members = cryptoparse.parse_members(u["path"])
    except Exception as e:
        return jsonify(error=f"not a readable zip: {e}"), 400
    state.remember_members(zid, members)
    enc = [m for m in members if m["encrypted"]]
    kinds = {}
    for m in enc:
        kinds[m["kind"]] = kinds.get(m["kind"], 0) + 1
    return jsonify(
        members=[{k: m[k] for k in ("index", "name", "kind", "encrypted", "csize") if k in m}
                 for m in members],
        encrypted=len(enc), kinds=kinds)


@bp.post("/jobs")
def start_job():
    d = request.get_json(silent=True)
    if not isinstance(d, dict):
        d = {}
    zid = d.get("zip_id")
    u = state.UPLOADS.get(zid)
    if not u:
        return jsonify(error="unknown zip"), 404
    members = state.get_members(zid)
    if not members:
        try:
            members = cryptoparse.parse_members(u["path"])
            state.remember_members(zid, members)
        except Exception as e:
            return jsonify(error=f"not a readable zip: {e}"), 400

    try:
        member = cryptoparse.pick_member(members, d.get("member_index"))
        cfg = _validate_cfg(d)
    except (ValueError, FileNotFoundError) as e:
        return jsonify(error=str(e)), 400
    except PermissionError as e:
        return jsonify(error=str(e)), 403

    jid = uuid.uuid4().hex
    job = jobs.Job(jid, zid, member, cfg)
    state.JOBS[jid] = job
    state.prune_jobs(config.MAX_JOBS_KEPT)
    threading.Thread(target=jobs.run_job, args=(job,), daemon=True).start()
    return jsonify(job_id=jid), 201


def _validate_cfg(d: dict) -> dict:
    """validate the attack config at the boundary; raises on bad input."""
    mode = d.get("mode", "dict")
    if mode not in _MODES:
        raise ValueError(f"mode must be one of {', '.join(_MODES)}")

    cfg = {
        "mode": mode,
        "wordlist": d.get("wordlist"),
        "mask": d.get("mask", ""),
        "charset": d.get("charset", ""),
        "min_len": int(d.get("min_len", 1)),
        "max_len": int(d.get("max_len", 8)),
        "prefix": d.get("prefix", ""),
        "suffix_mask": d.get("suffix_mask", ""),
        "custom": d.get("custom") or {},
        "workers": _validate_workers(d.get("workers")),
    }
    if cfg["mode"] in ("dict", "hybrid"):
        cfg["wordlist"] = _resolve_wordlist(cfg["wordlist"])
    if cfg["mode"] == "mask" and not cfg["mask"]:
        raise ValueError("mask required")
    if cfg["mode"] == "brute" and not cfg["charset"]:
        raise ValueError("charset required")
    if len(cfg["charset"]) > config.MAX_CHARSET_LEN:
        raise ValueError(f"charset exceeds {config.MAX_CHARSET_LEN} chars")
    if not 0 <= cfg["min_len"] <= config.LEN_LIMIT:
        raise ValueError(f"min_len must be 0..{config.LEN_LIMIT}")
    if not cfg["min_len"] <= cfg["max_len"] <= config.LEN_LIMIT:
        raise ValueError(f"max_len must be between min_len and {config.LEN_LIMIT}")
    # exercises mask parsing + custom set rules so bad configs fail before a job exists
    candidates.mask_sets(cfg["mask"] or "?d", cfg["custom"])
    if cfg["suffix_mask"]:
        candidates.mask_sets(cfg["suffix_mask"], cfg["custom"])
    return cfg


def _validate_workers(w):
    if w is None:
        return None
    w = int(w)
    if not 1 <= w <= config.MAX_WORKERS:
        raise ValueError(f"workers must be 1..{config.MAX_WORKERS}")
    return w


def _resolve_wordlist(spec: str) -> str:
    """absolute path or app-root-relative; must live under an allowed root."""
    if not spec:
        raise ValueError("wordlist required")
    path = spec if os.path.isabs(spec) else os.path.join(config.APP_ROOT, spec)
    real = os.path.realpath(path)
    roots = [os.path.realpath(r) for r in config.ALLOWED_WORDLIST_ROOTS]
    if not any(real == r or real.startswith(r + os.sep) for r in roots):
        raise PermissionError("wordlist path not allowed")
    if not os.path.isfile(real):
        raise FileNotFoundError(f"wordlist not found: {spec}")
    return real


# ---------------------------------------------------------------- job control

@bp.get("/jobs")
def list_jobs():
    """all known jobs, newest first - a refreshed page reattaches to the top
    one (preferring a queued/running/stopping job if present)."""
    out = []
    for j in sorted(state.JOBS.values(), key=lambda j: j.started, reverse=True):
        with j.lock:
            d = {"job_id": j.id, "zip_id": j.zip_id, "state": j.state,
                 "mode": j.cfg.get("mode"), "member": j.member.get("name"),
                 "done": j.done, "found": j.found, "error": j.error,
                 "started": j.started}
            total = j.total
            d["total"] = str(total) if isinstance(total, int) and total > 2 ** 53 else total
        out.append(d)
    return jsonify(items=out)


@bp.get("/jobs/<jid>")
def status(jid):
    job = state.JOBS.get(jid)
    if not job:
        return jsonify(error="unknown job"), 404
    with job.lock:
        d = {k: getattr(job, k) for k in ("state", "done", "rate", "eta", "found", "sample", "error")}
        total = job.total
        log = list(job.log)
        d["total"] = str(total) if isinstance(total, int) and total > 2 ** 53 else total
    d.update(job_id=jid, elapsed=(job.ended or time.time()) - job.started, log=log)
    return jsonify(d)


@bp.post("/jobs/<jid>/stop")
def stop(jid):
    job = state.JOBS.get(jid)
    if not job:
        return jsonify(error="unknown job"), 404
    jobs.request_stop(job)
    return jsonify(ok=True)


# ---------------------------------------------------------------- verify / export

@bp.post("/archives/<zid>/verify")
def verify(zid):
    u = state.UPLOADS.get(zid)
    if not u:
        return jsonify(error="unknown upload"), 404
    members = state.get_members(zid)
    if not members:
        try:
            members = cryptoparse.parse_members(u["path"])
            state.remember_members(zid, members)
        except Exception as e:
            return jsonify(error=f"not a readable zip: {e}"), 400
    if not [m for m in members if m["encrypted"]]:
        return jsonify(results=[], note="zip is not encrypted"), 200

    meta = cryptoparse.pick_member(members)
    tester = tester_for(meta)
    payload = request.get_json(silent=True)
    if not isinstance(payload, dict):
        payload = {}
    pwds = payload.get("passwords") or []
    if len(pwds) > config.MAX_VERIFY_PASSWORDS:
        return jsonify(error=f"max {config.MAX_VERIFY_PASSWORDS} passwords per request"), 400
    out = []
    for pw in pwds:
        if not isinstance(pw, str) or len(pw) > config.MAX_PASSWORD_LEN:
            return jsonify(error="each password must be a string up to "
                                 f"{config.MAX_PASSWORD_LEN} chars"), 400
        out.append({"password": pw, "ok": bool(tester(pw.encode("utf-8")))})
    return jsonify(member=meta["name"], kind=meta["kind"], results=out)


@bp.get("/archives/<zid>/export")
def export(zid):
    u = state.UPLOADS.get(zid)
    if not u:
        return jsonify(error="unknown upload"), 404
    members = state.get_members(zid)
    if not members:
        try:
            members = cryptoparse.parse_members(u["path"])
            state.remember_members(zid, members)
        except Exception as e:
            return jsonify(error=f"not a readable zip: {e}"), 400
    try:
        return jsonify(bridge.build_export(u["path"], members))
    except FileNotFoundError as e:
        return jsonify(error=str(e)), 404
    except RuntimeError as e:
        return jsonify(error=str(e)), 500
