"""in-memory server state - uploads, parsed members, attack jobs; prune helpers."""
import os
import time

UPLOADS = {}  # zip_id -> {path, name, size}
MEMBERS = {}  # zip_id -> [member meta dicts]
JOBS = {}     # job_id -> jobs.Job


def remember_upload(zid: str, path: str, name: str, size: int) -> None:
    UPLOADS[zid] = {"path": path, "name": name, "size": size}


def remember_members(zid: str, members: list) -> None:
    MEMBERS[zid] = members


def get_members(zid: str):
    return MEMBERS.get(zid)


def prune_jobs(max_keep: int) -> None:
    """drop oldest terminal jobs when the table grows past the cap."""
    terminal = [j for j in JOBS.values() if j.state not in ("queued", "running", "stopping")]
    terminal.sort(key=lambda j: j.started)
    while len(JOBS) > max_keep and terminal:
        JOBS.pop(terminal.pop(0).id, None)


def prune_uploads(upload_dir: str, max_keep: int) -> None:
    """delete oldest stale uploads (files on disk, then the table entry)."""
    entries = []
    for zid, u in list(UPLOADS.items()):
        if not os.path.isfile(u["path"]):
            UPLOADS.pop(zid, None)
            continue
        entries.append((os.path.getmtime(u["path"]), zid))
    entries.sort()
    while len(entries) > max_keep:
        _, zid = entries.pop(0)
        u = UPLOADS.pop(zid, None)
        if u:
            try:
                os.unlink(u["path"])
            except OSError:
                pass
    # catch orphan files from earlier crashes that the table no longer knows
    known = {u["path"] for u in UPLOADS.values()}
    for n in os.listdir(upload_dir):
        p = os.path.join(upload_dir, n)
        if p not in known and time.time() - os.path.getmtime(p) > 24 * 3600:
            try:
                os.unlink(p)
            except OSError:
                pass
