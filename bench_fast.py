"""live benchmark on the user's real zip against the 2M/s target.

rate is measured from done-deltas over short monotonic windows, so a
host clock resync cannot poison it. jobs: brute lower+digits 1-4
(exhausts ~1.7M for a clean full-run timing), brute 1-5 (hits at
~17.5M), and a dict pass over the 10M xato list stopped after ~12s.
"""
import json
import time

from check_refresh import call, upload

ZIP = r"C:\Users\Administrator\Desktop\New folder (2).zip"
END = ("found", "exhausted", "stopped", "error")


def rate_window(jid, span=4.0):
    """average tries/sec over one monotonic window from done-deltas."""
    t0 = time.monotonic()
    d0 = call(f"/jobs/{jid}")["done"]
    while time.monotonic() - t0 < span:
        time.sleep(0.3)
    s = call(f"/jobs/{jid}")
    dt = time.monotonic() - t0
    return (s["done"] - d0) / dt if dt > 0 else 0.0, s


def run(cfg, label, stop_after=None, max_s=600):
    zid = upload(ZIP)["id"]
    cfg["zip_id"] = zid
    jid = call("/jobs", data=json.dumps(cfg).encode(),
               headers={"Content-Type": "application/json"})["job_id"]
    t0 = time.monotonic()
    while time.monotonic() - t0 < max_s:
        s = call(f"/jobs/{jid}")
        if s["state"] in END:
            break
        if stop_after and time.monotonic() - t0 > stop_after:
            call(f"/jobs/{jid}/stop", data=b"", method="POST")
            while call(f"/jobs/{jid}")["state"] not in END:
                time.sleep(0.2)
            s = call(f"/jobs/{jid}")
            break
        time.sleep(0.3)
    dt = time.monotonic() - t0
    r, _ = rate_window(jid, 3.0) if s["state"] == "running" else (0, None)
    rate = r or (s["done"] / dt if dt else 0)
    print(f"{label}: state={s['state']} done={s['done']:,} in {dt:.1f}s "
          f"-> {rate/1e6:.2f}M/s")
    if s["found"]:
        print(f"  password: {s['found']}")


def main():
    run({"mode": "brute", "charset": "abcdefghijklmnopqrstuvwxyz0123456789",
         "min_len": 1, "max_len": 4}, "brute lower+digits 1-4 (full run)")
    run({"mode": "brute", "charset": "abcdefghijklmnopqrstuvwxyz0123456789",
         "min_len": 1, "max_len": 5}, "brute lower+digits 1-5 (to hit)")
    wls = {w["name"]: w["path"] for w in call("/wordlists")["items"]}
    run({"mode": "dict", "wordlist": wls["common-10m-xato.txt"]},
        "dict xato-10m", stop_after=12)


if __name__ == "__main__":
    main()
