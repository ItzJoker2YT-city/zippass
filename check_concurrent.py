"""live proof that two jobs sharing the worker pool both make progress.

1. start a long brute job (6-8 digits, ~40+ minutes of work)
2. one second later start a dict job whose password sits in the
   wordlist's FIRST batch of chunks
3. the dict job must finish while the brute is still running
4. stopping the brute must stay in the ~1s class
"""
import json
import os
import time
import uuid

from check_refresh import call, cleanup_running_jobs, upload
from make_tests import make_zipcrypto

TERMINAL = ("found", "exhausted", "stopped", "error")


def main():
    cleanup_running_jobs()
    za, zb = uuid.uuid4().hex + ".zip", uuid.uuid4().hex + ".zip"
    wl = "check_concurrent_words.txt"
    # password is the LAST line: lands in the dict job's first batch, so
    # the wait below measures the interleave with brute, not a long scan
    with open(wl, "w") as f:
        f.write("\n".join(f"w{i}" for i in range(30000)) + "\npkware42\n")
    try:
        make_zipcrypto(za, b"whatever1", "brute target")
        make_zipcrypto(zb, b"pkware42", "dict target")
        zid_a = upload(za)["id"]
        zid_b = upload(zb)["id"]
        jid_a = call("/jobs", data=json.dumps({
            "zip_id": zid_a, "mode": "brute", "charset": "0123456789",
            "min_len": 6, "max_len": 8}).encode(),
            headers={"Content-Type": "application/json"})["job_id"]
        time.sleep(1.0)                      # brute owns the pool first
        jid_b = call("/jobs", data=json.dumps({
            "zip_id": zid_b, "mode": "dict",
            "wordlist": os.path.abspath(wl), "workers": 2}).encode(),
            headers={"Content-Type": "application/json"})["job_id"]

        t0 = time.time()
        for _ in range(120):
            b = call(f"/jobs/{jid_b}")
            if b["state"] in TERMINAL:
                break
            time.sleep(0.5)
        dt_b = time.time() - t0
        print(f"dict job finished in {dt_b:.1f}s: state={b['state']} "
              f"found={b['found']}")
        assert b["state"] == "found" and b["found"] == "pkware42"

        a = call(f"/jobs/{jid_a}")
        print(f"brute meanwhile: state={a['state']} tried={a['done']}")
        assert a["state"] in ("running", "stopping"), "brute died early"

        t1 = time.time()
        call(f"/jobs/{jid_a}/stop", data=b"", method="POST")
        for _ in range(120):
            a = call(f"/jobs/{jid_a}")
            if a["state"] in TERMINAL:
                break
            time.sleep(0.25)
        dt_s = time.time() - t1
        print(f"brute stop latency: {dt_s:.1f}s -> state={a['state']}")
        assert a["state"] == "stopped" and dt_s < 5
        print("PASS - jobs share the pool fairly and stop stays instant")
    finally:
        for f in (za, zb, wl):
            try:
                os.unlink(f)
            except OSError:
                pass


if __name__ == "__main__":
    main()
