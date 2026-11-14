"""live stop-button audit: click stop via the API exactly like the UI does,
measure how long until the job actually reaches 'stopped'."""
import json
import time
import urllib.request

from make_tests import make_aes_zip, make_zipcrypto
from check_refresh import call, upload


def run_case(label, cfg, builder):
    import uuid, os
    tmp = uuid.uuid4().hex + ".zip"
    builder(tmp)
    try:
        zid = upload(tmp)["id"]
        jid = call("/jobs", data=json.dumps({"zip_id": zid, **cfg}).encode(),
                   headers={"Content-Type": "application/json"})["job_id"]
        time.sleep(1.0)                      # let it get into its first task
        t0 = time.time()
        call(f"/jobs/{jid}/stop", data=b"", method="POST")   # the button's call
        for _ in range(120):
            s = call(f"/jobs/{jid}")
            if s["state"] in ("stopped", "exhausted", "found", "error"):
                break
            time.sleep(0.25)
        dt = time.time() - t0
        print(f"[{label}] stop click -> terminal '{s['state']}' in {dt:.1f}s "
              f"(tried={s['done']})")
        return dt
    finally:
        try:
            os.unlink(tmp)
        except OSError:
            pass


def main():
    d1 = run_case("zipcrypto brute 6-8 digits",
                  {"mode": "brute", "charset": "0123456789",
                   "min_len": 6, "max_len": 8},
                  lambda p: make_zipcrypto(p, b"l3gacy", "stop audit payload"))
    d2 = run_case("AES-256 brute 6-8 digits",
                  {"mode": "brute", "charset": "0123456789",
                   "min_len": 6, "max_len": 8},
                  lambda p: make_aes_zip(p, b"aeS-9zz"))
    print("worst-case stop latency:", f"{max(d1, d2):.1f}s")


if __name__ == "__main__":
    main()
