"""broad ladder against the real zip, no user hints available: cover the
highest-probability spaces in order, first hit wins. designed to run
unattended in the background; progress lands in broad_ladder.log."""
import os

from check_refresh import call, cleanup_running_jobs, upload
from crack_theirs import report, run_job

HERE = os.path.dirname(os.path.abspath(__file__))
ZIP = r"C:\Users\Administrator\Desktop\New folder (2).zip"
XATO1M = os.path.join(HERE, "xato1m.txt")
PWDB1M = os.path.join(HERE, "pwdb1m.txt")
ROCKYOU = os.path.join(HERE, "rockyou.txt")
ROCKYOU_DONE = os.path.join(HERE, "rockyou.done")

MIXED = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
LOWER_DIGIT = "abcdefghijklmnopqrstuvwxyz0123456789"


def rockyou_ready():
    """the curl retry loop leaves rockyou.done only after a clean exit-0
    download, so a partial file is never fed to the app."""
    return os.path.exists(ROCKYOU_DONE) and os.path.exists(ROCKYOU)


def hit(s):
    return s["state"] == "found"


def main():
    cleanup_running_jobs()
    zid = upload(ZIP)["id"]

    s = run_job("dict xato-top1m", {"zip_id": zid, "mode": "dict",
                                   "wordlist": XATO1M}, 1800)
    if hit(s):
        report(s)
        return
    s = run_job("dict pwdb-top1m", {"zip_id": zid, "mode": "dict",
                                    "wordlist": PWDB1M}, 1800)
    if hit(s):
        report(s)
        return

    ran_rockyou = False
    if rockyou_ready():
        s = run_job("dict rockyou", {"zip_id": zid, "mode": "dict",
                                     "wordlist": ROCKYOU}, 3600)
        ran_rockyou = True
        if hit(s):
            report(s)
            return

    s = run_job("brute mixed+digits 1-4",
                {"zip_id": zid, "mode": "brute", "charset": MIXED,
                 "min_len": 1, "max_len": 4}, 3600)
    if hit(s):
        report(s)
        return
    s = run_job("brute lower+digits 1-5",
                {"zip_id": zid, "mode": "brute", "charset": LOWER_DIGIT,
                 "min_len": 1, "max_len": 5}, 7200)
    if hit(s):
        report(s)
        return
    s = run_job("hybrid xato-top1m + ?d?d",
                {"zip_id": zid, "mode": "hybrid", "wordlist": XATO1M,
                 "suffix_mask": "?d?d"}, 7200)
    if hit(s):
        report(s)
        return

    # rockyou may have finished downloading while the earlier steps ran
    if rockyou_ready() and not ran_rockyou:
        s = run_job("dict rockyou", {"zip_id": zid, "mode": "dict",
                                     "wordlist": ROCKYOU}, 3600)
        if hit(s):
            report(s)
            return

    print("LADDER COMPLETE - no hit. next options: printable-ascii 1-4, "
          "upper+digits 1-5, hybrid top1m+?d?d?d (each hours on this box).")


if __name__ == "__main__":
    main()
