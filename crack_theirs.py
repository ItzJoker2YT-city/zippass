"""one-off: attack the user's real zip (Desktop 'New folder (2).zip')
through the live app: targeted dict, common passwords, word+digits
hybrids, then cheap short brutes. stops at the first hit."""
import json
import os
import time
import urllib.error
import uuid

from check_refresh import call, cleanup_running_jobs, upload

TERMINAL = ("found", "exhausted", "stopped", "error")
ZIP = r"C:\Users\Administrator\Desktop\New folder (2).zip"


def run_job(label, cfg, timeout):
    jid = call("/jobs", data=json.dumps(cfg).encode(),
               headers={"Content-Type": "application/json"})["job_id"]
    t0 = time.time()
    for _ in range(int(timeout / 0.5)):
        s = call(f"/jobs/{jid}")
        if s["state"] in TERMINAL:
            break
        time.sleep(0.5)
    else:
        call(f"/jobs/{jid}/stop", data=b"", method="POST")   # don't leak jobs
        for _ in range(40):
            s = call(f"/jobs/{jid}")
            if s["state"] in TERMINAL:
                break
            time.sleep(0.25)
        print(f"[{label}] TIMED OUT after {time.time() - t0:.1f}s - stopped",
              flush=True)
        return s
    dt = time.time() - t0
    print(f"[{label}] {dt:6.1f}s state={s['state']} tried={s['done']} "
          f"found={s['found']}", flush=True)
    return s


def main():
    cleanup_running_jobs()
    zid = upload(ZIP)["id"]
    a = call(f"/archives/{zid}")
    print(f"analyze: encrypted={a['encrypted']} kinds={a['kinds']} "
          f"members={[m['name'] for m in a['members']]}", flush=True)

    # 1. targeted + common-password dictionary
    wl = "crack_words.txt"
    guesses = [
        # the song title itself, all reasonable spellings
        "The Whoopsie-Daisy School Song", "The Whoopsie Daisy School Song",
        "TheWhoopsieDaisySchoolSong", "whoopsiedaisyschoolsong",
        "Whoopsie-Daisy-School-Song", "whoopsie daisy school song",
        "the whoopsie daisy school song", "TheWhoopsie-DaisySchoolSong",
        "Whoopsie Daisy School Song", "whoopsie-daisy school song",
        "whoopsie", "daisy", "Whoopsie", "Daisy", "whoopsiedaisy",
        "WhoopsieDaisy", "whoopsie-daisy", "whoopsie daisy", "WHOOPSIEDAISY",
        "school", "song", "songs", "music", "mp3", "MP3", "SchoolSong",
        "schoolsong", "daisyschool", "whoopsieschool", "thesong", "TheSong",
        "New folder (2)", "newfolder2", "NewFolder2", "newfolder(2)",
        "123456", "12345", "1234", "123", "12345678", "123456789", "1234567",
        "password", "Password", "password1", "password123", "passw0rd",
        "P@ssw0rd", "Passw0rd", "admin", "Admin", "admin123", "letmein",
        "welcome", "monkey", "dragon", "qwerty", "abc123", "111111", "123123",
        "000000", "iloveyou", "sunshine", "princess", "football", "baseball",
        "starwars", "trustno1", "hunter2", "secret", "test", "root", "toor",
        "master", "superman", "batman", "spiderman", "charlie", "jordan",
        "michael", "jennifer", "joshua", "daniel", "hannah", "thomas",
        "soccer", "hockey", "killer", "george", "andrew", "ashley", "bailey",
        "summer", "winter", "spring", "hello", "love", "lol", "zxcvbn",
        "asdfgh", "1q2w3e4r", "qwerty123", "1qaz2wsx", "zaq12wsx", "pass",
    ]
    with open(wl, "w", encoding="utf-8") as f:
        f.write("\n".join(guesses) + "\n")
    wl_abs = os.path.abspath(wl)
    try:
        s = run_job("dict targeted", {"zip_id": zid, "mode": "dict",
                                      "wordlist": wl_abs}, 60)
        if s["state"] == "found":
            report(s)
            return

        # 2. word + 2 digits (song123 style)
        s = run_job("hybrid word+?d?d",
                    {"zip_id": zid, "mode": "hybrid", "wordlist": wl_abs,
                     "suffix_mask": "?d?d"}, 60)
        if s["state"] == "found":
            report(s)
            return

        # round 1 already exhausted: digits 1-6, lower 1-4, lower+digit 1-3,
        # word+?d?d?d - see the transcript

        # 3. the last cheap alphanumeric space
        s = run_job("brute lower+digit 1-4",
                    {"zip_id": zid, "mode": "brute",
                     "charset": "abcdefghijklmnopqrstuvwxyz0123456789",
                     "min_len": 1, "max_len": 4}, 300)
        if s["state"] == "found":
            report(s)
            return

        print("NO HIT in the cheap spaces - see options in the report.")
    finally:
        for f in (wl,):
            try:
                os.unlink(f)
            except OSError:
                pass


def report(s):
    print(f"PASSWORD FOUND: {s['found']}")
    try:
        # the single-job status payload has no zip_id - pull it from the
        # jobs list (newest first) instead
        items = call("/jobs")["items"]
        zid = next(i["zip_id"] for i in items if i.get("state") == "found"
                   and i.get("found") == s["found"])
        v = call(f"/archives/{zid}/verify",
                 data=json.dumps({"password": s["found"]}).encode(),
                 headers={"Content-Type": "application/json"})
        print(f"verify endpoint: {v}")
    except Exception as e:      # reporting nicety - the find stands on its own
        print(f"(verify endpoint skipped: {e!r})")


if __name__ == "__main__":
    main()
