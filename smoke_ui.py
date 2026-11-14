"""smoke test the new ui helpers: page renders the guide + quick-start,
built-in wordlists are listed, and a quick-start-style dict job runs
against one of them. stops the job after a few seconds."""
from check_refresh import call, upload

ZIP = r"C:\Users\Administrator\Desktop\New folder (2).zip"


def main():
    # 1. page renders with the helpers
    import urllib.request
    html = urllib.request.urlopen("http://127.0.0.1:5000/").read().decode("utf-8")
    for needle in ("how to use - 3 steps", "quick-start", "est-mask",
                   "data-qs=\"rockyou\"", "workers (leave empty"):
        assert needle in html, f"page missing: {needle}"
    print("page: guide + quick-start + estimator present")

    # 2. built-in lists visible
    wls = call("/wordlists")["items"]
    names = {w["name"]: w["path"] for w in wls}
    assert "rockyou.txt" in names and "common-passwords-1m.txt" in names, names
    print(f"wordlists endpoint: {sorted(names)}")

    # 3. quick-start-style dict job
    zid = upload(ZIP)["id"]
    jid = call("/jobs", data=__import__("json").dumps(
        {"zip_id": zid, "mode": "dict",
         "wordlist": names["common-passwords-1m.txt"]}).encode(),
        headers={"Content-Type": "application/json"})["job_id"]
    import time
    time.sleep(4)
    s = call(f"/jobs/{jid}")
    print(f"dict job on built-in list: state={s['state']} tried={s['done']}")
    call(f"/jobs/{jid}/stop", data=b"", method="POST")
    for _ in range(40):
        s = call(f"/jobs/{jid}")
        if s["state"] in ("found", "exhausted", "stopped", "error"):
            break
        time.sleep(0.25)
    assert s["state"] in ("found", "stopped"), s
    print(f"stop lands: state={s['state']}")
    print("SMOKE PASS")


if __name__ == "__main__":
    main()
