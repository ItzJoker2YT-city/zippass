"""live proof that a page refresh reattaches to a running attack.

1. start a long brute job via the API
2. snapshot its progress
3. simulate a refresh: GET / (fresh page), GET /api/v1/jobs, GET /api/v1/uploads
   - exactly what index.html's restore() now does on load
4. snapshot again: counters must have kept climbing across the refresh
5. stop the job, confirm clean stop
"""
import io
import json
import time
import urllib.error
import urllib.request
import uuid

from make_tests import make_zipcrypto

BASE = "http://127.0.0.1:5000/api/v1"


def call(path, data=None, headers=None, method=None):
    r = urllib.request.Request(BASE + path, data=data, headers=headers or {},
                               method=method)
    with urllib.request.urlopen(r, timeout=30) as resp:
        return json.loads(resp.read().decode())


def get_page():
    with urllib.request.urlopen("http://127.0.0.1:5000/", timeout=30) as resp:
        return resp.read().decode()


def upload(path):
    body = io.BytesIO()
    boundary = uuid.uuid4().hex
    with open(path, "rb") as f:
        payload = f.read()
    body.write(f"--{boundary}\r\n".encode())
    body.write(b'Content-Disposition: form-data; name="file"; filename="t.zip"\r\n')
    body.write(b"Content-Type: application/zip\r\n\r\n")
    body.write(payload)
    body.write(f"\r\n--{boundary}--\r\n".encode())
    return call("/uploads", data=body.getvalue(),
                headers={"Content-Type": f"multipart/form-data; boundary={boundary}"})


def cleanup_running_jobs():
    """stop any non-terminal jobs a previous crashed run left behind, so a
    live check always starts from a quiet server."""
    try:
        for j in call("/jobs")["items"]:
            if j["state"] in ("queued", "running", "stopping"):
                try:
                    call(f"/jobs/{j['job_id']}/stop", data=b"", method="POST")
                except urllib.error.HTTPError:
                    pass               # already finished between list and stop
        for _ in range(60):
            left = [j for j in call("/jobs")["items"]
                    if j["state"] in ("queued", "running", "stopping")]
            if not left:
                return
            time.sleep(0.3)
    except urllib.error.URLError:
        pass    # server down - the run below fails loudly on its own


def main():
    cleanup_running_jobs()
    tmp = str(uuid.uuid4().hex + ".zip")
    make_zipcrypto(tmp, b"l3gacy", "refresh test payload")
    try:
        zid = upload(tmp)["id"]
        jid = call("/jobs", data=json.dumps({
            "zip_id": zid, "mode": "brute", "charset": "0123456789",
            "min_len": 6, "max_len": 8}).encode(),
            headers={"Content-Type": "application/json"})["job_id"]
        time.sleep(2.0)
        s1 = call(f"/jobs/{jid}")
        for _ in range(60):                 # wait for the first worker task to land
            if s1["done"] > 0:
                break
            time.sleep(0.5)
            s1 = call(f"/jobs/{jid}")
        print(f"before refresh: state={s1['state']} tried={s1['done']}")
        assert s1["done"] > 0, "no progress after 30s - results are not flowing"

        # --- the refresh: what the new page does on load -------------------
        html = get_page()
        assert "restore()" in html, "page missing restore() bootstrap"
        jobs = call("/jobs")["items"]
        top = jobs[0]
        assert top["job_id"] == jid, "running job not at top of /jobs"
        assert top["state"] in ("queued", "running", "stopping"), top["state"]
        ups = call("/uploads")["items"]
        assert any(u["id"] == zid for u in ups), "upload missing from /uploads"
        print(f"refresh reattach: job state={top['state']}, archive restored "
              f"({ups[0]['name']})")

        time.sleep(2.5)
        s2 = call(f"/jobs/{jid}")
        for _ in range(60):                 # results must keep landing post-refresh
            if s2["done"] > s1["done"]:
                break
            time.sleep(0.5)
            s2 = call(f"/jobs/{jid}")
        print(f"after refresh:  state={s2['state']} tried={s2['done']}")
        assert s2["done"] > s1["done"], "job did not keep running across refresh"

        call(f"/jobs/{jid}/stop", data=b"", method="POST")
        for _ in range(60):
            s3 = call(f"/jobs/{jid}")
            if s3["state"] in ("stopped", "exhausted", "found", "error"):
                break
            time.sleep(0.3)
        print(f"stop after reattach: state={s3['state']} tried={s3['done']}")
        assert s3["state"] == "stopped"
        print("PASS - refresh keeps the attack running and the page reattaches")
    finally:
        import os
        try:
            os.unlink(tmp)
        except OSError:
            pass


if __name__ == "__main__":
    main()
