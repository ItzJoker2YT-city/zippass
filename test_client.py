"""end-to-end client: upload, analyze, dictionary crack (zipcrypto), brute crack
(AES), verify endpoint, export endpoint. pure urllib - no extra deps."""
import json
import time
import urllib.request

BASE = "http://127.0.0.1:5000"


def post_multipart(path, field, fname, content):
    b = "----zippass42"
    body = (f"--{b}\r\nContent-Disposition: form-data; name=\"{field}\"; "
            f"filename=\"{fname}\"\r\nContent-Type: application/octet-stream\r\n\r\n"
            ).encode() + content + f"\r\n--{b}--\r\n".encode()
    req = urllib.request.Request(BASE + path, data=body, method="POST")
    req.add_header("Content-Type", f"multipart/form-data; boundary={b}")
    return json.loads(urllib.request.urlopen(req).read())


def post_json(path, data):
    req = urllib.request.Request(BASE + path, data=json.dumps(data).encode(), method="POST")
    req.add_header("Content-Type", "application/json")
    try:
        return json.loads(urllib.request.urlopen(req).read())
    except urllib.error.HTTPError as e:
        return json.loads(e.read())


def get(path):
    try:
        body = urllib.request.urlopen(BASE + path).read().decode()
    except urllib.error.HTTPError as e:
        body = e.read().decode()
    try:
        return json.loads(body)
    except json.JSONDecodeError:
        return {"error": body[:300] or "empty response"}


def wait_job(jid, label):
    t0 = time.time()
    while True:
        s = get(f"/api/v1/jobs/{jid}")
        if s.get("error"):
            print(f"  status error: {s['error']}")
            return s
        if s["state"] in ("found", "exhausted", "stopped", "error"):
            el = time.time() - t0
            print(f"  [{label}] state={s['state']} tried={s['done']} "
                  f"rate={s['rate']:.0f}/s elapsed={el:.1f}s")
            if s.get("found"):
                print(f"  [{label}] PASSWORD = {s['found']}")
            return s
        time.sleep(0.4)


def run(label, zip_path, mode, cfg):
    u = post_multipart("/api/v1/uploads", "file", zip_path.split("\\")[-1], open(zip_path, "rb").read())
    a = get(f"/api/v1/archives/{u['id']}")
    kinds = a.get("kinds", {})
    print(f"[{label}] uploaded {u['name']}, encrypted members: {a['encrypted']}, kinds: {kinds}")
    j = post_json("/api/v1/jobs", {"zip_id": u["id"], "mode": mode, **cfg})
    if j.get("error"):
        print(f"  start error: {j['error']}")
        return
    return wait_job(j["job_id"], label)


def main():
    run("dict-zipcrypto", r"tests\zc.zip", "dict", {"wordlist": r"tests\wl.txt"})
    run("brute-aes", r"tests\aes.zip", "brute",
        {"charset": "0123456789", "min_len": 5, "max_len": 5})
    run("brute-zipcrypto", r"tests\zc.zip", "brute",
        {"charset": "0123456789", "min_len": 5, "max_len": 5})

    # verify endpoint
    u = post_multipart("/api/v1/uploads", "file", "zc.zip", open(r"tests\zc.zip", "rb").read())
    v = post_json(f"/api/v1/archives/{u['id']}/verify", {"passwords": ["wrongpass", "l3gacy"]})
    print("[verify] target:", v.get("member"), v.get("kind"))
    for r in v.get("results", []):
        print(f"  {'OK ' if r['ok'] else 'BAD'} {r['password']}")

    # export bridge
    e = get(f"/api/v1/archives/{u['id']}/export")
    print("[export]", e.get("error") or f"hash len {len(e.get('hash',''))}, commands: {e.get('commands')}")


if __name__ == "__main__":
    main()
