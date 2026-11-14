"""HTTP boundary + one live dictionary attack through the worker pool."""
import io
import random
import string
import time

import pytest

from make_tests import make_aes_zip, make_zipcrypto


def _upload(client, data, name):
    return client.post("/api/v1/uploads",
                       data={"file": (io.BytesIO(data), name)},
                       content_type="multipart/form-data")


def _zc_bytes(tmp_path, body="unit payload"):
    path = tmp_path / "t.zip"
    make_zipcrypto(str(path), b"pkware42", body)
    return path.read_bytes()


def test_upload_rejects_non_zip(client):
    r = _upload(client, b"this is not a zip at all", "nope.zip")
    assert r.status_code == 400 and "zip" in r.get_json()["error"]


def test_upload_requires_file(client):
    assert client.post("/api/v1/uploads", data={}).status_code == 400


def test_analyze(client, tmp_path):
    r = _upload(client, _zc_bytes(tmp_path), "t.zip")
    assert r.status_code == 201
    a = client.get(f"/api/v1/archives/{r.get_json()['id']}")
    body = a.get_json()
    assert a.status_code == 200
    assert body["encrypted"] == 1 and body["kinds"] == {"zipcrypto": 1}
    assert body["members"][0]["kind"] == "zipcrypto"


def test_analyze_unknown_id(client):
    assert client.get("/api/v1/archives/deadbeef").status_code == 404


def test_ui_served(client):
    r = client.get("/")
    assert r.status_code == 200
    html = r.get_data(as_text=True)
    assert "drop a .zip here" in html and "/api/v1/jobs" in html
    assert "restore()" in html   # refresh-reattach bootstrap runs on load


def test_list_uploads_newest_first(client, tmp_path):
    zid1 = _upload(client, _zc_bytes(tmp_path), "t1.zip").get_json()["id"]
    zid2 = _upload(client, _zc_bytes(tmp_path), "t2.zip").get_json()["id"]
    ups = client.get("/api/v1/uploads").get_json()["items"]
    assert [u["id"] for u in ups] == [zid2, zid1]      # newest first
    assert ups[0]["name"] == "t2.zip" and ups[0]["size"] > 0


def test_list_jobs_reattach_payload(client, tmp_path):
    zid = _upload(client, _zc_bytes(tmp_path), "t.zip").get_json()["id"]
    wl = tmp_path / "w.txt"
    wl.write_text("aaa\npkware42\n")
    jid = client.post("/api/v1/jobs",
                      json={"zip_id": zid, "mode": "dict",
                            "wordlist": str(wl), "workers": 2}).get_json()["job_id"]
    _wait_terminal(client, jid)
    items = client.get("/api/v1/jobs").get_json()["items"]
    top = items[0]                                     # newest job first
    assert top["job_id"] == jid
    assert top["zip_id"] == zid and top["mode"] == "dict"
    assert top["state"] == "found" and top["found"] == "pkware42"
    assert top["total"] == 2
    # the status endpoint a refreshed page polls still serves the same job
    s = client.get(f"/api/v1/jobs/{jid}").get_json()
    assert s["state"] == "found" and s["found"] == "pkware42"


def test_jobs_list_shows_running_job(client, tmp_path):
    zid = _upload(client, _zc_bytes(tmp_path), "t.zip").get_json()["id"]
    jid = client.post("/api/v1/jobs",
                      json={"zip_id": zid, "mode": "brute", "charset": "0123456789",
                            "min_len": 6, "max_len": 8, "workers": 2}).get_json()["job_id"]
    try:
        items = client.get("/api/v1/jobs").get_json()["items"]
        assert items[0]["job_id"] == jid
        assert items[0]["state"] in ("queued", "running", "stopping")
    finally:
        client.post(f"/api/v1/jobs/{jid}/stop")
        _wait_terminal(client, jid)


def test_job_unknown_zip(client):
    r = client.post("/api/v1/jobs", json={"zip_id": "nope", "mode": "dict"})
    assert r.status_code == 404


def test_job_validation_errors(client, tmp_path):
    zid = _upload(client, _zc_bytes(tmp_path), "t.zip").get_json()["id"]
    wl = tmp_path / "w.txt"
    wl.write_text("x\n")
    cases = [
        {"mode": "nope"},                                        # bad mode
        {"mode": "mask", "mask": "?9"},                          # bad mask token
        {"mode": "mask", "mask": "?1"},                          # missing custom set
        {"mode": "brute", "charset": ""},                        # empty charset
        {"mode": "brute", "charset": "a", "min_len": 8, "max_len": 2},   # inverted lengths
        {"mode": "brute", "charset": "a", "min_len": 1, "max_len": 99},  # over len cap
        {"mode": "dict", "wordlist": str(wl), "workers": 999},   # over worker cap
        {"mode": "dict", "wordlist": str(tmp_path / "missing.txt")},     # not found
    ]
    for cfg in cases:
        r = client.post("/api/v1/jobs", json={"zip_id": zid, **cfg})
        assert r.status_code == 400, cfg
        assert "error" in r.get_json(), cfg


def test_wordlist_path_traversal_blocked(client, tmp_path):
    zid = _upload(client, _zc_bytes(tmp_path), "t.zip").get_json()["id"]
    outside = tmp_path.parent / "outside.txt"
    outside.write_text("x\n")
    r = client.post("/api/v1/jobs",
                    json={"zip_id": zid, "mode": "dict",
                          "wordlist": str(tmp_path.parent / "outside.txt")})
    assert r.status_code == 403


def test_status_unknown_job(client):
    assert client.get("/api/v1/jobs/deadbeef").status_code == 404


def test_verify(client, tmp_path):
    zid = _upload(client, _zc_bytes(tmp_path), "t.zip").get_json()["id"]
    r = client.post(f"/api/v1/archives/{zid}/verify",
                    json={"passwords": ["wrongpass", "pkware42", ""]})
    body = r.get_json()
    assert r.status_code == 200 and body["kind"] == "zipcrypto"
    assert [x["ok"] for x in body["results"]] == [False, True, False]


def test_verify_rejects_bad_payload(client, tmp_path):
    zid = _upload(client, _zc_bytes(tmp_path), "t.zip").get_json()["id"]
    too_long = "x" * 300
    for payload in (["ok", 42], [too_long]):
        r = client.post(f"/api/v1/archives/{zid}/verify", json={"passwords": payload})
        assert r.status_code == 400


def test_verify_big_member_cdata(client, tmp_path):
    """a big deflate member carries an encrypted cdata head in its meta;
    the verify tester must decode that hex to bytes - a str would crash
    the check-byte filter on the first passer (regression). the body is
    incompressible so csize-12 crosses the 512-byte cdata threshold."""
    rng = random.Random(7)
    body = "".join(rng.choices(string.ascii_letters + string.digits, k=1400))
    zid = _upload(client, _zc_bytes(tmp_path, body), "t.zip").get_json()["id"]
    r = client.post(f"/api/v1/archives/{zid}/verify",
                    json={"passwords": ["wrongpass", "pkware42"]})
    res = r.get_json()
    assert r.status_code == 200
    assert [x["ok"] for x in res["results"]] == [False, True]


def test_export_without_john(client, tmp_path):
    zid = _upload(client, _zc_bytes(tmp_path), "t.zip").get_json()["id"]
    r = client.get(f"/api/v1/archives/{zid}/export")
    assert r.status_code in (200, 404)   # 404 on machines without john
    if r.status_code == 404:
        assert "zip2john" in r.get_json()["error"]


def _wait_terminal(client, jid, timeout=120):
    deadline = time.time() + timeout
    while time.time() < deadline:
        s = client.get(f"/api/v1/jobs/{jid}").get_json()
        if s["state"] in ("found", "exhausted", "stopped", "error"):
            return s
        time.sleep(0.2)
    raise AssertionError("job did not finish in time")


def test_live_dict_crack(client, tmp_path):
    zid = _upload(client, _zc_bytes(tmp_path), "t.zip").get_json()["id"]
    wl = tmp_path / "w.txt"
    wl.write_text("aaa\nbbb\npkware42\nccc\n")
    r = client.post("/api/v1/jobs",
                    json={"zip_id": zid, "mode": "dict",
                          "wordlist": str(wl), "workers": 2})
    assert r.status_code == 201, r.get_json()
    s = _wait_terminal(client, r.get_json()["job_id"])
    assert s["state"] == "found" and s["found"] == "pkware42"


def test_live_stop(client, tmp_path):
    zid = _upload(client, _zc_bytes(tmp_path), "t.zip").get_json()["id"]
    r = client.post("/api/v1/jobs",
                    json={"zip_id": zid, "mode": "brute", "charset": "0123456789",
                          "min_len": 6, "max_len": 8, "workers": 2})
    jid = r.get_json()["job_id"]
    client.post(f"/api/v1/jobs/{jid}/stop")
    s = _wait_terminal(client, jid)
    assert s["state"] == "stopped"


def test_stop_responsive_during_first_task(client, tmp_path):
    """stop must take effect in seconds, not wait out a worker task. one
    65536-candidate AES task runs minutes; the old loop only checked the
    stop flag between task results."""
    path = tmp_path / "aes.zip"
    make_aes_zip(str(path), b"aeS-9zz")
    zid = _upload(client, path.read_bytes(), "aes.zip").get_json()["id"]
    jid = client.post("/api/v1/jobs",
                      json={"zip_id": zid, "mode": "brute", "charset": "0123456789",
                            "min_len": 6, "max_len": 8, "workers": 2}).get_json()["job_id"]
    time.sleep(0.5)                     # job is inside its first task now
    t0 = time.time()
    client.post(f"/api/v1/jobs/{jid}/stop")
    s = _wait_terminal(client, jid, timeout=8)
    assert s["state"] == "stopped" and time.time() - t0 < 8


def test_dict_after_stopped_brute_completes(client, tmp_path):
    """a fresh job must never queue behind a stopped job's stranded tasks."""
    zid = _upload(client, _zc_bytes(tmp_path), "t.zip").get_json()["id"]
    jid = client.post("/api/v1/jobs",
                      json={"zip_id": zid, "mode": "brute", "charset": "0123456789",
                            "min_len": 6, "max_len": 6, "workers": 2}).get_json()["job_id"]
    time.sleep(1.5)                     # brute submitted its first batch it will never see
    client.post(f"/api/v1/jobs/{jid}/stop")
    _wait_terminal(client, jid, timeout=10)
    wl = tmp_path / "w.txt"
    wl.write_text("aaa\npkware42\n")
    jid2 = client.post("/api/v1/jobs",
                       json={"zip_id": zid, "mode": "dict", "wordlist": str(wl),
                             "workers": 2}).get_json()["job_id"]
    s = _wait_terminal(client, jid2, timeout=60)
    assert s["state"] == "found" and s["found"] == "pkware42"


def test_dict_completes_while_brute_shares_pool(client, tmp_path):
    """two jobs sharing the pool must both progress. before batched
    feeding, the first job's feeder dumped its whole stream (1700+ tasks,
    ~40 minutes of work) into the shared queue and the job that joined
    later made zero progress."""
    za = _upload(client, _zc_bytes(tmp_path), "a.zip").get_json()["id"]
    zb = _upload(client, _zc_bytes(tmp_path), "b.zip").get_json()["id"]
    jid_a = client.post("/api/v1/jobs",
                        json={"zip_id": za, "mode": "brute", "charset": "0123456789",
                              "min_len": 6, "max_len": 8}).get_json()["job_id"]
    # pw sits in the wordlist's LAST chunk, so it lands in the dict job's
    # FIRST batch - the wait below measures the interleave with brute,
    # not a long scan
    wl = tmp_path / "big.txt"
    wl.write_text("\n".join(f"w{i}" for i in range(30000)) + "\npkware42\n")
    jid_b = client.post("/api/v1/jobs",
                        json={"zip_id": zb, "mode": "dict", "wordlist": str(wl),
                              "workers": 2}).get_json()["job_id"]
    s = _wait_terminal(client, jid_b, timeout=60)
    assert s["state"] == "found" and s["found"] == "pkware42"
    a = client.get(f"/api/v1/jobs/{jid_a}").get_json()
    assert a["state"] in ("running", "stopping")    # brute was still going
    client.post(f"/api/v1/jobs/{jid_a}/stop")
    assert _wait_terminal(client, jid_a, timeout=10)["state"] == "stopped"
