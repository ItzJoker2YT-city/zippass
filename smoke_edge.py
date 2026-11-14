"""smoke tests for browser-triggered paths + odd archive shapes."""
import os
import zipfile

from make_tests import TESTS, make_dd_zip, make_zipcrypto
import test_client as tc


def main():
    # 1. data-descriptor zipcrypto: stdlib read-back, then dict attack through the api
    dd = os.path.join(TESTS, "dd.zip")
    make_dd_zip(dd, b"descript", "descriptor flag archive")
    with zipfile.ZipFile(dd) as zf:
        back = zf.read("dd.txt", pwd=b"descript")
    assert back.startswith(b"descriptor"), "dd build failed"
    print("[+] dd.zip - data-descriptor zipcrypto, stdlib read-back OK")

    wl = os.path.join(TESTS, "small.txt")
    with open(wl, "w") as f:
        f.write("nope1\nnope2\ndescript\nnope3\n")

    tc.run("dict-dd", dd, "dict", {"wordlist": wl})

    # 2. wordlist upload endpoint (browser button)
    w = tc.post_multipart("/api/v1/wordlists", "file", "small.txt", open(wl, "rb").read())
    print("[+] wordlist upload:", w.get("name"), w.get("size"))

    # 3. verify with an empty string + unicode password
    u = tc.post_multipart("/api/v1/uploads", "file", "zc.zip",
                          open(os.path.join(TESTS, "zc.zip"), "rb").read())
    v = tc.post_json(f"/api/v1/archives/{u['id']}/verify", {"passwords": ["", "l3gacy", "passwörd"]})
    print("[+] verify edge:", [(r["password"], r["ok"]) for r in v.get("results", [])])

    # 4. mask mode with custom set + unicode literal
    tc.run("mask-zc", os.path.join(TESTS, "zc.zip"), "mask",
           {"mask": "?1?d?d", "custom": {"c1": "l"}})

    # 5. a second zipcrypto archive with a digits password, bounded brute space
    zc2 = os.path.join(TESTS, "zc2.zip")
    make_zipcrypto(zc2, b"89071", "second archive, digits password")
    tc.run("brute-zc2", zc2, "brute",
           {"charset": "0123456789", "min_len": 5, "max_len": 5})


if __name__ == "__main__":
    main()
