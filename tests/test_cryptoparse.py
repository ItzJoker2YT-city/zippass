"""archive structure parsing: zipcrypto, data-descriptor, winzip AES, target pick."""
import zlib

import pytest

from make_tests import make_aes_zip, make_dd_zip, make_zipcrypto
from zippass import cryptoparse

CONTENT = "unit test archive payload"


def _zc_meta(tmp_path, pwd=b"pkware42", name="secret.txt"):
    path = str(tmp_path / "zc.zip")
    make_zipcrypto(path, pwd, CONTENT, name=name)
    return path, cryptoparse.parse_members(path)


def test_zipcrypto_member(tmp_path):
    path, members = _zc_meta(tmp_path)
    m = members[0]
    assert m["kind"] == "zipcrypto" and m["encrypted"] is True
    check = (zlib.crc32(CONTENT.encode()) >> 24) & 0xFF
    assert m["check"] == check
    assert len(bytes.fromhex(m["raw12"])) == 12
    assert m["path"] == path


def test_data_descriptor_member(tmp_path):
    path = str(tmp_path / "dd.zip")
    make_dd_zip(path, b"descript", "descriptor flag archive")
    m = cryptoparse.parse_members(path)[0]
    # bit-3 archives check against dos time, not crc
    assert m["check"] == (0x6C40 >> 8) & 0xFF


def test_aes_member(tmp_path):
    path = str(tmp_path / "aes.zip")
    make_aes_zip(path, b"aeS-9zz")
    m = cryptoparse.parse_members(path)[0]
    assert m["kind"] == "aes" and m["strength"] == 256
    assert m["salt_len"] == 16 and m["dklen"] == 66      # 2*keylen+2, aes-256
    assert len(bytes.fromhex(m["pv"])) == 2


def test_plain_member(tmp_path):
    import pyzipper
    path = str(tmp_path / "plain.zip")
    with pyzipper.ZipFile(path, "w") as zf:
        zf.writestr("open.txt", "not encrypted")
    m = cryptoparse.parse_members(path)[0]
    assert m["encrypted"] is False and m["kind"] == "plain"


def test_pick_member_smallest_payload():
    members = [
        {"index": 0, "name": "plain", "encrypted": False, "kind": "plain", "csize": 1},
        {"index": 1, "name": "small-zc", "encrypted": True, "kind": "zipcrypto", "csize": 500},
        {"index": 2, "name": "big-aes", "encrypted": True, "kind": "aes",
         "csize": 9999, "payload_len": 9981},
    ]
    assert cryptoparse.pick_member(members)["index"] == 1
    assert cryptoparse.pick_member(members, 2)["index"] == 2


def test_pick_member_errors():
    members = [
        {"index": 0, "name": "plain", "encrypted": False, "kind": "plain", "csize": 1},
        {"index": 1, "name": "enc", "encrypted": True, "kind": "zipcrypto", "csize": 10},
    ]
    with pytest.raises(ValueError):
        cryptoparse.pick_member([{"index": 0, "encrypted": False}])   # nothing encrypted
    with pytest.raises(ValueError):
        cryptoparse.pick_member(members, 0)                            # pinned a plain member
    with pytest.raises(ValueError):
        cryptoparse.pick_member(members, 5)                            # unknown index
