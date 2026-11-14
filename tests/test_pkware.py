"""PKWARE cipher: enc/dec roundtrip and wrong-password behavior."""
import os

from make_tests import PkCrypt
from zippass.pkware import PkDecryptor


def test_roundtrip():
    pwd = b"s3cret!x"
    data = os.urandom(5000)
    encrypted = PkCrypt(pwd).enc(data)
    assert PkDecryptor(pwd).decrypt(encrypted) == data


def test_roundtrip_empty_and_odd_lengths():
    pwd = b"p"
    for n in (0, 1, 11, 12, 13):
        data = os.urandom(n)
        assert PkDecryptor(pwd).decrypt(PkCrypt(pwd).enc(data)) == data


def test_wrong_password_differs():
    pwd = b"correct"
    data = b"plaintext goes here" * 4
    encrypted = PkCrypt(pwd).enc(data)
    wrong = PkDecryptor(b"incorrect").decrypt(encrypted)
    assert wrong != data
