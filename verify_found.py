"""independent verification of the found password, no app involved:
plain zipfile decrypt-read of the member - zipfile raises BadZipFile on
any CRC mismatch, and the mp3 magic ('ID3') proves a real payload."""
import zipfile

ZIP = r"C:\Users\Administrator\Desktop\New folder (2).zip"
PWD = "jokwe"

with zipfile.ZipFile(ZIP) as zf:
    name = "New folder (2)/The Whoopsie-Daisy School Song.mp3"
    data = zf.read(name, pwd=PWD.encode())   # CRC-checked on read
    print(f"decrypted OK: {len(data)} bytes, head={data[:3]!r}")
    assert len(data) == 1357657, "size mismatch"
    assert data[:3] == b"ID3", "not an mp3 payload"
print("VERIFY PASS - password 'jokwe' opens the archive")
