"""john/hashcat bridge - locate zip2john and emit ready-to-run commands."""
import os
import shutil
import subprocess

JOHN_DIRS = [
    r"C:\Program Files\John the Ripper jumbo\run",
    r"C:\Program Files (x86)\John the Ripper jumbo\run",
    r"C:\john\run",
    "/usr/bin", "/usr/local/bin", "/opt/john/run",
]


def find_tool(name: str):
    """path to a tool via PATH then the common john install dirs, or None."""
    p = shutil.which(name)
    if p:
        return p
    for d in JOHN_DIRS:
        p = os.path.join(d, name)
        if os.path.isfile(p):
            return p
        if os.name == "nt" and os.path.isfile(p + ".exe"):
            return p + ".exe"
    return None


def build_export(archive_path: str, members: list) -> dict:
    """run zip2john on the archive, return the hash line + command suggestions.

    raises FileNotFoundError when zip2john is absent, RuntimeError on failure.
    """
    z2j = find_tool("zip2john")
    if not z2j:
        raise FileNotFoundError("zip2john (john the ripper) not found on this machine")
    try:
        r = subprocess.run([z2j, archive_path], capture_output=True, text=True, timeout=120)
        lines = (r.stdout or "").strip().splitlines()
        hash_line = next((l for l in lines if l.startswith("$") or ":$" in l), "")
    except subprocess.TimeoutExpired as e:
        raise RuntimeError("zip2john timed out") from e
    except OSError as e:
        raise RuntimeError(f"zip2john failed to run: {e}") from e
    if not hash_line:
        raise RuntimeError("zip2john produced no hash")

    kinds = {m["kind"] for m in members if m["encrypted"]}
    hcat = find_tool("hashcat")
    cmds = [
        "john --wordlist=rockyou.txt hash.txt",
        "john --mask=?a?a?a?a?a?a?a?a hash.txt",
    ]
    if hcat:
        mode = 13600 if "aes" in kinds else 17200
        cmds.append(f"hashcat -a 0 -m {mode} -w 4 hash.txt rockyou.txt")
        cmds.append(f"hashcat -a 3 -m {mode} -w 4 hash.txt ?a?a?a?a?a?a?a?a")
    return {
        "hash": hash_line,
        "commands": cmds,
        "found_john": True,
        "found_hashcat": bool(hcat),
        "note": "john feeds on the $zip2$ line directly; hashcat wants its native "
                "formats (13600 winzip-aes, 17200/17210/17220 pkzip) - if it rejects "
                "the line, extract salt+verifier per its example hashes.",
    }
