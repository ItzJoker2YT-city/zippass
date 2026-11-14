"""one-off: smart mangled patterns around the song title / folder name -
capitalization, leetspeak, digit / year / symbol suffixes, initialisms.
runs alongside the background ladder (batched feeding keeps both fair).
NEVER call cleanup_running_jobs here - it would kill the ladder's job."""
import os

from crack_theirs import report, run_job

HERE = os.path.dirname(os.path.abspath(__file__))
ZIP = r"C:\Users\Administrator\Desktop\New folder (2).zip"
WL = os.path.join(HERE, "smart_patterns.txt")

BASES = [
    "whoopsie", "daisy", "whoopsiedaisy", "whoopsie-daisy", "whoopsie daisy",
    "school", "song", "schoolsong", "daisyschool", "schoolsongs",
    "whoopsiedaisyschoolsong", "music", "mp3", "newfolder", "newfolder2",
    "folder", "wdss", "twdss", "wds", "thesong",
]
YEARS = [str(y) for y in range(1950, 2027)]
SYMS = ["", "!", "!!", ".", "?", "#", "123", "1234", "01", "1", "12", "69",
        "420", "007", "07", "99", "666", "777", "2020", "2021", "2022",
        "2023", "2024", "2025", "2026"]
LEET = str.maketrans({"a": "4", "e": "3", "i": "1", "o": "0", "s": "5",
                      "t": "7"})


def variants(base: str) -> list:
    out = []
    for b in (base, base.capitalize(), base.upper(),
              base.translate(LEET), base.capitalize().translate(LEET)):
        out.append(b)
        for suf in YEARS:
            out.append(b + suf)
        for suf in SYMS:
            if suf:
                out.append(b + suf)
    # doubled and reversed compounds
    out += [base + base, base.capitalize() + base.capitalize()]
    return out


def main():
    seen, lines = set(), []
    for base in BASES:
        for v in variants(base):
            if v not in seen:
                seen.add(v)
                lines.append(v)
    with open(WL, "w", encoding="utf-8") as f:
        f.write("\n".join(lines) + "\n")
    print(f"wordlist: {len(lines)} candidates", flush=True)

    zid = None
    s = run_job("smart patterns", {"zip_id": _zip_id(), "mode": "dict",
                                   "wordlist": WL}, 600)
    if s["state"] == "found":
        report(s)


def _zip_id():
    """fresh upload each run - no cleanup calls here."""
    from check_refresh import upload
    return upload(ZIP)["id"]


if __name__ == "__main__":
    main()
