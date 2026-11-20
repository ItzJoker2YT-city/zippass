"""live validation of the app's cloud driver: ghcompute.run_gh_job -
dispatch -> run registration -> progress polling -> artifact collect ->
local confirm, in-process (what the flask thread does)."""
import json
import os
import tempfile
import uuid

from make_tests import make_aes_zip
from zippass import cryptoparse, ghcompute, jobs

d = tempfile.mkdtemp()
p = os.path.join(d, "driver.zip")
make_aes_zip(p, b"k4p")
meta = cryptoparse.pick_member(cryptoparse.parse_members(p))
cfg = {"mode": "brute", "charset": "abcdefghijklmnopqrstuvwxyz0123456789",
       "min_len": 1, "max_len": 3}
job = jobs.Job(uuid.uuid4().hex, "smoke", meta, cfg)
job.gh = {"token": None, "repo": "ItzJoker2YT-city/zippass", "ref": None,
          "shards": 2}                      # token None -> gh cli login
ghcompute.run_gh_job(job)                   # synchronous, like the thread
print("state:", job.state)
print("found:", job.found)
print("done/total:", job.done, "/", job.total)
print("run url:", job.gh_run_url)
print("error:", job.error)
print("--- log ---")
for line in job.log:
    print(" ", line)
assert job.state == "found" and job.found == "k4p", "driver did not find"
print("DRIVER PATH OK")
