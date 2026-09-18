from pathlib import Path
import json, subprocess

ROOT=Path(__file__).resolve().parents[1]
path=ROOT/"repo-lock.json"
data=json.loads(path.read_text())
for repo in data["repositories"]:
    url=repo["url"]
    proc=subprocess.run(
        ["git","ls-remote",url,"HEAD"],
        text=True,capture_output=True
    )
    if proc.returncode:
        print(f"FAILED {repo['id']} {url}: {proc.stderr.strip()}")
        continue
    sha=proc.stdout.split()[0]
    repo["commit"]=sha
    print(repo["id"],sha)
path.write_text(json.dumps(data,indent=2)+"\n")
