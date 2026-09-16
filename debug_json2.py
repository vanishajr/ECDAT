import json
from pathlib import Path

path = Path("ecdat/tests/fixtures/source/ground_truth.json")
print(f"Path: {path}")
print(f"Exists: {path.exists()}")
print(f"Absolute: {path.absolute()}")

if path.exists():
    with open(path) as f:
        data = json.load(f)
    print(f"Fixtures count: {len(data.get('fixtures', []))}")
    for f in data.get('fixtures', []):
        print(f"  {f['fixture_path']}: {len(f.get('expected_findings', []))} expected")