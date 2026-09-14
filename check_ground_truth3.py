import json
with open('ecdat/tests/fixtures/source/ground_truth.json') as f:
    data = json.load(f)

for fixture in data['fixtures']:
    if 'ed25519_ops.py' in fixture['fixture_path']:
        print(f'Fixture: {fixture["fixture_path"]}')
        for exp in fixture['expected_findings']:
            print(f'  Expected: canonical={exp["canonical"]}, curve={exp.get("curve")}, op_type={exp.get("operation_type")}, function={exp.get("function")}, line={exp.get("location", {}).get("line")}')