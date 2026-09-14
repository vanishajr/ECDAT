import json
with open('ecdat/tests/fixtures/source/ground_truth.json') as f:
    data = json.load(f)
print('Keys:', data.keys())
print('Fixtures count:', len(data.get('fixtures', [])))