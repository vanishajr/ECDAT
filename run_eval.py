import sys
sys.path.insert(0, r"C:\Users\Shubh Mehta\Documents\Default Project")

from ecdat.benchmarks.evaluate_pass2 import ComprehensiveEvaluator
from pathlib import Path

evaluator = ComprehensiveEvaluator(Path("ecdat/tests/fixtures/source"))
summary = evaluator.run_full_evaluation()
print("Done")