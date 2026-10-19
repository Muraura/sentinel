"""Score a saved investigation trace against a scenario's answer key.

Usage:
  .venv/bin/python scripts/score_trace.py                      # the latest trace in traces/
  .venv/bin/python scripts/score_trace.py traces/2026-10-08T....json --scenario INC-001
"""
import argparse
import json
import sys
from pathlib import Path

SENTINEL_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(SENTINEL_DIR))
from evals.scoring import load_scenario, score_report  # noqa: E402

parser = argparse.ArgumentParser()
parser.add_argument("trace", nargs="?", help="trace file (default: the latest)")
parser.add_argument("--scenario", default="INC-001")
args = parser.parse_args()

path = Path(args.trace) if args.trace else max((SENTINEL_DIR / "traces").glob("*.json"))
trace = json.loads(path.read_text())
score = score_report(trace["answer"], load_scenario(args.scenario))

print(f"Trace:    {path.name}")
print(f"Question: {trace['question']}")
print(f"Models:   {', '.join(trace.get('models_used') or [trace.get('model', '?')])} · {trace['steps']} steps · "
      f"{len(trace['tool_calls'])} tool calls · {trace['duration_s']}s\n")
print(f"Evidence recall  {score.evidence_recall:.0%}  found {score.evidence_found}")
print(f"                       missed {score.evidence_missed}")
print("Key findings")
for check in score.key_findings:
    print(f"  {'✅' if check.passed else '❌'} {check.name}" + (f" ({check.detail})" if check.detail else ""))
print(f"Hallucinated IDs {score.hallucinated_ids or 'none'}")
print(f"False alarms     {score.false_alarms or 'none'}")
print(f"Severity         {'✅' if score.severity.passed else '❌'} {score.severity.name}")
print(f"\n{score.summary()}")
