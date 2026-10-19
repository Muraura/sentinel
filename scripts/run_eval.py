"""Run every question of one or more scenarios through Sentinel, score each report, and save the results.

Usage:
  .venv/bin/python scripts/run_eval.py --provider ollama                       # every scenario, 1 run each
  .venv/bin/python scripts/run_eval.py --provider ollama --scenario INC-002
  .venv/bin/python scripts/run_eval.py --provider claude --runs 3              # repeat to measure consistency
  .venv/bin/python scripts/run_eval.py --provider ollama --label "after tool fix"

Each scenario asks about its incident from several angles, and BENIGN-001 checks Sentinel can say "nothing
happened". Results go to evals/results/<timestamp>-<provider>.json so runs can be compared over time.
"""
import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

SENTINEL_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(SENTINEL_DIR))
from agent.investigator import investigate  # noqa: E402
from agent.providers import build_providers  # noqa: E402
from evals.scoring import GROUND_TRUTH_DIR, load_scenario, score_report  # noqa: E402

RESULTS_DIR = SENTINEL_DIR / "evals" / "results"
ALL_SCENARIOS = sorted(p.stem for p in GROUND_TRUTH_DIR.glob("*.json"))

parser = argparse.ArgumentParser()
parser.add_argument("--scenario", nargs="+", default=ALL_SCENARIOS, choices=ALL_SCENARIOS)
parser.add_argument("--provider", choices=["claude", "ollama", "huggingface", "gemini"], required=True)
parser.add_argument("--runs", type=int, default=1, help="repeat each question to measure consistency")
parser.add_argument("--effort", default="medium", help="Claude only")
parser.add_argument("--label", default="", help="a note saved with the results, e.g. what changed")
args = parser.parse_args()

provider = build_providers(args.provider, args.effort)[0]
rows = []
for scenario_id in args.scenario:
    scenario = load_scenario(scenario_id)
    for q_index, question in enumerate(scenario["example_questions"], start=1):
        for run in range(1, args.runs + 1):
            print(f"[{scenario_id} Q{q_index} run {run}] {question}", flush=True)
            trace = investigate(question, providers=[provider])
            score = score_report(trace.answer, scenario)
            rows.append({
                "scenario": scenario_id, "question": question, "run": run, "investigation_id": trace.id,
                "score": score.model_dump(), "steps": trace.steps, "tool_calls": len(trace.tool_calls),
                "tool_errors": sum(c.is_error for c in trace.tool_calls),
                "tools_used": sorted({c.name for c in trace.tool_calls}),
                "tokens": trace.input_tokens + trace.output_tokens, "duration_s": trace.duration_s,
                "models": trace.models_used, "stop_reason": trace.stop_reason,
            })
            print(f"         {score.summary()} · {trace.steps} steps · {trace.duration_s}s", flush=True)


def summarise(subset: list[dict]) -> dict:
    n = len(subset)
    names = [c["name"] for c in subset[0]["score"]["key_findings"]]
    return {
        "runs": n,
        "overall": sum(r["score"]["overall"] for r in subset) / n,
        "evidence_recall": sum(r["score"]["evidence_recall"] for r in subset) / n,
        "finding_rates": {name: sum(r["score"]["key_findings"][i]["passed"] for r in subset) / n
                          for i, name in enumerate(names)},
        "severity_right": sum(r["score"]["severity"]["passed"] for r in subset) / n,
        "runs_with_invented_ids": sum(bool(r["score"]["hallucinated_ids"]) for r in subset),
        "runs_with_false_alarms": sum(bool(r["score"]["false_alarms"]) for r in subset),
        "avg_steps": sum(r["steps"] for r in subset) / n,
        "avg_duration_s": sum(r["duration_s"] for r in subset) / n,
        "avg_tokens": sum(r["tokens"] for r in subset) / n,
    }


summaries = {sid: summarise([r for r in rows if r["scenario"] == sid]) for sid in args.scenario}
print("\n" + "=" * 78)
print(f"{args.provider} · {len(rows)} runs" + (f" · {args.label}" if args.label else ""))
for sid, s in summaries.items():
    print(f"\n{sid}: overall {s['overall']:.0%} · evidence steps {s['evidence_recall']:.0%} · severity right "
          f"{s['severity_right']:.0%} · invented IDs in {s['runs_with_invented_ids']}/{s['runs']} · false alarms in "
          f"{s['runs_with_false_alarms']}/{s['runs']} · avg {s['avg_steps']:.1f} steps, {s['avg_duration_s']:.0f}s")
    for name, rate in s["finding_rates"].items():
        print(f"  {rate:5.0%}  {name}")

RESULTS_DIR.mkdir(parents=True, exist_ok=True)
stamp = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H%M%S")
out = RESULTS_DIR / f"{stamp}-{args.provider}.json"
out.write_text(json.dumps({"provider": args.provider, "label": args.label, "scenarios": args.scenario,
                           "summaries": summaries, "runs": rows}, indent=2, default=str))
print(f"\nSaved {out.relative_to(SENTINEL_DIR)}")
