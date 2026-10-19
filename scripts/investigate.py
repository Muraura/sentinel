"""Ask Sentinel a question.

Usage:
  .venv/bin/python scripts/investigate.py "Investigate the authentication failures around 02:00"
  .venv/bin/python scripts/investigate.py --effort high "Why did camera CAM-A-SERVERROOM-01 go offline?"
  .venv/bin/python scripts/investigate.py --provider ollama "Was there suspicious access to Building A last night?"

--provider auto (default): Claude first, Ollama if Claude is unavailable. claude / ollama / huggingface / gemini: only that one.
"""
import argparse
import logging
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from agent.investigator import investigate  # noqa: E402
from agent.providers import PROVIDER_CHOICES, build_providers  # noqa: E402

parser = argparse.ArgumentParser(description="Run a Sentinel investigation")
parser.add_argument("question")
parser.add_argument("--effort", choices=["low", "medium", "high", "xhigh", "max"], default="medium",
                    help="Claude only: how hard it thinks")
parser.add_argument("--provider", choices=PROVIDER_CHOICES, default="auto")
parser.add_argument("--debug", action="store_true",
                    help="also show the raw data: prompts sent, LLM responses, history appended")
args = parser.parse_args()
logging.basicConfig(level=logging.INFO, format="%(message)s")  # show the step-by-step narration
if args.debug:
    logging.getLogger("sentinel").setLevel(logging.DEBUG)

trace = investigate(args.question, effort=args.effort, providers=build_providers(args.provider, args.effort))

print("\n" + "=" * 80 + "\n")
print(trace.answer)
print("\n" + "=" * 80)
errors = sum(c.is_error for c in trace.tool_calls)
print(f"{trace.steps} steps · {len(trace.tool_calls)} tool calls ({errors} errors) · {trace.duration_s}s · "
      f"tokens in {trace.input_tokens:,} (cache read {trace.cache_read_tokens:,}) / out {trace.output_tokens:,} · "
      f"stop: {trace.stop_reason}")
print(f"models: {', '.join(trace.models_used) or 'none'}")
for e in trace.provider_errors:
    print(f"  step {e['step']}: {e['provider']} skipped: {e['error'][:150]}")
print("Trace saved in traces/")
