#!/usr/bin/env bash
# Assemble the files for the Hugging Face Space from an ALLOWLIST, then check nothing private slipped in.
# Usage:  deploy/huggingface/prepare_space.sh /path/to/space-folder
set -euo pipefail
cd "$(dirname "$0")/../.."
OUT="${1:?usage: prepare_space.sh <output folder>}"
mkdir -p "$OUT"

# Only these go public. Anything not listed (logs/, .env, traces/, evals/results/...) stays on this machine.
for path in agent actions api db demo mcp_server schemas tools \
            evals/__init__.py evals/scoring.py \
            data/synthetic data/knowledge \
            scripts/__init__.py scripts/clean_data.py scripts/ingest.py scripts/ingest_security.py \
            scripts/generate_security_data.py scripts/generate_sample_logs.py scripts/investigate.py \
            Dockerfile .dockerignore requirements.txt requirements-demo.txt .env.example; do
  mkdir -p "$OUT/$(dirname "$path")"
  rsync -a --exclude '__pycache__' --exclude '.DS_Store' "$path" "$OUT/$(dirname "$path")/"
done
cp deploy/huggingface/README.md "$OUT/README.md"

# Safety gate: refuse to finish if anything private is present
problems=$(cd "$OUT" && { find . -name '.env' -o -path './logs*' -o -path './traces*' -o -name '*.log'; \
           grep -rlE 'sk-ant-|hf_[A-Za-z0-9]{20,}' . 2>/dev/null || true; } | sort -u)
if [ -n "$problems" ]; then
  echo "REFUSING: private files or secrets found in $OUT:"; echo "$problems"; exit 1
fi
echo "Space files ready in $OUT ($(find "$OUT" -type f | wc -l | tr -d ' ') files). Nothing private found."
