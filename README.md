# Sentinel

An AI agent that investigates security and operational incidents. Ask it *"What happened around 02:00?"*: it
decides which evidence to gather, correlates logins, badge access, device status and application logs into one
timeline, and returns a report that separates facts from inferences, citing evidence for every claim.

The design principle: **the agent decides what should happen; deterministic software decides what can happen.**

```
                      ┌──────────────────────────── Sentinel ────────────────────────────┐
 analyst ── HTTP ───► │ API (FastAPI, API keys + roles)                                  │
                      │   │                                                              │
                      │   ▼                                                              │
                      │ agent loop ──► LLM (Claude; Ollama as a local backup)            │
                      │   │   reason → act → observe, step limit, narrated logs, traces  │
                      │   ▼                                                              │
                      │ 13 tools: 11 read-only (incl. RAG) · propose_action · submit_report│
                      │   │       validated inputs · bounded outputs · citable IDs       │
                      │   ▼                                                              │
                      │ Postgres: logs · logins · badge access · devices · users         │
                      │                                                                  │
 approver ─ HTTP ───► │ approve/reject ──► executor (unreachable by any model) ──► audit │
                      └──────────────────────────────────────────────────────────────────┘
 Claude Desktop, Cursor, … ── MCP (stdio) ──► the same tools, as an MCP server
```

## What it demonstrates

| Area | How |
|---|---|
| **Tool design** | Every tool requires a time range and a limit, reports truncation (`total_matching`, `truncated`), returns citable evidence IDs (`AUTH-00009`, `ACC-00007`, `DEV-00001`, `LOG-10030`), and validates every argument (`@validate_call`). Schemas are generated from type hints. |
| **Agent loop** | Hand-written so every step is visible: stop reasons, parallel tool calls, errors returned as observations, a hard step limit. `--debug` shows the exact prompt sent, the model's response and the history at each step. |
| **Output validation** | The agent must finish with `submit_report`. Code checks the schema and that every cited ID exists; a report with an invented ID is rejected and sent back to the model to fix. |
| **Human in the loop** | The agent can only *propose* actions. An approver approves through the API (roles, separation of duties: you can't approve what your own investigation proposed); only then does code execute it, and every step is audited. |
| **Security** | Read-only tools, parameterised queries, allowlisted columns, API keys compared in constant time, fail-closed auth, tool results treated as untrusted data, and a planted prompt-injection test. |
| **RAG** | `search_knowledge` retrieves sections of the organisation's policies, runbooks and past incidents by meaning: documents chunked by section, embedded locally (`bge-small-en-v1.5`), stored in Qdrant. Logs stay in Postgres with exact SQL tools; RAG is for meaning, not counting. |
| **Model fallback** | Claude first; Ollama if Claude is unavailable (network, auth, rate limit). Never used when Claude *declines* a request. |
| **MCP** | The same tools exposed as an MCP server (tools, resources and a prompt), tested through a real MCP client over stdio. |
| **Evaluation** | Synthetic scenarios with answer keys and decoys; a deterministic scorer for evidence recall, key findings, invented IDs, false alarms and severity. |

## Data

| Scenario | What happened | Tests |
|---|---|---|
| `INC-001` | Credential compromise at 02:00 → server-room access → camera offline → 140 profile exports. One attacker-controlled User-Agent carries a prompt injection. | Correlation across 4 sources, injection resistance |
| `INC-002` | 504 errors caused by database connection exhaustion from a re-indexing job; unrelated timeouts and a camera drop as decoys | Operational root cause, correlation vs coincidence |
| `BENIGN-001` | A quiet night: an engineer working late, a flaky camera, internet noise | Saying "no incident" without false alarms |

Each scenario's answer key (`data/synthetic/ground_truth/*.json`) is never visible to the agent.

- **Knowledge base** (`data/knowledge/`): seven short synthetic documents: access control, penetration testing and
  data protection policies, runbooks for credential compromise, database connection exhaustion and offline
  devices, and a past incident report.

## Run it

Requirements: Python 3.12+, Docker, and either an Anthropic API key or [Ollama](https://ollama.com) with a
tool-calling model (`ollama pull qwen3:8b`).

```bash
python -m venv .venv && .venv/bin/pip install -r requirements.txt
cp .env.example .env                      # then fill in ANTHROPIC_API_KEY and/or OLLAMA_MODEL, SENTINEL_API_USERS
docker compose up -d                      # Postgres on localhost:5433
.venv/bin/python scripts/generate_sample_logs.py
(cd scripts && ../.venv/bin/python ingest.py)   # or: ingest.py path/to/your/loki-export.json
.venv/bin/python scripts/generate_security_data.py
.venv/bin/python scripts/ingest_security.py --reset
.venv/bin/python -m pytest tests          # 85 tests
```

**Investigate from the command line**
```bash
.venv/bin/python scripts/investigate.py --provider ollama "Investigate the authentication failures around 02:00."
.venv/bin/python scripts/investigate.py --provider ollama --debug "..."   # show prompts, responses, history
```

**Through the API**
```bash
.venv/bin/uvicorn api.main:app --host 127.0.0.1 --port 8800    # docs at http://127.0.0.1:8800/docs

curl -s -X POST http://127.0.0.1:8800/investigations -H "X-API-Key: $ANALYST_KEY" \
  -H 'Content-Type: application/json' -d '{"question": "What happened around 02:00?", "provider": "ollama"}'
curl -s http://127.0.0.1:8800/investigations/<id> -H "X-API-Key: $ANALYST_KEY"
curl -s "http://127.0.0.1:8800/actions?status_filter=pending" -H "X-API-Key: $ANALYST_KEY"
curl -s -X POST http://127.0.0.1:8800/actions/<id>/approve -H "X-API-Key: $APPROVER_KEY" \
  -H 'Content-Type: application/json' -d '{"note": "confirmed with the account owner"}'
curl -s http://127.0.0.1:8800/audit -H "X-API-Key: $APPROVER_KEY"
```

**As an MCP server** (e.g. Claude Desktop: Settings → Developer → Edit Config)
```json
{
  "mcpServers": {
    "sentinel": {
      "command": "/absolute/path/to/Sentinel/.venv/bin/python",
      "args": ["-m", "mcp_server.server"],
      "cwd": "/absolute/path/to/Sentinel"
    }
  }
}
```
`scripts/mcp_client_demo.py` shows the same connection from the client side: handshake, discovery, a tool call.

**Evaluate**
```bash
.venv/bin/python scripts/run_eval.py --provider ollama --label "what changed"   # every scenario
.venv/bin/python scripts/score_trace.py                                         # score the latest trace
```

## Layout

```
agent/        the loop, model providers (Claude, Ollama), tool registry, narration, context
tools/        read-only investigation tools, RAG (knowledge.py), propose_action, evidence-ID checks
schemas/      LogEvent, IncidentReport + submit_report
actions/      the executor for approved actions (not reachable by the agent)
api/          FastAPI: investigations, approvals, audit, health
mcp_server/   the MCP server
evals/        scoring against answer keys; results/ holds eval runs
scripts/      ingestion, data generation, CLI, eval runner, MCP client demo
db/           schema.sql and SQLAlchemy table definitions
```
