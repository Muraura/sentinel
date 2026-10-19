"""Score an investigation report against a scenario's answer key (data/synthetic/ground_truth/*.json).

Everything here is deterministic code: string and ID matching, no LLM. That makes it cheap, repeatable and
explainable, but it can only check what is mechanically checkable. Judging the quality of reasoning
(are the inferences sound? is "missing evidence" really missing?) needs an LLM judge or a human: a later step.

Each scenario's answer key defines what to check (data/synthetic/ground_truth/<id>.json), so adding a scenario
needs no code change:
  expected.severity      acceptable severities, e.g. ["HIGH", "CRITICAL"] or ["NONE", "LOW"]
  expected.timeline      steps; a step is found if the report cites any of its refs or contains any of its markers
  expected.key_findings  each passes if the report cites any refs_any, contains any text_any, and contains no text_none

Checks:
  evidence_recall   share of the answer key's timeline steps the report cites evidence for. Counted per step,
                    not per ID: six failed logins are one fact, and counting them six times would let the
                    easiest evidence inflate the score
  key_findings      the incident's essential facts, each one yes/no
  hallucinated_ids  cited IDs that don't exist in the database (should be none)
  false_alarms      decoys the report treats as part of the incident
  severity          the report's severity matches the expected one
"""
import json
import re
from pathlib import Path

from pydantic import BaseModel

from tools.evidence import evidence_like_tokens, existing_ids

GROUND_TRUTH_DIR = Path(__file__).resolve().parent.parent / "data" / "synthetic" / "ground_truth"

# Sections where naming a decoy means the report treats it as part of the incident
ACCUSING_SECTIONS = ("summary", "facts", "inferences", "recommended actions")
CLEARING_SECTION = "not suspicious"


class Check(BaseModel):
    name: str
    passed: bool
    detail: str = ""


class Score(BaseModel):
    scenario: str
    evidence_recall: float          # 0.0 - 1.0, per timeline step
    evidence_found: list[str]
    evidence_missed: list[str]
    key_findings: list[Check]
    hallucinated_ids: list[str]
    false_alarms: list[str]
    severity: Check
    overall: float                  # mean of the five components, for a quick comparison only

    def summary(self) -> str:
        findings = sum(c.passed for c in self.key_findings)
        return (f"overall {self.overall:.0%} | evidence steps {self.evidence_recall:.0%} | findings {findings}/{len(self.key_findings)} | "
                f"hallucinated IDs {len(self.hallucinated_ids)} | false alarms {len(self.false_alarms)} | "
                f"severity {'ok' if self.severity.passed else 'wrong'}")


def load_scenario(scenario_id: str) -> dict:
    return json.loads((GROUND_TRUTH_DIR / f"{scenario_id}.json").read_text())


def sections(report: str) -> dict[str, str]:
    """Split a markdown report on '## ' headings -> {"summary": "...", "timeline": "...", ...}."""
    result, current = {}, "preamble"
    for line in report.splitlines():
        if line.startswith("## "):
            current = line[3:].strip().lower()
            result.setdefault(current, "")
        else:
            result[current] = result.get(current, "") + line + "\n"
    return result


def _section(parts: dict[str, str], name: str) -> str:
    """Headings vary slightly ("Severity and confidence", "Severity"): match by prefix."""
    return "\n".join(text for heading, text in parts.items() if heading.startswith(name))


def _check(spec: dict, text: str, cited: set[str]) -> Check:
    lower = text.lower()
    reasons, passed = [], True
    if spec.get("refs_any"):
        hit = set(spec["refs_any"]) & cited
        passed &= bool(hit)
        reasons.append(f"cites {', '.join(sorted(hit)) if hit else 'none of ' + ', '.join(spec['refs_any'])}")
    if spec.get("text_any"):
        hit = [t for t in spec["text_any"] if t.lower() in lower]
        passed &= bool(hit)
        reasons.append(f"mentions {hit[0]!r}" if hit else f"never mentions {spec['text_any']}")
    if spec.get("text_none"):
        hit = [t for t in spec["text_none"] if t.lower() in lower]
        passed &= not hit
        reasons.append(f"says {hit[0]!r}" if hit else "avoids the forbidden phrases")
    return Check(name=spec["name"], passed=passed, detail="; ".join(reasons))


def score_report(report: str, scenario: dict) -> Score:
    expected = scenario["expected"]
    text = report or ""
    lower = text.lower()
    cited = evidence_like_tokens(text)
    parts = sections(text)

    # 1. Evidence recall, per timeline step: found if any of its refs is cited or any of its markers appears
    expected_ids = [ref for step in expected["timeline"] for ref in step.get("refs", [])]
    found = [r for r in expected_ids if r in cited]
    missed = [r for r in expected_ids if r not in cited]
    scored_steps = [step for step in expected["timeline"] if step.get("refs") or step.get("markers")]
    hits = [bool(set(step.get("refs", [])) & cited) or any(m.lower() in lower for m in step.get("markers", []))
            for step in scored_steps]
    recall = sum(hits) / len(hits) if hits else 1.0

    # 2. Key findings, as the answer key defines them
    findings = [_check(spec, text, cited) for spec in expected["key_findings"]]

    # 3. Invented IDs: evidence-shaped tokens that don't exist (unknown prefixes never do)
    hallucinated = sorted(cited - existing_ids(cited)) if cited else []

    # 4. False alarms: a decoy named in an accusing section, and not cleared under "Not suspicious"
    accusing = "\n".join(_section(parts, s) for s in ACCUSING_SECTIONS).lower()
    cleared = _section(parts, CLEARING_SECTION).lower()
    false_alarms = []
    for decoy in scenario["decoys"]:
        markers = [m.lower() for m in decoy.get("entities", [])] + [r.lower() for r in decoy["refs"]]
        named = [m for m in markers if m in accusing]
        if named and not any(m in cleared for m in markers):
            false_alarms.append(f"{named[0]}: {decoy['why_benign']}")

    # 5. Severity: any acceptable label, as a whole word, in the severity section
    acceptable = expected["severity"] if isinstance(expected["severity"], list) else [expected["severity"]]
    severity_text = _section(parts, "severity") or text
    severity = Check(name=f"severity is {' or '.join(acceptable)}",
                     passed=any(re.search(rf"\b{re.escape(a)}\b", severity_text, re.IGNORECASE) for a in acceptable),
                     detail=" ".join(severity_text.split())[:80])

    components = [
        recall,
        sum(c.passed for c in findings) / len(findings) if findings else 1.0,
        0.0 if hallucinated else 1.0,
        max(0.0, 1 - len(false_alarms) / max(1, len(scenario["decoys"]))),
        1.0 if severity.passed else 0.0,
    ]
    return Score(
        scenario=scenario["id"], evidence_recall=round(recall, 3), evidence_found=found, evidence_missed=missed,
        key_findings=findings, hallucinated_ids=hallucinated, false_alarms=false_alarms, severity=severity,
        overall=round(sum(components) / len(components), 3),
    )
