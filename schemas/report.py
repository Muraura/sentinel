"""The incident report as a validated structure, and submit_report: the tool the agent uses to hand it in.

Asking for evidence in the prompt is a request. This makes it a check: a report is accepted only if
  - it matches the schema (severity is one of five levels, every fact has at least one evidence ID, ...)
  - every evidence ID is well-formed (AUTH-00009, ACC-00007, DEV-00001, LOG-10030)
  - every evidence ID exists in the database
Otherwise submit_report raises, the error goes back to the model as an observation, and it must fix the report.
"""
from typing import Annotated, Literal

from pydantic import BaseModel, Field, validate_call

from tools.evidence import EVIDENCE_ID, evidence_like_tokens, existing_ids

EvidenceId = Annotated[str, Field(pattern=rf"^(?:{EVIDENCE_ID})$", description="An ID returned by a tool")]
Text = Annotated[str, Field(min_length=1, max_length=1000)]


class TimelineEntry(BaseModel):
    time: Annotated[str, Field(min_length=1, max_length=40, description="UTC, e.g. 2026-09-30 02:08")]
    what: Text
    evidence: list[EvidenceId] = []


class Fact(BaseModel):
    statement: Text
    evidence: Annotated[list[EvidenceId], Field(min_length=1, description="A fact must cite at least one ID")]


class Inference(BaseModel):
    statement: Text
    confidence: Literal["low", "medium", "high"]
    reasoning: Text


class Cleared(BaseModel):
    item: Text
    reason: Text


class RecommendedAction(BaseModel):
    action: Text
    target: Annotated[str, Field(min_length=1, max_length=200)]
    reason: Text


class IncidentReport(BaseModel):
    summary: Annotated[str, Field(min_length=1, max_length=2000)]
    severity: Literal["NONE", "LOW", "MEDIUM", "HIGH", "CRITICAL"]
    confidence: Annotated[int, Field(ge=0, le=100, description="How sure you are of the assessment, in percent")]
    timeline: list[TimelineEntry]
    facts: list[Fact]
    inferences: list[Inference]
    missing_evidence: list[Text]
    not_suspicious: list[Cleared]
    recommended_actions: list[RecommendedAction]

    def cited_ids(self) -> set[str]:
        return {e for t in self.timeline for e in t.evidence} | {e for f in self.facts for e in f.evidence}

    def to_markdown(self) -> str:
        def ids(evidence):
            return f" ({', '.join(evidence)})" if evidence else ""
        lines = ["## Summary", self.summary, "", "## Severity and confidence",
                 f"{self.severity}, confidence {self.confidence}%", "", "## Timeline"]
        lines += [f"- {t.time}: {t.what}{ids(t.evidence)}" for t in self.timeline] or ["- (none)"]
        lines += ["", "## Facts"] + ([f"- {f.statement}{ids(f.evidence)}" for f in self.facts] or ["- (none)"])
        lines += ["", "## Inferences"] + ([f"- {i.statement} (confidence: {i.confidence}). {i.reasoning}"
                                           for i in self.inferences] or ["- (none)"])
        lines += ["", "## Missing evidence"] + ([f"- {m}" for m in self.missing_evidence] or ["- (none)"])
        lines += ["", "## Not suspicious"] + ([f"- {c.item}: {c.reason}" for c in self.not_suspicious] or ["- (none)"])
        lines += ["", "## Recommended actions (for human approval)"] + (
            [f"- {a.action} → {a.target}: {a.reason}" for a in self.recommended_actions] or ["- (none)"])
        return "\n".join(lines)


@validate_call
def submit_report(
    summary: Annotated[str, Field(min_length=1, max_length=2000)],
    severity: Literal["NONE", "LOW", "MEDIUM", "HIGH", "CRITICAL"],
    confidence: Annotated[int, Field(ge=0, le=100)],
    timeline: list[TimelineEntry],
    facts: list[Fact],
    inferences: list[Inference],
    missing_evidence: list[Text],
    not_suspicious: list[Cleared],
    recommended_actions: list[RecommendedAction],
) -> IncidentReport:
    """Submit your final assessment. Call this exactly once, when your investigation is complete; it ends the
    investigation. Every fact must cite at least one evidence ID that a tool returned to you (AUTH-, ACC-, DEV-,
    LOG-). If the report is rejected, read the error, fix the report and submit again."""
    report = IncidentReport(
        summary=summary, severity=severity, confidence=confidence, timeline=timeline, facts=facts,
        inferences=inferences, missing_evidence=missing_evidence, not_suspicious=not_suspicious,
        recommended_actions=recommended_actions,
    )
    # Every ID-shaped token anywhere in the report must exist, not only those in the evidence lists:
    # an invented "USER-00001" in the summary is as misleading as one in a fact
    mentioned = report.cited_ids() | evidence_like_tokens(report.model_dump_json())
    unknown = sorted(mentioned - existing_ids(mentioned))
    if unknown:
        raise ValueError(f"these evidence IDs do not exist: {', '.join(unknown)}. Cite only IDs that tools returned "
                         f"to you; remove or replace them and submit again")
    return report
