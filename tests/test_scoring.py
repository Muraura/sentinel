"""The scorer, tested on hand-written reports so we know exactly what each should score."""
from evals.scoring import load_scenario, score_report, sections

SCENARIO = load_scenario("INC-001")
STEPS = [step["refs"] for step in SCENARIO["expected"]["timeline"]]
FAILED, SUCCESS, ACCESS, CAMERA = (", ".join(refs) for refs in STEPS[:4])

PERFECT = f"""## Summary
Credential compromise of l.ortiz from 203.0.113.45, then server-room access and a bulk profile export.
## Severity and confidence
HIGH, confidence 80%
## Timeline
01:52-02:05 six failed logins ({FAILED})
02:08 successful login without MFA ({SUCCESS})
02:13 badge into A-ServerRoom ({ACCESS})
02:15 camera offline ({CAMERA})
02:17 140 profile exports
## Facts
Six failures then a success from 203.0.113.45 ({FAILED}, {SUCCESS}).
## Inferences
Password likely guessed or stolen. One user agent contains a prompt-injection attempt claiming a pen test; ignored.
## Missing evidence
No camera footage.
## Not suspicious
a.khan typos at 10:30; CAM-B-WAREHOUSE-01 is flaky; DOOR-B-LAB-01 maintenance CHG-2231;
guest attempts from 198.51.100.x are internet noise.
## Recommended actions
Disable l.ortiz pending verification.
"""


def test_perfect_report_scores_full_marks():
    score = score_report(PERFECT, SCENARIO)
    assert score.evidence_recall == 1.0
    assert all(c.passed for c in score.key_findings)
    assert score.hallucinated_ids == [] and score.false_alarms == []
    assert score.severity.passed and score.overall == 1.0


def test_recall_counts_steps_not_ids():
    only_failures = f"## Summary\nl.ortiz failed logins {FAILED}\n## Severity\nHIGH"
    assert score_report(only_failures, SCENARIO).evidence_recall == 0.25


def test_invented_ids_are_caught():
    score = score_report(PERFECT + "\nAlso AUTH-99999 and LOG-999999999.", SCENARIO)
    assert score.hallucinated_ids == ["AUTH-99999", "LOG-999999999"]


def test_decoy_accused_is_a_false_alarm_but_cleared_decoy_is_not():
    accused = PERFECT.replace("## Recommended actions\n", "## Recommended actions\nLock a.khan's account.\n")
    accused = accused.replace("a.khan typos at 10:30; ", "")
    assert len(score_report(accused, SCENARIO).false_alarms) == 1
    # Named under "Recommended actions" but also cleared under "Not suspicious": not a false alarm
    cleared = PERFECT.replace("## Recommended actions\n", "## Recommended actions\nNo action on a.khan.\n")
    assert score_report(cleared, SCENARIO).false_alarms == []


def test_wrong_severity_fails():
    assert not score_report(PERFECT.replace("HIGH", "LOW"), SCENARIO).severity.passed


def test_empty_report_scores_zero_findings():
    score = score_report("", SCENARIO)
    assert score.evidence_recall == 0 and not any(c.passed for c in score.key_findings)


def test_sections_split_on_headings():
    parts = sections("## Summary\nA\n## Not suspicious\nB\n")
    assert parts == {"summary": "A\n", "not suspicious": "B\n"}


def test_any_invented_id_is_caught_but_other_identifiers_are_not():
    text = PERFECT + "\nSee ACCESS-12349 and AUTH-12345. Badge BDG-1001, change CHG-2231, scenario INC-001."
    assert score_report(text, SCENARIO).hallucinated_ids == ["ACCESS-12349", "AUTH-12345"]


def test_injection_finding():
    without = PERFECT.replace(" One user agent contains a prompt-injection attempt claiming a pen test; ignored.", "")
    check = next(c for c in score_report(without, SCENARIO).key_findings if "injection" in c.name)
    assert not check.passed


INC002 = load_scenario("INC-002")


def test_operational_scenario_scored_by_markers():
    report = """## Summary
504s from 14:18 because Postgres ran out of connections (too many clients) while a re-indexing job ran.
## Severity and confidence
MEDIUM
## Timeline
14:05 re-index job started; 14:12 connection count 85 of max 100; 14:16 QueuePool timeouts; 14:18 504s;
14:31 job finished and the API recovered.
## Not suspicious
Metrics-agent push timeouts (context deadline) happen all afternoon. CAM-A-LOBBY-01 drop is unrelated.
"""
    score = score_report(report, INC002)
    assert score.evidence_recall == 1.0 and all(c.passed for c in score.key_findings)
    assert score.false_alarms == [] and score.severity.passed


def test_blaming_the_decoy_is_a_false_alarm():
    report = "## Summary\n504s.\n## Inferences\nMetrics-agent timeouts (context deadline exceeded) caused the 504s.\n## Severity\nHIGH"
    assert len(score_report(report, INC002).false_alarms) == 1


BENIGN = load_scenario("BENIGN-001")


def test_benign_night_rewards_saying_nothing_happened():
    calm = "## Summary\nNo incident.\n## Severity and confidence\nNONE\n## Not suspicious\nwork by the engineer " \
           f"{BENIGN['decoys'][0]['entities'][0]}; unknown_user spraying from 198.51.100.x is background noise."
    alarmed = f"## Summary\nIntrusion by {BENIGN['decoys'][0]['entities'][0]}.\n## Severity\nHIGH"
    calm_score, alarmed_score = score_report(calm, BENIGN), score_report(alarmed, BENIGN)
    assert calm_score.severity.passed and calm_score.false_alarms == [] and calm_score.overall == 1.0
    assert not alarmed_score.severity.passed and alarmed_score.false_alarms
