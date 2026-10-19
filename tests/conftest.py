import sys
from pathlib import Path

# Make Sentinel/ and Sentinel/scripts/ importable from every test
SENTINEL_DIR = Path(__file__).resolve().parent.parent
sys.path[:0] = [str(SENTINEL_DIR), str(SENTINEL_DIR / "scripts")]


import pytest  # noqa: E402


@pytest.fixture(autouse=True)
def plain_text_answers_allowed(monkeypatch):
    """Most loop tests script a plain-text final answer; the submit_report tests switch this back on."""
    import agent.investigator as investigator
    monkeypatch.setattr(investigator, "REQUIRE_STRUCTURED_REPORT", False)
