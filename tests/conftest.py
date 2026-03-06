"""Shared fixtures for MedSecure pipeline tests."""

import json
import sys
from pathlib import Path
from unittest.mock import AsyncMock, patch

import pytest

# Add orchestrator/ and dashboard/ to sys.path so bare imports work
ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(ROOT / "orchestrator"))
sys.path.insert(0, str(ROOT / "dashboard"))

from sarif_parser import Finding, FindingGroup  # noqa: E402

FIXTURES_DIR = Path(__file__).parent / "fixtures"
SARIF_DIR = ROOT / "sarif"


# ── SARIF fixtures ──────────────────────────────────────────────

@pytest.fixture
def sarif_path():
    """Path to the real 536KB SARIF file (may not exist in CI)."""
    return SARIF_DIR / "javascript.sarif"


@pytest.fixture
def minimal_sarif_data():
    """Dict loaded from the minimal test SARIF fixture."""
    return json.loads((FIXTURES_DIR / "minimal_sarif.json").read_text())


@pytest.fixture
def tmp_sarif_file(tmp_path):
    """Write minimal SARIF to a temp dir and return the path."""
    src = FIXTURES_DIR / "minimal_sarif.json"
    dst = tmp_path / "test.sarif"
    dst.write_text(src.read_text())
    return dst


# ── Finding / FindingGroup factories ────────────────────────────

@pytest.fixture
def sample_finding_factory():
    """Factory callable — create a Finding with sensible defaults."""

    def _make(**overrides):
        defaults = {
            "rule_id": "js/sql-injection",
            "file": "vulnerable-app/routes/patients.js",
            "start_line": 12,
            "end_line": 12,
            "start_column": 5,
            "end_column": 42,
            "level": "error",
            "precision": "high",
            "security_severity": "8.8",
            "problem_severity": "error",
            "message": "This query depends on a user-provided value.",
            "short_description": "SQL injection",
            "full_description": "Building a SQL query from user-controlled sources is vulnerable.",
            "help_text": "Use parameterized queries.",
            "cwe_ids": ["CWE-89"],
            "tags": ["security", "external/cwe/cwe-089"],
        }
        defaults.update(overrides)
        return Finding(**defaults)

    return _make


@pytest.fixture
def sample_finding(sample_finding_factory):
    """Single pre-built Finding."""
    return sample_finding_factory()


@pytest.fixture
def sample_finding_group(sample_finding_factory):
    """FindingGroup with 3 findings (for grouped template tests)."""
    findings = [
        sample_finding_factory(start_line=12, end_line=12),
        sample_finding_factory(start_line=20, end_line=20),
        sample_finding_factory(start_line=35, end_line=35),
    ]
    return FindingGroup(
        rule_id="js/sql-injection",
        file="vulnerable-app/routes/patients.js",
        findings=findings,
    )


@pytest.fixture
def single_finding_group(sample_finding):
    """FindingGroup with 1 finding (for single template tests)."""
    return FindingGroup(
        rule_id=sample_finding.rule_id,
        file=sample_finding.file,
        findings=[sample_finding],
    )


# ── Tracker fixtures ────────────────────────────────────────────

@pytest.fixture
def sample_tracked_sessions(sample_finding_group):
    """3 TrackedSession objects with mixed statuses."""
    from tracker import TrackedSession

    return [
        TrackedSession(
            group=sample_finding_group,
            session_id="sess-001",
            session_url="https://app.devin.ai/sessions/sess-001",
            status="completed",
            pr_url="https://github.com/example/pull/10",
            started_at=1000.0,
            finished_at=1005.3,
        ),
        TrackedSession(
            group=sample_finding_group,
            session_id="sess-002",
            session_url="https://app.devin.ai/sessions/sess-002",
            status="failed",
            started_at=1000.0,
            finished_at=1003.0,
        ),
        TrackedSession(
            group=sample_finding_group,
            session_id="sess-003",
            session_url="https://app.devin.ai/sessions/sess-003",
            status="needs_human_review",
            started_at=1000.0,
            finished_at=1008.0,
        ),
    ]


# ── Global autouse: patch asyncio.sleep ─────────────────────────

@pytest.fixture(autouse=True)
def fast_sleep():
    """Patch asyncio.sleep to return immediately in all tests."""
    with patch("asyncio.sleep", new_callable=AsyncMock):
        yield
