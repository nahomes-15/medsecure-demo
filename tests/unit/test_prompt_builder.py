"""Tests for orchestrator/prompt_builder.py."""

import pytest
from prompt_builder import (
    _primary_cwe,
    _safe_filename,
    build_prompt,
    build_tags,
    build_title,
)

pytestmark = pytest.mark.unit


# ── build_prompt ────────────────────────────────────────────────

class TestBuildPrompt:
    def test_build_prompt_single(self, single_finding_group):
        prompt = build_prompt(single_finding_group)
        assert "js/sql-injection" in prompt
        assert "patients.js" in prompt
        assert "L12" in prompt or "Line**: 12" in prompt
        # Uses SINGLE_TEMPLATE (no "ALL X instances")
        assert "ALL" not in prompt

    def test_build_prompt_grouped(self, sample_finding_group):
        prompt = build_prompt(sample_finding_group)
        assert "3" in prompt  # count
        assert "ALL 3 instances" in prompt
        assert "js/sql-injection" in prompt

    def test_build_prompt_no_cwes(self, sample_finding_factory):
        from sarif_parser import FindingGroup

        f = sample_finding_factory(cwe_ids=[])
        group = FindingGroup(rule_id=f.rule_id, file=f.file, findings=[f])
        prompt = build_prompt(group)
        assert "N/A" in prompt

    def test_build_prompt_contains_branch_name(self, single_finding_group):
        prompt = build_prompt(single_finding_group)
        assert "security/fix-" in prompt

    def test_build_prompt_contains_pr_title(self, single_finding_group):
        prompt = build_prompt(single_finding_group)
        assert "PR title" in prompt
        assert "remediate" in prompt


# ── build_title ─────────────────────────────────────────────────

class TestBuildTitle:
    def test_build_title_single(self, single_finding_group):
        title = build_title(single_finding_group)
        assert title == "Fix SQL injection in patients.js (CWE-89)"

    def test_build_title_grouped(self, sample_finding_group):
        title = build_title(sample_finding_group)
        assert title == "Fix 3x SQL injection in patients.js (CWE-89)"

    def test_build_title_no_cwes(self, sample_finding_factory):
        from sarif_parser import FindingGroup

        f = sample_finding_factory(cwe_ids=[])
        group = FindingGroup(rule_id=f.rule_id, file=f.file, findings=[f])
        title = build_title(group)
        assert "(N/A)" in title


# ── build_tags ──────────────────────────────────────────────────

class TestBuildTags:
    def test_build_tags(self, single_finding_group):
        tags = build_tags(single_finding_group)
        assert "security" in tags
        assert "js/sql-injection" in tags
        assert "error" in tags
        assert "CWE-89" in tags

    def test_build_tags_no_cwes(self, sample_finding_factory):
        from sarif_parser import FindingGroup

        f = sample_finding_factory(cwe_ids=[])
        group = FindingGroup(rule_id=f.rule_id, file=f.file, findings=[f])
        tags = build_tags(group)
        assert "security" in tags
        assert "js/sql-injection" in tags
        assert "error" in tags
        assert len(tags) == 3  # no CWE appended


# ── _safe_filename / _primary_cwe ───────────────────────────────

class TestHelpers:
    def test_safe_filename(self):
        assert _safe_filename("vulnerable-app/routes/auth.js") == "auth-js"

    def test_safe_filename_nested(self):
        assert _safe_filename("a/b/c/d/deep.ts") == "deep-ts"

    def test_primary_cwe_empty(self):
        assert _primary_cwe([]) == "N/A"

    def test_primary_cwe_returns_first(self):
        assert _primary_cwe(["CWE-89", "CWE-79"]) == "CWE-89"
