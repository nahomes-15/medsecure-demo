"""Tests for orchestrator/sarif_parser.py."""

import json

import pytest
from sarif_parser import (
    SarifParseError,
    _extract_cwes,
    _should_skip,
    group_findings,
    parse_sarif,
)

pytestmark = pytest.mark.unit


# ── _should_skip ────────────────────────────────────────────────

class TestShouldSkip:
    def test_should_skip_test_files(self):
        assert _should_skip("test/foo.js") is True

    def test_should_skip_node_modules(self):
        assert _should_skip("node_modules/x.js") is True

    def test_should_skip_vendor(self):
        assert _should_skip("vendor/lib.js") is True

    def test_should_skip_minified(self):
        assert _should_skip("app.min.js") is True

    def test_should_not_skip_source(self):
        assert _should_skip("routes/auth.js") is False


# ── _extract_cwes ───────────────────────────────────────────────

class TestExtractCwes:
    def test_extract_cwes_single(self):
        assert _extract_cwes(["external/cwe/cwe-079"]) == ["CWE-79"]

    def test_extract_cwes_multiple(self):
        tags = ["external/cwe/cwe-089", "security", "external/cwe/cwe-079"]
        result = _extract_cwes(tags)
        assert result == ["CWE-89", "CWE-79"]

    def test_extract_cwes_empty(self):
        assert _extract_cwes([]) == []

    def test_extract_cwes_non_cwe_tags(self):
        assert _extract_cwes(["security", "correctness"]) == []

    def test_extract_cwes_leading_zeros(self):
        assert _extract_cwes(["external/cwe/cwe-089"]) == ["CWE-89"]


# ── Finding dataclass ───────────────────────────────────────────

class TestFinding:
    def test_finding_id_format(self, sample_finding):
        fid = sample_finding.finding_id
        assert fid == "js/sql-injection-vulnerable-app-routes-patients-js-L12"

    def test_finding_id_unique(self, sample_finding_factory):
        f1 = sample_finding_factory(start_line=12)
        f2 = sample_finding_factory(start_line=20)
        assert f1.finding_id != f2.finding_id


# ── parse_sarif ─────────────────────────────────────────────────

class TestParseSarif:
    def test_parse_sarif_minimal(self, tmp_sarif_file):
        findings = parse_sarif(tmp_sarif_file)
        assert len(findings) == 2

    def test_parse_sarif_skips_test_files(self, tmp_path):
        """SARIF with a test/ path finding should be filtered out."""
        sarif = {
            "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
            "version": "2.1.0",
            "runs": [{
                "tool": {
                    "driver": {"name": "CodeQL", "rules": []},
                    "extensions": [{
                        "name": "codeql/javascript-queries",
                        "rules": [{
                            "id": "js/xss",
                            "shortDescription": {"text": "XSS"},
                            "fullDescription": {"text": "XSS vuln"},
                            "help": {"text": "Fix it"},
                            "defaultConfiguration": {"level": "warning"},
                            "properties": {"tags": ["security"]},
                        }],
                    }],
                },
                "results": [{
                    "ruleId": "js/xss",
                    "message": {"text": "XSS"},
                    "locations": [{
                        "physicalLocation": {
                            "artifactLocation": {"uri": "test/helpers.js"},
                            "region": {"startLine": 1},
                        },
                    }],
                    "rule": {"index": 0, "toolComponent": {"index": 0}},
                }],
            }],
        }
        p = tmp_path / "skip.sarif"
        p.write_text(json.dumps(sarif))
        assert parse_sarif(p) == []

    def test_parse_sarif_real_file(self, sarif_path):
        if not sarif_path.exists():
            pytest.skip("Real SARIF file not present")
        findings = parse_sarif(sarif_path)
        assert len(findings) == 28

    def test_parse_sarif_fields(self, tmp_sarif_file):
        findings = parse_sarif(tmp_sarif_file)
        f = findings[0]
        assert f.rule_id == "js/sql-injection"
        assert f.file == "vulnerable-app/routes/patients.js"
        assert f.start_line == 12
        assert f.level == "error"
        assert f.precision == "high"
        assert f.security_severity == "8.8"
        assert f.cwe_ids == ["CWE-89"]
        assert f.short_description == "SQL injection"
        assert f.message == "This query depends on a user-provided value."
        assert f.help_text == "Use parameterized queries or prepared statements."

    def test_parse_sarif_missing_file(self, tmp_path):
        with pytest.raises(SarifParseError, match="not found"):
            parse_sarif(tmp_path / "nonexistent.sarif")

    def test_parse_sarif_invalid_json(self, tmp_path):
        bad = tmp_path / "bad.sarif"
        bad.write_text("not valid json {{{")
        with pytest.raises(SarifParseError, match="Invalid JSON"):
            parse_sarif(bad)

    def test_parse_sarif_no_runs(self, tmp_path):
        p = tmp_path / "empty.sarif"
        p.write_text(json.dumps({"version": "2.1.0"}))
        with pytest.raises(SarifParseError, match="No 'runs'"):
            parse_sarif(p)

    def test_parse_sarif_malformed_result_skipped(self, tmp_path):
        """Results with missing locations should be silently skipped."""
        sarif = {
            "version": "2.1.0",
            "runs": [{
                "tool": {"driver": {"name": "CodeQL", "rules": []}, "extensions": []},
                "results": [{"ruleId": "bad", "locations": [{}]}],
            }],
        }
        p = tmp_path / "malformed.sarif"
        p.write_text(json.dumps(sarif))
        assert parse_sarif(p) == []


# ── group_findings ──────────────────────────────────────────────

class TestGroupFindings:
    def test_group_findings_groups_by_rule_and_file(self, sample_finding_factory):
        findings = [
            sample_finding_factory(start_line=10),
            sample_finding_factory(start_line=20),
        ]
        groups = group_findings(findings)
        assert len(groups) == 1
        assert len(groups[0].findings) == 2

    def test_group_findings_splits_different_files(self, sample_finding_factory):
        findings = [
            sample_finding_factory(file="a.js"),
            sample_finding_factory(file="b.js"),
        ]
        groups = group_findings(findings)
        assert len(groups) == 2

    def test_group_findings_severity_order(self, sample_finding_factory):
        findings = [
            sample_finding_factory(level="warning", rule_id="warn-rule", file="a.js"),
            sample_finding_factory(level="error", rule_id="err-rule", file="b.js"),
        ]
        groups = group_findings(findings)
        assert groups[0].level == "error"
        assert groups[1].level == "warning"

    def test_group_findings_empty(self):
        assert group_findings([]) == []

    def test_group_findings_real_file(self, sarif_path):
        if not sarif_path.exists():
            pytest.skip("Real SARIF file not present")
        findings = parse_sarif(sarif_path)
        groups = group_findings(findings)
        assert len(groups) == 13
