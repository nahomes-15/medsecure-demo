"""Parse CodeQL SARIF v2.1.0 output into enriched findings."""

import json
import re
from dataclasses import dataclass
from pathlib import Path


class SarifParseError(Exception):
    """Raised when a SARIF file cannot be parsed."""


SKIP_PATTERNS = ["test/", "__tests__/", "node_modules/", "vendor/", ".min.js"]

SEVERITY_ORDER = {"error": 0, "warning": 1, "note": 2, "none": 3}


@dataclass
class Finding:
    """A single CodeQL finding enriched with rule metadata."""

    rule_id: str
    file: str
    start_line: int
    end_line: int | None
    start_column: int
    end_column: int | None
    level: str
    precision: str
    security_severity: str
    problem_severity: str
    message: str
    short_description: str
    full_description: str
    help_text: str
    cwe_ids: list[str]
    tags: list[str]

    @property
    def finding_id(self) -> str:
        safe_file = self.file.replace("/", "-").replace(".", "-")
        return f"{self.rule_id}-{safe_file}-L{self.start_line}"


@dataclass
class FindingGroup:
    """Findings grouped by rule_id + file for a single Devin session."""

    rule_id: str
    file: str
    findings: list[Finding]

    @property
    def level(self) -> str:
        return self.findings[0].level

    @property
    def short_description(self) -> str:
        return self.findings[0].short_description

    @property
    def cwe_ids(self) -> list[str]:
        return self.findings[0].cwe_ids

    @property
    def security_severity(self) -> str:
        return self.findings[0].security_severity


def _build_rule_index(run: dict) -> dict[str, dict]:
    """Build a lookup from (toolComponent index, rule index) -> rule definition."""
    rules = {}
    for ext_idx, ext in enumerate(run["tool"].get("extensions", [])):
        for rule_idx, rule in enumerate(ext.get("rules", [])):
            rules[(ext_idx, rule_idx)] = rule
    # Also check driver rules
    for rule_idx, rule in enumerate(run["tool"]["driver"].get("rules", [])):
        rules[("driver", rule_idx)] = rule
    return rules


def _resolve_rule(result: dict, rule_index: dict) -> dict | None:
    """Resolve a result's rule reference to the full rule definition."""
    ref = result.get("rule", {})
    tc = ref.get("toolComponent", {})
    ext_idx = tc.get("index")
    rule_idx = ref.get("index")

    if ext_idx is not None and rule_idx is not None:
        return rule_index.get((ext_idx, rule_idx))
    if rule_idx is not None:
        return rule_index.get(("driver", rule_idx))
    return None


def _extract_cwes(tags: list[str]) -> list[str]:
    """Pull CWE IDs from tags like 'external/cwe/cwe-089'."""
    cwes = []
    for tag in tags:
        m = re.match(r"external/cwe/cwe-(\d+)", tag)
        if m:
            cwes.append(f"CWE-{int(m.group(1))}")
    return cwes


def _should_skip(uri: str) -> bool:
    return any(pattern in uri for pattern in SKIP_PATTERNS)


def parse_sarif(sarif_path: str | Path) -> list[Finding]:
    """Parse a SARIF file and return enriched findings.

    Raises:
        SarifParseError: If the file is missing, not valid JSON, or has an
            unexpected SARIF structure.
    """
    path = Path(sarif_path)
    if not path.exists():
        raise SarifParseError(f"SARIF file not found: {path}")

    try:
        data = json.loads(path.read_text())
    except json.JSONDecodeError as exc:
        raise SarifParseError(f"Invalid JSON in {path}: {exc}") from exc

    runs = data.get("runs")
    if not runs:
        raise SarifParseError(f"No 'runs' array in SARIF file: {path}")

    run = runs[0]
    rule_index = _build_rule_index(run)
    findings: list[Finding] = []

    for result in run.get("results", []):
        try:
            loc = result["locations"][0]["physicalLocation"]
            uri = loc["artifactLocation"]["uri"]
        except (KeyError, IndexError):
            continue  # skip malformed results

        if _should_skip(uri):
            continue

        rule = _resolve_rule(result, rule_index)
        if rule is None:
            continue

        props = rule.get("properties", {})
        tags = props.get("tags", [])
        default_cfg = rule.get("defaultConfiguration", {})
        region = loc.get("region", {})

        findings.append(Finding(
            rule_id=result.get("ruleId", "unknown"),
            file=uri,
            start_line=region.get("startLine", 0),
            end_line=region.get("endLine"),
            start_column=region.get("startColumn", 0),
            end_column=region.get("endColumn"),
            level=default_cfg.get("level", "warning"),
            precision=props.get("precision", "unknown"),
            security_severity=props.get("security-severity", ""),
            problem_severity=props.get("problem.severity", ""),
            message=result.get("message", {}).get("text", ""),
            short_description=rule.get("shortDescription", {}).get("text", ""),
            full_description=rule.get("fullDescription", {}).get("text", ""),
            help_text=rule.get("help", {}).get("text", ""),
            cwe_ids=_extract_cwes(tags),
            tags=tags,
        ))

    return findings


def group_findings(findings: list[Finding]) -> list[FindingGroup]:
    """Group by (rule_id, file), sort by severity."""
    groups: dict[tuple[str, str], list[Finding]] = {}
    for f in findings:
        key = (f.rule_id, f.file)
        groups.setdefault(key, []).append(f)

    result = [
        FindingGroup(rule_id=k[0], file=k[1], findings=v)
        for k, v in groups.items()
    ]
    result.sort(key=lambda g: SEVERITY_ORDER.get(g.level, 99))
    return result


if __name__ == "__main__":
    import sys

    sarif_path = sys.argv[1] if len(sys.argv) > 1 else "../sarif/javascript.sarif"
    findings = parse_sarif(sarif_path)
    groups = group_findings(findings)

    print(f"Parsed {len(findings)} findings -> {len(groups)} groups\n")
    for g in groups:
        lines = ", ".join(f"L{f.start_line}" for f in g.findings)
        cwes = ", ".join(g.cwe_ids) or "none"
        print(f"  [{g.level:7s}] {g.rule_id:50s} {g.file}  ({lines})  [{cwes}]")
