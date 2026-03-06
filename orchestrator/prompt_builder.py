"""Build Devin prompts from SARIF findings using one universal template.

The structured output format is enforced via JSON Schema in the API request
(structured_output_schema field), so we don't need to describe the format
in the prompt — just tell Devin to update structured output as it works.
"""

from sarif_parser import FindingGroup

SINGLE_TEMPLATE = """\
You are fixing a security vulnerability found by CodeQL static analysis.

## Finding
- **Rule**: {rule_id}
- **Vulnerability**: {short_description}
- **Severity**: {level}
- **Precision**: {precision}
- **Security Severity Score**: {security_severity}
- **File**: {file}
- **Line**: {start_line}

## What CodeQL Found
{message}

## About This Vulnerability
{full_description}

## Remediation Guidance
{help_text}

## CWE References
{cwe_list}

## Your Task
1. Go to the file and line indicated above
2. Read the surrounding code to understand the context
3. Implement the minimal fix that remediates this specific vulnerability
4. Do not change unrelated code
5. Run any existing tests to make sure nothing breaks
6. Open a PR with a clear title and description

**Branch name**: security/fix-{rule_id}-{safe_filename}-L{start_line}
**PR title**: fix: remediate {short_description} in {filename} ({primary_cwe})
**PR description**: Should explain what the vulnerability was, what was changed, and why the fix is correct. Reference the CWE ID.

Update your structured output as you work — set finding_id to "{finding_id}", file to "{file}", and cwe to "{primary_cwe}". Set status to "completed" when the PR is opened, or "needs_human_review" if you encounter something you can't confidently fix.\
"""
# Schema enforcement lives in the API request, not these templates

GROUPED_TEMPLATE = """\
You are fixing multiple instances of the same security vulnerability found by CodeQL static analysis.

## Finding
- **Rule**: {rule_id}
- **Vulnerability**: {short_description}
- **Severity**: {level}
- **Precision**: {precision}
- **Security Severity Score**: {security_severity}
- **File**: {file}
- **Affected Lines**: {lines_list}

## What CodeQL Found
{messages}

## About This Vulnerability
{full_description}

## Remediation Guidance
{help_text}

## CWE References
{cwe_list}

## Your Task
1. Go to the file indicated above
2. Fix ALL {count} instances of this vulnerability at the lines listed
3. Read the surrounding code to understand the context for each instance
4. Implement the minimal fix for each instance
5. Do not change unrelated code
6. Run any existing tests to make sure nothing breaks
7. Open a single PR covering all fixes in this file

**Branch name**: security/fix-{rule_id}-{safe_filename}
**PR title**: fix: remediate {count}x {short_description} in {filename} ({primary_cwe})
**PR description**: Should explain what the vulnerability was, what was changed at each location, and why the fixes are correct. Reference the CWE ID.

Update your structured output as you work — set finding_id to "{group_id}", file to "{file}", and cwe to "{primary_cwe}". Set status to "completed" when the PR is opened, or "needs_human_review" if you encounter something you can't confidently fix.\
"""


def _safe_filename(filepath: str) -> str:
    # dots/slashes break git branch names
    return filepath.split("/")[-1].replace(".", "-")


def _primary_cwe(cwe_ids: list[str]) -> str:
    return cwe_ids[0] if cwe_ids else "N/A"


def build_prompt(group: FindingGroup) -> str:
    """Build a Devin prompt for a finding group."""
    # rule-level metadata is identical across a group; grab from first
    f0 = group.findings[0]
    filename = group.file.split("/")[-1]
    safe_fn = _safe_filename(group.file)
    primary = _primary_cwe(f0.cwe_ids)
    cwe_list = ", ".join(f0.cwe_ids) if f0.cwe_ids else "None identified"

    if len(group.findings) == 1:
        return SINGLE_TEMPLATE.format(
            rule_id=f0.rule_id,
            short_description=f0.short_description,
            level=f0.level,
            precision=f0.precision,
            security_severity=f0.security_severity or "N/A",
            file=f0.file,
            start_line=f0.start_line,
            message=f0.message,
            full_description=f0.full_description,
            help_text=f0.help_text,
            cwe_list=cwe_list,
            safe_filename=safe_fn,
            filename=filename,
            primary_cwe=primary,
            finding_id=f0.finding_id,
        )

    lines_list = ", ".join(f"L{f.start_line}" for f in group.findings)
    messages = "\n\n".join(
        f"**Line {f.start_line}**: {f.message}" for f in group.findings
    )

    return GROUPED_TEMPLATE.format(
        rule_id=f0.rule_id,
        short_description=f0.short_description,
        level=f0.level,
        precision=f0.precision,
        security_severity=f0.security_severity or "N/A",
        file=group.file,
        lines_list=lines_list,
        messages=messages,
        full_description=f0.full_description,
        help_text=f0.help_text,
        cwe_list=cwe_list,
        count=len(group.findings),
        safe_filename=safe_fn,
        filename=filename,
        primary_cwe=primary,
        group_id=f"{f0.rule_id}-{safe_fn}",  # synthetic ID — no single finding applies
    )


def build_title(group: FindingGroup) -> str:
    """Build a human-readable session title for the Devin dashboard."""
    f0 = group.findings[0]
    filename = group.file.split("/")[-1]
    primary = _primary_cwe(f0.cwe_ids)
    if len(group.findings) == 1:
        return f"Fix {f0.short_description} in {filename} ({primary})"
    return f"Fix {len(group.findings)}x {f0.short_description} in {filename} ({primary})"


def build_tags(group: FindingGroup) -> list[str]:
    """Build tags for a Devin session from a finding group."""
    tags = ["security", group.rule_id, group.level]
    tags.extend(group.cwe_ids)
    return tags


if __name__ == "__main__":
    from sarif_parser import group_findings, parse_sarif

    findings = parse_sarif("../sarif/javascript.sarif")
    groups = group_findings(findings)

    for g in groups:
        prompt = build_prompt(g)
        tags = build_tags(g)
        title = build_title(g)
        print(f"{'='*80}")
        print(f"TITLE: {title}")
        print(f"GROUP: {g.rule_id} | {g.file} | {len(g.findings)} finding(s)")
        print(f"TAGS: {tags}")
        print(f"PROMPT LENGTH: {len(prompt)} chars")
        print(f"{'='*80}")
        print(prompt[:500])
        print("...\n")
