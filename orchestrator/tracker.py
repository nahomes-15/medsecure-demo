"""Track Devin sessions and generate pipeline results."""

import asyncio
import logging
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone

from devin_client import DevinClient, MockDevinClient, TERMINAL_STATES
from sarif_parser import FindingGroup

logger = logging.getLogger(__name__)


@dataclass
class TrackedSession:
    group: FindingGroup
    session_id: str
    session_url: str
    status: str = "dispatched"
    pr_url: str | None = None
    started_at: float = field(default_factory=time.time)
    finished_at: float | None = None


async def poll_sessions(
    client: DevinClient | MockDevinClient,
    sessions: list[TrackedSession],
    initial_interval: float = 2.0,
    max_interval: float = 30.0,
) -> None:
    """Poll all sessions until every one reaches a terminal state.

    v3 terminal states (top-level status): exit, error, suspended
    v3 status_detail tells us the granular outcome:
      - "finished" = Devin completed successfully
      - "waiting_for_user" = Devin is blocked, needs human input
      - "error" = something went wrong
      - "inactivity" / "usage_limit_exceeded" = timed out or hit ACU cap
    """
    pending = {s.session_id: s for s in sessions}
    interval = initial_interval

    while pending:
        for sid, tracked in list(pending.items()):
            try:
                result = await client.get_session(sid)
            except Exception as e:
                logger.warning(f"  Poll error for {sid}: {e}")
                continue

            # Still running — not in a terminal state yet
            if result.status not in TERMINAL_STATES:
                tracked.status = "in_progress"
                continue

            # Terminal state reached
            tracked.finished_at = time.time()
            tracked.pr_url = result.pr_urls[0] if result.pr_urls else None
            so = result.structured_output or {}

            if result.status_detail == "finished":
                # Devin finished — check for PR or structured output
                if tracked.pr_url or so.get("status") == "completed":
                    tracked.status = "completed"
                elif so.get("status") == "needs_human_review":
                    tracked.status = "needs_human_review"
                else:
                    tracked.status = "completed"
            elif result.status_detail == "waiting_for_user":
                tracked.status = "needs_human_review"
            elif result.status == "error":
                tracked.status = "failed"
            elif result.status == "suspended":
                # suspended for other reasons (inactivity, usage limit, etc.)
                tracked.status = "needs_human_review"
            else:
                tracked.status = "failed"

            elapsed = tracked.finished_at - tracked.started_at
            logger.info(
                f"  {sid} -> {tracked.status} ({elapsed:.1f}s)"
                + (f" PR: {tracked.pr_url}" if tracked.pr_url else "")
            )
            del pending[sid]

        if pending:
            await asyncio.sleep(interval)
            interval = min(interval * 2, max_interval)


def generate_report(sessions: list[TrackedSession]) -> dict:
    """Build the pipeline-results.json structure."""
    now = datetime.now(timezone.utc).isoformat()
    findings_out = []

    for s in sessions:
        elapsed = (s.finished_at or time.time()) - s.started_at
        for f in s.group.findings:
            findings_out.append({
                "finding_id": f.finding_id,
                "rule_id": f.rule_id,
                "short_description": f.short_description,
                "level": f.level,
                "precision": f.precision,
                "security_severity": f.security_severity,
                "cwe_ids": f.cwe_ids,
                "file": f.file,
                "start_line": f.start_line,
                "end_line": f.end_line,
                "message": f.message,
                "status": s.status,
                "session_id": s.session_id,
                "session_url": s.session_url,
                "pr_url": s.pr_url,
                "elapsed_seconds": round(elapsed, 1),
            })

    completed = sum(1 for s in sessions if s.status == "completed")
    review = sum(1 for s in sessions if s.status == "needs_human_review")
    failed = sum(1 for s in sessions if s.status == "failed")
    in_progress = sum(1 for s in sessions if s.status in ("dispatched", "in_progress"))

    return {
        "pipeline_run": {
            "timestamp": now,
            "total_findings": len(findings_out),
            "total_sessions": len(sessions),
            "completed": completed,
            "needs_human_review": review,
            "failed": failed,
            "in_progress": in_progress,
            "remediation_rate": round(completed / len(sessions) * 100, 1) if sessions else 0,
        },
        "findings": findings_out,
    }


def print_summary(report: dict) -> None:
    """Print a human-readable markdown summary to stdout."""
    stats = report["pipeline_run"]
    print("\n" + "=" * 60)
    print("  MEDSECURE SECURITY REMEDIATION — PIPELINE RESULTS")
    print("=" * 60)
    print(f"  Timestamp:          {stats['timestamp']}")
    print(f"  Total findings:     {stats['total_findings']}")
    print(f"  Devin sessions:     {stats['total_sessions']}")
    print(f"  Completed (PR):     {stats['completed']}")
    print(f"  Needs review:       {stats['needs_human_review']}")
    print(f"  Failed:             {stats['failed']}")
    print(f"  Remediation rate:   {stats['remediation_rate']}%")
    print("=" * 60)

    for f in report["findings"]:
        icon = {"completed": "+", "needs_human_review": "?", "failed": "x"}.get(
            f["status"], "."
        )
        cwe = f["cwe_ids"][0] if f["cwe_ids"] else "N/A"
        pr = f" -> {f['pr_url']}" if f["pr_url"] else ""
        print(f"  [{icon}] {f['rule_id']:45s} {f['file']}:L{f['start_line']}  ({cwe}){pr}")

    print()
