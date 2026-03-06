"""Tests for orchestrator/tracker.py."""

from unittest.mock import AsyncMock

import pytest
from devin_client import SessionResult
from tracker import TrackedSession, generate_report, poll_sessions, print_summary

pytestmark = pytest.mark.integration


# ── TrackedSession defaults ─────────────────────────────────────

class TestTrackedSession:
    def test_tracked_session_defaults(self, sample_finding_group):
        ts = TrackedSession(
            group=sample_finding_group,
            session_id="ts-001",
            session_url="https://app.devin.ai/sessions/ts-001",
        )
        assert ts.status == "dispatched"
        assert ts.pr_url is None
        assert ts.started_at > 0
        assert ts.finished_at is None


# ── generate_report ─────────────────────────────────────────────

class TestGenerateReport:
    def test_generate_report_structure(self, sample_tracked_sessions):
        report = generate_report(sample_tracked_sessions)
        assert "pipeline_run" in report
        assert "findings" in report

    def test_generate_report_counts(self, sample_tracked_sessions):
        report = generate_report(sample_tracked_sessions)
        stats = report["pipeline_run"]
        assert stats["total_sessions"] == 3
        assert stats["completed"] == 1
        assert stats["failed"] == 1
        assert stats["needs_human_review"] == 1

    def test_generate_report_rate(self, sample_tracked_sessions):
        report = generate_report(sample_tracked_sessions)
        # 1 completed / 3 sessions = 33.3%
        assert report["pipeline_run"]["remediation_rate"] == 33.3

    def test_generate_report_empty(self):
        report = generate_report([])
        stats = report["pipeline_run"]
        assert stats["total_findings"] == 0
        assert stats["total_sessions"] == 0
        assert stats["remediation_rate"] == 0

    def test_generate_report_findings_expand(self, sample_tracked_sessions):
        """Each session has a group with 3 findings → 3 entries per session."""
        report = generate_report(sample_tracked_sessions)
        # 3 sessions * 3 findings each = 9 finding entries
        assert len(report["findings"]) == 9

    def test_generate_report_elapsed(self, sample_tracked_sessions):
        report = generate_report(sample_tracked_sessions)
        first = report["findings"][0]
        # sess-001: finished_at 1005.3 - started_at 1000.0 = 5.3
        assert first["elapsed_seconds"] == 5.3


# ── print_summary ───────────────────────────────────────────────

class TestPrintSummary:
    def test_print_summary_output(self, sample_tracked_sessions, capsys):
        report = generate_report(sample_tracked_sessions)
        print_summary(report)
        output = capsys.readouterr().out
        assert "MEDSECURE" in output
        assert "Remediation rate" in output
        assert "33.3%" in output


# ── poll_sessions ───────────────────────────────────────────────

class TestPollSessions:
    async def test_poll_sessions_completes(self, sample_finding_group):
        """Mock client returns terminal state → sessions updated."""
        mock_client = AsyncMock()
        mock_client.get_session.return_value = SessionResult(
            session_id="poll-1",
            url="https://app.devin.ai/sessions/poll-1",
            status="exit",
            status_detail="finished",
            structured_output={"status": "completed"},
            pr_urls=["https://github.com/example/pull/7"],
        )

        session = TrackedSession(
            group=sample_finding_group,
            session_id="poll-1",
            session_url="https://app.devin.ai/sessions/poll-1",
        )
        await poll_sessions(mock_client, [session])
        assert session.status == "completed"
        assert session.pr_url == "https://github.com/example/pull/7"

    async def test_poll_sessions_retries_on_error(self, sample_finding_group):
        """get_session raises on first call, succeeds on second."""
        mock_client = AsyncMock()
        mock_client.get_session.side_effect = [
            Exception("network error"),
            SessionResult(
                session_id="poll-2",
                url="https://app.devin.ai/sessions/poll-2",
                status="exit",
                status_detail="finished",
                structured_output=None,
                pr_urls=[],
            ),
        ]

        session = TrackedSession(
            group=sample_finding_group,
            session_id="poll-2",
            session_url="https://app.devin.ai/sessions/poll-2",
        )
        await poll_sessions(mock_client, [session])
        assert session.status == "completed"

    async def test_poll_sessions_status_mapping(self, sample_finding_group):
        """Various status_detail values → correct tracked.status."""
        cases = [
            ("exit", "finished", None, "completed"),
            ("suspended", "waiting_for_user", None, "needs_human_review"),
            ("error", "error", None, "failed"),
            ("suspended", "inactivity", None, "needs_human_review"),
        ]
        for status, detail, so, expected in cases:
            mock_client = AsyncMock()
            mock_client.get_session.return_value = SessionResult(
                session_id="map-1",
                url="https://app.devin.ai/sessions/map-1",
                status=status,
                status_detail=detail,
                structured_output=so,
                pr_urls=[],
            )
            session = TrackedSession(
                group=sample_finding_group,
                session_id="map-1",
                session_url="https://app.devin.ai/sessions/map-1",
            )
            await poll_sessions(mock_client, [session])
            assert session.status == expected, f"status={status}, detail={detail} → expected {expected}, got {session.status}"

    async def test_poll_sessions_backoff(self, sample_finding_group):
        """Interval doubles each cycle when sessions are still pending."""
        call_count = 0

        async def get_sess(sid):
            nonlocal call_count
            call_count += 1
            if call_count < 3:
                return SessionResult(
                    session_id=sid,
                    url=f"https://app.devin.ai/sessions/{sid}",
                    status="running",
                    status_detail="working",
                    structured_output=None,
                    pr_urls=[],
                )
            return SessionResult(
                session_id=sid,
                url=f"https://app.devin.ai/sessions/{sid}",
                status="exit",
                status_detail="finished",
                structured_output=None,
                pr_urls=[],
            )

        mock_client = AsyncMock()
        mock_client.get_session.side_effect = get_sess

        session = TrackedSession(
            group=sample_finding_group,
            session_id="back-1",
            session_url="https://app.devin.ai/sessions/back-1",
        )
        await poll_sessions(mock_client, [session], initial_interval=1.0)
        assert session.status == "completed"
        assert call_count == 3
