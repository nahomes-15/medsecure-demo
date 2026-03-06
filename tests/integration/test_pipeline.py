"""Tests for orchestrator/pipeline.py."""

import argparse
from unittest.mock import AsyncMock, patch

import pytest
from pipeline import parse_args, run_pipeline

pytestmark = pytest.mark.integration


# ── parse_args ──────────────────────────────────────────────────

class TestParseArgs:
    def test_parse_args_defaults(self):
        with patch("sys.argv", ["pipeline.py", "--sarif", "test.sarif"]):
            args = parse_args()
        assert args.sarif == "test.sarif"
        assert args.mode == "mock"
        assert args.repo == "medsecure-demo"
        assert args.output == "pipeline-results.json"

    def test_parse_args_all_flags(self):
        with patch("sys.argv", [
            "pipeline.py",
            "--sarif", "/tmp/scan.sarif",
            "--mode", "live",
            "--repo", "my-repo",
            "--output", "out.json",
        ]):
            args = parse_args()
        assert args.sarif == "/tmp/scan.sarif"
        assert args.mode == "live"
        assert args.repo == "my-repo"
        assert args.output == "out.json"

    def test_parse_args_missing_sarif(self):
        with patch("sys.argv", ["pipeline.py"]):
            with pytest.raises(SystemExit):
                parse_args()

    def test_parse_args_invalid_mode(self):
        with patch("sys.argv", ["pipeline.py", "--sarif", "x.sarif", "--mode", "invalid"]):
            with pytest.raises(SystemExit):
                parse_args()


# ── run_pipeline ────────────────────────────────────────────────

class TestRunPipeline:
    async def test_run_pipeline_dry_run(self, tmp_sarif_file, capsys, tmp_path):
        args = argparse.Namespace(
            sarif=str(tmp_sarif_file),
            mode="dry-run",
            repo="test-repo",
            output=str(tmp_path / "out.json"),
        )
        await run_pipeline(args)
        output = capsys.readouterr().out
        assert "SESSION" in output
        assert "js/sql-injection" in output

    async def test_run_pipeline_mock(self, tmp_sarif_file, tmp_path):
        output_path = tmp_path / "results.json"
        args = argparse.Namespace(
            sarif=str(tmp_sarif_file),
            mode="mock",
            repo="test-repo",
            output=str(output_path),
        )
        await run_pipeline(args)
        assert output_path.exists()
        import json
        report = json.loads(output_path.read_text())
        assert "pipeline_run" in report
        assert report["pipeline_run"]["total_sessions"] == 2

    async def test_run_pipeline_missing_sarif(self, tmp_path):
        args = argparse.Namespace(
            sarif=str(tmp_path / "nonexistent.sarif"),
            mode="mock",
            repo="test-repo",
            output=str(tmp_path / "out.json"),
        )
        with pytest.raises(SystemExit):
            await run_pipeline(args)

    async def test_run_pipeline_dispatch_failure(self, tmp_sarif_file, tmp_path):
        """One dispatch fails → others continue, report still generated."""
        output_path = tmp_path / "results.json"
        args = argparse.Namespace(
            sarif=str(tmp_sarif_file),
            mode="mock",
            repo="test-repo",
            output=str(output_path),
        )

        call_count = 0

        async def failing_create(prompt, tags, title, repo, **kw):
            nonlocal call_count
            call_count += 1
            if call_count == 1:
                raise Exception("dispatch failed")
            # For subsequent calls, use a simple mock result
            from devin_client import SessionResult
            return SessionResult(
                session_id=f"ok-{call_count}",
                url=f"https://app.devin.ai/sessions/ok-{call_count}",
                status="running",
                status_detail="working",
                structured_output=None,
                pr_urls=[],
            )

        with patch("pipeline.get_client") as mock_get:
            mock_client = AsyncMock()
            mock_client.create_session.side_effect = failing_create
            # Make poll return terminal immediately
            mock_client.get_session.return_value = AsyncMock(
                session_id="ok-2",
                url="https://app.devin.ai/sessions/ok-2",
                status="exit",
                status_detail="finished",
                structured_output=None,
                pr_urls=[],
            )
            # get_session needs to return a SessionResult, not AsyncMock
            from devin_client import SessionResult
            mock_client.get_session.return_value = SessionResult(
                session_id="ok-2",
                url="https://app.devin.ai/sessions/ok-2",
                status="exit",
                status_detail="finished",
                structured_output=None,
                pr_urls=[],
            )
            mock_get.return_value = mock_client

            await run_pipeline(args)

        assert output_path.exists()
        import json
        report = json.loads(output_path.read_text())
        # 2 groups in minimal SARIF, 1 failed dispatch → 1 session tracked
        assert report["pipeline_run"]["total_sessions"] == 1
