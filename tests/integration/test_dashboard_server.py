"""Tests for dashboard/server.py.

Spins up a real HTTPServer on a random port in a daemon thread,
with fetch_sessions mocked to return fake data.
"""

import json
import threading
import time
from http.server import HTTPServer
from unittest.mock import patch
from urllib.request import Request, urlopen

import pytest

pytestmark = pytest.mark.integration

# We need to patch server module globals before importing the handler
import server as dashboard_server  # noqa: E402
from server import DashboardHandler, build_dashboard_data  # noqa: E402

# ── Test server fixture ─────────────────────────────────────────

FAKE_API_RESPONSE = {
    "items": [
        {
            "session_id": "dash-001",
            "title": "Fix SQL injection in patients.js (CWE-89)",
            "status": "exit",
            "status_detail": "finished",
            "acus_consumed": 1.5,
            "created_at": int(time.time()),
            "pull_requests": [{"pr_url": "https://github.com/example/pull/10", "pr_state": "open"}],
            "structured_output": {"status": "completed", "file": "routes/patients.js"},
            "tags": ["security", "js/sql-injection", "error", "CWE-89"],
            "is_archived": False,
        },
        {
            "session_id": "dash-002",
            "title": "Fix XSS in notes.js (CWE-79)",
            "status": "error",
            "status_detail": "error",
            "acus_consumed": 0.3,
            "created_at": int(time.time()),
            "pull_requests": [],
            "structured_output": {"status": "in_progress", "file": "routes/notes.js"},
            "tags": ["security", "js/xss", "warning", "CWE-79"],
            "is_archived": False,
        },
        {
            "session_id": "dash-003",
            "title": "Fix Weak hash in auth.js (CWE-328)",
            "status": "running",
            "status_detail": "waiting_for_user",
            "acus_consumed": 2.0,
            "created_at": int(time.time()),
            "pull_requests": [],
            "structured_output": {"status": "in_progress", "file": "middleware/auth.js"},
            "tags": ["security", "js/insufficient-password-hash", "warning", "CWE-328"],
            "is_archived": False,
        },
    ]
}


@pytest.fixture(scope="module")
def test_server():
    """Start a test dashboard server on a random port, mocking external calls."""
    # Patch fetch_sessions to return fake data
    original_fetch = dashboard_server.fetch_sessions
    dashboard_server.fetch_sessions = lambda: FAKE_API_RESPONSE
    # Set _server_start to 0 so all sessions pass the filter
    original_start = dashboard_server._server_start
    dashboard_server._server_start = 0
    # Set sarif counts
    original_counts = dashboard_server._sarif_counts
    dashboard_server._sarif_counts = {"findings": 28, "groups": 13}
    # Reset dispatch state
    dashboard_server._dispatch["running"] = False
    dashboard_server._dispatch["dispatched"] = 0
    dashboard_server._dispatch["failed"] = 0
    dashboard_server._dispatch["total"] = 0
    dashboard_server._dispatch["log"] = []

    server = HTTPServer(("127.0.0.1", 0), DashboardHandler)
    port = server.server_address[1]
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()

    yield f"http://127.0.0.1:{port}"

    server.shutdown()
    dashboard_server.fetch_sessions = original_fetch
    dashboard_server._server_start = original_start
    dashboard_server._sarif_counts = original_counts


def _get(url, path):
    return urlopen(f"{url}{path}", timeout=5)


def _post(url, path):
    req = Request(f"{url}{path}", data=b"", method="POST")
    return urlopen(req, timeout=5)


def _get_json(url, path):
    resp = _get(url, path)
    return json.loads(resp.read())


# ── GET / ───────────────────────────────────────────────────────

class TestDashboardGET:
    def test_get_root(self, test_server):
        resp = _get(test_server, "/")
        assert resp.status == 200
        body = resp.read().decode()
        assert "MedSecure" in body

    def test_get_api_sessions(self, test_server):
        data = _get_json(test_server, "/api/sessions")
        assert "sessions" in data
        assert "summary" in data
        assert "dispatch" in data

    def test_api_sessions_summary_fields(self, test_server):
        data = _get_json(test_server, "/api/sessions")
        summary = data["summary"]
        assert "total_findings" in summary
        assert "total_groups" in summary
        assert "sessions_dispatched" in summary
        assert "sessions_completed" in summary
        assert "prs_opened" in summary

    def test_api_sessions_cors(self, test_server):
        resp = _get(test_server, "/api/sessions")
        cors = resp.headers.get("Access-Control-Allow-Origin")
        assert cors == "*"

    def test_404_unknown_route(self, test_server):
        from urllib.error import HTTPError

        with pytest.raises(HTTPError) as exc_info:
            _get(test_server, "/api/nonexistent")
        assert exc_info.value.code == 404


# ── POST /api/dispatch ──────────────────────────────────────────

class TestDispatch:
    def test_post_dispatch_starts(self, test_server):
        # Mock run_dispatch to avoid actually dispatching
        with patch.object(dashboard_server, "run_dispatch"):
            data = json.loads(_post(test_server, "/api/dispatch").read())
        assert data["ok"] is True

    def test_post_dispatch_rejects_concurrent(self, test_server):
        from urllib.error import HTTPError

        dashboard_server._dispatch["running"] = True
        try:
            with pytest.raises(HTTPError) as exc_info:
                _post(test_server, "/api/dispatch")
            assert exc_info.value.code == 409
        finally:
            dashboard_server._dispatch["running"] = False


# ── build_dashboard_data ────────────────────────────────────────

class TestBuildDashboardData:
    def test_build_dashboard_data_structure(self, test_server):
        data = build_dashboard_data()
        assert "sessions" in data
        assert "summary" in data
        assert "dispatch" in data

    def test_build_dashboard_data_status_mapping(self, test_server):
        data = build_dashboard_data()
        statuses = {s["session_id"]: s["display_status"] for s in data["sessions"]}
        assert statuses["dash-001"] == "completed"
        assert statuses["dash-002"] == "failed"
        assert statuses["dash-003"] == "needs_review"

    def test_sarif_counts_populated(self, test_server):
        data = build_dashboard_data()
        assert data["summary"]["total_findings"] == 28
        assert data["summary"]["total_groups"] == 13


# ── Session control endpoints ───────────────────────────────────

class TestSessionControl:
    def test_session_terminate_endpoint(self, test_server):
        """POST /api/session/{id}/terminate calls terminate_session."""
        with patch.object(dashboard_server, "terminate_session", return_value={"ok": True}):
            # session IDs must match [a-f0-9]+ pattern in the route
            data = json.loads(_post(test_server, "/api/session/abc123def/terminate").read())
        assert data["ok"] is True
        assert data["action"] == "terminated"

    def test_session_archive_endpoint(self, test_server):
        """POST /api/session/{id}/archive calls archive_session."""
        with patch.object(dashboard_server, "archive_session", return_value={"ok": True}):
            data = json.loads(_post(test_server, "/api/session/abc123def/archive").read())
        assert data["ok"] is True
        assert data["action"] == "archived"
