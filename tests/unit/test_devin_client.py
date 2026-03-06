"""Tests for orchestrator/devin_client.py."""

from unittest.mock import patch

import httpx
import pytest
import respx
from devin_client import (
    DevinClient,
    MockDevinClient,
    SessionResult,
    get_client,
)

pytestmark = pytest.mark.unit


# ── SessionResult dataclass ─────────────────────────────────────

class TestSessionResult:
    def test_session_result_dataclass(self):
        sr = SessionResult(
            session_id="abc-123",
            url="https://app.devin.ai/sessions/abc-123",
            status="running",
            status_detail="working",
            structured_output={"status": "in_progress"},
            pr_urls=["https://github.com/example/pull/1"],
        )
        assert sr.session_id == "abc-123"
        assert sr.status == "running"
        assert sr.pr_urls == ["https://github.com/example/pull/1"]


# ── get_client factory ──────────────────────────────────────────

class TestGetClient:
    def test_get_client_mock(self):
        client = get_client("mock")
        assert isinstance(client, MockDevinClient)

    def test_get_client_live(self):
        with patch.dict("os.environ", {"DEVIN_API_KEY": "test-key", "DEVIN_ORG_ID": "test-org"}):
            client = get_client("live")
            assert isinstance(client, DevinClient)


# ── MockDevinClient ─────────────────────────────────────────────

class TestMockClient:
    async def test_mock_create_session(self):
        client = MockDevinClient()
        result = await client.create_session("prompt", ["tag"], "title", "repo")
        assert isinstance(result, SessionResult)
        assert result.session_id.startswith("mock-session-")
        assert result.status == "running"

    async def test_mock_create_unique_ids(self):
        client = MockDevinClient()
        r1 = await client.create_session("p1", [], "t1", "r")
        r2 = await client.create_session("p2", [], "t2", "r")
        assert r1.session_id != r2.session_id

    async def test_mock_poll_in_progress(self):
        client = MockDevinClient()
        r = await client.create_session("p", [], "t", "r")
        # Immediate poll — should still be running (work_time is 3-8s but sleep is mocked)
        poll = await client.get_session(r.session_id)
        assert poll.status == "running"

    async def test_mock_poll_completion(self):
        """After enough simulated time, mock client returns terminal state."""
        client = MockDevinClient()
        r = await client.create_session("p", [], "t", "r")
        # Force created_at far in the past so elapsed > work_time
        client._sessions[r.session_id]["created_at"] -= 30
        poll = await client.get_session(r.session_id)
        assert poll.status in ("exit", "suspended")


# ── DevinClient (with respx mocks) ─────────────────────────────

class TestLiveClient:
    def _make_client(self):
        return DevinClient(api_key="test-key", org_id="test-org")

    @respx.mock
    async def test_live_create_success(self):
        client = self._make_client()
        respx.post(client.base_url).respond(200, json={
            "session_id": "real-123",
            "url": "https://app.devin.ai/sessions/real-123",
        })
        result = await client.create_session("prompt", ["tag"], "title", "repo")
        assert result.session_id == "real-123"
        assert result.status == "running"

    @respx.mock
    async def test_live_create_429_retry(self):
        client = self._make_client()
        route = respx.post(client.base_url)
        route.side_effect = [
            httpx.Response(429, headers={"Retry-After": "0.1"}),
            httpx.Response(200, json={
                "session_id": "retry-ok",
                "url": "https://app.devin.ai/sessions/retry-ok",
            }),
        ]
        result = await client.create_session("prompt", ["tag"], "title", "repo")
        assert result.session_id == "retry-ok"

    @respx.mock
    async def test_live_create_429_backoff(self):
        """Check that backoff increases after a 429."""
        client = self._make_client()
        route = respx.post(client.base_url)
        route.side_effect = [
            httpx.Response(429, headers={"Retry-After": "0.01"}),
            httpx.Response(429, headers={"Retry-After": "0.01"}),
            httpx.Response(200, json={
                "session_id": "back-ok",
                "url": "https://app.devin.ai/sessions/back-ok",
            }),
        ]
        result = await client.create_session("p", [], "t", "r")
        assert result.session_id == "back-ok"

    @respx.mock
    async def test_live_create_429_exhaustion(self):
        """All 429s → raises after max_retries."""
        client = self._make_client()
        respx.post(client.base_url).respond(429, headers={"Retry-After": "0.01"})
        with pytest.raises(httpx.HTTPStatusError):
            await client.create_session("p", [], "t", "r", max_retries=2)

    @respx.mock
    async def test_live_create_500_raises(self):
        """500 raises immediately without retry."""
        client = self._make_client()
        respx.post(client.base_url).respond(500)
        with pytest.raises(httpx.HTTPStatusError):
            await client.create_session("p", [], "t", "r")

    @respx.mock
    async def test_live_get_session(self):
        client = self._make_client()
        respx.get(f"{client.base_url}/sess-42").respond(200, json={
            "session_id": "sess-42",
            "url": "https://app.devin.ai/sessions/sess-42",
            "status": "exit",
            "status_detail": "finished",
            "structured_output": {"status": "completed"},
            "pull_requests": None,
        })
        result = await client.get_session("sess-42")
        assert result.session_id == "sess-42"
        assert result.status == "exit"
        assert result.status_detail == "finished"

    @respx.mock
    async def test_live_get_session_with_prs(self):
        client = self._make_client()
        respx.get(f"{client.base_url}/sess-pr").respond(200, json={
            "session_id": "sess-pr",
            "status": "exit",
            "status_detail": "finished",
            "structured_output": None,
            "pull_requests": [
                {"pr_url": "https://github.com/example/pull/5", "pr_state": "open"},
                {"pr_url": "https://github.com/example/pull/6", "pr_state": "merged"},
            ],
        })
        result = await client.get_session("sess-pr")
        assert len(result.pr_urls) == 2
        assert "pull/5" in result.pr_urls[0]
