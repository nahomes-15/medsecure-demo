"""Devin API v3 client with live and mock modes.

API Reference: https://docs.devin.ai/api-reference/v3/overview

v3 key differences from v1:
- Endpoint: /v3/organizations/{org_id}/sessions
- Auth: service user token (cog_ prefix) via Bearer header
- Request: adds repos[], title, structured_output_schema, session_secrets
- Response status: new, claimed, running, exit, error, suspended, resuming
- Response status_detail: working, waiting_for_user, waiting_for_approval,
  finished, inactivity, error, etc.
- pull_requests is an array of {pr_url, pr_state} (not a single object)
"""

import asyncio
import logging
import os
import random
import time
from dataclasses import dataclass

import httpx

logger = logging.getLogger(__name__)

# v3 terminal states (top-level status field)
TERMINAL_STATES = {"exit", "error", "suspended"}

# Structured output schema (JSON Schema Draft 7) — enforced by Devin, not just requested
STRUCTURED_OUTPUT_SCHEMA = {
    "type": "object",
    "properties": {
        "status": {
            "type": "string",
            "enum": ["in_progress", "completed", "needs_human_review"],
        },
        "finding_id": {"type": "string"},
        "cwe": {"type": "string"},
        "file": {"type": "string"},
        "pr_url": {"type": ["string", "null"]},
        "summary": {"type": "string"},
    },
    "required": ["status", "finding_id", "file", "summary"],
}


@dataclass
class SessionResult:
    session_id: str
    url: str
    status: str           # top-level: running, exit, error, suspended, etc.
    status_detail: str    # granular: working, finished, waiting_for_user, etc.
    structured_output: dict | None
    pr_urls: list[str]    # v3 returns array of PRs


class DevinClient:
    """Real Devin API v3 client."""

    def __init__(
        self,
        api_key: str | None = None,
        org_id: str | None = None,
    ) -> None:
        self.api_key = api_key or os.environ.get("DEVIN_API_KEY", "")
        self.org_id = org_id or os.environ.get("DEVIN_ORG_ID", "")
        if not self.api_key:
            raise ValueError("DEVIN_API_KEY is required for live mode")
        if not self.org_id:
            raise ValueError("DEVIN_ORG_ID is required for live mode")
        self.base_url = f"https://api.devin.ai/v3/organizations/{self.org_id}/sessions"
        self.headers = {"Authorization": f"Bearer {self.api_key}"}

    async def create_session(
        self, prompt: str, tags: list[str], title: str, repo: str,
        max_retries: int = 5,
    ) -> SessionResult:
        body = {
            "prompt": prompt,
            "title": title,
            "tags": tags,
            "repos": [repo],
            "idempotent": True,
            "structured_output_schema": STRUCTURED_OUTPUT_SCHEMA,
            "max_acu_limit": 3,
        }
        backoff = 2.0
        for attempt in range(1, max_retries + 1):
            async with httpx.AsyncClient(timeout=30) as client:
                resp = await client.post(
                    self.base_url, json=body, headers=self.headers,
                )
                if resp.status_code == 429:
                    retry_after = float(resp.headers.get("Retry-After", backoff))
                    wait = max(retry_after, backoff)
                    logger.warning(
                        f"    Rate limited (429), attempt {attempt}/{max_retries}, "
                        f"retrying in {wait:.1f}s..."
                    )
                    await asyncio.sleep(wait)
                    backoff = min(backoff * 2, 60)
                    continue
                resp.raise_for_status()
                data = resp.json()
                return SessionResult(
                    session_id=data["session_id"],
                    url=data["url"],
                    status="running",
                    status_detail="working",
                    structured_output=None,
                    pr_urls=[],
                )
        raise httpx.HTTPStatusError(
            f"Rate limited after {max_retries} retries",
            request=resp.request, response=resp,
        )

    async def get_session(self, session_id: str) -> SessionResult:
        async with httpx.AsyncClient(timeout=30) as client:
            resp = await client.get(
                f"{self.base_url}/{session_id}",
                headers=self.headers,
            )
            resp.raise_for_status()
            data = resp.json()
            prs = data.get("pull_requests") or []
            return SessionResult(
                session_id=data["session_id"],
                url=data.get("url", f"https://app.devin.ai/sessions/{data['session_id']}"),
                status=data.get("status", "running"),
                status_detail=data.get("status_detail", ""),
                structured_output=data.get("structured_output"),
                pr_urls=[pr["pr_url"] for pr in prs if pr.get("pr_url")],
            )


class MockDevinClient:
    """Simulates Devin API v3 with realistic delays and outcomes."""

    def __init__(self) -> None:
        self._sessions: dict[str, dict] = {}
        self._counter: int = 0

    async def create_session(
        self, prompt: str, tags: list[str], title: str, repo: str
    ) -> SessionResult:
        await asyncio.sleep(random.uniform(0.3, 0.8))
        self._counter += 1
        sid = f"mock-session-{self._counter:03d}"
        self._sessions[sid] = {
            "created_at": time.time(),
            "tags": tags,
            "outcome": random.choices(
                ["completed", "needs_human_review"], weights=[85, 15]
            )[0],
        }
        logger.info(f"  [mock] Created session {sid}")
        return SessionResult(
            session_id=sid,
            url=f"https://app.devin.ai/sessions/{sid}",
            status="running",
            status_detail="working",
            structured_output=None,
            pr_urls=[],
        )

    async def get_session(self, session_id: str) -> SessionResult:
        await asyncio.sleep(random.uniform(0.1, 0.3))
        session = self._sessions[session_id]
        elapsed = time.time() - session["created_at"]

        # Simulate work: takes 3-8 seconds in mock mode
        work_time = random.uniform(3, 8)
        if elapsed < work_time:
            return SessionResult(
                session_id=session_id,
                url=f"https://app.devin.ai/sessions/{session_id}",
                status="running",
                status_detail="working",
                structured_output={"status": "in_progress"},
                pr_urls=[],
            )

        outcome = session["outcome"]
        pr_urls = []
        if outcome == "completed":
            pr_num = random.randint(10, 99)
            pr_urls = [f"https://github.com/medsecure/patient-portal/pull/{pr_num}"]

        return SessionResult(
            session_id=session_id,
            url=f"https://app.devin.ai/sessions/{session_id}",
            status="exit" if outcome == "completed" else "suspended",
            status_detail="finished" if outcome == "completed" else "waiting_for_user",
            structured_output={"status": outcome, "pr_url": pr_urls[0] if pr_urls else None},
            pr_urls=pr_urls,
        )


def get_client(mode: str) -> DevinClient | MockDevinClient:
    if mode == "mock":
        return MockDevinClient()
    return DevinClient()
