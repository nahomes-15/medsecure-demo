"""Lightweight dashboard server with Devin API polling + dispatch.

Usage:
    python server.py                       # default port 3333
    python server.py --port 8080
    DEVIN_API_KEY=cog_... python server.py  # override key

Endpoints:
    GET  /              Dashboard HTML (data injected server-side)
    GET  /api/sessions  Live session data from Devin API
    POST /api/dispatch  Dispatch queued findings to Devin (with retry + backoff)
    POST /api/session/<id>/terminate  Kill a session permanently
    POST /api/session/<id>/archive    Put a session to sleep
"""

import argparse
import json
import os
import re
import subprocess
import sys
import threading
import time
from http.server import HTTPServer, SimpleHTTPRequestHandler
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

# Load .env from project root if present
_env_path = Path(__file__).parent.parent / ".env"
if _env_path.exists():
    for line in _env_path.read_text().splitlines():
        line = line.strip()
        if line and not line.startswith("#") and "=" in line:
            k, v = line.split("=", 1)
            os.environ.setdefault(k.strip(), v.strip())

ORG_ID = os.environ.get("DEVIN_ORG_ID", "")
API_KEY = os.environ.get("DEVIN_API_KEY", "")
BASE_URL = f"https://api.devin.ai/v3/organizations/{ORG_ID}/sessions"

DASHBOARD_DIR = Path(__file__).parent
ORCHESTRATOR_DIR = DASHBOARD_DIR.parent / "orchestrator"
SARIF_PATH = DASHBOARD_DIR.parent / "sarif" / "javascript.sarif"

# Parse SARIF once at startup to get accurate counts
def _count_sarif() -> dict[str, int]:
    try:
        sys.path.insert(0, str(ORCHESTRATOR_DIR))
        from sarif_parser import group_findings, parse_sarif
        findings = parse_sarif(SARIF_PATH)
        groups = group_findings(findings)
        return {"findings": len(findings), "groups": len(groups)}
    except Exception:
        return {"findings": 0, "groups": 0}

_sarif_counts = _count_sarif()

# Timestamp: only show sessions created after server start
_server_start = int(time.time()) - 5  # 5s fudge for clock skew with Devin API

# Session cache
_cache = {"data": None, "ts": 0}
CACHE_TTL = 8  # Devin polls at ~10s; stay under to feel live

# Dispatch state — GIL protects dict key writes here
_dispatch = {
    "running": False,
    "log": [],            # list of {ts, msg, level}
    "dispatched": 0,
    "failed": 0,
    "total": 0,
}


def fetch_sessions() -> dict:
    """Fetch all sessions from Devin API with caching."""
    now = time.time()
    if _cache["data"] and (now - _cache["ts"]) < CACHE_TTL:
        return _cache["data"]

    req = Request(BASE_URL, headers={
        "Authorization": f"Bearer {API_KEY}",
        "Content-Type": "application/json",
    })
    try:
        with urlopen(req, timeout=10) as resp:
            data = json.loads(resp.read())
        _cache["data"] = data
        _cache["ts"] = now
        return data
    except URLError as e:
        print(f"[warn] Devin API error: {e}")
        return _cache["data"] or {"items": []}


def create_session_with_retry(
    prompt: str, tags: list[str], title: str, repo: str, max_retries: int = 6,
) -> dict:
    """Create a Devin session with exponential backoff on 429."""
    body = json.dumps({
        "prompt": prompt,
        "title": title,
        "tags": tags,
        "repos": [repo],
        "idempotent": True,
        "structured_output_schema": {
            "type": "object",
            "properties": {
                "status": {"type": "string", "enum": ["in_progress", "completed", "needs_human_review"]},
                "finding_id": {"type": "string"},
                "cwe": {"type": "string"},
                "file": {"type": "string"},
                "pr_url": {"type": ["string", "null"]},
                "summary": {"type": "string"},
            },
            "required": ["status", "finding_id", "file", "summary"],
        },
        "max_acu_limit": 3,
    }).encode()

    backoff = 2.0
    for attempt in range(1, max_retries + 1):
        req = Request(BASE_URL, data=body, headers={
            "Authorization": f"Bearer {API_KEY}",
            "Content-Type": "application/json",
        }, method="POST")
        try:
            with urlopen(req, timeout=30) as resp:
                return json.loads(resp.read())
        except HTTPError as e:
            if e.code == 429:
                retry_after = e.headers.get("Retry-After")
                wait = float(retry_after) if retry_after else backoff
                wait = max(wait, backoff)
                _dispatch_log("warning",
                    f"Rate limited (429), attempt {attempt}/{max_retries}, "
                    f"waiting {wait:.0f}s..."
                )
                time.sleep(wait)
                backoff = min(backoff * 2, 60)  # cap at 60s per Devin guidance
                continue
            raise
    raise Exception(f"Rate limited after {max_retries} retries")


def _dispatch_log(level: str, msg: str) -> None:
    """Thread-safe dispatch log append."""
    _dispatch["log"].append({
        "ts": time.strftime("%H:%M:%S"),
        "level": level,
        "msg": msg,
    })
    print(f"[dispatch/{level}] {msg}")


MAX_CONCURRENT = 5
SLOT_POLL_INTERVAL = 15  # seconds between checking for free slots


def _count_active_sessions() -> int:
    """Count non-terminal sessions from the Devin API (ignores cache)."""
    req = Request(BASE_URL, headers={
        "Authorization": f"Bearer {API_KEY}",
        "Content-Type": "application/json",
    })
    try:
        with urlopen(req, timeout=10) as resp:
            data = json.loads(resp.read())
        active = [s for s in data.get("items", [])
                  if s.get("status") not in ("exit", "error", "suspended")
                  and not s.get("is_archived")]
        return len(active)
    except Exception:
        return MAX_CONCURRENT  # fail closed: assume full if API unreachable


def _wait_for_slot() -> None:
    """Block until there's a free concurrent slot."""
    while True:
        active = _count_active_sessions()
        if active < MAX_CONCURRENT:
            _dispatch_log("info", f"{active}/{MAX_CONCURRENT} slots used — slot available")
            return
        _dispatch_log("info",
            f"{active}/{MAX_CONCURRENT} slots full, waiting {SLOT_POLL_INTERVAL}s for a session to finish..."
        )
        time.sleep(SLOT_POLL_INTERVAL)


def run_dispatch(repo: str = "medsecure-demo") -> None:
    """Background thread: dispatch findings with concurrency-aware batching.

    Devin enforces a 5-session concurrent limit. This dispatcher:
    1. Sends up to 5 sessions
    2. Waits for a slot to free up before sending the next
    3. Repeats until all groups are dispatched
    """
    if _dispatch["running"]:
        return
    _dispatch["running"] = True
    _dispatch["log"] = []
    _dispatch["dispatched"] = 0
    _dispatch["failed"] = 0

    try:
        # Load orchestrator modules
        sys.path.insert(0, str(ORCHESTRATOR_DIR))
        from prompt_builder import build_prompt, build_tags, build_title
        from sarif_parser import group_findings, parse_sarif

        findings = parse_sarif(SARIF_PATH)
        groups = group_findings(findings)

        to_dispatch = []
        for g in groups:
            to_dispatch.append((g, build_prompt(g), build_tags(g), build_title(g)))

        _dispatch["total"] = len(to_dispatch)
        _dispatch_log("info", f"Found {len(to_dispatch)} groups to dispatch (max {MAX_CONCURRENT} concurrent)")

        if not to_dispatch:
            _dispatch_log("info", "Nothing to dispatch")
            return

        stagger = 2.0  # seconds between dispatches within a batch
        for i, (_g, prompt, tags, title) in enumerate(to_dispatch):
            # Before each dispatch, ensure we have a free slot
            if i > 0:
                if i < MAX_CONCURRENT:
                    # First batch fits in free slots; just avoid burst
                    _dispatch_log("info", f"Staggering {stagger:.0f}s...")
                    time.sleep(stagger)
                else:
                    # Slots full — block until one session finishes
                    _dispatch_log("info", f"Waiting for a free slot before dispatching [{i+1}/{len(to_dispatch)}]...")
                    _wait_for_slot()
                    time.sleep(stagger)

            try:
                _dispatch_log("info", f"[{i+1}/{len(to_dispatch)}] Dispatching: {title}")
                result = create_session_with_retry(prompt, tags, title, repo)
                sid = result.get("session_id", "?")
                _dispatch_log("info", f"[{i+1}/{len(to_dispatch)}] Success -> {sid}")
                _dispatch["dispatched"] += 1
                _cache["ts"] = 0  # force fresh data on next dashboard poll
            except Exception as e:
                _dispatch_log("error", f"[{i+1}/{len(to_dispatch)}] Failed: {e}")
                _dispatch["failed"] += 1

        _dispatch_log("info",
            f"Dispatch complete: {_dispatch['dispatched']} succeeded, "
            f"{_dispatch['failed']} failed"
        )
    except Exception as e:
        _dispatch_log("error", f"Dispatch crashed: {e}")
    finally:
        _dispatch["running"] = False


def fetch_pr_diff(pr_number: int | str) -> dict:
    """Fetch PR file diffs from GitHub via gh CLI."""
    try:
        result = subprocess.run(
            ["gh", "api", f"repos/nahomes-15/medsecure-demo/pulls/{pr_number}/files"],
            capture_output=True, text=True, timeout=10,
        )
        if result.returncode != 0:
            return {"error": result.stderr.strip(), "files": []}

        files = json.loads(result.stdout)
        # Filter out huge generated files (package-lock.json etc)
        clean = []
        for f in files:
            if "lock" in f["filename"] or f.get("additions", 0) > 500:
                clean.append({
                    "filename": f["filename"],
                    "status": f["status"],
                    "additions": f["additions"],
                    "deletions": f["deletions"],
                    "patch": f"(File too large — {f['additions']}+ lines)",
                })
            else:
                clean.append({
                    "filename": f["filename"],
                    "status": f["status"],
                    "additions": f["additions"],
                    "deletions": f["deletions"],
                    "patch": f.get("patch", ""),
                })
        return {"files": clean, "pr_number": pr_number}
    except Exception as e:
        return {"error": str(e), "files": []}


def terminate_session(session_id: str) -> dict:
    """Permanently terminate a Devin session (DELETE)."""
    url = f"{BASE_URL}/{session_id}"
    req = Request(url, headers={
        "Authorization": f"Bearer {API_KEY}",
        "Content-Type": "application/json",
    }, method="DELETE")
    try:
        with urlopen(req, timeout=15) as resp:
            _cache["ts"] = 0  # invalidate cache
            return json.loads(resp.read())
    except HTTPError as e:
        body = e.read().decode() if e.fp else ""
        raise Exception(f"HTTP {e.code}: {body}") from e


def archive_session(session_id: str) -> dict:
    """Archive (sleep) a Devin session (POST /archive)."""
    url = f"{BASE_URL}/{session_id}/archive"
    req = Request(url, data=b"", headers={
        "Authorization": f"Bearer {API_KEY}",
        "Content-Type": "application/json",
    }, method="POST")
    try:
        with urlopen(req, timeout=15) as resp:
            _cache["ts"] = 0  # invalidate cache
            return json.loads(resp.read())
    except HTTPError as e:
        body = e.read().decode() if e.fp else ""
        raise Exception(f"HTTP {e.code}: {body}") from e


def build_dashboard_data() -> dict:
    """Transform Devin API response into dashboard-shaped data."""
    api = fetch_sessions()
    all_items = api.get("items", [])
    # Only show sessions created after server start (clean slate each run)
    items = [s for s in all_items if s.get("created_at", 0) >= _server_start]

    sessions = []
    for s in items:
        so = s.get("structured_output") or {}
        tags = s.get("tags", [])

        rule_id = next((t for t in tags if t.startswith("js/")), "")
        level = "error" if "error" in tags else ("warning" if "warning" in tags else "note")
        cwe_ids = [t for t in tags if t.startswith("CWE-")]

        # Priority: structured_output > API error > human-in-the-loop
        so_status = so.get("status", "in_progress")
        if so_status == "completed":
            display_status = "completed"
        elif s.get("status") == "error":
            display_status = "failed"
        elif s.get("status_detail") == "waiting_for_user":
            display_status = "needs_review"
        else:
            display_status = "in_progress"

        sessions.append({
            "session_id": s["session_id"],
            "title": s.get("title", ""),
            "status": s.get("status", ""),
            "status_detail": s.get("status_detail", ""),
            "display_status": display_status,
            "acus_consumed": s.get("acus_consumed", 0),
            "created_at": s.get("created_at", 0),
            "pull_requests": s.get("pull_requests", []),
            "structured_output": so,
            "rule_id": rule_id,
            "level": level,
            "cwe_ids": cwe_ids,
            "file": so.get("file", ""),
            "short_description": s.get("title", "").replace("Fix ", "").split(" in ")[0],
            "security_severity": "",
        })

    completed = sum(1 for s in sessions if s["display_status"] == "completed")
    prs = sum(1 for s in sessions if s.get("pull_requests"))
    total_acus = round(sum(s["acus_consumed"] for s in sessions), 2)

    return {
        "sessions": sessions,
        "summary": {
            "total_findings": _sarif_counts["findings"],
            "total_groups": _sarif_counts["groups"],
            "sessions_dispatched": len(sessions),
            "sessions_completed": completed,
            "prs_opened": prs,
            "queued_remaining": max(0, _sarif_counts["groups"] - len(sessions)),
            "total_acus": total_acus,
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        },
        "dispatch": {
            "running": _dispatch["running"],
            "dispatched": _dispatch["dispatched"],
            "failed": _dispatch["failed"],
            "total": _dispatch["total"],
            "log": _dispatch["log"][-20:],  # last 20 entries
        },
    }


class DashboardHandler(SimpleHTTPRequestHandler):
    def __init__(self, *args: object, **kwargs: object) -> None:
        super().__init__(*args, directory=str(DASHBOARD_DIR), **kwargs)

    def do_GET(self) -> None:
        # PR diff endpoint: /api/pr/3
        pr_match = re.match(r"^/api/pr/(\d+)$", self.path)

        if self.path == "/api/sessions":
            self._json_response(build_dashboard_data())
        elif pr_match:
            pr_num = pr_match.group(1)
            self._json_response(fetch_pr_diff(pr_num))
        elif self.path == "/" or self.path == "/index.html":
            html = (DASHBOARD_DIR / "index.html").read_text()
            try:
                initial = json.dumps(build_dashboard_data())
            except Exception:
                initial = "null"
            html = html.replace("INJECT_DATA_HERE", initial)  # SSR: avoids initial fetch flicker
            body = html.encode()
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        else:
            super().do_GET()

    def do_POST(self) -> None:
        # Session control: /api/session/<id>/terminate or /api/session/<id>/archive
        # Hex-only: rejects non-Devin session IDs at routing layer
        session_match = re.match(r"^/api/session/([a-f0-9]+)/(terminate|archive)$", self.path)

        if self.path == "/api/dispatch":
            if _dispatch["running"]:
                self._json_response({"ok": False, "error": "Dispatch already in progress"}, 409)
                return
            # Fire dispatch in background thread
            t = threading.Thread(target=run_dispatch, daemon=True)
            t.start()
            self._json_response({"ok": True, "message": "Dispatch started"})
        elif session_match:
            sid = session_match.group(1)
            action = session_match.group(2)
            try:
                if action == "terminate":
                    result = terminate_session(sid)
                    self._json_response({"ok": True, "action": "terminated", "session": result})
                else:
                    result = archive_session(sid)
                    self._json_response({"ok": True, "action": "archived", "session": result})
            except Exception as e:
                self._json_response({"ok": False, "error": str(e)}, 500)
        else:
            self.send_error(404)

    def _json_response(self, data: dict, status: int = 200) -> None:
        body = json.dumps(data).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format: str, *args: object) -> None:
        try:
            msg = str(args[0]) if args else ""
            if "/api/" not in msg:  # suppress noisy poll requests
                super().log_message(format, *args)
        except Exception:
            pass


def main() -> None:
    p = argparse.ArgumentParser()
    p.add_argument("--port", type=int, default=3333)
    args = p.parse_args()

    server = HTTPServer(("127.0.0.1", args.port), DashboardHandler)
    print(f"Dashboard: http://localhost:{args.port}")
    print(f"Devin org: {ORG_ID}")
    print(f"Cache TTL: {CACHE_TTL}s")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nShutting down.")


if __name__ == "__main__":
    main()
