# MedSecure Security Remediation Pipeline

Automated security vulnerability remediation for healthcare applications. Parses CodeQL SARIF output, generates targeted fix prompts, dispatches them to Devin AI agents, tracks session progress, and serves a real-time dashboard — turning static analysis findings into merged pull requests with zero manual triage.

## Architecture

```
┌─────────────┐     ┌──────────────┐     ┌────────────────┐     ┌──────────────┐
│  CodeQL CI  │────>│ SARIF Parser │────>│ Prompt Builder │────>│  Devin API   │
│  (GitHub    │     │              │     │                │     │  (v3)        │
│   Actions)  │     │ 28 findings  │     │ 13 grouped     │     │ 5 concurrent │
│             │     │ extracted    │     │ fix prompts    │     │ sessions     │
└─────────────┘     └──────────────┘     └────────────────┘     └──────┬───────┘
                                                                       │
┌─────────────────────────────────────────────────────────────────────┐ │
│                      Dashboard (localhost:3333)                      │ │
│  ┌──────────┐  ┌───────────┐  ┌──────────┐  ┌───────────────────┐  │ │
│  │ Sessions │  │ Compliance│  │ Dispatch  │  │   PR Diff Viewer  │  │<┘
│  │  Table   │  │    Bar    │  │  Controls │  │                   │  │
│  └──────────┘  └───────────┘  └──────────┘  └───────────────────┘  │
└─────────────────────────────────────────────────────────────────────┘
```

**End-to-end automation loop:**

```
CodeQL runs on push → SARIF artifact produced → remediate.yml triggers →
pipeline parses findings → groups by (rule, file) → dispatches to Devin →
Devin creates fix branches → PRs appear → dashboard shows live status
```

## Quick Start

### 1. Clone and configure

```bash
git clone https://github.com/nahomes-15/medsecure-demo.git
cd medsecure-demo
cp .env.example .env
# Edit .env with your Devin API credentials
```

### 2. Install dependencies

```bash
make install
# or manually:
python3 -m venv .venv
.venv/bin/pip install pytest pytest-asyncio pytest-cov respx ruff httpx
```

### 3. Run the pipeline

```bash
# Mock mode — simulates Devin sessions with realistic delays
make run-pipeline-mock

# Dry-run — prints prompts without dispatching
make run-pipeline-dry

# Live mode — dispatches to real Devin API (requires valid .env)
.venv/bin/python orchestrator/pipeline.py \
  --sarif sarif/javascript.sarif \
  --mode live \
  --repo medsecure-demo
```

### 4. Launch the dashboard

```bash
make run-dashboard
# Open http://localhost:3333
```

The dashboard polls the Devin API every 5 seconds and shows:
- Live session status with severity badges
- Compliance bar (completed / failed / needs review / in progress)
- One-click dispatch for queued findings
- Inline PR diff viewer
- Session terminate/archive controls

## Testing

```bash
make test              # run all 85 tests
make test-unit         # unit tests only
make test-integration  # integration tests only
make test-cov          # with coverage report (73%+ required)
make lint              # ruff linter
make check             # lint + test (CI gate)
```

Test suite covers:
- **SARIF parsing** — minimal fixture + real 549KB CodeQL output, error handling for malformed files
- **Prompt generation** — single/grouped templates, branch naming, tag construction
- **Devin client** — mock mode, live mode with respx-mocked httpx, 429 retry/backoff, error codes
- **Session tracking** — polling, status mapping, report generation, backoff verification
- **Pipeline orchestration** — argument parsing, dry-run/mock/live modes, dispatch failures
- **Dashboard server** — real HTTPServer on random port, API endpoints, CORS, session control

## CI/CD

| Workflow | Trigger | What it does |
|----------|---------|--------------|
| `ci.yml` | Push / PR | Lint + test + coverage gate |
| `codeql.yml` | Push to main | CodeQL security analysis |
| `remediate.yml` | CodeQL completion or manual `workflow_dispatch` | Downloads SARIF, runs pipeline, uploads results |

## Project Structure

```
medsecure-demo/
├── orchestrator/
│   ├── sarif_parser.py      # SARIF v2.1.0 parsing, Finding/FindingGroup dataclasses
│   ├── prompt_builder.py    # Devin prompt templates, title/tag construction
│   ├── devin_client.py      # Devin API v3 client (live + mock), retry logic
│   ├── tracker.py           # Async session polling, report generation
│   └── pipeline.py          # CLI entry point, orchestration flow
├── dashboard/
│   ├── server.py            # HTTP server, API polling, dispatch, PR diffs
│   └── index.html           # React dashboard (inline, no build step)
├── sarif/
│   └── javascript.sarif     # CodeQL output (28 findings, 13 groups)
├── vulnerable-app/          # Target Node.js app with intentional vulnerabilities
├── tests/                   # pytest suite (85 tests, 73%+ coverage)
├── .github/workflows/       # CI, CodeQL, and auto-remediation workflows
├── pyproject.toml           # Project config (pytest, ruff, coverage)
├── Makefile                 # Dev workflow automation
└── .env.example             # Environment variable template
```

## Production Considerations

This pipeline is built as a demonstration. For a production deployment, consider:

- **Persistent state**: Replace in-memory session tracking with a database (SQLite or Postgres) so pipeline state survives restarts and enables historical reporting
- **Webhook trigger**: Replace polling-based dispatch with a GitHub webhook listener that reacts to `code_scanning_alert` events, eliminating the need for `workflow_run` chaining
- **Dashboard auth**: Add authentication to the dashboard server — currently it binds to localhost only, but any multi-user deployment needs proper auth (OAuth or API key middleware)
- **RBAC for session control**: The terminate/archive endpoints have no authorization checks — in production, restrict these to admin roles to prevent accidental session termination
- **Rate limit coordination**: The current 5-session concurrent limit is hardcoded — a production system should query the Devin API for org-level limits and coordinate across multiple pipeline instances
- **Structured logging**: Replace print-based logging with structured JSON logs (e.g., `structlog`) for better observability in production monitoring stacks

## Demo Video

> [Loom video link placeholder — add after recording]
