# MedSecure Security Remediation Pipeline

**CodeQL finds vulnerabilities. Devin fixes them. Engineers just review the PRs.**

Built for a scenario where a healthcare company's security team is drowning in CodeQL findings that engineering never gets to — they're not sprint work, so they pile up until an auditor flags it. This pipeline takes the CodeQL SARIF output, groups related findings, dispatches them to Devin in parallel, and gives the security team a live dashboard so they can actually see things getting fixed. 28 findings → 13 Devin sessions → PRs in the review queue, no engineer had to touch it.

> [Watch the demo video →](#)

---

## How It Works

```
CodeQL scan                    Orchestrator                         Devin API
───────────                    ────────────                         ─────────
28 findings  ──→  Parse SARIF  ──→  Group by (rule, file)  ──→  13 sessions
(SARIF v2.1.0)    Filter noise      Build prompts with CWE      (5 concurrent)
                  Extract CWEs      context + remediation            │
                                    guidance from CodeQL             │
                                                                     ▼
                  Dashboard  ◄──────────────────────────────  Fix PRs opened
                  (live polling)                              on GitHub
```

The orchestrator is dumb on purpose. CodeQL already tells you what's wrong (via SARIF — rule descriptions, CWE references, remediation guidance). Devin figures out how to fix it. The orchestrator just reads the structured data, fills a prompt template, and calls the API. No per-vulnerability-type logic, no custom severity scoring. It works for anything CodeQL can detect.

## Dashboard

<!-- Add a real screenshot: ![Dashboard](docs/dashboard-screenshot.png) -->

The dashboard serves as the security team's real-time view into remediation progress. It polls the Devin API every 5 seconds and shows:

- Session status with severity badges and CWE references
- Compliance progress bar (completed / in progress / needs review / failed)
- One-click dispatch for all finding groups with concurrency-aware staggering
- Inline PR diff viewer — review Devin's code changes without leaving the dashboard
- Session controls (archive/terminate)

```bash
make run-dashboard    # serves on http://localhost:3333
```

## Pipeline Modes

```bash
# Mock — full pipeline with simulated Devin responses (no API calls, no cost)
make run-pipeline-mock

# Dry run — parses SARIF, builds prompts, prints them (verify before dispatching)
make run-pipeline-dry

# Live — dispatches to real Devin API (requires DEVIN_API_KEY and DEVIN_ORG_ID)
.venv/bin/python orchestrator/pipeline.py \
  --sarif sarif/javascript.sarif \
  --mode live \
  --repo medsecure-demo
```

## What Devin Actually Produced

In live test runs, Devin successfully remediated all high-severity findings:

| Finding | CWE | What Devin Did | ACU Cost |
|---------|-----|----------------|----------|
| Command injection in reports.js | CWE-78 | Replaced `exec()` with `execFile()` to prevent shell interpretation | ~0.5 |
| SQL injection in patients.js | CWE-89 | Switched to parameterized queries with placeholder binding | ~0.5 |
| Path traversal in reports.js | CWE-22 | Added `path.resolve()` + base directory validation | ~0.5 |
| Reflected XSS in notes.js | CWE-79 | Added escape-html sanitization (already a transitive Express dep) | ~0.5 |
| Missing CSRF in server.js | CWE-352 | Added csurf middleware to all state-changing routes | ~0.4 |

Each session costs roughly $0.50 and takes a few minutes. Total backlog remediation: under $10 and under an hour.

## Project Structure

```
medsecure-demo/
├── orchestrator/
│   ├── sarif_parser.py      # SARIF v2.1.0 → Finding/FindingGroup dataclasses
│   ├── prompt_builder.py    # Universal prompt template, title/tag builders
│   ├── devin_client.py      # Devin API v3 client + mock + 429 retry logic
│   ├── tracker.py           # Async session polling + report generation
│   └── pipeline.py          # CLI entry point
├── dashboard/
│   ├── server.py            # HTTP server with API proxy + dispatch engine
│   └── index.html           # React dashboard (single file, no build step)
├── sarif/
│   └── javascript.sarif     # Real CodeQL output (28 findings across 7 vuln types)
├── vulnerable-app/          # Intentionally vulnerable Express.js patient portal
├── tests/                   # 85 tests (73%+ coverage)
├── .github/workflows/
│   ├── ci.yml               # Lint + test + coverage gate
│   ├── codeql.yml           # CodeQL security analysis
│   └── remediate.yml        # Auto-dispatch on CodeQL completion
├── pyproject.toml           # pytest, ruff, coverage config
├── Makefile                 # Dev workflow automation (13 targets)
└── .env.example             # Required environment variables
```

## Setup

```bash
git clone https://github.com/nahomes-15/medsecure-demo.git
cd medsecure-demo
cp .env.example .env         # add your DEVIN_API_KEY and DEVIN_ORG_ID
make install                 # creates .venv, installs deps
```

## Testing

```bash
make test          # all 85 tests
make test-unit     # unit tests only
make test-cov      # with coverage (73%+ gate)
make lint          # ruff
make check         # lint + test (same as CI)
```

Test coverage spans SARIF parsing, prompt generation, Devin API client (with mocked HTTP via respx), session tracking/polling, pipeline orchestration, and dashboard server endpoints.

## CI/CD

| Workflow | Trigger | Purpose |
|----------|---------|---------|
| `ci.yml` | Push / PR | Lint + test + coverage gate |
| `codeql.yml` | Push to main | CodeQL security analysis |
| `remediate.yml` | CodeQL completion or manual | Downloads SARIF → runs pipeline → uploads results |

The `remediate.yml` workflow completes the automation loop: CodeQL scans on push → SARIF produced → pipeline auto-dispatches → Devin opens PRs → engineers review.
