"""MedSecure Security Remediation Pipeline — main entry point.

Usage:
    python pipeline.py --sarif ../sarif/javascript.sarif --mode mock
    python pipeline.py --sarif ../sarif/javascript.sarif --mode dry-run
    python pipeline.py --sarif ../sarif/javascript.sarif --mode live --repo medsecure-demo
"""

import argparse
import asyncio
import json
import logging
import sys
import time
from pathlib import Path

from devin_client import get_client
from prompt_builder import build_prompt, build_tags, build_title
from sarif_parser import SarifParseError, group_findings, parse_sarif
from tracker import TrackedSession, generate_report, poll_sessions, print_summary

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%H:%M:%S",
)
logger = logging.getLogger(__name__)


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="MedSecure Security Remediation Pipeline")
    p.add_argument("--sarif", required=True, help="Path to SARIF file")
    p.add_argument(
        "--mode",
        choices=["live", "dry-run", "mock"],
        default="mock",
        help="Execution mode (default: mock)",
    )
    p.add_argument("--repo", default="medsecure-demo", help="Devin repo identifier")
    p.add_argument("--output", default="pipeline-results.json", help="Output JSON path")
    return p.parse_args()


async def run_pipeline(args: argparse.Namespace) -> None:
    sarif_path = Path(args.sarif)

    # Step 1: Parse (with friendly error handling)
    logger.info(f"Parsing SARIF: {sarif_path}")
    try:
        findings = parse_sarif(sarif_path)
    except SarifParseError as e:
        logger.error(str(e))
        sys.exit(1)
    logger.info(f"  Found {len(findings)} findings")

    # Step 2: Filter & group
    groups = group_findings(findings)
    logger.info(f"  Grouped into {len(groups)} dispatch groups")
    for g in groups:
        lines = ", ".join(f"L{f.start_line}" for f in g.findings)
        logger.info(f"    [{g.level:7s}] {g.rule_id:45s} {g.file}  ({lines})")

    # Step 3: Build prompts
    logger.info("Building Devin prompts...")
    dispatches = []
    for g in groups:
        prompt = build_prompt(g)
        tags = build_tags(g)
        title = build_title(g)
        dispatches.append({"group": g, "prompt": prompt, "tags": tags, "title": title})
        logger.info(f"    {title}")

    # Dry-run: show prompts and exit
    if args.mode == "dry-run":
        logger.info("DRY RUN — printing prompts and exiting\n")
        for i, d in enumerate(dispatches):
            g = d["group"]
            print(f"\n{'='*80}")
            print(f"SESSION {i+1}/{len(dispatches)}: {d['title']}")
            print(f"Repo: {args.repo} | Tags: {d['tags']}")
            print(f"{'='*80}")
            print(d["prompt"])
        return

    # Step 4: Dispatch to Devin
    client = get_client(args.mode)
    logger.info(f"Dispatching {len(dispatches)} sessions ({args.mode} mode)...")
    start = time.time()

    sessions: list[TrackedSession] = []  # survives partial failures
    dispatch_delay = 1.5  # Devin 429s at ~1 req/s
    for i, d in enumerate(dispatches):
        g = d["group"]
        if i > 0:
            logger.info(f"    Waiting {dispatch_delay}s before next dispatch...")
            await asyncio.sleep(dispatch_delay)
        try:
            result = await client.create_session(
                prompt=d["prompt"],
                tags=d["tags"],
                title=d["title"],
                repo=args.repo,
            )
            sessions.append(TrackedSession(
                group=g,
                session_id=result.session_id,
                session_url=result.url,
            ))
            logger.info(f"    [{i+1}/{len(dispatches)}] Dispatched -> {result.session_id}")
        except Exception as e:
            # Non-fatal: one bad group shouldn't abort the batch
            logger.error(
                f"    [{i+1}/{len(dispatches)}] Dispatch failed for "
                f"{g.rule_id} in {g.file}: {e} — continuing with remaining groups"
            )

    # Step 5: Poll & track (blocks until all terminal)
    logger.info(f"Polling {len(sessions)} sessions...")
    await poll_sessions(client, sessions)
    elapsed = time.time() - start
    logger.info(f"All sessions complete in {elapsed:.1f}s")

    # Step 6: Generate report
    report = generate_report(sessions)
    output_path = Path(args.output)
    output_path.write_text(json.dumps(report, indent=2))
    logger.info(f"Report written to {output_path}")

    print_summary(report)


def main() -> None:
    args = parse_args()
    asyncio.run(run_pipeline(args))


if __name__ == "__main__":
    main()
