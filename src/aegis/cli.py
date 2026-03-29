# src/aegis/cli.py

import argparse
import logging
import os
import sys

from aegis.application.use_cases import SecurityAuditorUseCase
from aegis.domain.state import AuditStatus
from aegis.infrastructure.adapters.anthropic_adapter import AnthropicAdapter
from aegis.infrastructure.adapters.docker_sandbox import DockerSandbox
from aegis.infrastructure.adapters.grep_scanner import GrepScanner
from aegis.infrastructure.adapters.json_reporter import JsonReportWriter
from aegis.infrastructure.adapters.semgrep_scanner import SemgrepScanner

logger = logging.getLogger(__name__)


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="aegis",
        description="AEGIS: Agentic Exploit Generation in Isolated Sandboxes",
    )
    parser.add_argument(
        "repo_url",
        help="URL of the Git repository to audit",
    )
    parser.add_argument(
        "-s", "--scanner",
        choices=["grep", "semgrep"],
        default="grep",
        help="Scanner backend: 'grep' for regex matching, 'semgrep' for semantic analysis (default: grep)",
    )
    parser.add_argument(
        "-p", "--pattern",
        default=None,
        help="Regex pattern (grep) or Semgrep config (semgrep). Defaults: dangerous sinks regex / r/python.lang.security",
    )
    parser.add_argument(
        "-o", "--output-dir",
        default="reports",
        help="Directory for JSON reports (default: reports)",
    )
    parser.add_argument(
        "--network",
        action="store_true",
        help="Allow sandbox containers network access (required for web app targets)",
    )
    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Enable debug-level logging",
    )
    return parser


def _print_report(state, target_repo: str) -> None:
    vulns = state.identified_vulnerabilities
    verified = [v for v in vulns if v.is_verified]
    unverified = [v for v in vulns if not v.is_verified]

    print(f"\n{'=' * 60}")
    print(f"  AEGIS Audit Report — {target_repo}")
    print(f"  {len(verified)} verified / {len(vulns)} total findings")
    print(f"{'=' * 60}")

    if verified:
        print("\n  VERIFIED VULNERABILITIES:")
        for v in verified:
            print(f"    [{v.severity.value.upper():>8}] {v.cwe_id} — {v.title}")

    if unverified:
        print("\n  UNVERIFIED (could not confirm in sandbox):")
        for v in unverified:
            print(f"    [{v.severity.value.upper():>8}] {v.cwe_id} — {v.title}")

    print(f"\n{'=' * 60}\n")


def main(argv: list[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    )
    logging.getLogger("httpx").setLevel(logging.WARNING)

    api_key = os.environ.get("ANTHROPIC_API_KEY")
    if not api_key:
        logger.error("ANTHROPIC_API_KEY environment variable is not set")
        return 1

    query = args.pattern or ""
    if args.scanner == "semgrep":
        scanner = SemgrepScanner(repo_url=args.repo_url, config=query)
    else:
        scanner = GrepScanner(repo_url=args.repo_url, config=query)

    llm = AnthropicAdapter(api_key=api_key)
    sandbox = DockerSandbox(network=args.network)

    use_case = SecurityAuditorUseCase(
        llm_client=llm,
        scanner=scanner,
        sandbox=sandbox,
    )

    try:
        logger.info("Starting AEGIS audit of %s", args.repo_url)
        state = use_case.run_audit(target_repo=args.repo_url, semantic_query=query)

        if state.status == AuditStatus.COMPLETED:
            _print_report(state, args.repo_url)
            reporter = JsonReportWriter(output_dir=args.output_dir)
            report_path = reporter.write(state)
            print(f"  Full report: {report_path}\n")
            return 0

        logger.error("Audit failed.")
        return 1
    finally:
        scanner.cleanup()


if __name__ == "__main__":
    sys.exit(main())
