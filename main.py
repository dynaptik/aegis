import logging
import os
import sys

from aegis.application.use_cases import SecurityAuditorUseCase
from aegis.infrastructure.adapters.anthropic_adapter import AnthropicAdapter
from aegis.infrastructure.adapters.grep_scanner import GrepScanner
from aegis.infrastructure.adapters.docker_sandbox import DockerSandbox
from aegis.domain.state import AuditStatus

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s"
)
logging.getLogger("httpx").setLevel(logging.WARNING)
logger = logging.getLogger(__name__)


def main():
    api_key = os.environ.get("ANTHROPIC_API_KEY")
    if not api_key:
        logger.error("ANTHROPIC_API_KEY environment variable is not set")
        sys.exit(1)

    target_repo = sys.argv[1] if len(sys.argv) > 1 else None
    query = sys.argv[2] if len(sys.argv) > 2 else (
        r"\.execute\(|exec\(|eval\(|os\.system\(|subprocess\.\w+\(.*shell\s*=\s*True"
        r"|pickle\.loads?\(|open\(|\.format\(|urllib\.request\.urlopen\("
    )

    if not target_repo:
        logger.error("Usage: python main.py <repo_url> [regex_pattern]")
        sys.exit(1)

    scanner = GrepScanner(repo_url=target_repo)
    llm = AnthropicAdapter(api_key=api_key)
    sandbox = DockerSandbox()

    use_case = SecurityAuditorUseCase(
        llm_client=llm,
        scanner=scanner,
        sandbox=sandbox
    )

    try:
        logger.info("Starting AEGIS audit of %s", target_repo)
        state = use_case.run_audit(target_repo=target_repo, semantic_query=query)

        if state.status == AuditStatus.COMPLETED:
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
        else:
            logger.error("Audit failed.")
            sys.exit(1)
    finally:
        scanner.cleanup()


if __name__ == "__main__":
    main()
