# src/application/use_cases.py

import logging
from aegis.domain.models import SEVERITY_RANK, CodeLocation
from aegis.domain.state import AuditState, AuditStatus
from aegis.domain.exceptions import SecurityAgentError
from aegis.ports.llm import ILlmClient
from aegis.ports.scanner import ICodeScanner
from aegis.ports.sandbox import IExploitSandbox

logger = logging.getLogger(__name__)

class SecurityAuditorUseCase:
    """
    Orchestrates the agentic security workflow.
    Dependencies are injected via the constructor.
    """

    def __init__(
        self,
        llm_client: ILlmClient,
        scanner: ICodeScanner,
        sandbox: IExploitSandbox
    ):
        self.llm = llm_client
        self.scanner = scanner
        self.sandbox = sandbox

    def run_audit(self, target_repo: str, semantic_query: str) -> AuditState:
        """Executes the full end-to-end vulnerability discovery loop."""
        state = AuditState(target_repository=target_repo)

        try:
            locations = self._scan(state, semantic_query)
            if not locations:
                state.transition_to(AuditStatus.COMPLETED)
                return state

            self._analyze(state, locations, target_repo)
            if not state.identified_vulnerabilities:
                state.transition_to(AuditStatus.COMPLETED)
                return state

            removed = state.deduplicate()
            if removed:
                logger.info("Deduplicated: removed %d duplicates, %d unique remain",
                            removed, len(state.identified_vulnerabilities))

            self._verify(state, target_repo)
            state.transition_to(AuditStatus.COMPLETED)
            return state

        except SecurityAgentError as e:
            logger.error("Domain error during audit: %s", e)
            state.transition_to(AuditStatus.FAILED)
            return state

        except Exception as e:
            logger.critical("Unexpected infrastructure failure: %s", e)
            state.transition_to(AuditStatus.FAILED)
            return state

    def _scan(self, state: AuditState, semantic_query: str) -> list[CodeLocation]:
        state.transition_to(AuditStatus.SCANNING)
        logger.info("Phase 1/3: Scanning for suspicious code patterns …")
        return self.scanner.execute_semantic_query(semantic_query)

    def _analyze(self, state: AuditState, locations: list[CodeLocation], target_repo: str) -> None:
        state.transition_to(AuditStatus.ANALYZING)
        batches = self._group_by_file(locations)
        logger.info("Phase 2/3: Analyzing %d locations in %d batches …", len(locations), len(batches))
        context = f"Target Repository: {target_repo}\nFound {len(locations)} potential sinks."
        for file_path, locs in batches.items():
            combined = self._format_batch(file_path, locs)
            findings = self.llm.analyze_code_for_vulnerabilities(
                code_snippet=combined,
                context=context
            )
            for finding in findings:
                state.add_vulnerability(finding)
        logger.info("Identified %d potential vulnerabilities", len(state.identified_vulnerabilities))

    @staticmethod
    def _group_by_file(locations: list[CodeLocation]) -> dict[str, list[CodeLocation]]:
        groups: dict[str, list[CodeLocation]] = {}
        for loc in locations:
            groups.setdefault(loc.file_path, []).append(loc)
        return groups

    @staticmethod
    def _format_batch(file_path: str, locations: list[CodeLocation]) -> str:
        parts = [f"File: {file_path}"]
        for loc in locations:
            parts.append(f"\n--- lines {loc.start_line}-{loc.end_line} ---\n{loc.snippet}")
        return "\n".join(parts)

    def _verify(self, state: AuditState, target_repo: str) -> None:
        state.transition_to(AuditStatus.VERIFYING)
        vulns = sorted(
            state.identified_vulnerabilities,
            key=lambda v: SEVERITY_RANK.get(v.severity.value, 0),
            reverse=True,
        )
        state.identified_vulnerabilities = vulns
        logger.info("Phase 3/3: Verifying %d vulnerabilities in sandbox …", len(vulns))
        self.sandbox.setup_environment(repo_url=target_repo, commit_hash="HEAD")
        verified_count = 0
        try:
            for i, vuln in enumerate(vulns, 1):
                logger.debug("Verifying [%d/%d] %s: %s", i, len(vulns), vuln.cwe_id, vuln.title)
                exploit_code = self.llm.generate_exploit_script(
                    vulnerability=vuln,
                    target_info=target_repo
                )
                result = self.sandbox.run_exploit(exploit_code)
                if result.success:
                    vuln.is_verified = True
                    vuln.exploit_code = exploit_code
                    verified_count += 1
                elif "is not running" in result.stderr:
                    logger.error("Sandbox container died — aborting remaining verifications")
                    break
                else:
                    logger.debug("Verification failed for %s: %s", vuln.id, result.stderr)
        finally:
            self.sandbox.teardown()
        logger.info("Verification complete: %d/%d confirmed", verified_count, len(vulns))
