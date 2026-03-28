# src/application/use_cases.py

import logging
from aegis.domain.models import CodeLocation
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
        logger.info("Executing semantic query: %s", semantic_query)
        return self.scanner.execute_semantic_query(semantic_query)

    def _analyze(self, state: AuditState, locations: list[CodeLocation], target_repo: str) -> None:
        state.transition_to(AuditStatus.ANALYZING)
        context = f"Target Repository: {target_repo}\nFound {len(locations)} potential sinks."
        for loc in locations:
            findings = self.llm.analyze_code_for_vulnerabilities(
                code_snippet=loc.snippet,
                context=context
            )
            for finding in findings:
                state.add_vulnerability(finding)

    def _verify(self, state: AuditState, target_repo: str) -> None:
        state.transition_to(AuditStatus.VERIFYING)
        self.sandbox.setup_environment(repo_url=target_repo, commit_hash="HEAD")
        try:
            for vuln in state.identified_vulnerabilities:
                logger.info("Attempting to verify %s: %s", vuln.cwe_id, vuln.title)
                exploit_code = self.llm.generate_exploit_script(
                    vulnerability=vuln,
                    target_info=target_repo
                )
                result = self.sandbox.run_exploit(exploit_code)
                if result.success:
                    logger.warning("VULNERABILITY VERIFIED: %s", vuln.id)
                    vuln.is_verified = True
                else:
                    logger.info("Verification failed for %s. Sandbox output: %s", vuln.id, result.stderr)
        finally:
            self.sandbox.teardown()
