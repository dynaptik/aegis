# src/domain/use_cases.py
# Not sure if I should move use_cases to their
# own top-level to organize them better, maybe
# TODO refactor when more use cases are added

import logging
from typing import List
from aegis.domain.models import Vulnerability
from aegis.domain.state import AuditState, AuditStatus
from aegis.domain.exceptions import SecurityAgentError
from aegis.ports.llm import ILlmClient
from aegis.ports.scanner import ICodeScanner
from aegis.ports.sandbox import IExploitSandbox

logger = logging.getLogger(__name__)

class SecurityAuditorUseCase:
    """
    Orchestrates the agentic security workflow.
    Dependendies are injected via the constructor.
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
            # 1. Scanning
            state.transition_to(AuditStatus.SCANNING)
            logger.info(f"Executing semantic query: {semantic_query}")
            suspicious_locations = self.scanner.execute_semantic_query(semantic_query)

            if not suspicious_locations:
                logger.info("No suspicious locations found. Audit complete.")
                state.transition_to(AuditStatus.COMPLETED)
                return state
            
            # 2. Analyzing
            state.transition_to(AuditStatus.ANALYZING)
            context = f"Target Repository: {target_repo}\nFound {len(suspicious_locations)} potential sinks."

            for loc in suspicious_locations:
                # Here the agents is asked to "reason" about the code snippet
                findings = self.llm.analyze_code_for_vulnerabilities(
                    code_snippet=loc.snippet,
                    context=context
                )
                for finding in findings:
                    state.add_vulnerability(finding)

            if not state.identified_vulnerabilities:
                state.transition_to(AuditStatus.COMPLETED)
                return state
            
            # 3. Verify in the sandbox
            # TODO this is the tricky part, look for pattern for something like this
            state.transition_to(AuditStatus.VERIFYING)
            self.sandbox.setup_environment(repo_url=target_repo, commit_hash="HEAD")

            for vuln in state.identified_vulnerabilities:
                logger.info(f"Attempting to verify {vuln.cwe_id}: {vuln.title}")

                # Here the agent gets asked to write the exploit
                # TODO maybe - if this is the hardest part - change model here?
                # TODO add model picker to ILlm interface/abc - but is it still hexagonal architecture then?
                exploit_code = self.llm.generate_exploit_script(
                    vulnerability=vuln,
                    target_info=target_repo
                )

                # Execute the exploit in a sandbox
                # TODO its gonna be tricky to have the system also setup the target app properly based on the README
                # maybe this is another agent or infrastructure/adapter - or I do it manually for now
                result = self.sandbox.run_exploit(exploit_code)

                # if the script crashes the app or returns ideally the flag, mark as verified
                if result.success:
                    logger.warning(f"VULNERABILITY VERIFIED: {vuln.id}")
                    vuln.is_verified = True
                else:
                    logger.info(f"Verification failed for {vuln.id}. Sandbox output: {result.stderr}")

            # 4. Cleanup and wrap it up
            # TODO sanity check this - I don't want to DoS myself locally with endless sandbox containers
            # No code path should end without teardown?
            self.sandbox.teardown()
            state.transition_to(AuditStatus.COMPLETED)
            return state
        
        # No teardown here if I can make the agent "recover"?
        except SecurityAgentError as e:
            logger.error(f"Domain error during audit: {str(e)}")
            state.transition_to(AuditStatus.FAILED)
            return state
        
        # TODO see if I can expand Exception Handling if this is thrown too many times:
        except Exception as e:
            logger.critical(f"Unexpected infrastructure failure: {str(e)}")
            self.sandbox.teardown()
            state.transition_to(AuditStatus.FAILED)
            return state