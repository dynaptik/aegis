# tests/application/test_use_cases.py

from typing import List, Type
from pydantic import BaseModel
from aegis.domain.models import Vulnerability, CodeLocation, Severity, TaintPath
from aegis.domain.state import AuditStatus
from aegis.ports.llm import ILlmClient
from aegis.ports.scanner import ICodeScanner
from aegis.ports.sandbox import IExploitSandbox, ExecutionResult
from aegis.application.use_cases import SecurityAuditorUseCase

#
# Mocking the adapters for now
#
class MockScanner(ICodeScanner):
    def find_reference(self, symbol_name: str, file_path: str) -> List[CodeLocation]:
        return []

    def get_snippet(self, file_path: str, start_line: int, end_line: int) -> CodeLocation:
        pass

    def execute_semantic_query(self, query: str) -> List[CodeLocation]:
        # Pretending some SQL weirdness was found
        return [
            CodeLocation(
                file_path="src/db.py",
                start_line=10,
                end_line=12,
                snippet="cursor.execute(f'SELECT * FROM users WHERE id = {user_input}')"
            )
        ]

class MockLlmClient(ILlmClient):
    def analyze_code_for_vulnerabilities(self, code_snippet: str, context: str) -> List[Vulnerability]:
        # Pretending the agent identified a SQLi
        loc = CodeLocation(file_path="src/db.py", start_line=10, end_line=12, snippet=code_snippet)
        return [
            Vulnerability(
                id="VULN-001",
                cwe_id="CWE-89",
                title="SQL Injection",
                description="Unsanitized user input in query.",
                severity=Severity.HIGH,
                taint_path=TaintPath(source=loc, sink=loc), # simplified for testing
                is_verified=False
            )
        ]

    def generate_exploit_script(self, vulnerability: Vulnerability, target_info: str) -> str:
        return "import requests; requests.get('http://target/id?=1 OR 1=1')" # lets keep it simple

    def ask_structured(self, prompt: str, response_model: Type[BaseModel]) -> BaseModel:
        pass

class MockSandbox(IExploitSandbox):
    def __init__(self, should_succeed: bool = True):
        self.should_succeed = should_succeed
        self.teardown_called = False

    def setup_environment(self, repo_url: str, commit_hash: str) -> bool:
        return True

    def run_exploit(self, exploit_code: str, timeout_seconds: int = 30) -> ExecutionResult:
        # Pretending the exploit worked
        if self.should_succeed:
            return ExecutionResult(success=True, exit_code=0, stdout="Exploit worked!", stderr="")
        return ExecutionResult(success=False, exit_code=1, stdout="", stderr="Exploit failed.")

    def teardown(self) -> None:
        self.teardown_called = True

#
# Test cases for the application logic go here
# I will follow the arrange-act-assert pattern
#
def test_successful_audit_loop():
    """Test the happy path: finding a vuln, generating the exploit and verifying it."""
    # Arrange: injecting the mocks into the use case
    use_case = SecurityAuditorUseCase(
        llm_client=MockLlmClient(),
        scanner=MockScanner(),
        sandbox=MockSandbox(should_succeed=True)
    )

    # Act. Run the audit
    final_state = use_case.run_audit(target_repo="https://github.com/fake/repo", semantic_query="find sql injection")

    # Assert: did it meet expectations?
    assert final_state.status == AuditStatus.COMPLETED
    assert len(final_state.identified_vulnerabilities) == 1

    vuln = final_state.identified_vulnerabilities[0]
    assert vuln.id == "VULN-001"
    assert vuln.is_verified is True # because I set MockSandbox.should_succeed to True
    assert use_case.sandbox.teardown_called is True # Cleanup happened

def test_audit_loop_verification_fails():
    """Test the path where a vuln is found, but the exploit fails to trigger it."""
    # Arrange
    use_case = SecurityAuditorUseCase(
        llm_client=MockLlmClient(),
        scanner=MockScanner(),
        sandbox=MockSandbox(should_succeed=False) # Forcing the failure here
    )

    # Act
    final_state = use_case.run_audit(target_repo="https://github.com/fake/repo", semantic_query="find sql injection")

    # Assert
    assert final_state.status == AuditStatus.COMPLETED
    assert len(final_state.identified_vulnerabilities) == 1
    assert final_state.identified_vulnerabilities[0].is_verified is False # should be false!
    assert use_case.sandbox.teardown_called is True
