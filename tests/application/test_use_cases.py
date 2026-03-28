# tests/application/test_use_cases.py

from typing import List, Type
from pydantic import BaseModel
from aegis.domain.models import Vulnerability, CodeLocation, Severity, TaintPath
from aegis.domain.state import AuditStatus
from aegis.domain.exceptions import ScannerError, LlmError, SandboxError
from aegis.ports.llm import ILlmClient
from aegis.ports.scanner import ICodeScanner
from aegis.ports.sandbox import IExploitSandbox, ExecutionResult
from aegis.application.use_cases import SecurityAuditorUseCase

#
# Mocking the adapters
#
_DEFAULT_LOCATION = CodeLocation(
    file_path="src/db.py",
    start_line=10,
    end_line=12,
    snippet="cursor.execute(f'SELECT * FROM users WHERE id = {user_input}')"
)

def _make_vuln(vuln_id="VULN-001", snippet="x=1", title="SQL Injection"):
    loc = CodeLocation(file_path="src/db.py", start_line=10, end_line=12, snippet=snippet)
    return Vulnerability(
        id=vuln_id,
        cwe_id="CWE-89",
        title=title,
        description="Unsanitized user input in query.",
        severity=Severity.HIGH,
        taint_path=TaintPath(source=loc, sink=loc),
        is_verified=False
    )

class MockScanner(ICodeScanner):
    def __init__(self, locations=None, error=None):
        self._locations = locations if locations is not None else [_DEFAULT_LOCATION]
        self._error = error

    def find_reference(self, symbol_name: str, file_path: str) -> List[CodeLocation]:
        return []

    def get_snippet(self, file_path: str, start_line: int, end_line: int) -> CodeLocation:
        pass

    def execute_semantic_query(self, query: str) -> List[CodeLocation]:
        if self._error:
            raise self._error
        return self._locations

class MockLlmClient(ILlmClient):
    def __init__(self, vulns=None, analyze_error=None, exploit_error=None):
        self._vulns = vulns if vulns is not None else [_make_vuln()]
        self._analyze_error = analyze_error
        self._exploit_error = exploit_error

    def analyze_code_for_vulnerabilities(self, code_snippet: str, context: str) -> List[Vulnerability]:
        if self._analyze_error:
            raise self._analyze_error
        return self._vulns

    def generate_exploit_script(self, vulnerability: Vulnerability, target_info: str) -> str:
        if self._exploit_error:
            raise self._exploit_error
        return "import requests; requests.get('http://target/id?=1 OR 1=1')"

    def ask_structured(self, prompt: str, response_model: Type[BaseModel]) -> BaseModel:
        pass

class MockSandbox(IExploitSandbox):
    def __init__(self, should_succeed=True, setup_error=None, run_error=None):
        self.should_succeed = should_succeed
        self.setup_error = setup_error
        self.run_error = run_error
        self.teardown_called = False
        self.setup_called = False

    def setup_environment(self, repo_url: str, commit_hash: str) -> bool:
        if self.setup_error:
            raise self.setup_error
        self.setup_called = True
        return True

    def run_exploit(self, exploit_code: str, timeout_seconds: int = 30) -> ExecutionResult:
        if self.run_error:
            raise self.run_error
        if self.should_succeed:
            return ExecutionResult(success=True, exit_code=0, stdout="Exploit worked!", stderr="")
        return ExecutionResult(success=False, exit_code=1, stdout="", stderr="Exploit failed.")

    def teardown(self) -> None:
        self.teardown_called = True

#
# Happy path tests
#
def test_successful_audit_loop():
    """Test the happy path: finding a vuln, generating the exploit and verifying it."""
    sandbox = MockSandbox(should_succeed=True)
    use_case = SecurityAuditorUseCase(
        llm_client=MockLlmClient(),
        scanner=MockScanner(),
        sandbox=sandbox
    )

    final_state = use_case.run_audit(target_repo="https://github.com/fake/repo", semantic_query="find sql injection")

    assert final_state.status == AuditStatus.COMPLETED
    assert len(final_state.identified_vulnerabilities) == 1
    vuln = final_state.identified_vulnerabilities[0]
    assert vuln.id == "VULN-001"
    assert vuln.is_verified is True
    assert sandbox.teardown_called is True

def test_audit_loop_verification_fails():
    """Test the path where a vuln is found, but the exploit fails to trigger it."""
    sandbox = MockSandbox(should_succeed=False)
    use_case = SecurityAuditorUseCase(
        llm_client=MockLlmClient(),
        scanner=MockScanner(),
        sandbox=sandbox
    )

    final_state = use_case.run_audit(target_repo="https://github.com/fake/repo", semantic_query="find sql injection")

    assert final_state.status == AuditStatus.COMPLETED
    assert len(final_state.identified_vulnerabilities) == 1
    assert final_state.identified_vulnerabilities[0].is_verified is False
    assert sandbox.teardown_called is True

#
# Early exit tests
#
def test_audit_no_suspicious_locations():
    sandbox = MockSandbox()
    use_case = SecurityAuditorUseCase(
        llm_client=MockLlmClient(),
        scanner=MockScanner(locations=[]),
        sandbox=sandbox
    )

    final_state = use_case.run_audit(target_repo="https://github.com/fake/repo", semantic_query="find sql injection")

    assert final_state.status == AuditStatus.COMPLETED
    assert len(final_state.identified_vulnerabilities) == 0
    assert sandbox.setup_called is False
    assert sandbox.teardown_called is False

def test_audit_no_vulnerabilities_found():
    sandbox = MockSandbox()
    use_case = SecurityAuditorUseCase(
        llm_client=MockLlmClient(vulns=[]),
        scanner=MockScanner(),
        sandbox=sandbox
    )

    final_state = use_case.run_audit(target_repo="https://github.com/fake/repo", semantic_query="find sql injection")

    assert final_state.status == AuditStatus.COMPLETED
    assert len(final_state.identified_vulnerabilities) == 0
    assert sandbox.setup_called is False
    assert sandbox.teardown_called is False

#
# Error handling tests
#
def test_scanner_error_fails_audit():
    sandbox = MockSandbox()
    use_case = SecurityAuditorUseCase(
        llm_client=MockLlmClient(),
        scanner=MockScanner(error=ScannerError("CodeQL timed out")),
        sandbox=sandbox
    )

    final_state = use_case.run_audit(target_repo="https://github.com/fake/repo", semantic_query="find sql injection")

    assert final_state.status == AuditStatus.FAILED
    assert sandbox.setup_called is False
    assert sandbox.teardown_called is False

def test_llm_analysis_error_fails_audit():
    sandbox = MockSandbox()
    use_case = SecurityAuditorUseCase(
        llm_client=MockLlmClient(analyze_error=LlmError("API rate limited")),
        scanner=MockScanner(),
        sandbox=sandbox
    )

    final_state = use_case.run_audit(target_repo="https://github.com/fake/repo", semantic_query="find sql injection")

    assert final_state.status == AuditStatus.FAILED
    assert sandbox.setup_called is False
    assert sandbox.teardown_called is False

def test_llm_exploit_error_still_tears_down():
    sandbox = MockSandbox()
    use_case = SecurityAuditorUseCase(
        llm_client=MockLlmClient(exploit_error=LlmError("Malformed response")),
        scanner=MockScanner(),
        sandbox=sandbox
    )

    final_state = use_case.run_audit(target_repo="https://github.com/fake/repo", semantic_query="find sql injection")

    assert final_state.status == AuditStatus.FAILED
    assert sandbox.setup_called is True
    assert sandbox.teardown_called is True

def test_sandbox_setup_error_no_teardown():
    sandbox = MockSandbox(setup_error=SandboxError("Docker unavailable"))
    use_case = SecurityAuditorUseCase(
        llm_client=MockLlmClient(),
        scanner=MockScanner(),
        sandbox=sandbox
    )

    final_state = use_case.run_audit(target_repo="https://github.com/fake/repo", semantic_query="find sql injection")

    assert final_state.status == AuditStatus.FAILED
    assert sandbox.setup_called is False
    assert sandbox.teardown_called is False

def test_sandbox_run_error_still_tears_down():
    sandbox = MockSandbox(run_error=SandboxError("Container crashed"))
    use_case = SecurityAuditorUseCase(
        llm_client=MockLlmClient(),
        scanner=MockScanner(),
        sandbox=sandbox
    )

    final_state = use_case.run_audit(target_repo="https://github.com/fake/repo", semantic_query="find sql injection")

    assert final_state.status == AuditStatus.FAILED
    assert sandbox.teardown_called is True

def test_unexpected_exception_fails_audit():
    sandbox = MockSandbox()
    use_case = SecurityAuditorUseCase(
        llm_client=MockLlmClient(),
        scanner=MockScanner(error=RuntimeError("Something completely unexpected")),
        sandbox=sandbox
    )

    final_state = use_case.run_audit(target_repo="https://github.com/fake/repo", semantic_query="find sql injection")

    assert final_state.status == AuditStatus.FAILED

#
# Multi-vulnerability test
#
def test_multiple_vulns_partial_verification():
    """Three vulns found. Sandbox succeeds for 1st and 3rd, fails for 2nd."""
    vulns = [_make_vuln(f"VULN-{i}", title=f"SQL Injection via param{i}") for i in range(3)]

    call_count = 0
    class PartialSandbox(MockSandbox):
        def run_exploit(self, exploit_code, timeout_seconds=30):
            nonlocal call_count
            idx = call_count
            call_count += 1
            if idx == 1:
                return ExecutionResult(success=False, exit_code=1, stdout="", stderr="Failed")
            return ExecutionResult(success=True, exit_code=0, stdout="OK", stderr="")

    sandbox = PartialSandbox()
    use_case = SecurityAuditorUseCase(
        llm_client=MockLlmClient(vulns=vulns),
        scanner=MockScanner(),
        sandbox=sandbox
    )

    final_state = use_case.run_audit(target_repo="https://github.com/fake/repo", semantic_query="find sql injection")

    assert final_state.status == AuditStatus.COMPLETED
    assert len(final_state.identified_vulnerabilities) == 3
    assert final_state.identified_vulnerabilities[0].is_verified is True
    assert final_state.identified_vulnerabilities[1].is_verified is False
    assert final_state.identified_vulnerabilities[2].is_verified is True
    assert sandbox.teardown_called is True
