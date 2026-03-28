# src/ports/sandbox.py
# Somehow the agent needs to test its code, this
# abstracts away how untrusted exploit code is executed

from abc import ABC, abstractmethod
from dataclasses import dataclass

@dataclass
class ExecutionResult:
    """A simple DTO for sandbox results."""
    success: bool
    exit_code: int
    stdout: str
    stderr: str

class IExploitSandbox(ABC):
    """Outbound port for safely executing exploit scripts."""

    @abstractmethod
    def setup_environment(self, repo_url: str, commit_hash: str) -> bool:
        """Prepares the target application for testing."""

    @abstractmethod
    def run_exploit(self, exploit_code: str, timeout_seconds: int = 30) -> ExecutionResult:
        """Executes the generated exploit against the target."""

    @abstractmethod
    def teardown(self) -> None:
        """Cleans up the sandbox."""
