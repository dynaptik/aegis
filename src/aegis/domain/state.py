# src/domain/state.py
# "Anemic Domain Model" for now, I need to extend this
# TODO Add some behavior, error-handling and so on
from pydantic import BaseModel, Field
from typing import List, Optional
from enum import Enum
from aegis.domain.models import Vulnerability
from aegis.domain.exceptions import InvalidStateTransitionError

class AuditStatus(str, Enum):
    INIITIALIZED = "initialized"
    SCANNING = "scanning"
    ANALYZING = "analyzing"
    VERIFYING = "verifying"
    COMPLETED = "completed"
    FAILED = "failed"

class AuditState(BaseModel):
    """Tracks the current state of the agent's investigation"""
    target_repository: str
    status: AuditStatus = AuditStatus.INIITIALIZED

    # What the agent has found so far
    raw_code_snippets: List[str] = Field(default_factory=list)
    identified_vulnerabilities: List[Vulnerability] = Field(default_factory=list)

    # Execution trace for the agent's thought process
    agent_scatchpad: List[str] = Field(default_factory=list)

    def add_vulnerability(self, vuln: Vulnerability):
        self.identified_vulnerabilities.append(vuln)

    def transition_to(self, new_status: AuditStatus):
        # Example business logic: you can't verify if you haven't scanned yet
        if self.status == AuditStatus.INIITIALIZED and new_status == AuditStatus.VERIFYING:
            raise InvalidStateTransitionError("Cannot skip straight to verifying from initialized.")
        self.status = new_status