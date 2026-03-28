# src/domain/state.py
from typing import List
from enum import Enum
from pydantic import BaseModel, Field
from aegis.domain.models import Vulnerability
from aegis.domain.exceptions import InvalidStateTransitionError

class AuditStatus(str, Enum):
    INITIALIZED = "initialized"
    SCANNING = "scanning"
    ANALYZING = "analyzing"
    VERIFYING = "verifying"
    COMPLETED = "completed"
    FAILED = "failed"

_ALLOWED_TRANSITIONS: dict[AuditStatus, set[AuditStatus]] = {
    AuditStatus.INITIALIZED: {AuditStatus.SCANNING, AuditStatus.FAILED},
    AuditStatus.SCANNING:    {AuditStatus.ANALYZING, AuditStatus.COMPLETED, AuditStatus.FAILED},
    AuditStatus.ANALYZING:   {AuditStatus.VERIFYING, AuditStatus.COMPLETED, AuditStatus.FAILED},
    AuditStatus.VERIFYING:   {AuditStatus.COMPLETED, AuditStatus.FAILED},
    AuditStatus.COMPLETED:   set(),
    AuditStatus.FAILED:      set(),
}

class AuditState(BaseModel):
    """Tracks the current state of the agent's investigation"""
    target_repository: str
    status: AuditStatus = AuditStatus.INITIALIZED
    identified_vulnerabilities: List[Vulnerability] = Field(default_factory=list)

    def add_vulnerability(self, vuln: Vulnerability):
        self.identified_vulnerabilities.append(vuln)  # pylint: disable=no-member

    def deduplicate(self) -> int:
        """Remove duplicate vulnerabilities, keeping the highest severity.
        Returns the number of duplicates removed."""
        severity_rank = {"critical": 4, "high": 3, "medium": 2, "low": 1}
        seen: dict[str, int] = {}
        unique: list[Vulnerability] = []
        for vuln in self.identified_vulnerabilities:  # pylint: disable=no-member
            key = vuln.dedup_key
            if key in seen:
                existing_idx = seen[key]
                existing = unique[existing_idx]
                if severity_rank.get(vuln.severity.value, 0) > severity_rank.get(existing.severity.value, 0):
                    unique[existing_idx] = vuln
            else:
                seen[key] = len(unique)
                unique.append(vuln)
        removed = len(self.identified_vulnerabilities) - len(unique)
        self.identified_vulnerabilities = unique
        return removed

    def transition_to(self, new_status: AuditStatus) -> None:
        allowed = _ALLOWED_TRANSITIONS.get(self.status, set())
        if new_status not in allowed:
            raise InvalidStateTransitionError(
                f"Cannot transition from {self.status.value} to {new_status.value}"
            )
        self.status = new_status
