# tests/domain/test_state.py

import pytest
from aegis.domain.state import AuditState, AuditStatus
from aegis.domain.exceptions import InvalidStateTransitionError

def test_initial_audit_state():
    """Test that a new audit starts in the correct default state."""
    state = AuditState(target_repository="https://github.com/fake/repo")

    assert state.target_repository == "https://github.com/fake/repo"
    assert state.status == AuditStatus.INIITIALIZED
    assert len(state.identified_vulnerabilities) == 0

def test_valid_state_transition():
    """Test a normal progression from initialized to scanning."""
    state = AuditState(target_repository="https://github.com/fake/repo")
    state.transition_to(AuditStatus.SCANNING)

    assert state.status == AuditStatus.SCANNING

def test_invalid_state_transition():
    """Test that the domain rejects skipping the mandatory phases."""
    state = AuditState(target_repository="https://github.com/fake/repo")

    # enforcing so that you cannot jump straight from init to verifying
    with pytest.raises(InvalidStateTransitionError) as exc_info:
        state.transition_to(AuditStatus.VERIFYING)

    assert "Cannot skip straight to verifying" in str(exc_info.value)