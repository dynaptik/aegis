# tests/domain/test_state.py

import pytest
from aegis.domain.state import AuditState, AuditStatus
from aegis.domain.exceptions import InvalidStateTransitionError

def test_initial_audit_state():
    """Test that a new audit starts in the correct default state."""
    state = AuditState(target_repository="https://github.com/fake/repo")

    assert state.target_repository == "https://github.com/fake/repo"
    assert state.status == AuditStatus.INITIALIZED
    assert len(state.identified_vulnerabilities) == 0

def test_full_happy_path_transitions():
    state = AuditState(target_repository="https://github.com/fake/repo")
    for status in [AuditStatus.SCANNING, AuditStatus.ANALYZING, AuditStatus.VERIFYING, AuditStatus.COMPLETED]:
        state.transition_to(status)
    assert state.status == AuditStatus.COMPLETED

@pytest.mark.parametrize("start", [
    AuditStatus.INITIALIZED,
    AuditStatus.SCANNING,
    AuditStatus.ANALYZING,
    AuditStatus.VERIFYING,
])
def test_any_non_terminal_can_fail(start):
    state = AuditState(target_repository="https://github.com/fake/repo")
    state.status = start
    state.transition_to(AuditStatus.FAILED)
    assert state.status == AuditStatus.FAILED

@pytest.mark.parametrize("terminal", [AuditStatus.COMPLETED, AuditStatus.FAILED])
def test_terminal_states_reject_all(terminal):
    state = AuditState(target_repository="https://github.com/fake/repo")
    state.status = terminal
    for target in AuditStatus:
        if target == terminal:
            continue
        with pytest.raises(InvalidStateTransitionError):
            state.transition_to(target)

@pytest.mark.parametrize("start,target", [
    (AuditStatus.SCANNING, AuditStatus.INITIALIZED),
    (AuditStatus.ANALYZING, AuditStatus.SCANNING),
    (AuditStatus.VERIFYING, AuditStatus.ANALYZING),
    (AuditStatus.VERIFYING, AuditStatus.SCANNING),
])
def test_backward_transitions_rejected(start, target):
    state = AuditState(target_repository="https://github.com/fake/repo")
    state.status = start
    with pytest.raises(InvalidStateTransitionError):
        state.transition_to(target)

@pytest.mark.parametrize("start,target", [
    (AuditStatus.INITIALIZED, AuditStatus.ANALYZING),
    (AuditStatus.INITIALIZED, AuditStatus.VERIFYING),
    (AuditStatus.INITIALIZED, AuditStatus.COMPLETED),
    (AuditStatus.SCANNING, AuditStatus.VERIFYING),
])
def test_skip_transitions_rejected(start, target):
    state = AuditState(target_repository="https://github.com/fake/repo")
    state.status = start
    with pytest.raises(InvalidStateTransitionError):
        state.transition_to(target)

@pytest.mark.parametrize("start", [AuditStatus.SCANNING, AuditStatus.ANALYZING])
def test_early_exit_transitions(start):
    state = AuditState(target_repository="https://github.com/fake/repo")
    state.status = start
    state.transition_to(AuditStatus.COMPLETED)
    assert state.status == AuditStatus.COMPLETED
