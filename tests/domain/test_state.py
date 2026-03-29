# tests/domain/test_state.py

import pytest
from aegis.domain.models import Vulnerability, Severity
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


def _make_vuln(vuln_id, cwe_id, title, severity="high"):
    sev_map = {"low": Severity.LOW, "medium": Severity.MEDIUM,
               "high": Severity.HIGH, "critical": Severity.CRITICAL}
    return Vulnerability(id=vuln_id, cwe_id=cwe_id, title=title,
                         description="d", severity=sev_map[severity])


def test_deduplicate_removes_exact_duplicates():
    state = AuditState(target_repository="repo")
    state.add_vulnerability(_make_vuln("V-1", "CWE-89", "SQL Injection via id parameter"))
    state.add_vulnerability(_make_vuln("V-2", "CWE-89", "SQL Injection via id parameter"))
    removed = state.deduplicate()
    assert removed == 1
    assert len(state.identified_vulnerabilities) == 1


def test_deduplicate_removes_quote_variants():
    state = AuditState(target_repository="repo")
    state.add_vulnerability(_make_vuln("V-1", "CWE-89", "SQL Injection via 'id' parameter"))
    state.add_vulnerability(_make_vuln("V-2", "CWE-89", "SQL Injection via id parameter"))
    removed = state.deduplicate()
    assert removed == 1


def test_deduplicate_keeps_highest_severity():
    state = AuditState(target_repository="repo")
    state.add_vulnerability(_make_vuln("V-1", "CWE-79", "XSS via v param", severity="medium"))
    state.add_vulnerability(_make_vuln("V-2", "CWE-79", "XSS via v param", severity="critical"))
    state.deduplicate()
    assert state.identified_vulnerabilities[0].severity.value == "critical"


def test_deduplicate_preserves_distinct_vulns():
    state = AuditState(target_repository="repo")
    state.add_vulnerability(_make_vuln("V-1", "CWE-89", "SQL Injection via id parameter"))
    state.add_vulnerability(_make_vuln("V-2", "CWE-89", "SQL Injection via password parameter"))
    state.add_vulnerability(_make_vuln("V-3", "CWE-79", "XSS via v parameter"))
    removed = state.deduplicate()
    assert removed == 0
    assert len(state.identified_vulnerabilities) == 3


def test_deduplicate_no_vulns():
    state = AuditState(target_repository="repo")
    removed = state.deduplicate()
    assert removed == 0
