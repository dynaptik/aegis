# tests/domain/test_models.py

import pytest
from aegis.domain.models import CodeLocation, Severity, Vulnerability, TaintPath
from aegis.domain.exceptions import InvalidCodeLocationError

def test_code_location_valid():
    """Test that a logically sound code location is created successfully."""
    loc = CodeLocation(
        file_path="src/main.py",
        start_line=10,
        end_line=15,
        snippet="def hello():\n    pass"
    )
    assert loc.start_line == 10
    assert loc.file_path == "src/main.py"

def test_code_location_invalid_lines():
    """Test that domain exception is raised for impossible line numbers."""
    with pytest.raises(InvalidCodeLocationError, match="start_line cannot be greater than end_line"):
        CodeLocation(
            file_path="src/main.py",
            start_line=50,
            end_line=10,
            snippet="def hello():\n    pass"
        )

def test_vulnerability_creation():
    """Test standard instantiation of a Vulnerability entity."""
    loc = CodeLocation(file_path="app.py", start_line=1, end_line=2, snippet="x=1")
    path = TaintPath(source=loc, sink=loc)

    vuln = Vulnerability(
        id="VULN-999",
        cwe_id="CWE-79",
        title="XSS",
        description="Cross-site scripting found.",
        severity=Severity.CRITICAL,
        taint_path=path
    )

    assert vuln.severity == Severity.CRITICAL
    assert vuln.is_verified is False # should default to false


def test_dedup_key_normalizes_quotes_and_case():
    """Vulns with same CWE and titles differing only by quotes/case share a key."""
    v1 = Vulnerability(id="V-1", cwe_id="CWE-89", title="SQL Injection via 'id' parameter",
                       description="d", severity=Severity.HIGH)
    v2 = Vulnerability(id="V-2", cwe_id="CWE-89", title="SQL Injection via id parameter",
                       description="d", severity=Severity.CRITICAL)
    assert v1.dedup_key == v2.dedup_key


def test_dedup_key_differs_for_different_parameters():
    """Same CWE but different attack vectors produce different keys."""
    v1 = Vulnerability(id="V-1", cwe_id="CWE-89", title="SQL Injection via id parameter",
                       description="d", severity=Severity.HIGH)
    v2 = Vulnerability(id="V-2", cwe_id="CWE-89", title="SQL Injection via password parameter",
                       description="d", severity=Severity.HIGH)
    assert v1.dedup_key != v2.dedup_key


def test_dedup_key_differs_for_different_cwes():
    """Same title but different CWE IDs are not duplicates."""
    v1 = Vulnerability(id="V-1", cwe_id="CWE-79", title="Injection via v parameter",
                       description="d", severity=Severity.HIGH)
    v2 = Vulnerability(id="V-2", cwe_id="CWE-89", title="Injection via v parameter",
                       description="d", severity=Severity.HIGH)
    assert v1.dedup_key != v2.dedup_key
