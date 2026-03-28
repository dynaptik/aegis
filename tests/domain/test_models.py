# tests/domain/test_models.py

import pytest
from pydantic import ValidationError
from aegis.domain.models import CodeLocation, Severity, Vulnerability, TaintPath

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
    """Test that pydantic catches all mathematically impossible line numbers."""
    with pytest.raises(ValidationError) as exc_info:
        CodeLocation(
        file_path="src/main.py",
        start_line=50, # starts after it ends, should be caught
        end_line=10,
        snippet="def hello():\n    pass"
    )
        
    assert "start_line cannot be greater than end_line" in str(exc_info.value)

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