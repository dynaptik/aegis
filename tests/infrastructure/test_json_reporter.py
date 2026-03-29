# tests/infrastructure/test_json_reporter.py

import json

from aegis.domain.models import Vulnerability, Severity
from aegis.domain.state import AuditState, AuditStatus
from aegis.infrastructure.adapters.json_reporter import JsonReportWriter


def _make_vuln(vuln_id, cwe_id, title, severity=Severity.HIGH, verified=False):
    return Vulnerability(
        id=vuln_id, cwe_id=cwe_id, title=title,
        description="test", severity=severity, is_verified=verified,
    )


class TestJsonReportWriter:

    def test_creates_report_file(self, tmp_path):
        state = AuditState(target_repository="https://github.com/fake/repo")
        state.status = AuditStatus.COMPLETED

        writer = JsonReportWriter(output_dir=str(tmp_path))
        path = writer.write(state)

        assert path.endswith(".json")
        assert (tmp_path / path.split("/")[-1]).exists()

    def test_report_contains_metadata(self, tmp_path):
        state = AuditState(target_repository="https://github.com/fake/repo")
        state.status = AuditStatus.COMPLETED

        writer = JsonReportWriter(output_dir=str(tmp_path))
        report = json.loads((tmp_path / writer.write(state).split("/")[-1]).read_text())

        assert report["aegis_version"] == "0.1.0"
        assert report["target_repository"] == "https://github.com/fake/repo"
        assert report["status"] == "completed"
        assert "timestamp" in report

    def test_report_contains_vulnerabilities(self, tmp_path):
        state = AuditState(target_repository="https://github.com/fake/repo")
        state.add_vulnerability(_make_vuln("V-1", "CWE-89", "SQL Injection", verified=True))
        state.add_vulnerability(_make_vuln("V-2", "CWE-79", "XSS", severity=Severity.MEDIUM))
        state.status = AuditStatus.COMPLETED

        writer = JsonReportWriter(output_dir=str(tmp_path))
        report = json.loads((tmp_path / writer.write(state).split("/")[-1]).read_text())

        assert len(report["vulnerabilities"]) == 2
        assert report["vulnerabilities"][0]["cwe_id"] == "CWE-89"
        assert report["vulnerabilities"][0]["is_verified"] is True
        assert report["vulnerabilities"][1]["is_verified"] is False

    def test_summary_counts(self, tmp_path):
        state = AuditState(target_repository="https://github.com/fake/repo")
        state.add_vulnerability(_make_vuln("V-1", "CWE-89", "SQLi", Severity.CRITICAL, verified=True))
        state.add_vulnerability(_make_vuln("V-2", "CWE-79", "XSS", Severity.HIGH, verified=True))
        state.add_vulnerability(_make_vuln("V-3", "CWE-22", "Path Traversal", Severity.HIGH))
        state.status = AuditStatus.COMPLETED

        writer = JsonReportWriter(output_dir=str(tmp_path))
        report = json.loads((tmp_path / writer.write(state).split("/")[-1]).read_text())

        assert report["summary"]["total"] == 3
        assert report["summary"]["verified"] == 2
        assert report["summary"]["unverified"] == 1
        assert report["summary"]["by_severity"]["critical"] == 1
        assert report["summary"]["by_severity"]["high"] == 2

    def test_empty_audit(self, tmp_path):
        state = AuditState(target_repository="https://github.com/fake/repo")
        state.status = AuditStatus.COMPLETED

        writer = JsonReportWriter(output_dir=str(tmp_path))
        report = json.loads((tmp_path / writer.write(state).split("/")[-1]).read_text())

        assert report["summary"]["total"] == 0
        assert report["vulnerabilities"] == []

    def test_creates_output_dir(self, tmp_path):
        nested = tmp_path / "a" / "b" / "c"
        writer = JsonReportWriter(output_dir=str(nested))
        state = AuditState(target_repository="https://github.com/fake/repo")
        state.status = AuditStatus.COMPLETED

        path = writer.write(state)

        assert nested.exists()
        assert path.endswith(".json")

    def test_report_includes_exploit_code_for_verified(self, tmp_path):
        vuln = _make_vuln("V-1", "CWE-89", "SQLi", verified=True)
        vuln.exploit_code = "print('VULNERABILITY CONFIRMED')"
        state = AuditState(target_repository="https://github.com/fake/repo")
        state.add_vulnerability(vuln)
        state.add_vulnerability(_make_vuln("V-2", "CWE-79", "XSS"))
        state.status = AuditStatus.COMPLETED

        writer = JsonReportWriter(output_dir=str(tmp_path))
        report = json.loads((tmp_path / writer.write(state).split("/")[-1]).read_text())

        assert report["vulnerabilities"][0]["exploit_code"] == "print('VULNERABILITY CONFIRMED')"
        assert "exploit_code" not in report["vulnerabilities"][1]

    def test_filename_uses_repo_name(self, tmp_path):
        state = AuditState(target_repository="https://github.com/stamparm/DSVW")
        state.status = AuditStatus.COMPLETED

        writer = JsonReportWriter(output_dir=str(tmp_path))
        path = writer.write(state)

        assert "DSVW" in path.split("/")[-1]
