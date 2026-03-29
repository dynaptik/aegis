# tests/infrastructure/test_semgrep_scanner.py

import json
import subprocess
import textwrap
from unittest.mock import patch, MagicMock

import pytest
from aegis.infrastructure.adapters.semgrep_scanner import SemgrepScanner
from aegis.domain.exceptions import ScannerError


@pytest.fixture
def fake_repo(tmp_path):
    """Creates a minimal repo with a vulnerable Python file."""
    repo_dir = tmp_path / "repo"
    repo_dir.mkdir()

    app_py = repo_dir / "app.py"
    app_py.write_text(textwrap.dedent("""\
        import os
        import sqlite3

        def handle(user_input):
            os.system(user_input)
            conn = sqlite3.connect("db.sqlite3")
            cursor = conn.cursor()
            cursor.execute(f"SELECT * FROM users WHERE id = {user_input}")
            return cursor.fetchone()

        def safe():
            return "ok"
    """))

    subprocess.run(["git", "init"], cwd=repo_dir, capture_output=True, check=True)
    subprocess.run(["git", "add", "."], cwd=repo_dir, capture_output=True, check=True)
    subprocess.run(
        ["git", "commit", "-m", "init"],
        cwd=repo_dir, capture_output=True, check=True,
        env={"GIT_AUTHOR_NAME": "test", "GIT_AUTHOR_EMAIL": "t@t",
             "GIT_COMMITTER_NAME": "test", "GIT_COMMITTER_EMAIL": "t@t",
             "HOME": str(tmp_path), "PATH": "/usr/bin:/bin:/usr/local/bin"}
    )
    return repo_dir


def _semgrep_json(results):
    """Build a minimal Semgrep JSON output."""
    return json.dumps({"version": "1.0.0", "results": results, "errors": []})


def _make_finding(file_path, start_line, end_line, rule_id="test-rule"):
    return {
        "check_id": f"python.security.{rule_id}",
        "path": file_path,
        "start": {"line": start_line, "col": 1, "offset": 0},
        "end": {"line": end_line, "col": 40, "offset": 100},
        "extra": {
            "message": "Dangerous call detected",
            "severity": "ERROR",
            "metadata": {},
        },
    }


class TestSemgrepScanner:

    def test_parses_findings_into_code_locations(self, fake_repo, tmp_path):
        """Semgrep findings should map to CodeLocations with context."""
        app_path = str(fake_repo / "app.py")
        findings = [_make_finding(app_path, 5, 5, "os-system")]
        semgrep_output = _semgrep_json(findings)

        scanner = SemgrepScanner(repo_url=str(fake_repo), clone_dir=str(tmp_path / "clone"))
        with patch("aegis.infrastructure.adapters.semgrep_scanner.subprocess.run") as mock_run:
            # First call: git clone. Second call: semgrep.
            mock_run.side_effect = [
                MagicMock(returncode=0),  # git clone
                MagicMock(returncode=1, stdout=semgrep_output, stderr=""),  # semgrep
            ]
            locations = scanner.execute_semantic_query("r/python.lang.security")

        assert len(locations) == 1
        assert "os.system" in locations[0].snippet
        assert locations[0].start_line <= 5
        assert locations[0].end_line >= 5

    def test_multiple_findings_across_lines(self, fake_repo, tmp_path):
        app_path = str(fake_repo / "app.py")
        findings = [
            _make_finding(app_path, 5, 5, "os-system"),
            _make_finding(app_path, 8, 8, "sql-injection"),
        ]
        semgrep_output = _semgrep_json(findings)

        scanner = SemgrepScanner(repo_url=str(fake_repo), clone_dir=str(tmp_path / "clone"))
        with patch("aegis.infrastructure.adapters.semgrep_scanner.subprocess.run") as mock_run:
            mock_run.side_effect = [
                MagicMock(returncode=0),
                MagicMock(returncode=1, stdout=semgrep_output, stderr=""),
            ]
            locations = scanner.execute_semantic_query("r/python.lang.security")

        assert len(locations) == 2
        assert "os.system" in locations[0].snippet
        assert "cursor.execute" in locations[1].snippet

    def test_no_findings_returns_empty_list(self, fake_repo, tmp_path):
        semgrep_output = _semgrep_json([])

        scanner = SemgrepScanner(repo_url=str(fake_repo), clone_dir=str(tmp_path / "clone"))
        with patch("aegis.infrastructure.adapters.semgrep_scanner.subprocess.run") as mock_run:
            mock_run.side_effect = [
                MagicMock(returncode=0),
                MagicMock(returncode=0, stdout=semgrep_output, stderr=""),
            ]
            locations = scanner.execute_semantic_query("r/python.lang.security")

        assert not locations

    def test_semgrep_not_installed_raises_scanner_error(self, fake_repo, tmp_path):
        scanner = SemgrepScanner(repo_url=str(fake_repo), clone_dir=str(tmp_path / "clone"))
        with patch("aegis.infrastructure.adapters.semgrep_scanner.subprocess.run") as mock_run:
            mock_run.side_effect = [
                MagicMock(returncode=0),  # git clone
                FileNotFoundError(),      # semgrep not found
            ]
            with pytest.raises(ScannerError, match="not installed"):
                scanner.execute_semantic_query("r/python.lang.security")

    def test_semgrep_timeout_raises_scanner_error(self, fake_repo, tmp_path):
        scanner = SemgrepScanner(repo_url=str(fake_repo), clone_dir=str(tmp_path / "clone"))
        with patch("aegis.infrastructure.adapters.semgrep_scanner.subprocess.run") as mock_run:
            mock_run.side_effect = [
                MagicMock(returncode=0),
                subprocess.TimeoutExpired("semgrep", 300),
            ]
            with pytest.raises(ScannerError, match="timed out"):
                scanner.execute_semantic_query("r/python.lang.security")

    def test_semgrep_error_exit_code_raises_scanner_error(self, fake_repo, tmp_path):
        scanner = SemgrepScanner(repo_url=str(fake_repo), clone_dir=str(tmp_path / "clone"))
        with patch("aegis.infrastructure.adapters.semgrep_scanner.subprocess.run") as mock_run:
            mock_run.side_effect = [
                MagicMock(returncode=0),
                MagicMock(returncode=2, stdout="", stderr="Invalid config"),
            ]
            with pytest.raises(ScannerError, match="Semgrep failed"):
                scanner.execute_semantic_query("r/python.lang.security")

    def test_invalid_json_raises_scanner_error(self, fake_repo, tmp_path):
        scanner = SemgrepScanner(repo_url=str(fake_repo), clone_dir=str(tmp_path / "clone"))
        with patch("aegis.infrastructure.adapters.semgrep_scanner.subprocess.run") as mock_run:
            mock_run.side_effect = [
                MagicMock(returncode=0),
                MagicMock(returncode=0, stdout="not json at all", stderr=""),
            ]
            with pytest.raises(ScannerError, match="invalid JSON"):
                scanner.execute_semantic_query("r/python.lang.security")

    def test_get_snippet(self, fake_repo, tmp_path):
        scanner = SemgrepScanner(repo_url=str(fake_repo), clone_dir=str(tmp_path / "clone"))
        loc = scanner.get_snippet("app.py", start_line=5, end_line=5)

        assert "os.system" in loc.snippet
        assert loc.start_line == 5
        assert loc.end_line == 5

    def test_get_snippet_file_not_found(self, fake_repo, tmp_path):
        scanner = SemgrepScanner(repo_url=str(fake_repo), clone_dir=str(tmp_path / "clone"))
        with pytest.raises(ScannerError, match="File not found"):
            scanner.get_snippet("nonexistent.py", 1, 5)

    def test_cleanup(self, fake_repo):
        scanner = SemgrepScanner(repo_url=str(fake_repo))
        scanner.clone()
        assert scanner._repo_path.exists()
        scanner.cleanup()
        assert scanner._repo_path is None
