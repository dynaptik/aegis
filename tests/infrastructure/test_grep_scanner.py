# tests/infrastructure/test_grep_scanner.py

import subprocess
import textwrap
from pathlib import Path

import pytest
from aegis.infrastructure.adapters.grep_scanner import GrepScanner
from aegis.domain.exceptions import ScannerError


@pytest.fixture
def fake_repo(tmp_path):
    """Creates a minimal git repo with a vulnerable Python file."""
    repo_dir = tmp_path / "repo"
    repo_dir.mkdir()

    app_py = repo_dir / "app.py"
    app_py.write_text(textwrap.dedent("""\
        import sqlite3

        def get_user(user_id):
            conn = sqlite3.connect("db.sqlite3")
            cursor = conn.cursor()
            cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")
            return cursor.fetchone()

        def safe_query():
            return "nothing suspicious here"
    """))

    utils_dir = repo_dir / "utils"
    utils_dir.mkdir()
    (utils_dir / "helpers.py").write_text("def helper():\n    pass\n")

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


class TestGrepScanner:

    def test_execute_semantic_query_finds_sql_injection(self, fake_repo, tmp_path):
        scanner = GrepScanner(repo_url=str(fake_repo), clone_dir=str(tmp_path / "clone"))
        locations = scanner.execute_semantic_query(r"cursor\.execute\(f")

        assert len(locations) == 1
        loc = locations[0]
        assert loc.file_path == "app.py"
        assert "cursor.execute" in loc.snippet
        assert loc.start_line <= 6
        assert loc.end_line >= 6

    def test_execute_semantic_query_no_matches(self, fake_repo, tmp_path):
        scanner = GrepScanner(repo_url=str(fake_repo), clone_dir=str(tmp_path / "clone"))
        locations = scanner.execute_semantic_query(r"eval\(")

        assert locations == []

    def test_invalid_regex_raises_scanner_error(self, fake_repo, tmp_path):
        scanner = GrepScanner(repo_url=str(fake_repo), clone_dir=str(tmp_path / "clone"))
        with pytest.raises(ScannerError, match="Invalid regex"):
            scanner.execute_semantic_query("[invalid")

    def test_get_snippet_returns_correct_lines(self, fake_repo, tmp_path):
        scanner = GrepScanner(repo_url=str(fake_repo), clone_dir=str(tmp_path / "clone"))
        loc = scanner.get_snippet("app.py", start_line=5, end_line=7)

        assert loc.file_path == "app.py"
        assert loc.start_line == 5
        assert loc.end_line == 7
        assert "cursor" in loc.snippet

    def test_get_snippet_file_not_found(self, fake_repo, tmp_path):
        scanner = GrepScanner(repo_url=str(fake_repo), clone_dir=str(tmp_path / "clone"))
        with pytest.raises(ScannerError, match="File not found"):
            scanner.get_snippet("nonexistent.py", 1, 5)

    def test_find_reference_finds_symbol(self, fake_repo, tmp_path):
        scanner = GrepScanner(repo_url=str(fake_repo), clone_dir=str(tmp_path / "clone"))
        locations = scanner.find_reference("cursor.execute", "app.py")

        assert len(locations) == 1
        assert "cursor.execute" in locations[0].snippet

    def test_clone_invalid_repo_raises_scanner_error(self, tmp_path):
        scanner = GrepScanner(
            repo_url="https://invalid.example.com/no-such-repo.git",
            clone_dir=str(tmp_path / "clone")
        )
        with pytest.raises(ScannerError, match="Failed to clone"):
            scanner.clone()

    def test_cleanup_removes_temp_dir(self, fake_repo):
        scanner = GrepScanner(repo_url=str(fake_repo))
        scanner.clone()
        assert scanner._repo_path.exists()
        scanner.cleanup()
        assert scanner._repo_path is None

    def test_clone_is_idempotent(self, fake_repo, tmp_path):
        scanner = GrepScanner(repo_url=str(fake_repo), clone_dir=str(tmp_path / "clone"))
        path1 = scanner.clone()
        path2 = scanner.clone()
        assert path1 == path2
