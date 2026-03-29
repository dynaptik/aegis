# src/aegis/infrastructure/adapters/base_scanner.py

import logging
import subprocess
import tempfile
from pathlib import Path

from aegis.domain.models import CodeLocation
from aegis.domain.exceptions import ScannerError
from aegis.ports.scanner import ICodeScanner

logger = logging.getLogger(__name__)


class BaseScanner(ICodeScanner):
    """Shared logic for scanners that clone a git repo and read files."""

    def __init__(self, repo_url: str, clone_dir: str | None = None):
        self.repo_url = repo_url
        self._clone_dir = clone_dir
        self._repo_path: Path | None = None
        self._tmp_dir: tempfile.TemporaryDirectory | None = None

    def clone(self) -> Path:
        if self._repo_path and self._repo_path.exists():
            return self._repo_path

        if self._clone_dir:
            target = Path(self._clone_dir)
        else:
            self._tmp_dir = tempfile.TemporaryDirectory()  # pylint: disable=consider-using-with
            target = Path(self._tmp_dir.name)

        logger.info("Cloning %s …", self.repo_url)
        try:
            subprocess.run(
                ["git", "clone", "--depth", "1", self.repo_url, str(target / "repo")],
                capture_output=True, text=True, check=True, timeout=120,
            )
        except subprocess.CalledProcessError as e:
            raise ScannerError(f"Failed to clone repository: {e.stderr.strip()}") from e
        except subprocess.TimeoutExpired as e:
            raise ScannerError(f"Clone timed out for {self.repo_url}") from e

        self._repo_path = target / "repo"
        return self._repo_path

    def cleanup(self) -> None:
        if self._tmp_dir:
            self._tmp_dir.cleanup()
            self._tmp_dir = None
            self._repo_path = None

    def get_snippet(self, file_path: str, start_line: int, end_line: int) -> CodeLocation:
        repo_path = self.clone()
        target = repo_path / file_path
        if not target.is_file():
            raise ScannerError(f"File not found: {file_path}")

        try:
            lines = target.read_text(encoding="utf-8", errors="ignore").splitlines()
        except OSError as e:
            raise ScannerError(f"Cannot read file {file_path}: {e}") from e
        snippet = "\n".join(lines[start_line - 1:end_line])
        return CodeLocation(
            file_path=file_path,
            start_line=start_line,
            end_line=end_line,
            snippet=snippet,
        )
