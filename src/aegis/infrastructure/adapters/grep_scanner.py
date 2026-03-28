# src/aegis/infrastructure/adapters/grep_scanner.py

import logging
import re
import subprocess
import tempfile
from pathlib import Path
from typing import List

from aegis.domain.models import CodeLocation
from aegis.domain.exceptions import ScannerError
from aegis.ports.scanner import ICodeScanner

logger = logging.getLogger(__name__)

# how many lines of context to capture around a match
_CONTEXT_LINES = 3

class GrepScanner(ICodeScanner):
    """Scans a cloned git repository using regex pattern matching."""

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
            self._tmp_dir = tempfile.TemporaryDirectory()
            target = Path(self._tmp_dir.name)

        logger.info("Cloning %s …", self.repo_url)
        try:
            subprocess.run(
                ["git", "clone", "--depth", "1", self.repo_url, str(target / "repo")],
                capture_output=True, text=True, check=True, timeout=120
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

    def execute_semantic_query(self, query: str) -> List[CodeLocation]:
        repo_path = self.clone()
        logger.debug("Scanning with pattern: %s", query)

        try:
            pattern = re.compile(query)
        except re.error as e:
            raise ScannerError(f"Invalid regex pattern '{query}': {e}") from e

        locations = []
        for file_path in repo_path.rglob("*.py"):
            if ".git" in file_path.parts:
                continue
            try:
                lines = file_path.read_text(encoding="utf-8", errors="ignore").splitlines()
            except OSError:
                continue

            for i, line in enumerate(lines):
                if pattern.search(line):
                    start = max(0, i - _CONTEXT_LINES)
                    end = min(len(lines), i + _CONTEXT_LINES + 1)
                    snippet = "\n".join(lines[start:end])
                    rel_path = str(file_path.relative_to(repo_path))
                    locations.append(CodeLocation(
                        file_path=rel_path,
                        start_line=start + 1,
                        end_line=end,
                        snippet=snippet
                    ))

        logger.info("Found %d suspicious code locations", len(locations))
        return locations

    def find_reference(self, symbol_name: str, file_path: str) -> List[CodeLocation]:
        return self.execute_semantic_query(re.escape(symbol_name))

    def get_snippet(self, file_path: str, start_line: int, end_line: int) -> CodeLocation:
        repo_path = self.clone()
        target = repo_path / file_path
        if not target.is_file():
            raise ScannerError(f"File not found: {file_path}")

        lines = target.read_text(encoding="utf-8", errors="ignore").splitlines()
        snippet = "\n".join(lines[start_line - 1:end_line])
        return CodeLocation(
            file_path=file_path,
            start_line=start_line,
            end_line=end_line,
            snippet=snippet
        )
