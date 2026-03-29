# src/aegis/infrastructure/adapters/semgrep_scanner.py

import json
import logging
import subprocess
from pathlib import Path
from typing import List

from aegis.domain.models import CodeLocation
from aegis.domain.exceptions import ScannerError
from aegis.infrastructure.adapters.base_scanner import BaseScanner

logger = logging.getLogger(__name__)

_CONTEXT_LINES = 3
_DEFAULT_CONFIG = "r/python.lang.security"


class SemgrepScanner(BaseScanner):
    """Scans a cloned git repository using Semgrep security rules."""

    def __init__(self, repo_url: str, config: str = _DEFAULT_CONFIG, clone_dir: str | None = None):
        super().__init__(repo_url, clone_dir)
        self.config = config

    def execute_semantic_query(self, query: str) -> List[CodeLocation]:
        """Run Semgrep with security rules. The query param is the config string."""
        repo_path = self.clone()
        config = query if query != "" else self.config

        logger.info("Running Semgrep with config: %s", config)
        try:
            result = subprocess.run(
                [
                    "semgrep", "--config", config,
                    "--json", "--no-git-ignore", "--quiet",
                    str(repo_path),
                ],
                capture_output=True, text=True, check=False, timeout=300,
            )
        except FileNotFoundError as e:
            raise ScannerError("Semgrep is not installed or not on PATH") from e
        except subprocess.TimeoutExpired as e:
            raise ScannerError("Semgrep scan timed out") from e

        if result.returncode not in (0, 1):
            # 0 = no findings, 1 = findings found, anything else = error
            raise ScannerError(f"Semgrep failed: {result.stderr.strip()}")

        try:
            output = json.loads(result.stdout)
        except json.JSONDecodeError as e:
            raise ScannerError(f"Semgrep returned invalid JSON: {e}") from e

        locations = []
        for finding in output.get("results", []):
            location = self._finding_to_location(finding, repo_path)
            if location:
                locations.append(location)

        logger.info("Semgrep found %d findings", len(locations))
        return locations

    def _finding_to_location(self, finding: dict, repo_path: Path) -> CodeLocation | None:
        """Convert a Semgrep JSON finding into a CodeLocation with context."""
        file_path = Path(finding["path"])
        start_line = finding["start"]["line"]
        end_line = finding["end"]["line"]

        try:
            abs_path = file_path if file_path.is_absolute() else repo_path / file_path
            lines = abs_path.read_text(encoding="utf-8", errors="ignore").splitlines()
        except OSError:
            return None

        context_start = max(0, start_line - 1 - _CONTEXT_LINES)
        context_end = min(len(lines), end_line + _CONTEXT_LINES)
        snippet = "\n".join(lines[context_start:context_end])

        try:
            rel_path = str(file_path.relative_to(repo_path))
        except ValueError:
            rel_path = str(file_path)

        return CodeLocation(
            file_path=rel_path,
            start_line=context_start + 1,
            end_line=context_end,
            snippet=snippet,
        )

    def find_reference(self, symbol_name: str, file_path: str) -> List[CodeLocation]:
        """Semgrep doesn't do symbol lookup — fall back to pattern search."""
        return self.execute_semantic_query(f"--pattern '{symbol_name}'")
