# src/aegis/infrastructure/adapters/grep_scanner.py

import logging
import re
from typing import List

from aegis.domain.models import CodeLocation
from aegis.domain.exceptions import ScannerError
from aegis.infrastructure.adapters.base_scanner import BaseScanner

logger = logging.getLogger(__name__)

# how many lines of context to capture around a match
_CONTEXT_LINES = 3


class GrepScanner(BaseScanner):
    """Scans a cloned git repository using regex pattern matching."""

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
