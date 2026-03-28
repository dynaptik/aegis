# src/ports/scanner.py
# This interface would define how the agent sees the codebase
# Agnostic of if this is grep, SemGrep or CodeQL eventually

from abc import ABC, abstractmethod
from typing import List
from aegis.domain.models import CodeLocation

class ICodeScanner(ABC):
    """Outbound port for querying the codebase."""

    @abstractmethod
    def find_reference(self, symbol_name: str, file_path: str) -> List[CodeLocation]:
        """Find all places where a function or variable is used."""

    @abstractmethod
    def get_snippet(self, file_path: str, start_line: int, end_line: int) -> CodeLocation:
        """Extract a specific chunk of code."""

    @abstractmethod
    def execute_semantic_query(self, query: str) -> List[CodeLocation]:
        """Run a advanced query (e.g. a CodeQL taint tracking query)."""
