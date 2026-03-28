# src/ports/llm.py
# This would define how the agent "thinks" - don't punch me, Karsten

from abc import ABC, abstractmethod
from typing import List, Optional, Type, TypeVar
from pydantic import BaseModel
from aegis.domain.models import Vulnerability, CodeLocation

T = TypeVar('T', bound=BaseModel)

class ILlmClient(ABC):
    """Outbound port for interacting with the LLM/Agent."""

    @abstractmethod
    def analyze_code_for_vulnerabilities(self, code_snippet: str, context: str) -> List[Vulnerability]:
        """Asks LLM to find vulnerabilities in a snippet"""
        pass

    @abstractmethod
    def generate_exploit_script(self, vulnerability: Vulnerability, target_info: str) -> str:
        """Asks LLM to write a Python/Bash script to trigger the vulnerability."""
        pass

    @abstractmethod
    def ask_structured(self, prompt: str, response_model: Type[T]) -> T:
        """A generic method to force the LLM to return a specific Pydantic model."""
        pass
