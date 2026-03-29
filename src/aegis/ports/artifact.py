# src/aegis/ports/artifact.py

from abc import ABC, abstractmethod
from aegis.domain.models import Vulnerability

# TODO implement this port to store the exploits (artifact of exploit generation)

class IArtifactStore(ABC):
    """Safe capture of successful exploits, enables HITL verification"""

    @abstractmethod
    def save_exploit(self, vulnerability_id: str, code: str) -> str:
        pass
    