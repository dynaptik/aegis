# src/ports/reporter.py
# Abstracts how audit results are persisted
# Could be JSON, Markdown, HTML, or a database later

from abc import ABC, abstractmethod

from aegis.domain.state import AuditState


class IReportWriter(ABC):
    """Outbound port for persisting audit results."""

    @abstractmethod
    def write(self, state: AuditState) -> str:
        """Write the audit report. Returns the output path or identifier."""
