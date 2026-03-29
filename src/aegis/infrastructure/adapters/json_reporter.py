# src/aegis/infrastructure/adapters/json_reporter.py

import json
import logging
from datetime import datetime, timezone
from pathlib import Path

from aegis.domain.state import AuditState
from aegis.ports.reporter import IReportWriter

logger = logging.getLogger(__name__)


class JsonReportWriter(IReportWriter):
    """Writes audit results as a JSON file."""

    def __init__(self, output_dir: str = "reports"):
        self.output_dir = Path(output_dir)

    def write(self, state: AuditState) -> str:
        self.output_dir.mkdir(parents=True, exist_ok=True)

        timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
        repo_name = state.target_repository.rstrip("/").rsplit("/", maxsplit=1)[-1]
        filename = f"aegis_{repo_name}_{timestamp}.json"
        path = self.output_dir / filename

        vulns = state.identified_vulnerabilities
        verified = [v for v in vulns if v.is_verified]
        unverified = [v for v in vulns if not v.is_verified]

        report = {
            "aegis_version": "0.1.0",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "target_repository": state.target_repository,
            "status": state.status.value,
            "summary": {
                "total": len(vulns),
                "verified": len(verified),
                "unverified": len(unverified),
                "by_severity": self._count_by_severity(vulns),
            },
            "vulnerabilities": [
                self._serialize_vuln(v) for v in vulns
            ],
        }

        path.write_text(json.dumps(report, indent=2), encoding="utf-8")
        logger.info("Report written to %s", path)
        return str(path)

    @staticmethod
    def _serialize_vuln(v) -> dict:
        entry = {
            "id": v.id,
            "cwe_id": v.cwe_id,
            "title": v.title,
            "description": v.description,
            "severity": v.severity.value,
            "is_verified": v.is_verified,
        }
        if v.exploit_code:
            entry["exploit_code"] = v.exploit_code
        return entry

    @staticmethod
    def _count_by_severity(vulns) -> dict[str, int]:
        counts: dict[str, int] = {"critical": 0, "high": 0, "medium": 0, "low": 0}
        for v in vulns:
            counts[v.severity.value] = counts.get(v.severity.value, 0) + 1
        return counts
