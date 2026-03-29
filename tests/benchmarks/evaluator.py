# tests/benchmarks/evaluator.py

from __future__ import annotations

import logging
import subprocess
from datetime import datetime, timezone
from pathlib import Path

from .loader import load_aegis_report, load_ground_truth
from .matching import match_findings
from .models import (
    BenchmarkMetrics,
    BenchmarkResult,
    CweBreakdown,
    GroundTruthEntry,
    MatchResult,
)

logger = logging.getLogger(__name__)


def compute_metrics(
    match_result: MatchResult,
    gt_entries: list[GroundTruthEntry],
) -> BenchmarkMetrics:
    """Calculate precision, recall, F1, verification rate, and per-CWE breakdown."""
    tp = len(match_result.matched)
    fp = len(match_result.false_positives)
    fn = len(match_result.false_negatives)

    precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
    recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0.0

    verified_tps = sum(1 for m in match_result.matched if m.is_verified)
    verification_rate = verified_tps / tp if tp > 0 else 0.0

    # Per-CWE breakdown
    all_cwes: set[str] = set()
    for gt in gt_entries:
        all_cwes.add(gt.cwe_id)
    for fp_entry in match_result.false_positives:
        all_cwes.add(fp_entry["cwe_id"])

    per_cwe: dict[str, CweBreakdown] = {}
    for cwe in sorted(all_cwes):
        gt_count = sum(1 for gt in gt_entries if gt.cwe_id == cwe)
        found = sum(1 for m in match_result.matched if m.cwe_id == cwe)
        missed = sum(1 for fn_entry in match_result.false_negatives if fn_entry.cwe_id == cwe)
        extra = sum(1 for fp_entry in match_result.false_positives if fp_entry["cwe_id"] == cwe)
        per_cwe[cwe] = CweBreakdown(
            cwe_id=cwe, gt_count=gt_count, found=found, missed=missed, extra=extra,
        )

    return BenchmarkMetrics(
        true_positives=tp,
        false_positives=fp,
        false_negatives=fn,
        precision=round(precision, 4),
        recall=round(recall, 4),
        f1_score=round(f1, 4),
        verification_rate=round(verification_rate, 4),
        per_cwe=per_cwe,
    )


class BenchmarkEvaluator:
    """Orchestrates benchmark evaluation: load data -> match -> compute metrics -> save."""

    def __init__(self, ground_truth_dir: Path, results_dir: Path):
        self._gt_dir = ground_truth_dir
        self._results_dir = results_dir
        self._results_dir.mkdir(parents=True, exist_ok=True)

    def evaluate_report(self, report_path: Path, gt_name: str) -> BenchmarkResult:
        """Report-only mode: load an existing AEGIS JSON report and evaluate it."""
        manifest = load_ground_truth(self._gt_dir / f"{gt_name}.yaml")
        report = load_aegis_report(report_path)

        aegis_vulns = report["vulnerabilities"]
        match_result = match_findings(manifest.vulnerabilities, aegis_vulns)
        metrics = compute_metrics(match_result, manifest.vulnerabilities)

        result = BenchmarkResult(
            timestamp=datetime.now(timezone.utc).isoformat(),
            aegis_version=report.get("aegis_version", "unknown"),
            aegis_commit_sha=self._get_commit_sha(),
            target_repository=report["target_repository"],
            ground_truth_file=f"{gt_name}.yaml",
            report_file=str(report_path),
            execution_mode="report_only",
            metrics=metrics,
            matched=match_result.matched,
            false_positives=match_result.false_positives,
            false_negatives=[
                {"id": gt.id, "cwe_id": gt.cwe_id, "title": gt.title}
                for gt in match_result.false_negatives
            ],
            total_aegis_findings=len(aegis_vulns),
            total_ground_truth=len(manifest.vulnerabilities),
        )

        self._save_result(result, gt_name)
        return result

    @staticmethod
    def _get_commit_sha() -> str:
        """Get the current AEGIS git commit SHA."""
        try:
            proc = subprocess.run(
                ["git", "rev-parse", "HEAD"],
                capture_output=True, text=True, check=True, timeout=5,
            )
            return proc.stdout.strip()
        except Exception:
            return "unknown"

    def _save_result(self, result: BenchmarkResult, gt_name: str) -> Path:
        """Save benchmark result to a JSON file."""
        timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
        sha_short = result.aegis_commit_sha[:8]
        filename = f"{gt_name}_{sha_short}_{timestamp}.json"
        path = self._results_dir / filename
        path.write_text(result.model_dump_json(indent=2), encoding="utf-8")
        logger.info("Benchmark result saved to %s", path)
        return path
