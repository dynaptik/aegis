# tests/benchmarks/test_benchmark_dsvw.py

import pytest

pytestmark = pytest.mark.benchmark


class TestDSVWBenchmark:
    """Evaluate an existing AEGIS report against DSVW ground truth.

    Usage:
        pytest -m benchmark --aegis-report=reports/aegis_DSVW_20260329_142229.json -v
    """

    def test_evaluate_report(self, evaluator_persistent, aegis_report_path, gt_name, capsys):
        result = evaluator_persistent.evaluate_report(aegis_report_path, gt_name)
        m = result.metrics

        print(f"\n{'=' * 60}")
        print(f"  BENCHMARK: {result.target_repository}")
        print(f"  Commit:    {result.aegis_commit_sha[:8]}")
        print(f"  Findings:  {result.total_aegis_findings} reported, "
              f"{result.total_ground_truth} in ground truth")
        print(f"  Precision: {m.precision:.1%}")
        print(f"  Recall:    {m.recall:.1%}")
        print(f"  F1:        {m.f1_score:.1%}")
        print(f"  Verified:  {m.verification_rate:.1%}")
        print(f"{'=' * 60}")

        if result.false_negatives:
            print("\n  MISSED (False Negatives):")
            for fn in result.false_negatives:
                print(f"    - {fn['cwe_id']}: {fn['title']}")

        if result.false_positives:
            print("\n  EXTRA (False Positives):")
            for fp in result.false_positives:
                print(f"    - {fp['cwe_id']}: {fp['title']}")

        if m.per_cwe:
            print("\n  Per-CWE Breakdown:")
            for cwe_id, breakdown in sorted(m.per_cwe.items()):
                status = "OK" if breakdown.missed == 0 and breakdown.extra == 0 else "!!"
                print(f"    [{status}] {cwe_id}: "
                      f"{breakdown.found}/{breakdown.gt_count} found, "
                      f"{breakdown.extra} extra")

    def test_recall_above_threshold(self, evaluator, aegis_report_path, gt_name):
        result = evaluator.evaluate_report(aegis_report_path, gt_name)
        assert result.metrics.recall >= 0.75, (
            f"Recall {result.metrics.recall:.1%} below 75% threshold. "
            f"Missed: {[fn['title'] for fn in result.false_negatives]}"
        )

    def test_precision_above_threshold(self, evaluator, aegis_report_path, gt_name):
        result = evaluator.evaluate_report(aegis_report_path, gt_name)
        assert result.metrics.precision >= 0.80, (
            f"Precision {result.metrics.precision:.1%} below 80% threshold"
        )
