# tests/benchmarks/test_evaluator.py

from benchmarks.models import (
    GroundTruthEntry,
    MatchedFinding,
    MatchResult,
)
from benchmarks.evaluator import compute_metrics


def _matched(gt_id, vuln_id, cwe_id, verified=True, severity_correct=True):
    return MatchedFinding(
        ground_truth_id=gt_id, aegis_vuln_id=vuln_id, cwe_id=cwe_id,
        gt_title="t", aegis_title="t", matched_via="primary_keywords",
        severity_correct=severity_correct, is_verified=verified,
    )


def _gt(gt_id, cwe_id):
    return GroundTruthEntry(
        id=gt_id, cwe_id=cwe_id, title="t", severity="high", keywords=["k"],
    )


class TestComputeMetrics:

    def test_perfect_score(self):
        match_result = MatchResult(
            matched=[
                _matched("GT-1", "V-1", "CWE-89"),
                _matched("GT-2", "V-2", "CWE-79"),
                _matched("GT-3", "V-3", "CWE-78"),
            ],
            false_positives=[],
            false_negatives=[],
        )
        gt = [_gt("GT-1", "CWE-89"), _gt("GT-2", "CWE-79"), _gt("GT-3", "CWE-78")]
        metrics = compute_metrics(match_result, gt)

        assert metrics.true_positives == 3
        assert metrics.false_positives == 0
        assert metrics.false_negatives == 0
        assert metrics.precision == 1.0
        assert metrics.recall == 1.0
        assert metrics.f1_score == 1.0
        assert metrics.verification_rate == 1.0

    def test_zero_findings(self):
        match_result = MatchResult(
            matched=[],
            false_positives=[],
            false_negatives=[_gt("GT-1", "CWE-89"), _gt("GT-2", "CWE-79")],
        )
        gt = [_gt("GT-1", "CWE-89"), _gt("GT-2", "CWE-79")]
        metrics = compute_metrics(match_result, gt)

        assert metrics.true_positives == 0
        assert metrics.false_negatives == 2
        assert metrics.precision == 0.0
        assert metrics.recall == 0.0
        assert metrics.f1_score == 0.0

    def test_all_false_positives(self):
        match_result = MatchResult(
            matched=[],
            false_positives=[
                {"id": "V-1", "cwe_id": "CWE-999", "title": "Spurious"},
                {"id": "V-2", "cwe_id": "CWE-998", "title": "Also spurious"},
            ],
            false_negatives=[_gt("GT-1", "CWE-89")],
        )
        gt = [_gt("GT-1", "CWE-89")]
        metrics = compute_metrics(match_result, gt)

        assert metrics.precision == 0.0
        assert metrics.recall == 0.0
        assert metrics.false_positives == 2
        assert metrics.false_negatives == 1

    def test_partial_recall(self):
        match_result = MatchResult(
            matched=[_matched("GT-1", "V-1", "CWE-89")],
            false_positives=[],
            false_negatives=[_gt("GT-2", "CWE-79"), _gt("GT-3", "CWE-78")],
        )
        gt = [_gt("GT-1", "CWE-89"), _gt("GT-2", "CWE-79"), _gt("GT-3", "CWE-78")]
        metrics = compute_metrics(match_result, gt)

        assert metrics.true_positives == 1
        assert metrics.false_negatives == 2
        assert metrics.precision == 1.0
        assert metrics.recall == round(1 / 3, 4)

    def test_verification_rate_partial(self):
        match_result = MatchResult(
            matched=[
                _matched("GT-1", "V-1", "CWE-89", verified=True),
                _matched("GT-2", "V-2", "CWE-79", verified=False),
                _matched("GT-3", "V-3", "CWE-78", verified=True),
            ],
            false_positives=[],
            false_negatives=[],
        )
        gt = [_gt("GT-1", "CWE-89"), _gt("GT-2", "CWE-79"), _gt("GT-3", "CWE-78")]
        metrics = compute_metrics(match_result, gt)

        assert metrics.verification_rate == round(2 / 3, 4)

    def test_per_cwe_breakdown(self):
        match_result = MatchResult(
            matched=[
                _matched("GT-1", "V-1", "CWE-89"),
                _matched("GT-2", "V-2", "CWE-89"),
            ],
            false_positives=[
                {"id": "V-3", "cwe_id": "CWE-89", "title": "Extra SQLi"},
            ],
            false_negatives=[_gt("GT-3", "CWE-79")],
        )
        gt = [_gt("GT-1", "CWE-89"), _gt("GT-2", "CWE-89"), _gt("GT-3", "CWE-79")]
        metrics = compute_metrics(match_result, gt)

        assert "CWE-89" in metrics.per_cwe
        cwe89 = metrics.per_cwe["CWE-89"]
        assert cwe89.gt_count == 2
        assert cwe89.found == 2
        assert cwe89.missed == 0
        assert cwe89.extra == 1

        assert "CWE-79" in metrics.per_cwe
        cwe79 = metrics.per_cwe["CWE-79"]
        assert cwe79.gt_count == 1
        assert cwe79.found == 0
        assert cwe79.missed == 1
        assert cwe79.extra == 0

    def test_empty_inputs(self):
        match_result = MatchResult(matched=[], false_positives=[], false_negatives=[])
        metrics = compute_metrics(match_result, [])

        assert metrics.true_positives == 0
        assert metrics.precision == 0.0
        assert metrics.recall == 0.0
        assert metrics.f1_score == 0.0
        assert metrics.verification_rate == 0.0
        assert not metrics.per_cwe
