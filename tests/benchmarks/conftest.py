# tests/benchmarks/conftest.py

from pathlib import Path

import pytest

from benchmarks.evaluator import BenchmarkEvaluator

_BENCHMARKS_DIR = Path(__file__).parent
_GROUND_TRUTH_DIR = _BENCHMARKS_DIR / "ground_truth"
_RESULTS_DIR = _BENCHMARKS_DIR / "results"


@pytest.fixture
def ground_truth_dir():
    return _GROUND_TRUTH_DIR


@pytest.fixture
def results_dir():
    return _RESULTS_DIR


@pytest.fixture
def evaluator(tmp_path):
    """BenchmarkEvaluator that saves results to a temporary directory during tests."""
    return BenchmarkEvaluator(
        ground_truth_dir=_GROUND_TRUTH_DIR,
        results_dir=tmp_path / "results",
    )


@pytest.fixture
def evaluator_persistent():
    """BenchmarkEvaluator that saves results to the real results directory."""
    return BenchmarkEvaluator(
        ground_truth_dir=_GROUND_TRUTH_DIR,
        results_dir=_RESULTS_DIR,
    )


@pytest.fixture
def aegis_report_path(request):
    """Provided via --aegis-report CLI option."""
    path = request.config.getoption("--aegis-report")
    if path is None:
        pytest.skip("No --aegis-report provided; use --aegis-report=path/to/report.json")
    return Path(path)


@pytest.fixture
def gt_name(request):
    return request.config.getoption("--gt")
