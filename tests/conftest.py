# tests/conftest.py


def pytest_configure(config):
    config.addinivalue_line(
        "markers", "benchmark: ground truth evaluation tests (deselect with '-m not benchmark')"
    )


def pytest_addoption(parser):
    parser.addoption(
        "--aegis-report", action="store", default=None,
        help="Path to an existing AEGIS JSON report to evaluate (report-only mode)",
    )
    parser.addoption(
        "--gt", action="store", default="dsvw",
        help="Ground truth manifest name without .yaml extension (default: dsvw)",
    )
