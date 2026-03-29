# tests/benchmarks/loader.py

import json
from pathlib import Path

import yaml

from .models import GroundTruthManifest


def load_ground_truth(path: Path) -> GroundTruthManifest:
    """Load and validate a YAML ground truth manifest."""
    raw = yaml.safe_load(path.read_text(encoding="utf-8"))
    return GroundTruthManifest.model_validate(raw)


def load_aegis_report(path: Path) -> dict:
    """Load an AEGIS JSON report file."""
    return json.loads(path.read_text(encoding="utf-8"))


def find_latest_report(reports_dir: Path, repo_substring: str) -> Path | None:
    """Find the most recent report file matching a repository name."""
    candidates = sorted(
        reports_dir.glob(f"aegis_*{repo_substring}*.json"),
        key=lambda p: p.stat().st_mtime,
        reverse=True,
    )
    return candidates[0] if candidates else None
