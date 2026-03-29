# tests/benchmarks/models.py

from __future__ import annotations

from pydantic import BaseModel, Field


class GroundTruthEntry(BaseModel):
    """A single known vulnerability in a target repository."""
    id: str
    cwe_id: str
    title: str
    severity: str
    keywords: list[str]
    alt_keywords: list[str] = Field(default_factory=list)
    description: str = ""


class GroundTruthManifest(BaseModel):
    """Complete ground truth for one target repository."""
    repository: str
    description: str = ""
    vulnerabilities: list[GroundTruthEntry]


class MatchedFinding(BaseModel):
    """A pairing of a ground truth entry with an AEGIS finding."""
    ground_truth_id: str
    aegis_vuln_id: str
    cwe_id: str
    gt_title: str
    aegis_title: str
    matched_via: str  # "primary_keywords" or "alt_keywords"
    severity_correct: bool
    is_verified: bool


class MatchResult(BaseModel):
    """Output of the matching algorithm."""
    matched: list[MatchedFinding]
    false_positives: list[dict]  # unmatched AEGIS findings
    false_negatives: list[GroundTruthEntry]


class CweBreakdown(BaseModel):
    """Per-CWE metric breakdown."""
    cwe_id: str
    gt_count: int
    found: int
    missed: int
    extra: int


class BenchmarkMetrics(BaseModel):
    """Computed metrics from one benchmark evaluation."""
    true_positives: int
    false_positives: int
    false_negatives: int
    precision: float
    recall: float
    f1_score: float
    verification_rate: float
    per_cwe: dict[str, CweBreakdown] = Field(default_factory=dict)


class BenchmarkResult(BaseModel):
    """Complete result of one benchmark evaluation run."""
    timestamp: str
    aegis_version: str
    aegis_commit_sha: str
    target_repository: str
    ground_truth_file: str
    report_file: str | None = None
    execution_mode: str
    metrics: BenchmarkMetrics
    matched: list[MatchedFinding]
    false_positives: list[dict]
    false_negatives: list[dict]
    total_aegis_findings: int
    total_ground_truth: int
