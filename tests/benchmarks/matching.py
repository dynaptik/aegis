# tests/benchmarks/matching.py

from __future__ import annotations

import re

from .models import GroundTruthEntry, MatchedFinding, MatchResult


def _keywords_match(keywords: list[str], searchable: str) -> bool:
    """Return True if ALL keywords appear as whole words in the searchable text."""
    return all(re.search(r'\b' + re.escape(kw.lower()) + r'\b', searchable) for kw in keywords)


def _try_match(
    gt: GroundTruthEntry,
    candidates: list[dict],
    used_aegis_ids: set[str],
    keyword_field: str,
) -> MatchedFinding | None:
    """Try to match a GT entry against unused AEGIS findings using the specified keywords."""
    keywords = getattr(gt, keyword_field)
    if not keywords:
        return None

    for candidate in candidates:
        if candidate["id"] in used_aegis_ids:
            continue
        searchable = (candidate["title"] + " " + candidate.get("description", "")).lower()
        if _keywords_match(keywords, searchable):
            matched_via = "primary_keywords" if keyword_field == "keywords" else "alt_keywords"
            return MatchedFinding(
                ground_truth_id=gt.id,
                aegis_vuln_id=candidate["id"],
                cwe_id=gt.cwe_id,
                gt_title=gt.title,
                aegis_title=candidate["title"],
                matched_via=matched_via,
                severity_correct=candidate.get("severity", "") == gt.severity,
                is_verified=candidate.get("is_verified", False),
            )
    return None


def match_findings(
    gt_entries: list[GroundTruthEntry],
    aegis_vulns: list[dict],
) -> MatchResult:
    """Match AEGIS findings to ground truth entries using CWE + keyword matching.

    Two-pass algorithm:
      Pass 1: Match using primary keywords
      Pass 2: Match remaining using alt_keywords fallback
    """
    # Index AEGIS findings by CWE
    aegis_by_cwe: dict[str, list[dict]] = {}
    for vuln in aegis_vulns:
        aegis_by_cwe.setdefault(vuln["cwe_id"], []).append(vuln)

    matched: list[MatchedFinding] = []
    used_gt_ids: set[str] = set()
    used_aegis_ids: set[str] = set()

    # Pass 1: primary keywords
    for gt in gt_entries:
        candidates = aegis_by_cwe.get(gt.cwe_id, [])
        result = _try_match(gt, candidates, used_aegis_ids, "keywords")
        if result:
            matched.append(result)
            used_gt_ids.add(gt.id)
            used_aegis_ids.add(result.aegis_vuln_id)

    # Pass 2: alt_keywords fallback for unmatched GT entries
    for gt in gt_entries:
        if gt.id in used_gt_ids:
            continue
        candidates = aegis_by_cwe.get(gt.cwe_id, [])
        result = _try_match(gt, candidates, used_aegis_ids, "alt_keywords")
        if result:
            matched.append(result)
            used_gt_ids.add(gt.id)
            used_aegis_ids.add(result.aegis_vuln_id)

    # Collect unmatched
    false_negatives = [gt for gt in gt_entries if gt.id not in used_gt_ids]
    false_positives = [
        {"id": v["id"], "cwe_id": v["cwe_id"], "title": v["title"]}
        for v in aegis_vulns
        if v["id"] not in used_aegis_ids
    ]

    return MatchResult(
        matched=matched,
        false_positives=false_positives,
        false_negatives=false_negatives,
    )
