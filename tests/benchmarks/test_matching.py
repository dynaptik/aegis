# tests/benchmarks/test_matching.py

from benchmarks.models import GroundTruthEntry
from benchmarks.matching import match_findings


def _gt(gt_id, cwe_id, title, severity="critical", keywords=None, alt_keywords=None):
    return GroundTruthEntry(
        id=gt_id, cwe_id=cwe_id, title=title, severity=severity,
        keywords=keywords or [], alt_keywords=alt_keywords or [],
    )


def _finding(vuln_id, cwe_id, title, severity="critical", verified=True, description=""):
    return {
        "id": vuln_id, "cwe_id": cwe_id, "title": title,
        "description": description, "severity": severity, "is_verified": verified,
    }


class TestKeywordMatching:

    def test_exact_cwe_and_keyword_match(self):
        gt = [_gt("GT-1", "CWE-89", "SQLi via id", keywords=["id", "parameter"])]
        findings = [_finding("V-1", "CWE-89", "SQL Injection via 'id' parameter")]
        result = match_findings(gt, findings)

        assert len(result.matched) == 1
        assert not result.false_negatives
        assert not result.false_positives

    def test_same_cwe_different_keywords_not_confused(self):
        gt = [
            _gt("GT-1", "CWE-89", "SQLi via id", keywords=["id", "parameter"]),
            _gt("GT-2", "CWE-89", "SQLi via password", keywords=["password"]),
        ]
        findings = [
            _finding("V-1", "CWE-89", "SQL Injection via 'id' parameter"),
            _finding("V-2", "CWE-89", "SQL Injection via 'password' in /login"),
        ]
        result = match_findings(gt, findings)

        assert len(result.matched) == 2
        # GT-1 matches V-1, GT-2 matches V-2
        matched_pairs = {(m.ground_truth_id, m.aegis_vuln_id) for m in result.matched}
        assert ("GT-1", "V-1") in matched_pairs
        assert ("GT-2", "V-2") in matched_pairs

    def test_three_same_cwe_distinguished_by_keywords(self):
        """Simulates the DSVW case: 3 distinct CWE-89 vulnerabilities."""
        gt = [
            _gt("GT-1", "CWE-89", "SQLi id", keywords=["id", "parameter"]),
            _gt("GT-2", "CWE-89", "SQLi comment", keywords=["comment"]),
            _gt("GT-3", "CWE-89", "SQLi password", keywords=["password"]),
        ]
        findings = [
            _finding("V-1", "CWE-89", "SQL Injection via 'id' parameter"),
            _finding("V-2", "CWE-89", "SQL Injection via 'comment' parameter (INSERT)"),
            _finding("V-3", "CWE-89", "SQL Injection via 'password' parameter in /login"),
        ]
        result = match_findings(gt, findings)

        assert len(result.matched) == 3
        assert not result.false_negatives
        assert not result.false_positives

    def test_alt_keywords_fallback(self):
        gt = [_gt("GT-1", "CWE-918", "SSRF", keywords=["ssrf"],
                   alt_keywords=["request", "forgery"])]
        findings = [_finding("V-1", "CWE-918", "Server-Side Request Forgery via path")]
        result = match_findings(gt, findings)

        assert len(result.matched) == 1
        assert result.matched[0].matched_via == "alt_keywords"

    def test_primary_keywords_preferred_over_alt(self):
        gt = [_gt("GT-1", "CWE-79", "XSS", keywords=["callback"],
                   alt_keywords=["xss"])]
        findings = [_finding("V-1", "CWE-79", "JSONP Callback Injection")]
        result = match_findings(gt, findings)

        assert len(result.matched) == 1
        assert result.matched[0].matched_via == "primary_keywords"

    def test_unmatched_gt_is_false_negative(self):
        gt = [_gt("GT-1", "CWE-89", "SQLi", keywords=["id"])]
        result = match_findings(gt, [])

        assert not result.matched
        assert len(result.false_negatives) == 1
        assert result.false_negatives[0].id == "GT-1"

    def test_unmatched_finding_is_false_positive(self):
        findings = [_finding("V-1", "CWE-999", "Something unexpected")]
        result = match_findings([], findings)

        assert not result.matched
        assert len(result.false_positives) == 1
        assert result.false_positives[0]["id"] == "V-1"

    def test_greedy_matching_one_gt_two_findings(self):
        """One GT entry, two AEGIS findings with same CWE — only one matches."""
        gt = [_gt("GT-1", "CWE-89", "SQLi via id", keywords=["id"])]
        findings = [
            _finding("V-1", "CWE-89", "SQL Injection via id param"),
            _finding("V-2", "CWE-89", "Another SQL Injection via id"),
        ]
        result = match_findings(gt, findings)

        assert len(result.matched) == 1
        assert len(result.false_positives) == 1

    def test_severity_correctness_tracked(self):
        gt = [_gt("GT-1", "CWE-79", "XSS", severity="high", keywords=["xss"])]
        findings = [_finding("V-1", "CWE-79", "Reflected XSS", severity="medium")]
        result = match_findings(gt, findings)

        assert result.matched[0].severity_correct is False

    def test_severity_correct_when_matching(self):
        gt = [_gt("GT-1", "CWE-79", "XSS", severity="high", keywords=["xss"])]
        findings = [_finding("V-1", "CWE-79", "Reflected XSS", severity="high")]
        result = match_findings(gt, findings)

        assert result.matched[0].severity_correct is True

    def test_verification_status_captured(self):
        gt = [_gt("GT-1", "CWE-89", "SQLi", keywords=["injection"])]
        findings = [_finding("V-1", "CWE-89", "SQL Injection", verified=False)]
        result = match_findings(gt, findings)

        assert result.matched[0].is_verified is False

    def test_keyword_search_includes_description(self):
        """Keywords should match against description, not just title."""
        gt = [_gt("GT-1", "CWE-918", "SSRF", keywords=["ssrf"])]
        findings = [_finding("V-1", "CWE-918", "Request Forgery via path",
                             description="This is an SSRF vulnerability")]
        result = match_findings(gt, findings)

        assert len(result.matched) == 1

    def test_case_insensitive_matching(self):
        gt = [_gt("GT-1", "CWE-89", "SQLi", keywords=["SQL", "Injection"])]
        findings = [_finding("V-1", "CWE-89", "sql injection via id")]
        result = match_findings(gt, findings)

        assert len(result.matched) == 1

    def test_different_cwe_never_matches(self):
        gt = [_gt("GT-1", "CWE-89", "SQLi", keywords=["injection"])]
        findings = [_finding("V-1", "CWE-79", "XSS Injection")]
        result = match_findings(gt, findings)

        assert not result.matched
        assert len(result.false_negatives) == 1
        assert len(result.false_positives) == 1

    def test_empty_inputs(self):
        result = match_findings([], [])

        assert not result.matched
        assert not result.false_negatives
        assert not result.false_positives
