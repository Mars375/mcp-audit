"""Tests for P7 — transitive risk score integration into trust score composite."""

import pytest
from mcp_audit.scoring import compute_trust_score, _supply_chain_pillar


def _make_dep(
    quality_score=100,
    vulns=None,
    maint=None,
    meta=None,
    source=None,
    transitive=None,
):
    """Helper to build a dep result dict."""
    return {
        "quality_score": quality_score,
        "vulnerabilities": vulns or [],
        "maintenance_status": maint or {
            "health": "good",
            "commit_frequency": "high",
            "stars": 500,
            "forks": 50,
            "last_update": "2026-03-01T00:00:00Z",
            "last_release": "2026-03-01T00:00:00Z",
        },
        "metadata": meta or {},
        "source": source,
        "transitive": transitive,
    }


def _make_transitive(risk_score=0):
    """Helper to build a transitive report with a given risk_score."""
    return {
        "package_name": "test-pkg",
        "ecosystem": "npm",
        "total_deps": 10,
        "max_depth": 2,
        "vulnerable_deps": 0,
        "total_vulns": 0,
        "critical_count": 0,
        "high_count": 0,
        "dependencies": [],
        "risk_score": risk_score,
        "tools_used": ["registry+osv"],
    }


class TestSupplyChainPillarTransitive:
    """Test that _supply_chain_pillar returns correct transitive penalties."""

    def test_no_transitive_no_penalty(self):
        """Without transitive data, no penalty should be applied."""
        dep = _make_dep(source="npm:express")
        score, penalty = _supply_chain_pillar(dep)
        assert penalty == 0
        assert score > 0

    def test_transitive_none_no_penalty(self):
        """With transitive=None, no penalty should be applied."""
        dep = _make_dep(source="npm:express", transitive=None)
        score, penalty = _supply_chain_pillar(dep)
        assert penalty == 0

    def test_low_risk_no_penalty(self):
        """risk_score ≤ 50 should not trigger a penalty."""
        dep = _make_dep(
            source="npm:express",
            transitive=_make_transitive(risk_score=50),
        )
        score, penalty = _supply_chain_pillar(dep)
        assert penalty == 0

    def test_medium_risk_penalty_10(self):
        """50 < risk_score ≤ 75 should apply -10 penalty."""
        dep = _make_dep(
            source="npm:express",
            transitive=_make_transitive(risk_score=60),
        )
        score, penalty = _supply_chain_pillar(dep)
        assert penalty == 10

    def test_high_risk_penalty_20(self):
        """risk_score > 75 should apply -20 penalty."""
        dep = _make_dep(
            source="npm:express",
            transitive=_make_transitive(risk_score=90),
        )
        score, penalty = _supply_chain_pillar(dep)
        assert penalty == 20

    def test_just_above_50_penalty_10(self):
        """risk_score = 51 should trigger -10 penalty."""
        dep = _make_dep(
            source="npm:express",
            transitive=_make_transitive(risk_score=51),
        )
        score, penalty = _supply_chain_pillar(dep)
        assert penalty == 10

    def test_just_above_75_penalty_20(self):
        """risk_score = 76 should trigger -20 penalty."""
        dep = _make_dep(
            source="npm:express",
            transitive=_make_transitive(risk_score=76),
        )
        score, penalty = _supply_chain_pillar(dep)
        assert penalty == 20

    def test_score_floor_zero(self):
        """Supply chain pillar score should not go below 0."""
        # No source, no stars, high transitive risk → should floor at 0
        dep = _make_dep(
            source=None,
            maint={"health": "unknown", "commit_frequency": "unknown", "last_update": "unknown", "stars": 0, "forks": 0, "last_release": None},
            transitive=_make_transitive(risk_score=95),
        )
        score, penalty = _supply_chain_pillar(dep)
        assert score >= 0
        assert penalty == 20


class TestTrustScoreTransitiveIntegration:
    """Test compute_trust_score with transitive risk data."""

    def test_trust_score_without_transitive(self):
        """Score should work as before without transitive data."""
        dep = _make_dep()
        result = compute_trust_score(dep)
        assert "score" in result
        assert "transitive_risk_penalty" not in result
        assert "transitive_risk_score" not in result

    def test_trust_score_with_low_transitive(self):
        """Low transitive risk should not change score vs no transitive."""
        dep_base = _make_dep()
        dep_trans = _make_dep(transitive=_make_transitive(risk_score=25))

        result_base = compute_trust_score(dep_base)
        result_trans = compute_trust_score(dep_trans)

        # Same supply_chain pillar score
        assert result_trans["supply_chain"] == result_base["supply_chain"]
        assert result_trans["score"] == result_base["score"]

    def test_trust_score_drops_with_medium_transitive(self):
        """Medium transitive risk should reduce total score."""
        dep_base = _make_dep()
        dep_trans = _make_dep(transitive=_make_transitive(risk_score=60))

        result_base = compute_trust_score(dep_base)
        result_trans = compute_trust_score(dep_trans)

        assert result_trans["supply_chain"] < result_base["supply_chain"]
        assert result_trans["score"] < result_base["score"]
        assert result_trans.get("transitive_risk_penalty") == 10
        assert result_trans.get("transitive_risk_score") == 60

    def test_trust_score_drops_with_high_transitive(self):
        """High transitive risk should reduce total score even more."""
        dep_base = _make_dep()
        dep_trans = _make_dep(transitive=_make_transitive(risk_score=90))

        result_base = compute_trust_score(dep_base)
        result_trans = compute_trust_score(dep_trans)

        assert result_trans["supply_chain"] < result_base["supply_chain"]
        assert result_trans["score"] < result_base["score"]
        assert result_trans.get("transitive_risk_penalty") == 20
        assert result_trans.get("transitive_risk_score") == 90

    def test_transitive_exposed_in_output(self):
        """When penalty is applied, transitive_risk_penalty and risk_score should be in output."""
        dep = _make_dep(transitive=_make_transitive(risk_score=65))
        result = compute_trust_score(dep)
        assert "transitive_risk_penalty" in result
        assert "transitive_risk_score" in result
        assert result["transitive_risk_penalty"] == 10
        assert result["transitive_risk_score"] == 65

    def test_transitive_not_exposed_when_no_penalty(self):
        """When no penalty, transitive keys should not be in output."""
        dep = _make_dep(transitive=_make_transitive(risk_score=30))
        result = compute_trust_score(dep)
        assert "transitive_risk_penalty" not in result
        assert "transitive_risk_score" not in result

    def test_grade_can_drop_from_transitive(self):
        """High transitive risk can cause a grade drop."""
        # Build a dep that would be grade B without transitive but drops to C with it
        dep_moderate = _make_dep(
            quality_score=70,
            maint={"health": "good", "commit_frequency": "medium", "last_update": "2026-03-01T00:00:00Z", "stars": 50, "forks": 5, "last_release": "2026-03-01T00:00:00Z"},
            source="npm:some-pkg",
        )
        result_no_trans = compute_trust_score(dep_moderate)

        dep_with_trans = _make_dep(
            quality_score=70,
            maint={"health": "good", "commit_frequency": "medium", "last_update": "2026-03-01T00:00:00Z", "stars": 50, "forks": 5, "last_release": "2026-03-01T00:00:00Z"},
            source="npm:some-pkg",
            transitive=_make_transitive(risk_score=80),
        )
        result_with_trans = compute_trust_score(dep_with_trans)

        assert result_with_trans["score"] < result_no_trans["score"]
        # Grade should drop or stay same (never go up)
        assert result_with_trans["grade"] >= result_no_trans["grade"]  # D > C > B > A alphabetically

    def test_empty_transitive_no_penalty(self):
        """Empty transitive dict should not trigger penalty."""
        dep = _make_dep(source="npm:express", transitive={})
        score, penalty = _supply_chain_pillar(dep)
        assert penalty == 0
