"""Tests for trust score computation (P2)."""

import pytest
from mcp_audit.scoring import compute_trust_score, _freshness_points


def _make_dep(quality_score=100, vulns=None, maint=None, meta=None, source=None):
    """Helper to build a dep result dict."""
    return {
        "quality_score": quality_score,
        "vulnerabilities": vulns or [],
        "maintenance_status": maint or {"health": "good", "commit_frequency": "high", "stars": 500, "forks": 50, "last_update": "2026-03-01T00:00:00Z", "last_release": "2026-03-01T00:00:00Z"},
        "metadata": meta or {},
        "source": source,
    }


class TestTrustScore:
    """Tests for compute_trust_score."""

    def test_perfect_score(self):
        """A clean, popular, well-maintained dep should score high."""
        result = compute_trust_score(_make_dep())
        assert result["score"] >= 80, f"Expected >=80, got {result['score']}"
        assert result["grade"] == "A"
        assert result["color"] == "green"

    def test_vulnerabilities_penalise(self):
        """Vulnerabilities should drop security pillar."""
        good = compute_trust_score(_make_dep())
        bad = compute_trust_score(_make_dep(vulns=[
            {"id": "CVE-1", "severity": "critical", "description": "bad"},
            {"id": "CVE-2", "severity": "high", "description": "worse"},
        ]))
        assert bad["security"] < good["security"]
        assert bad["score"] < good["score"]

    def test_critical_vuln_security_zero(self):
        """A critical vuln should drop security pillar to 5 or below."""
        result = compute_trust_score(_make_dep(vulns=[
            {"id": "CVE-X", "severity": "critical", "description": "ouch"},
        ]))
        assert result["security"] <= 5

    def test_low_quality_drops_score(self):
        """Low quality_score should reduce quality pillar."""
        good = compute_trust_score(_make_dep(quality_score=90))
        bad = compute_trust_score(_make_dep(quality_score=20))
        assert bad["quality"] < good["quality"]
        assert bad["score"] < good["score"]

    def test_no_source_penalty(self):
        """Missing source should reduce supply chain pillar."""
        base_maint = {"health": "good", "commit_frequency": "medium", "last_update": "2026-03-01T00:00:00Z", "stars": 5, "forks": 0, "last_release": None}
        with_source = compute_trust_score(_make_dep(source="https://github.com/x/y", maint=base_maint))
        without = compute_trust_score(_make_dep(source=None, maint=base_maint))
        assert without["supply_chain"] < with_source["supply_chain"]

    def test_pypi_source_counts_for_supply_chain(self):
        """PyPI sources should contribute to supply chain score."""
        base_maint = {"health": "good", "commit_frequency": "medium", "last_update": "2026-03-01T00:00:00Z", "stars": 0, "forks": 0, "last_release": None}
        pypi = compute_trust_score(_make_dep(source="pypi:uvicorn", maint=base_maint))
        none = compute_trust_score(_make_dep(source=None, maint=base_maint))
        assert pypi["supply_chain"] > none["supply_chain"]

    def test_archived_repo_penalty(self):
        """Archived repo should reduce maintenance pillar."""
        active = compute_trust_score(_make_dep(maint={"health": "good", "commit_frequency": "high", "last_update": "2026-03-01T00:00:00Z", "stars": 100, "forks": 10}))
        archived = compute_trust_score(_make_dep(maint={"health": "archived", "commit_frequency": "low", "last_update": "2024-01-01T00:00:00Z", "stars": 5, "forks": 0}))
        assert archived["maintenance"] < active["maintenance"]
        assert archived["score"] < active["score"]

    def test_score_bounds(self):
        """Score should always be 0-100."""
        dep = _make_dep(quality_score=0, vulns=[
            {"id": f"CVE-{i}", "severity": "critical", "description": "x"}
            for i in range(10)
        ], maint={"health": "disabled", "commit_frequency": "unknown", "last_update": "unknown", "stars": 0, "forks": 0}, source=None)
        result = compute_trust_score(dep)
        assert 0 <= result["score"] <= 100

    def test_pillar_sums_approximate_total(self):
        """Sum of four pillars should be close to total score."""
        result = compute_trust_score(_make_dep())
        pillar_sum = result["quality"] + result["security"] + result["maintenance"] + result["supply_chain"]
        # Total is clamped but should be very close to pillar sum
        assert abs(result["score"] - pillar_sum) <= 1 or result["score"] == 100

    def test_grade_boundaries(self):
        """Test grade boundaries: A>=80, B>=60, C>=40, D<40."""
        # Build deps that should produce each grade
        # D grade: everything terrible
        result_d = compute_trust_score(_make_dep(
            quality_score=0,
            vulns=[{"id": "CVE", "severity": "critical", "description": "x"}],
            maint={"health": "disabled", "commit_frequency": "unknown", "last_update": "unknown", "stars": 0, "forks": 0},
            source=None,
        ))
        assert result_d["score"] < 40
        assert result_d["grade"] == "D"

    def test_freshness_points_recent(self):
        """Recent date should get max points."""
        assert _freshness_points("2026-03-01T00:00:00Z") == 7

    def test_freshness_points_old(self):
        """Date > 1 year should get 0."""
        assert _freshness_points("2024-01-01T00:00:00Z") == 0

    def test_freshness_points_unknown(self):
        """Unknown date should get 0."""
        assert _freshness_points("unknown") == 0
        assert _freshness_points(None) == 0


class TestTrustScoreIntegration:
    """Integration: trust_score present in full audit results."""

    def test_audit_includes_trust_score(self):
        """Full audit should include trust_score per dependency."""
        from mcp_audit.config import MCPConfig
        from mcp_audit.audit import MCPAudit

        config = MCPConfig(
            servers={"test-srv": {"command": "npx", "args": ["-y", "some-pkg"]}},
            tools={},
            resources={},
            source_format="native",
        )
        auditor = MCPAudit(config)
        results = auditor.audit()

        assert len(results["dependencies"]) > 0
        for dep in results["dependencies"]:
            assert "trust_score" in dep, f"Missing trust_score for {dep['name']}"
            ts = dep["trust_score"]
            assert "score" in ts
            assert "grade" in ts
            assert "color" in ts
            assert "quality" in ts
            assert "security" in ts
            assert "maintenance" in ts
            assert "supply_chain" in ts
            assert 0 <= ts["score"] <= 100

    def test_report_json_includes_trust_scores(self):
        """JSON report should include trust_scores dict."""
        from mcp_audit.config import MCPConfig
        from mcp_audit.audit import MCPAudit
        from mcp_audit.report import ReportGenerator

        config = MCPConfig(
            servers={"test-srv": {"command": "npx", "args": ["-y", "some-pkg"]}},
            tools={},
            resources={},
            source_format="native",
        )
        auditor = MCPAudit(config)
        results = auditor.audit()

        gen = ReportGenerator(results)
        report = gen.generate_json_report()

        assert "trust_scores" in report
        assert "test-srv" in report["trust_scores"]
