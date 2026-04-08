"""
Tests for supply_chain module — transitive dependency analysis.
"""

import json
import os
import pytest
from unittest.mock import patch, MagicMock

from mcp_audit.supply_chain import (
    analyze_transitive_deps,
    compute_transitive_risk_score,
    _osv_query,
    _make_transitive_dep,
    _make_report,
    _get_npm_dep_names,
    _get_pypi_dep_names,
    _parse_osv_severity,
    _parse_npm_audit_output,
    _parse_pip_audit_output,
    _resolve_npm_deps_osv,
    _resolve_pypi_deps_osv,
    _build_report,
)


# ── Unit tests: risk score computation ──────────────────────────

class TestComputeTransitiveRiskScore:
    """Test the risk score formula independently."""

    def test_zero_deps_zero_risk(self):
        score = compute_transitive_risk_score(
            total_deps=0, max_depth=0,
            vulnerable_deps=0, critical_count=0, high_count=0,
        )
        assert score == 0

    def test_many_deps_adds_score(self):
        score = compute_transitive_risk_score(
            total_deps=200, max_depth=0,
            vulnerable_deps=0, critical_count=0, high_count=0,
        )
        assert score >= 25  # 200 > 100 → +25

    def test_depth_adds_score(self):
        score = compute_transitive_risk_score(
            total_deps=0, max_depth=8,
            vulnerable_deps=0, critical_count=0, high_count=0,
        )
        assert score >= 15  # depth > 6 → +15

    def test_vulnerable_deps_adds_score(self):
        score = compute_transitive_risk_score(
            total_deps=0, max_depth=0,
            vulnerable_deps=10, critical_count=0, high_count=0,
        )
        assert score >= 30  # > 5 vuln deps → +30

    def test_critical_severity_adds_score(self):
        score = compute_transitive_risk_score(
            total_deps=0, max_depth=0,
            vulnerable_deps=0, critical_count=2, high_count=0,
        )
        assert score >= 30  # 2 * 15 = 30

    def test_high_severity_adds_score(self):
        score = compute_transitive_risk_score(
            total_deps=0, max_depth=0,
            vulnerable_deps=0, critical_count=0, high_count=4,
        )
        assert score >= 30  # 4 * 8 = 32 → capped at 30

    def test_combined_capped_at_100(self):
        score = compute_transitive_risk_score(
            total_deps=500, max_depth=10,
            vulnerable_deps=20, critical_count=5, high_count=10,
        )
        assert score == 100

    def test_medium_deps(self):
        score = compute_transitive_risk_score(
            total_deps=35, max_depth=0,
            vulnerable_deps=0, critical_count=0, high_count=0,
        )
        assert score == 12  # 20 < 35 <= 50

    def test_small_deps(self):
        score = compute_transitive_risk_score(
            total_deps=10, max_depth=0,
            vulnerable_deps=0, critical_count=0, high_count=0,
        )
        assert score == 5  # 5 < 10 <= 20

    def test_medium_depth(self):
        score = compute_transitive_risk_score(
            total_deps=0, max_depth=5,
            vulnerable_deps=0, critical_count=0, high_count=0,
        )
        assert score == 10  # 4 < 5 <= 6

    def test_shallow_depth(self):
        score = compute_transitive_risk_score(
            total_deps=0, max_depth=3,
            vulnerable_deps=0, critical_count=0, high_count=0,
        )
        assert score == 5  # 2 < 3 <= 4

    def test_few_vulnerable_deps(self):
        score = compute_transitive_risk_score(
            total_deps=0, max_depth=0,
            vulnerable_deps=1, critical_count=0, high_count=0,
        )
        assert score == 10  # 0 < 1 <= 2

    def test_some_vulnerable_deps(self):
        score = compute_transitive_risk_score(
            total_deps=0, max_depth=0,
            vulnerable_deps=3, critical_count=0, high_count=0,
        )
        assert score == 20  # 2 < 3 <= 5


# ── Unit tests: helper functions ────────────────────────────────

class TestMakeTransitiveDep:
    def test_basic(self):
        dep = _make_transitive_dep("requests", "PyPI", 1)
        assert dep["name"] == "requests"
        assert dep["ecosystem"] == "PyPI"
        assert dep["depth"] == 1
        assert dep["vulnerable"] is False
        assert dep["vulnerabilities"] == []

    def test_vulnerable(self):
        dep = _make_transitive_dep("lodash", "npm", 2, vulnerable=True, vulnerabilities=[{"id": "CVE-1"}])
        assert dep["vulnerable"] is True
        assert len(dep["vulnerabilities"]) == 1


class TestMakeReport:
    def test_basic_report(self):
        report = _make_report(
            package_name="test-pkg", ecosystem="npm",
            total_deps=10, max_depth=3, vulnerable_deps=1,
            total_vulns=2, critical_count=0, high_count=1,
            dependencies=[], risk_score=15, tools_used=["registry+osv"],
        )
        assert report["package_name"] == "test-pkg"
        assert report["total_deps"] == 10
        assert report["risk_score"] == 15
        assert report["tools_used"] == ["registry+osv"]


class TestParseOsvSeverity:
    def test_critical(self):
        vuln = {"severity": [{"score": 9.5}]}
        assert _parse_osv_severity(vuln) == "critical"

    def test_high(self):
        vuln = {"severity": [{"score": 7.5}]}
        assert _parse_osv_severity(vuln) == "high"

    def test_medium(self):
        vuln = {"severity": [{"score": 5.0}]}
        assert _parse_osv_severity(vuln) == "medium"

    def test_low(self):
        vuln = {"severity": [{"score": 2.0}]}
        assert _parse_osv_severity(vuln) == "low"

    def test_cvss_string_high(self):
        vuln = {"severity": [{"score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}]}
        assert _parse_osv_severity(vuln) == "high"

    def test_cvss_string_medium(self):
        vuln = {"severity": [{"score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N"}]}
        # C:L → doesn't match C:H, defaults to medium
        assert _parse_osv_severity(vuln) == "medium"

    def test_no_severity(self):
        vuln = {"severity": []}
        assert _parse_osv_severity(vuln) == "low"


# ── Integration tests with mocked network ───────────────────────

class TestResolveNpmDepsOsv:
    """Test npm registry resolution with mocked HTTP."""

    @patch("mcp_audit.supply_chain.requests.get")
    @patch("mcp_audit.supply_chain.requests.post")
    def test_basic_resolution(self, mock_post, mock_get):
        # Mock npm registry response
        npm_response = MagicMock()
        npm_response.status_code = 200
        npm_response.json.return_value = {
            "dist-tags": {"latest": "1.0.0"},
            "versions": {
                "1.0.0": {
                    "dependencies": {"lodash": "^4.17.0", "axios": "^1.0.0"}
                }
            }
        }

        # Mock sub-dependencies (empty to stop recursion)
        sub_response = MagicMock()
        sub_response.status_code = 200
        sub_response.json.return_value = {
            "dist-tags": {"latest": "1.0.0"},
            "versions": {"1.0.0": {"dependencies": {}}}
        }

        mock_get.side_effect = [npm_response, sub_response, sub_response]

        # Mock OSV.dev (no vulns)
        osv_response = MagicMock()
        osv_response.status_code = 200
        osv_response.json.return_value = {"vulns": []}
        mock_post.return_value = osv_response

        deps, vulns = _resolve_npm_deps_osv("test-pkg", max_depth=2, verbose=False)
        assert len(deps) == 2
        assert deps[0]["name"] == "lodash"
        assert deps[1]["name"] == "axios"
        assert all(not d["vulnerable"] for d in deps)

    @patch("mcp_audit.supply_chain.requests.get")
    def test_registry_failure(self, mock_get):
        mock_get.return_value = MagicMock(status_code=404)
        deps, vulns = _resolve_npm_deps_osv("nonexistent-pkg", max_depth=2)
        assert deps == []
        assert vulns == []


class TestResolvePypiDepsOsv:
    """Test PyPI registry resolution with mocked HTTP."""

    @patch("mcp_audit.supply_chain.requests.get")
    @patch("mcp_audit.supply_chain.requests.post")
    def test_basic_resolution(self, mock_post, mock_get):
        pypi_response = MagicMock()
        pypi_response.status_code = 200
        pypi_response.json.return_value = {
            "info": {
                "requires_dist": ["requests>=2.0", "pydantic>=2.0"],
            }
        }

        sub_response = MagicMock()
        sub_response.status_code = 200
        sub_response.json.return_value = {
            "info": {"requires_dist": []}
        }

        mock_get.side_effect = [pypi_response, sub_response, sub_response]

        osv_response = MagicMock()
        osv_response.status_code = 200
        osv_response.json.return_value = {"vulns": []}
        mock_post.return_value = osv_response

        deps, vulns = _resolve_pypi_deps_osv("test-pkg", max_depth=2)
        assert len(deps) == 2
        assert deps[0]["name"] == "requests"
        assert deps[1]["name"] == "pydantic"

    @patch("mcp_audit.supply_chain.requests.get")
    def test_registry_failure(self, mock_get):
        mock_get.return_value = MagicMock(status_code=500)
        deps, vulns = _resolve_pypi_deps_osv("bad-pkg", max_depth=2)
        assert deps == []


class TestOsvQuery:
    @patch("mcp_audit.supply_chain.requests.post")
    def test_vulnerabilities_found(self, mock_post):
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "vulns": [
                {"id": "GHSA-1234", "summary": "Test vuln", "severity": [{"score": 8.0}]},
            ]
        }
        mock_post.return_value = mock_response

        vulns = _osv_query("lodash", "npm")
        assert len(vulns) == 1
        assert vulns[0]["id"] == "GHSA-1234"
        assert vulns[0]["severity"] == "high"

    @patch("mcp_audit.supply_chain.requests.post")
    def test_no_vulnerabilities(self, mock_post):
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {}
        mock_post.return_value = mock_response

        vulns = _osv_query("safe-pkg", "npm")
        assert vulns == []


# ── Top-level analyze_transitive_deps ───────────────────────────

class TestAnalyzeTransitiveDeps:
    def test_unknown_ecosystem_returns_none(self):
        result = analyze_transitive_deps("pkg", "unknown")
        assert result is None

    @patch("mcp_audit.supply_chain._analyze_npm")
    def test_npm_delegation(self, mock_npm):
        mock_npm.return_value = {"package_name": "pkg", "ecosystem": "npm"}
        result = analyze_transitive_deps("pkg", "npm")
        assert result is not None
        assert result["ecosystem"] == "npm"
        mock_npm.assert_called_once()

    @patch("mcp_audit.supply_chain._analyze_pypi")
    def test_pypi_delegation(self, mock_pypi):
        mock_pypi.return_value = {"package_name": "pkg", "ecosystem": "PyPI"}
        result = analyze_transitive_deps("pkg", "PyPI")
        assert result is not None
        assert result["ecosystem"] == "PyPI"
        mock_pypi.assert_called_once()


# ── CLI audit parsing ───────────────────────────────────────────

class TestParseNpmAuditOutput:
    def test_empty_audit(self):
        data = {"metadata": {}, "vulnerabilities": {}}
        result = _parse_npm_audit_output(data)
        assert result["deps"] == []
        assert result["vulns"] == []

    def test_with_vulnerabilities(self):
        data = {
            "metadata": {"dependencies": 5},
            "vulnerabilities": {
                "lodash": {
                    "severity": "high",
                    "via": [
                        {"source": "GHSA-1234", "title": "Prototype pollution", "name": "lodash", "url": "https://..."}
                    ]
                }
            }
        }
        result = _parse_npm_audit_output(data)
        assert len(result["vulns"]) == 1
        assert result["vulns"][0]["severity"] == "high"
        assert result["vulns"][0]["package"] == "lodash"
        assert len(result["deps"]) == 5


class TestParsePipAuditOutput:
    def test_empty_audit(self):
        data = {"dependencies": [], "vulnerabilities": []}
        result = _parse_pip_audit_output(data)
        assert result["deps"] == []
        assert result["vulns"] == []

    def test_with_vulnerabilities(self):
        data = {
            "dependencies": [{"name": "requests", "depth": 1}],
            "vulnerabilities": [
                {"id": "PYSEC-1234", "description": "SSL issue", "package_name": "requests", "aliases": ["CVE-2024-0001"]}
            ]
        }
        result = _parse_pip_audit_output(data)
        assert len(result["deps"]) == 1
        assert len(result["vulns"]) == 1
        assert result["vulns"][0]["id"] == "PYSEC-1234"
        assert result["vulns"][0]["severity"] == "medium"  # has aliases


# ── Build report tests ──────────────────────────────────────────

class TestBuildReport:
    def test_basic(self):
        deps = [
            _make_transitive_dep("dep1", "npm", 1, vulnerable=True, vulnerabilities=[{"severity": "critical"}]),
            _make_transitive_dep("dep2", "npm", 2),
        ]
        vulns = [{"severity": "critical", "id": "V1"}]
        report = _build_report("pkg", "npm", deps, vulns, ["registry+osv"])
        assert report["total_deps"] == 2
        assert report["vulnerable_deps"] == 1
        assert report["critical_count"] == 1
        assert report["risk_score"] > 0

    def test_empty_deps(self):
        report = _build_report("pkg", "npm", [], [], ["registry+osv"])
        assert report["total_deps"] == 0
        assert report["risk_score"] == 0


# ── Get dep names helpers ──────────────────────────────────────

class TestGetNpmDepNames:
    @patch("mcp_audit.supply_chain.requests.get")
    def test_success(self, mock_get):
        mock_get.return_value = MagicMock(
            status_code=200,
            json=MagicMock(return_value={
                "dist-tags": {"latest": "1.0.0"},
                "versions": {"1.0.0": {"dependencies": {"lodash": "^4.0.0"}}}
            })
        )
        names = _get_npm_dep_names("test-pkg")
        assert names == ["lodash"]

    @patch("mcp_audit.supply_chain.requests.get")
    def test_failure(self, mock_get):
        mock_get.return_value = MagicMock(status_code=500)
        names = _get_npm_dep_names("bad-pkg")
        assert names == []


class TestGetPypiDepNames:
    @patch("mcp_audit.supply_chain.requests.get")
    def test_success(self, mock_get):
        mock_get.return_value = MagicMock(
            status_code=200,
            json=MagicMock(return_value={
                "info": {"requires_dist": ["requests>=2.0", "pyyaml"]}
            })
        )
        names = _get_pypi_dep_names("test-pkg")
        assert "requests" in names
        assert "pyyaml" in names

    @patch("mcp_audit.supply_chain.requests.get")
    def test_no_requires_dist(self, mock_get):
        mock_get.return_value = MagicMock(
            status_code=200,
            json=MagicMock(return_value={"info": {}})
        )
        names = _get_pypi_dep_names("simple-pkg")
        assert names == []

    @patch("mcp_audit.supply_chain.requests.get")
    def test_extras_filtered(self, mock_get):
        """Deps with extras conditions should still extract base name."""
        mock_get.return_value = MagicMock(
            status_code=200,
            json=MagicMock(return_value={
                "info": {"requires_dist": ["requests>=2.0 ; extra == 'http'"]}
            })
        )
        names = _get_pypi_dep_names("test-pkg")
        assert names == ["requests"]
