"""
Tests for SBOM export (CycloneDX and SPDX).
"""

import json
import pytest
from mcp_audit.sbom import (
    generate_sbom,
    _generate_cyclonedx,
    _generate_spdx,
    _bom_ref,
    _spdx_id,
    _build_purl,
    _ecosystem_from_source,
    _parse_ecosystem_version,
    _cyclonedx_component,
    _cyclonedx_vulnerability,
    _spdx_package,
)


# ── Fixtures ────────────────────────────────────────────────────

def _sample_audit_results():
    """Minimal audit results for testing."""
    return {
        "summary": {
            "total_dependencies": 3,
            "servers": 2,
            "tools": 1,
            "vulnerabilities": 2,
        },
        "dependencies": [
            {
                "name": "filesystem",
                "type": "server",
                "source": "npm:@modelcontextprotocol/server-filesystem",
                "quality_score": 85,
                "vulnerabilities": [
                    {
                        "id": "GHSA-xxxx-xxxx-xxxx",
                        "severity": "high",
                        "description": "Test vulnerability",
                        "url": "https://osv.dev/vuln/GHSA-xxxx-xxxx-xxxx",
                    }
                ],
                "maintenance_status": {
                    "health": "good",
                    "latest_version": "1.2.0",
                },
                "metadata": {},
                "trust_score": {"score": 78, "grade": "C+"},
                "transitive": {
                    "package_name": "@modelcontextprotocol/server-filesystem",
                    "ecosystem": "npm",
                    "total_deps": 12,
                    "max_depth": 3,
                    "vulnerable_deps": 1,
                    "total_vulns": 2,
                    "critical_count": 0,
                    "high_count": 1,
                    "dependencies": [
                        {"name": "express", "ecosystem": "npm", "depth": 1, "vulnerable": False, "vulnerabilities": []},
                        {"name": "lodash", "ecosystem": "npm", "depth": 2, "vulnerable": True, "vulnerabilities": [{"id": "GHSA-yyyy", "severity": "high"}]},
                    ],
                    "risk_score": 25,
                    "tools_used": ["registry+osv"],
                },
            },
            {
                "name": "my-python-server",
                "type": "server",
                "source": "pypi:mcp-python-server",
                "quality_score": 90,
                "vulnerabilities": [],
                "maintenance_status": {
                    "health": "good",
                    "latest_version": "0.5.1",
                },
                "metadata": {},
                "trust_score": {"score": 92, "grade": "A"},
                "transitive": {
                    "package_name": "mcp-python-server",
                    "ecosystem": "PyPI",
                    "total_deps": 5,
                    "max_depth": 2,
                    "vulnerable_deps": 0,
                    "total_vulns": 0,
                    "critical_count": 0,
                    "high_count": 0,
                    "dependencies": [
                        {"name": "requests", "ecosystem": "PyPI", "depth": 1, "vulnerable": False, "vulnerabilities": []},
                    ],
                    "risk_score": 5,
                    "tools_used": ["registry+osv"],
                },
            },
            {
                "name": "github-tool",
                "type": "tool",
                "source": "https://github.com/example/tool",
                "quality_score": 75,
                "vulnerabilities": [],
                "maintenance_status": {"health": "warning"},
                "metadata": {},
                "trust_score": {"score": 65, "grade": "D+"},
            },
        ],
        "vulnerabilities": [],
        "quality_issues": [],
        "recommendations": [],
    }


# ── Test generate_sbom ──────────────────────────────────────────

class TestGenerateSBOM:
    def test_cyclonedx_format(self):
        results = _sample_audit_results()
        output = generate_sbom(results, fmt="cyclonedx")
        doc = json.loads(output)
        assert doc["bomFormat"] == "CycloneDX"
        assert doc["specVersion"] == "1.5"
        assert "components" in doc
        assert len(doc["components"]) == 3

    def test_spdx_format(self):
        results = _sample_audit_results()
        output = generate_sbom(results, fmt="spdx")
        doc = json.loads(output)
        assert doc["spdxVersion"] == "SPDX-2.3"
        assert "packages" in doc
        assert len(doc["packages"]) == 3

    def test_invalid_format_raises(self):
        results = _sample_audit_results()
        with pytest.raises(ValueError, match="Unsupported SBOM format"):
            generate_sbom(results, fmt="invalid")


# ── Test CycloneDX specifics ───────────────────────────────────

class TestCycloneDX:
    def test_metadata_structure(self):
        results = _sample_audit_results()
        doc = _generate_cyclonedx(results)
        assert "metadata" in doc
        assert doc["metadata"]["tools"][0]["name"] == "mcp-audit"
        assert doc["metadata"]["component"]["name"] == "mcp-config"

    def test_component_server_type(self):
        results = _sample_audit_results()
        doc = _generate_cyclonedx(results)
        fs_comp = doc["components"][0]
        assert fs_comp["type"] == "service"
        assert fs_comp["name"] == "filesystem"

    def test_component_tool_type(self):
        results = _sample_audit_results()
        doc = _generate_cyclonedx(results)
        gh_comp = doc["components"][2]
        assert gh_comp["type"] == "library"
        assert gh_comp["name"] == "github-tool"

    def test_purl_npm(self):
        results = _sample_audit_results()
        doc = _generate_cyclonedx(results)
        fs_comp = doc["components"][0]
        assert "purl" in fs_comp
        assert fs_comp["purl"].startswith("pkg:npm/")

    def test_purl_pypi(self):
        results = _sample_audit_results()
        doc = _generate_cyclonedx(results)
        py_comp = doc["components"][1]
        assert "purl" in py_comp
        assert py_comp["purl"].startswith("pkg:pypi/")

    def test_version_included(self):
        results = _sample_audit_results()
        doc = _generate_cyclonedx(results)
        fs_comp = doc["components"][0]
        assert fs_comp["version"] == "1.2.0"

    def test_vulnerabilities_attached(self):
        results = _sample_audit_results()
        doc = _generate_cyclonedx(results)
        fs_comp = doc["components"][0]
        assert "vulnerabilities" in fs_comp
        assert len(fs_comp["vulnerabilities"]) == 1
        assert fs_comp["vulnerabilities"][0]["id"] == "GHSA-xxxx-xxxx-xxxx"

    def test_no_vulnerabilities_when_clean(self):
        results = _sample_audit_results()
        doc = _generate_cyclonedx(results)
        py_comp = doc["components"][1]
        assert "vulnerabilities" not in py_comp

    def test_dependencies_from_transitive(self):
        results = _sample_audit_results()
        doc = _generate_cyclonedx(results)
        assert "dependencies" in doc
        # First dep has transitive data
        deps = doc["dependencies"]
        assert len(deps) == 2  # Only 2 deps have transitive data
        assert "dependsOn" in deps[0]
        assert len(deps[0]["dependsOn"]) == 2  # express + lodash

    def test_serial_number_format(self):
        results = _sample_audit_results()
        doc = _generate_cyclonedx(results)
        assert doc["serialNumber"].startswith("urn:uuid:")

    def test_empty_results(self):
        doc = _generate_cyclonedx({"dependencies": [], "summary": {}})
        assert doc["components"] == []
        assert "dependencies" not in doc


# ── Test SPDX specifics ────────────────────────────────────────

class TestSPDX:
    def test_document_structure(self):
        results = _sample_audit_results()
        doc = _generate_spdx(results)
        assert doc["SPDXID"] == "SPDXRef-Document"
        assert doc["dataLicense"] == "CC0-1.0"
        assert "creationInfo" in doc
        assert "creators" in doc["creationInfo"]

    def test_package_structure(self):
        results = _sample_audit_results()
        doc = _generate_spdx(results)
        pkg = doc["packages"][0]
        assert "SPDXID" in pkg
        assert pkg["name"] == "filesystem"
        assert pkg["downloadLocation"] == "NOASSERTION"
        assert pkg["filesAnalyzed"] is False

    def test_version_info(self):
        results = _sample_audit_results()
        doc = _generate_spdx(results)
        pkg = doc["packages"][0]
        assert pkg["versionInfo"] == "1.2.0"

    def test_external_references_purl(self):
        results = _sample_audit_results()
        doc = _generate_spdx(results)
        pkg = doc["packages"][0]
        assert "externalReferences" in pkg
        purl_ref = [r for r in pkg["externalReferences"] if r["referenceType"] == "purl"]
        assert len(purl_ref) == 1

    def test_vulnerability_attribution(self):
        results = _sample_audit_results()
        doc = _generate_spdx(results)
        pkg = doc["packages"][0]
        assert "attributionTexts" in pkg
        assert "GHSA-xxxx-xxxx-xxxx" in pkg["attributionTexts"][0]

    def test_relationships_describes(self):
        results = _sample_audit_results()
        doc = _generate_spdx(results)
        rels = doc["relationships"]
        describes = [r for r in rels if r["relationshipType"] == "DESCRIBES"]
        assert len(describes) == 3

    def test_relationships_depends_on(self):
        results = _sample_audit_results()
        doc = _generate_spdx(results)
        rels = doc["relationships"]
        depends = [r for r in rels if r["relationshipType"] == "DEPENDS_ON"]
        assert len(depends) == 3  # 2 from npm server + 1 from PyPI server

    def test_empty_results(self):
        doc = _generate_spdx({"dependencies": [], "summary": {}})
        assert doc["packages"] == []


# ── Test helpers ────────────────────────────────────────────────

class TestHelpers:
    def test_bom_ref_basic(self):
        assert _bom_ref("express", "npm:express") == "pkg:mcp-audit/express"

    def test_bom_ref_scoped(self):
        ref = _bom_ref("@scope/pkg", "npm:@scope/pkg")
        assert "%40scope" in ref

    def test_spdx_id_basic(self):
        sid = _spdx_id("requests", "PyPI")
        assert sid == "SPDXRef-pypi-requests"

    def test_spdx_id_npm(self):
        sid = _spdx_id("express", "npm")
        assert sid == "SPDXRef-npm-express"

    def test_spdx_id_no_ecosystem(self):
        sid = _spdx_id("my-server", "")
        assert sid == "SPDXRef-my_server"

    def test_build_purl_npm(self):
        assert _build_purl("express", "npm", "4.18.0") == "pkg:npm/express@4.18.0"

    def test_build_purl_npm_scoped(self):
        purl = _build_purl("@scope/pkg", "npm", "1.0.0")
        assert purl == "pkg:npm/%40scope/pkg@1.0.0"

    def test_build_purl_pypi(self):
        assert _build_purl("requests", "pypi", "2.31.0") == "pkg:pypi/requests@2.31.0"

    def test_build_purl_no_version(self):
        assert _build_purl("express", "npm", None) == "pkg:npm/express"

    def test_build_purl_unknown_ecosystem(self):
        assert _build_purl("something", "unknown", "1.0") is None

    def test_ecosystem_from_source_npm(self):
        assert _ecosystem_from_source("npm:express") == "npm"

    def test_ecosystem_from_source_pypi(self):
        assert _ecosystem_from_source("pypi:requests") == "pypi"

    def test_ecosystem_from_source_github(self):
        assert _ecosystem_from_source("https://github.com/org/repo") == "github"

    def test_ecosystem_from_source_empty(self):
        assert _ecosystem_from_source("") == ""

    def test_parse_ecosystem_version_npm(self):
        dep = {
            "source": "npm:express",
            "maintenance_status": {"latest_version": "4.18.0"},
            "metadata": {},
        }
        eco, ver = _parse_ecosystem_version(dep)
        assert eco == "npm"
        assert ver == "4.18.0"

    def test_parse_ecosystem_version_from_transitive(self):
        dep = {
            "source": "",
            "maintenance_status": {},
            "metadata": {},
            "transitive": {"ecosystem": "PyPI"},
        }
        eco, ver = _parse_ecosystem_version(dep)
        assert eco == "pypi"


# ── Test CycloneDX vulnerability ────────────────────────────────

class TestCycloneDXVulnerability:
    def test_high_severity(self):
        vuln = _cyclonedx_vulnerability({
            "id": "CVE-2024-0001",
            "severity": "high",
            "description": "Test vuln",
            "url": "https://osv.dev/vuln/CVE-2024-0001",
        })
        assert vuln["id"] == "CVE-2024-0001"
        assert vuln["ratings"][0]["severity"] == "high"
        assert vuln["description"] == "Test vuln"

    def test_critical_severity(self):
        vuln = _cyclonedx_vulnerability({"id": "CVE-2024-0002", "severity": "critical"})
        assert vuln["ratings"][0]["severity"] == "critical"

    def test_unknown_severity_no_ratings(self):
        vuln = _cyclonedx_vulnerability({"id": "CVE-2024-0003", "severity": "unknown"})
        assert "ratings" not in vuln


# ── Test integration with CLI ──────────────────────────────────

class TestSBOMIntegration:
    def test_cyclonedx_output_valid_json(self):
        """Verify the full pipeline produces valid JSON."""
        results = _sample_audit_results()
        output = generate_sbom(results, fmt="cyclonedx")
        doc = json.loads(output)
        # Re-serialize to verify no encoding issues
        assert json.dumps(doc)

    def test_spdx_output_valid_json(self):
        results = _sample_audit_results()
        output = generate_sbom(results, fmt="spdx")
        doc = json.loads(output)
        assert json.dumps(doc)

    def test_sbom_with_no_transitive_data(self):
        """Dependencies without transitive data should still appear as components."""
        results = {
            "dependencies": [
                {
                    "name": "simple-server",
                    "type": "server",
                    "source": "",
                    "quality_score": 80,
                    "vulnerabilities": [],
                    "maintenance_status": {},
                    "metadata": {},
                }
            ],
            "summary": {},
        }
        cd = _generate_cyclonedx(results)
        assert len(cd["components"]) == 1
        assert "dependencies" not in cd  # No transitive data

        sp = _generate_spdx(results)
        assert len(sp["packages"]) == 1
        # DESCRIBES relationship but no DEPENDS_ON
        depends_on = [r for r in sp["relationships"] if r["relationshipType"] == "DEPENDS_ON"]
        assert len(depends_on) == 0
