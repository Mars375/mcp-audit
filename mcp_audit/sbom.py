"""
SBOM (Software Bill of Materials) export for MCP Audit.

Generates CycloneDX JSON and SPDX JSON formats from audit results,
using transitive dependency data collected by supply_chain.py.
"""

import json
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional


# ── Public API ─────────────────────────────────────────────────

def generate_sbom(
    audit_results: Dict[str, Any],
    fmt: str = "cyclonedx",
) -> str:
    """Generate an SBOM from audit results.

    Args:
        audit_results: Full audit result dict from MCPAudit.audit().
        fmt: "cyclonedx" or "spdx".

    Returns:
        JSON string of the SBOM document.
    """
    if fmt == "cyclonedx":
        doc = _generate_cyclonedx(audit_results)
    elif fmt == "spdx":
        doc = _generate_spdx(audit_results)
    else:
        raise ValueError(f"Unsupported SBOM format: {fmt!r}. Use 'cyclonedx' or 'spdx'.")
    return json.dumps(doc, indent=2)


# ── CycloneDX ──────────────────────────────────────────────────

def _generate_cyclonedx(audit_results: Dict[str, Any]) -> Dict[str, Any]:
    """Generate a CycloneDX JSON SBOM (v1.5 spec).

    Uses the transitive dependency data from supply_chain analysis
    to build a complete dependency tree.
    """
    now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    serial = f"urn:uuid:{uuid.uuid4()}"

    components: List[Dict[str, Any]] = []
    dependencies: List[Dict[str, Any]] = []

    for dep in audit_results.get("dependencies", []):
        comp = _cyclonedx_component(dep)
        components.append(comp)

        # Build dependency tree from transitive data
        dep_entry = _cyclonedx_dependency(dep)
        if dep_entry:
            dependencies.append(dep_entry)

    doc = {
        "$schema": "http://cyclonedx.org/schema/bom-1.5.schema.json",
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "serialNumber": serial,
        "version": 1,
        "metadata": {
            "timestamp": now,
            "tools": [
                {
                    "vendor": "mcp-audit",
                    "name": "mcp-audit",
                    "version": "0.1.0",
                }
            ],
            "component": {
                "type": "application",
                "name": "mcp-config",
                "bom-ref": "mcp-config",
            },
        },
        "components": components,
    }

    if dependencies:
        doc["dependencies"] = dependencies

    return doc


def _cyclonedx_component(dep: Dict[str, Any]) -> Dict[str, Any]:
    """Build a CycloneDX component entry from an audit dependency."""
    source = dep.get("source", "")
    name = dep["name"]
    bom_ref = _bom_ref(name, source)

    # Determine component type
    comp_type = "library"
    if dep.get("type") == "server":
        comp_type = "service"
    elif dep.get("type") == "tool":
        comp_type = "library"

    # Ecosystem / version
    ecosystem, version = _parse_ecosystem_version(dep)

    comp: Dict[str, Any] = {
        "type": comp_type,
        "name": name,
        "bom-ref": bom_ref,
    }

    if version:
        comp["version"] = version

    # PURL (Package URL)
    purl = _build_purl(name, ecosystem, version)
    if purl:
        comp["purl"] = purl

    # Vulnerabilities attached to this component
    vulns = dep.get("vulnerabilities", [])
    if vulns:
        comp["vulnerabilities"] = [_cyclonedx_vulnerability(v) for v in vulns]

    # External references
    ext_refs = []
    if source and source.startswith(("http://", "https://")):
        ext_refs.append({"type": "website", "url": source})
    if ext_refs:
        comp["externalReferences"] = ext_refs

    return comp


def _cyclonedx_vulnerability(vuln: Dict[str, Any]) -> Dict[str, Any]:
    """Build a CycloneDX vulnerability entry."""
    severity = vuln.get("severity", "unknown")
    sev_map = {
        "critical": "critical",
        "high": "high",
        "medium": "medium",
        "low": "low",
    }
    ratings = []
    if severity in sev_map:
        ratings.append({
            "source": {
                "name": "OSV",
                "url": vuln.get("url", "https://osv.dev"),
            },
            "severity": sev_map[severity],
        })

    entry: Dict[str, Any] = {
        "id": vuln.get("id", "unknown"),
    }
    if ratings:
        entry["ratings"] = ratings
    if vuln.get("description"):
        entry["description"] = vuln["description"]
    return entry


def _cyclonedx_dependency(dep: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """Build a CycloneDX dependency entry from transitive data."""
    transitive = dep.get("transitive")
    if not transitive:
        return None

    source = dep.get("source", "")
    name = dep["name"]
    bom_ref = _bom_ref(name, source)

    trans_deps = []
    for td in transitive.get("dependencies", []):
        td_ref = _bom_ref(td["name"], _ecosystem_prefix(td.get("ecosystem", "")))
        trans_deps.append(td_ref)

    entry: Dict[str, Any] = {
        "ref": bom_ref,
    }
    if trans_deps:
        entry["dependsOn"] = trans_deps
    return entry


# ── SPDX ────────────────────────────────────────────────────────

def _generate_spdx(audit_results: Dict[str, Any]) -> Dict[str, Any]:
    """Generate an SPDX JSON SBOM (v2.3 spec)."""
    now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    doc_namespace = f"https://mcp-audit.dev/sbom/{uuid.uuid4()}"

    packages: List[Dict[str, Any]] = []
    relationships: List[Dict[str, Any]] = []

    root_spdx_id = "SPDXRef-Document"

    for dep in audit_results.get("dependencies", []):
        pkg = _spdx_package(dep, doc_namespace)
        packages.append(pkg)

        # DESCRIBES relationship
        relationships.append({
            "spdxElementId": root_spdx_id,
            "relationshipType": "DESCRIBES",
            "relatedSpdxElement": pkg["SPDXID"],
        })

        # Transitive dependency relationships
        transitive = dep.get("transitive")
        if transitive:
            for td in transitive.get("dependencies", []):
                td_id = _spdx_id(td["name"], td.get("ecosystem", ""))
                relationships.append({
                    "spdxElementId": pkg["SPDXID"],
                    "relationshipType": "DEPENDS_ON",
                    "relatedSpdxElement": td_id,
                })

    doc = {
        "spdxVersion": "SPDX-2.3",
        "dataLicense": "CC0-1.0",
        "SPDXID": "SPDXRef-Document",
        "name": "mcp-audit-sbom",
        "documentNamespace": doc_namespace,
        "creationInfo": {
            "created": now,
            "creators": [
                "Tool: mcp-audit-0.1.0",
            ],
        },
        "packages": packages,
    }

    if relationships:
        doc["relationships"] = relationships

    return doc


def _spdx_package(dep: Dict[str, Any], namespace: str) -> Dict[str, Any]:
    """Build an SPDX package entry from an audit dependency."""
    source = dep.get("source", "")
    name = dep["name"]
    spdx_id = _spdx_id(name, _ecosystem_from_source(source))

    ecosystem, version = _parse_ecosystem_version(dep)

    pkg: Dict[str, Any] = {
        "SPDXID": spdx_id,
        "name": name,
        "downloadLocation": "NOASSERTION",
    }

    if version:
        pkg["versionInfo"] = version

    pkg["filesAnalyzed"] = False

    # External references
    ext_refs = []
    purl = _build_purl(name, ecosystem, version)
    if purl:
        ext_refs.append({
            "referenceCategory": "PACKAGE_MANAGER",
            "referenceType": "purl",
            "referenceLocator": purl,
        })
    if source and source.startswith(("http://", "https://")):
        ext_refs.append({
            "referenceCategory": "OTHER",
            "referenceType": "sourceUrl",
            "referenceLocator": source,
        })
    if ext_refs:
        pkg["externalReferences"] = ext_refs

    # Vulnerabilities as attribution texts
    vulns = dep.get("vulnerabilities", [])
    if vulns:
        vuln_ids = [v.get("id", "unknown") for v in vulns]
        pkg["attributionTexts"] = [f"Known vulnerabilities: {', '.join(vuln_ids)}"]

    return pkg


# ── Helpers ─────────────────────────────────────────────────────

def _bom_ref(name: str, source: str) -> str:
    """Generate a deterministic BOM reference."""
    safe_name = name.replace("/", "::").replace("@", "%40")
    return f"pkg:mcp-audit/{safe_name}"


def _spdx_id(name: str, ecosystem: str) -> str:
    """Generate a valid SPDX identifier."""
    safe = name.replace("-", "_").replace(".", "_").replace("/", "-").replace("@", "%40")
    prefix = ""
    if ecosystem == "npm":
        prefix = "npm-"
    elif ecosystem in ("PyPI", "pypi"):
        prefix = "pypi-"
    return f"SPDXRef-{prefix}{safe}"


def _parse_ecosystem_version(dep: Dict[str, Any]) -> tuple:
    """Extract ecosystem and version from dependency data."""
    source = dep.get("source", "")
    meta = dep.get("metadata", {})
    maint = dep.get("maintenance_status", {})

    ecosystem = _ecosystem_from_source(source)
    version = maint.get("latest_version") or meta.get("version")

    # Also check transitive data
    transitive = dep.get("transitive")
    if not ecosystem and transitive:
        ecosystem = transitive.get("ecosystem", "").lower()

    return ecosystem, version


def _ecosystem_from_source(source: str) -> str:
    """Determine ecosystem from source string."""
    if source.startswith("npm:") or ".npmjs.com" in source:
        return "npm"
    elif source.startswith("pypi:") or "pypi.org" in source:
        return "pypi"
    elif "github.com" in source:
        return "github"
    return ""


def _ecosystem_prefix(ecosystem: str) -> str:
    """Return prefix like 'npm:' or 'pypi:' from ecosystem name."""
    mapping = {"npm": "npm:", "PyPI": "pypi:", "pypi": "pypi:", "github": "github:"}
    return mapping.get(ecosystem, "")


def _build_purl(name: str, ecosystem: str, version: Optional[str]) -> Optional[str]:
    """Build a Package URL (purl) string."""
    if ecosystem == "npm":
        purl_name = name.replace("@", "%40")
        base = f"pkg:npm/{purl_name}"
    elif ecosystem in ("pypi", "PyPI"):
        base = f"pkg:pypi/{name}"
    else:
        return None

    if version:
        base += f"@{version}"
    return base
