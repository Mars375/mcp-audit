"""
Transitive dependency analysis for MCP servers.

Resolves the full dependency tree for npm and PyPI packages, checks each
sub-dependency against OSV.dev for known vulnerabilities, and computes a
transitive risk score that feeds into the supply-chain pillar.
"""

import json
import os
import shutil
import subprocess
import tempfile
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import quote

import requests


# ── Data classes (plain dicts for simplicity) ──────────────────

def _make_transitive_dep(
    name: str,
    ecosystem: str,
    depth: int,
    vulnerable: bool = False,
    vulnerabilities: Optional[List[Dict[str, Any]]] = None,
) -> Dict[str, Any]:
    return {
        "name": name,
        "ecosystem": ecosystem,
        "depth": depth,
        "vulnerable": vulnerable,
        "vulnerabilities": vulnerabilities or [],
    }


def _make_report(
    package_name: str,
    ecosystem: str,
    total_deps: int,
    max_depth: int,
    vulnerable_deps: int,
    total_vulns: int,
    critical_count: int,
    high_count: int,
    dependencies: List[Dict[str, Any]],
    risk_score: int,
    tools_used: List[str],
) -> Dict[str, Any]:
    return {
        "package_name": package_name,
        "ecosystem": ecosystem,
        "total_deps": total_deps,
        "max_depth": max_depth,
        "vulnerable_deps": vulnerable_deps,
        "total_vulns": total_vulns,
        "critical_count": critical_count,
        "high_count": high_count,
        "dependencies": dependencies,
        "risk_score": risk_score,
        "tools_used": tools_used,
    }


# ── Public API ─────────────────────────────────────────────────

def analyze_transitive_deps(
    package_name: str,
    ecosystem: str,  # "npm" or "PyPI"
    *,
    max_depth: int = 3,
    verbose: bool = False,
) -> Optional[Dict[str, Any]]:
    """Analyse transitive dependencies and return a risk report.

    Strategy:
      1. Try CLI tools (npm audit / pip-audit) if available.
      2. Fall back to registry API resolution + OSV.dev queries.

    Args:
        package_name: The direct package name (no prefix).
        ecosystem: "npm" or "PyPI".
        max_depth: Maximum dependency tree depth to resolve.
        verbose: Print progress.

    Returns:
        A report dict, or None if resolution fails entirely.
    """
    if ecosystem == "npm":
        return _analyze_npm(package_name, max_depth=max_depth, verbose=verbose)
    elif ecosystem == "PyPI":
        return _analyze_pypi(package_name, max_depth=max_depth, verbose=verbose)
    return None


# ── npm ─────────────────────────────────────────────────────────

def _analyze_npm(
    package_name: str,
    *,
    max_depth: int = 3,
    verbose: bool = False,
) -> Optional[Dict[str, Any]]:
    tools_used: List[str] = []

    # Strategy 1: npm audit (if npm available)
    npm_result = _npm_audit_cli(package_name, verbose=verbose)
    if npm_result is not None:
        tools_used.append("npm-audit")
        deps = npm_result["deps"]
        vulns = npm_result["vulns"]
    else:
        # Strategy 2: registry resolution + OSV.dev
        if verbose:
            print(f"  📦 npm audit unavailable, using registry + OSV.dev for {package_name}")
        deps, vulns = _resolve_npm_deps_osv(package_name, max_depth=max_depth, verbose=verbose)
        tools_used.append("registry+osv")

    return _build_report(package_name, "npm", deps, vulns, tools_used)


def _npm_audit_cli(
    package_name: str,
    *,
    verbose: bool = False,
) -> Optional[Dict[str, Any]]:
    """Run npm audit in a temp project. Returns {deps, vulns} or None."""
    npm_path = shutil.which("npm")
    if not npm_path:
        return None

    with tempfile.TemporaryDirectory(prefix="mcp-audit-npm-") as tmpdir:
        pkg_json = {
            "name": "mcp-audit-check",
            "version": "0.0.0",
            "dependencies": {package_name: "*"},
        }
        pkg_path = os.path.join(tmpdir, "package.json")
        with open(pkg_path, "w") as f:
            json.dump(pkg_json, f)

        try:
            subprocess.run(
                [npm_path, "install", "--no-optional", "--no-fund", "--quiet"],
                cwd=tmpdir, capture_output=True, timeout=120,
            )
        except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
            return None

        try:
            result = subprocess.run(
                [npm_path, "audit", "--json"],
                cwd=tmpdir, capture_output=True, timeout=60, text=True,
            )
        except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
            return None

        try:
            audit_data = json.loads(result.stdout)
        except (json.JSONDecodeError, ValueError):
            return None

        return _parse_npm_audit_output(audit_data, verbose=verbose)


def _parse_npm_audit_output(
    audit_data: Dict[str, Any],
    *,
    verbose: bool = False,
) -> Dict[str, Any]:
    """Parse npm audit --json output into deps + vulns."""
    deps: List[Dict[str, Any]] = []
    vulns: List[Dict[str, Any]] = []

    metadata = audit_data.get("metadata", {})
    total_deps = metadata.get("dependencies", 0) + metadata.get("devDependencies", 0)

    vulnerabilities = audit_data.get("vulnerabilities", {})
    for _vuln_name, vuln_info in vulnerabilities.items():
        severity = vuln_info.get("severity", "low")
        via = vuln_info.get("via", [])
        if isinstance(via, list):
            for v in via:
                if isinstance(v, dict):
                    vulns.append({
                        "id": v.get("source", vuln_info.get("name", "unknown")),
                        "severity": severity,
                        "description": v.get("title", ""),
                        "package": v.get("name", _vuln_name),
                        "url": v.get("url", ""),
                    })

    # Build simple dep list
    for i in range(min(total_deps, 500)):
        deps.append(_make_transitive_dep(
            name=f"dep-{i}",
            ecosystem="npm",
            depth=1,
        ))

    return {"deps": deps, "vulns": vulns}


def _resolve_npm_deps_osv(
    package_name: str,
    *,
    max_depth: int = 3,
    verbose: bool = False,
) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
    """Resolve npm deps via registry + OSV.dev queries."""
    deps: List[Dict[str, Any]] = []
    vulns: List[Dict[str, Any]] = []

    encoded = quote(package_name, safe="")
    try:
        resp = requests.get(f"https://registry.npmjs.org/{encoded}", timeout=15)
        if resp.status_code != 200:
            return deps, vulns
        data = resp.json()
    except Exception:
        return deps, vulns

    latest = data.get("dist-tags", {}).get("latest")
    if not latest:
        return deps, vulns

    version_data = data.get("versions", {}).get(latest, {})
    direct_deps = list(version_data.get("dependencies", {}).keys())

    # BFS
    visited = set()
    queue = [(name, 1) for name in direct_deps]
    while queue:
        dep_name, depth = queue.pop(0)
        if dep_name in visited or depth > max_depth:
            continue
        visited.add(dep_name)

        dep_vulns = _osv_query(dep_name, "npm", verbose=verbose)
        is_vuln = len(dep_vulns) > 0
        deps.append(_make_transitive_dep(
            name=dep_name,
            ecosystem="npm",
            depth=depth,
            vulnerable=is_vuln,
            vulnerabilities=dep_vulns,
        ))
        vulns.extend(dep_vulns)

        if depth < max_depth and len(visited) < 100:
            sub_deps = _get_npm_dep_names(dep_name, verbose=verbose)
            for sd in sub_deps[:20]:
                if sd not in visited:
                    queue.append((sd, depth + 1))

    return deps, vulns


def _get_npm_dep_names(package_name: str, *, verbose: bool = False) -> List[str]:
    """Get direct dependency names for an npm package."""
    encoded = quote(package_name, safe="")
    try:
        resp = requests.get(f"https://registry.npmjs.org/{encoded}", timeout=10)
        if resp.status_code != 200:
            return []
        data = resp.json()
        latest = data.get("dist-tags", {}).get("latest")
        if not latest:
            return []
        version_data = data.get("versions", {}).get(latest, {})
        return list(version_data.get("dependencies", {}).keys())
    except Exception:
        return []


# ── PyPI ────────────────────────────────────────────────────────

def _analyze_pypi(
    package_name: str,
    *,
    max_depth: int = 3,
    verbose: bool = False,
) -> Optional[Dict[str, Any]]:
    tools_used: List[str] = []

    # Strategy 1: pip-audit (if available)
    pip_result = _pip_audit_cli(package_name, verbose=verbose)
    if pip_result is not None:
        tools_used.append("pip-audit")
        deps = pip_result["deps"]
        vulns = pip_result["vulns"]
    else:
        if verbose:
            print(f"  📦 pip-audit unavailable, using PyPI registry + OSV.dev for {package_name}")
        deps, vulns = _resolve_pypi_deps_osv(package_name, max_depth=max_depth, verbose=verbose)
        tools_used.append("registry+osv")

    return _build_report(package_name, "PyPI", deps, vulns, tools_used)


def _pip_audit_cli(
    package_name: str,
    *,
    verbose: bool = False,
) -> Optional[Dict[str, Any]]:
    """Run pip-audit for a single package. Returns {deps, vulns} or None."""
    pip_audit_path = shutil.which("pip-audit")
    if not pip_audit_path:
        return None

    with tempfile.TemporaryDirectory(prefix="mcp-audit-pip-") as tmpdir:
        req_path = os.path.join(tmpdir, "requirements.txt")
        with open(req_path, "w") as f:
            f.write(f"{package_name}\n")

        try:
            result = subprocess.run(
                [pip_audit_path, "-r", req_path, "--format", "json"],
                cwd=tmpdir, capture_output=True, timeout=120, text=True,
            )
        except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
            return None

        try:
            audit_data = json.loads(result.stdout)
        except (json.JSONDecodeError, ValueError):
            return None

        return _parse_pip_audit_output(audit_data)


def _parse_pip_audit_output(audit_data: Dict[str, Any]) -> Dict[str, Any]:
    """Parse pip-audit JSON output."""
    deps: List[Dict[str, Any]] = []
    vulns: List[Dict[str, Any]] = []

    for dep_info in audit_data.get("dependencies", []):
        name = dep_info.get("name", "unknown")
        deps.append(_make_transitive_dep(
            name=name,
            ecosystem="PyPI",
            depth=dep_info.get("depth", 1),
        ))

    for vuln_info in audit_data.get("vulnerabilities", []):
        vulns.append({
            "id": vuln_info.get("id", "unknown"),
            "severity": _estimate_pip_audit_severity(vuln_info),
            "description": vuln_info.get("description", ""),
            "package": vuln_info.get("package_name", "unknown"),
            "url": f"https://osv.dev/vuln/{vuln_info.get('id', '')}",
        })

    return {"deps": deps, "vulns": vulns}


def _estimate_pip_audit_severity(vuln_info: Dict[str, Any]) -> str:
    """Estimate severity from pip-audit vulnerability data."""
    if vuln_info.get("aliases"):
        return "medium"
    return "low"


def _resolve_pypi_deps_osv(
    package_name: str,
    *,
    max_depth: int = 3,
    verbose: bool = False,
) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
    """Resolve PyPI deps via registry + OSV.dev queries."""
    deps: List[Dict[str, Any]] = []
    vulns: List[Dict[str, Any]] = []

    try:
        resp = requests.get(f"https://pypi.org/pypi/{package_name}/json", timeout=15)
        if resp.status_code != 200:
            return deps, vulns
        data = resp.json()
    except Exception:
        return deps, vulns

    info = data.get("info", {})
    requires_dist = info.get("requires_dist") or []

    direct_deps = []
    for req in requires_dist:
        base = (
            req.split(";")[0]
            .split(">=")[0]
            .split("<=")[0]
            .split("==")[0]
            .split("!")[0]
            .split("~=")[0]
            .strip()
        )
        if base and base[0].isalpha():
            direct_deps.append(base)

    # BFS
    visited = set()
    queue = [(name, 1) for name in direct_deps]
    while queue:
        dep_name, depth = queue.pop(0)
        if dep_name.lower() in visited or depth > max_depth:
            continue
        visited.add(dep_name.lower())

        dep_vulns = _osv_query(dep_name, "PyPI", verbose=verbose)
        is_vuln = len(dep_vulns) > 0
        deps.append(_make_transitive_dep(
            name=dep_name,
            ecosystem="PyPI",
            depth=depth,
            vulnerable=is_vuln,
            vulnerabilities=dep_vulns,
        ))
        vulns.extend(dep_vulns)

        if depth < max_depth and len(visited) < 100:
            sub_deps = _get_pypi_dep_names(dep_name, verbose=verbose)
            for sd in sub_deps[:20]:
                if sd.lower() not in visited:
                    queue.append((sd, depth + 1))

    return deps, vulns


def _get_pypi_dep_names(package_name: str, *, verbose: bool = False) -> List[str]:
    """Get direct dependency names for a PyPI package."""
    try:
        resp = requests.get(f"https://pypi.org/pypi/{package_name}/json", timeout=10)
        if resp.status_code != 200:
            return []
        data = resp.json()
        requires_dist = data.get("info", {}).get("requires_dist") or []
        result = []
        for req in requires_dist:
            base = (
                req.split(";")[0]
                .split(">=")[0]
                .split("<=")[0]
                .split("==")[0]
                .split("!")[0]
                .split("~=")[0]
                .strip()
            )
            if base and base[0].isalpha():
                result.append(base)
        return result
    except Exception:
        return []


# ── OSV.dev shared ──────────────────────────────────────────────

def _osv_query(
    package_name: str,
    ecosystem: str,
    *,
    verbose: bool = False,
) -> List[Dict[str, Any]]:
    """Query OSV.dev for known vulnerabilities in a package."""
    vulns: List[Dict[str, Any]] = []
    try:
        payload = {
            "package": {
                "name": package_name,
                "ecosystem": ecosystem,
            }
        }
        resp = requests.post("https://api.osv.dev/v1/query", json=payload, timeout=10)
        if resp.status_code != 200:
            return vulns
        data = resp.json()
        for v in data.get("vulns", []):
            severity = _parse_osv_severity(v)
            vulns.append({
                "id": v.get("id", "unknown"),
                "severity": severity,
                "description": v.get("summary", ""),
                "url": f"https://osv.dev/vuln/{v.get('id', '')}",
            })
    except Exception as e:
        if verbose:
            print(f"  ⚠️  OSV query failed for {package_name}: {e}")
    return vulns


def _parse_osv_severity(vuln: Dict[str, Any]) -> str:
    """Parse severity from OSV.dev vulnerability entry."""
    for sev in vuln.get("severity", []):
        score = sev.get("score")
        if isinstance(score, (int, float)):
            if score >= 9.0:
                return "critical"
            elif score >= 7.0:
                return "high"
            elif score >= 4.0:
                return "medium"
            else:
                return "low"
        if isinstance(score, str) and "CVSS" in score:
            if "C:H" in score and ("I:H" in score or "A:H" in score):
                return "high"
            if "C:H" in score:
                return "high"
            return "medium"
    return "low"


# ── Report building ─────────────────────────────────────────────

def _build_report(
    package_name: str,
    ecosystem: str,
    deps: List[Dict[str, Any]],
    vulns: List[Dict[str, Any]],
    tools_used: List[str],
) -> Dict[str, Any]:
    """Build the final transitive risk report."""
    total_deps = len(deps)
    max_depth = max((d["depth"] for d in deps), default=0)
    vulnerable_deps = sum(1 for d in deps if d["vulnerable"])
    total_vulns = len(vulns)
    critical_count = sum(1 for v in vulns if v.get("severity") == "critical")
    high_count = sum(1 for v in vulns if v.get("severity") == "high")

    risk_score = compute_transitive_risk_score(
        total_deps=total_deps,
        max_depth=max_depth,
        vulnerable_deps=vulnerable_deps,
        critical_count=critical_count,
        high_count=high_count,
    )

    return _make_report(
        package_name=package_name,
        ecosystem=ecosystem,
        total_deps=total_deps,
        max_depth=max_depth,
        vulnerable_deps=vulnerable_deps,
        total_vulns=total_vulns,
        critical_count=critical_count,
        high_count=high_count,
        dependencies=deps,
        risk_score=risk_score,
        tools_used=tools_used,
    )


def compute_transitive_risk_score(
    *,
    total_deps: int,
    max_depth: int,
    vulnerable_deps: int,
    critical_count: int,
    high_count: int,
) -> int:
    """Compute a transitive risk score 0-100 (0=safe, 100=max risk).

    This is a PENALTY score — higher means more risk.
    It will be inverted when applying to the supply-chain pillar.
    """
    score = 0

    # Number of transitive deps (0-25)
    if total_deps > 100:
        score += 25
    elif total_deps > 50:
        score += 18
    elif total_deps > 20:
        score += 12
    elif total_deps > 5:
        score += 5

    # Depth of dependency tree (0-15)
    if max_depth > 6:
        score += 15
    elif max_depth > 4:
        score += 10
    elif max_depth > 2:
        score += 5

    # Vulnerable deps (0-30)
    if vulnerable_deps > 5:
        score += 30
    elif vulnerable_deps > 2:
        score += 20
    elif vulnerable_deps > 0:
        score += 10

    # Critical/high severity (0-30)
    score += min(30, critical_count * 15 + high_count * 8)

    return min(100, score)
