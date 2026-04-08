"""
Trust score computation for MCP dependencies.

Composite score /100 based on four pillars:
  - Quality    (0-25): config completeness, source clarity
  - Security   (0-25): vulnerability count & severity
  - Maintenance(0-25): freshness, commit frequency, health
  - Supply chain (0-25): stars, forks, known publisher, release cadence, transitive risk
"""

from typing import Dict, Any, List, Optional, Tuple
from datetime import datetime, timezone


SEVERITY_WEIGHTS = {
    "critical": 20,
    "high": 12,
    "medium": 6,
    "low": 2,
}


def compute_trust_score(dep_result: Dict[str, Any]) -> Dict[str, Any]:
    """Compute a composite trust score 0-100 for a dependency.

    Args:
        dep_result: A dependency result dict from MCPAudit (must contain
            quality_score, vulnerabilities, maintenance_status, metadata).
            May also contain "transitive" with a "risk_score" key (0-100).

    Returns:
        Dict with keys: score, quality, security, maintenance, supply_chain,
        transitive_risk_penalty, transitive_risk_score, grade, color.
    """
    quality = _quality_pillar(dep_result)
    security = _security_pillar(dep_result)
    maintenance = _maintenance_pillar(dep_result)
    supply_chain, transitive_penalty = _supply_chain_pillar(dep_result)

    total = quality + security + maintenance + supply_chain
    total = max(0, min(100, total))

    if total >= 80:
        grade, color = "A", "green"
    elif total >= 60:
        grade, color = "B", "yellow"
    elif total >= 40:
        grade, color = "C", "red"
    else:
        grade, color = "D", "bold red"

    result = {
        "score": total,
        "quality": quality,
        "security": security,
        "maintenance": maintenance,
        "supply_chain": supply_chain,
        "grade": grade,
        "color": color,
    }

    # Expose transitive risk penalty detail when present
    if transitive_penalty > 0:
        result["transitive_risk_penalty"] = transitive_penalty
        result["transitive_risk_score"] = dep_result.get("transitive", {}).get("risk_score", 0)

    return result


# ── Pillar helpers ──────────────────────────────────────────────

def _quality_pillar(dep: Dict[str, Any]) -> int:
    """Quality pillar (0-25). Derived from existing quality_score (0-100)."""
    qs = dep.get("quality_score", 0)
    # Scale 0-100 → 0-25
    return int(qs * 25 / 100)


def _security_pillar(dep: Dict[str, Any]) -> int:
    """Security pillar (0-25). Penalised per vulnerability by severity."""
    vulns: List[Dict[str, Any]] = dep.get("vulnerabilities", [])
    penalty = 0
    for v in vulns:
        severity = v.get("severity", "low")
        penalty += SEVERITY_WEIGHTS.get(severity, 2)
    return max(0, 25 - penalty)


def _maintenance_pillar(dep: Dict[str, Any]) -> int:
    """Maintenance pillar (0-25). Based on health, commit frequency, freshness."""
    ms: Dict[str, Any] = dep.get("maintenance_status", {})
    score = 0

    # Health (0-10)
    health = ms.get("health", "unknown")
    health_points = {"good": 10, "warning": 5, "archived": 0, "disabled": 0, "unknown": 3}
    score += health_points.get(health, 3)

    # Commit frequency (0-8)
    freq = ms.get("commit_frequency", "unknown")
    freq_points = {"high": 8, "medium": 5, "low": 2, "unknown": 3}
    score += freq_points.get(freq, 3)

    # Freshness — last_update within 6 months → 7, within 1 year → 4, else 0
    last = ms.get("last_update", "unknown")
    freshness = _freshness_points(last)
    score += freshness

    return min(25, score)


def _supply_chain_pillar(dep: Dict[str, Any]) -> Tuple[int, int]:
    """Supply-chain pillar (0-25). Stars, forks, release cadence, known source,
    transitive risk penalty.

    Returns:
        Tuple of (score: int, transitive_penalty: int).
    """
    ms: Dict[str, Any] = dep.get("maintenance_status", {})
    meta: Dict[str, Any] = dep.get("metadata", {})
    score = 0
    transitive_penalty = 0

    # Stars (0-8)
    stars = ms.get("stars", 0)
    if stars >= 1000:
        score += 8
    elif stars >= 100:
        score += 6
    elif stars >= 10:
        score += 3

    # Forks (0-5)
    forks = ms.get("forks", 0)
    if forks >= 100:
        score += 5
    elif forks >= 10:
        score += 3
    elif forks >= 1:
        score += 1

    # Has a release (0-7)
    last_release = ms.get("last_release")
    if last_release and last_release not in ("unknown", None):
        score += 5
        # Bonus freshness
        score += _freshness_points(last_release, max_points=2)

    # Source is specified (0-5)
    source = dep.get("source")
    if source:
        source_str = str(source)
        if "github.com" in source_str:
            score += 5
        elif source_str.startswith("npm:"):
            score += 4
        elif source_str.startswith("pypi:"):
            score += 4
        elif source_str.startswith(("http://", "https://")):
            score += 3
    else:
        score += 0

    # Transitive risk penalty (P7)
    # risk_score is 0-100 penalty from supply_chain.py (higher = more risky)
    transitive = dep.get("transitive", {})
    risk_score = transitive.get("risk_score", 0) if transitive else 0
    if risk_score > 75:
        transitive_penalty = 20
    elif risk_score > 50:
        transitive_penalty = 10

    return max(0, min(25, score - transitive_penalty)), transitive_penalty


def _freshness_points(date_str: str, max_points: int = 7) -> int:
    """Assign points based on how recent a date string is."""
    if not date_str or date_str == "unknown":
        return 0
    try:
        dt = datetime.fromisoformat(str(date_str).replace("Z", "+00:00"))
        now = datetime.now(timezone.utc)
        days = (now - dt).days
        if days <= 180:
            return max_points
        elif days <= 365:
            return max_points * 4 // 7
        else:
            return 0
    except Exception:
        return 0
