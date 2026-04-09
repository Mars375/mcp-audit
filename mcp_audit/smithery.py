"""
Smithery registry client for mcp-audit.

Resolves MCP servers installed via Smithery (https://smithery.ai) and
enriches audit data with registry metadata: use count, verification
status, security scan, tools, and connections.
"""

import re
import os
from typing import Any, Dict, List, Optional
from urllib.parse import quote

import requests

from .cache import get_cache


SMITHERY_REGISTRY_URL = "https://registry.smithery.ai"
SMITHERY_API_URL = "https://api.smithery.ai"


def _headers() -> Dict[str, str]:
    """Build request headers, adding Bearer token if available."""
    h = {"Accept": "application/json"}
    key = os.environ.get("SMITHERY_API_KEY")
    if key:
        h["Authorization"] = f"Bearer {key}"
    return h


def is_smithery_source(source: Optional[str], metadata: Optional[Dict[str, Any]] = None) -> bool:
    """Detect whether a dependency originates from Smithery.

    Heuristics:
      - source starts with 'smithery:'
      - command/args contain '@smithery/cli'
      - metadata has explicit smithery markers
    """
    if not source and not metadata:
        return False

    if source:
        if source.startswith("smithery:"):
            return True

    if metadata:
        command = metadata.get("command", "")
        args = metadata.get("args", [])
        args_str = " ".join(str(a) for a in args) if isinstance(args, list) else str(args)

        # Smithery CLI invocation
        if "@smithery/cli" in command or "@smithery/cli" in args_str:
            return True

        # Smithery marker in metadata
        if metadata.get("_registry") == "smithery":
            return True

    return False


def extract_qualified_name(source: Optional[str], metadata: Optional[Dict[str, Any]] = None) -> Optional[str]:
    """Extract a Smithery qualified name (namespace/server) from source or metadata.

    Returns None if no valid qualified name can be extracted.
    """
    if not source and not metadata:
        return None

    # Explicit smithery: prefix
    if source and source.startswith("smithery:"):
        qname = source[len("smithery:"):]
        if "/" in qname:
            return qname.lstrip("@")

    # From metadata args — look for qualified name pattern
    if metadata:
        args = metadata.get("args", [])
        if isinstance(args, list):
            for arg in args:
                # Pattern: @namespace/server or namespace/server
                m = re.match(r"^@?([\w-]+/[\w-]+(?:@[\w.-]+)?)$", str(arg))
                if m:
                    return m.group(1).lstrip("@")

    # Source itself looks like a qualified name
    if source:
        m = re.match(r"^@?([\w-]+/[\w-]+)$", source)
        if m:
            return m.group(1)

    return None


def fetch_server_info(qualified_name: str, verbose: bool = False) -> Optional[Dict[str, Any]]:
    """Fetch server details from the Smithery registry.

    Uses the public registry endpoint first; falls back to authenticated
    API if SMITHERY_API_KEY is set.

    Returns normalized server info dict or None if not found.
    """
    if not qualified_name or "/" not in qualified_name:
        return None

    # Try public registry first
    try:
        encoded = quote(qualified_name, safe="")
        url = f"{SMITHERY_REGISTRY_URL}/servers/{encoded}"
        cache = get_cache()
        data = cache.cached_get(url, headers=_headers(), timeout=10)
        if data:
            return _normalize_server(data)
    except Exception as exc:
        if verbose:
            print(f"  ⚠️  Smithery registry lookup failed for {qualified_name}: {exc}")

    # Fallback to authenticated API
    if os.environ.get("SMITHERY_API_KEY"):
        try:
            url = f"{SMITHERY_API_URL}/servers/{quote(qualified_name, safe='')}"
            data = cache.cached_get(url, headers=_headers(), timeout=10)
            if data:
                return _normalize_server(data)
        except requests.RequestException:
            pass

    return None


def search_servers(query: str, page: int = 1, page_size: int = 10, verbose: bool = False) -> Dict[str, Any]:
    """Search the Smithery registry for servers matching a query.

    Returns dict with 'servers' list and 'pagination' info.
    """
    try:
        params = {"q": query, "page": page, "pageSize": page_size}
        url = f"{SMITHERY_REGISTRY_URL}/servers"
        cache = get_cache()
        data = cache.cached_get(url, headers=_headers(), params=params, timeout=15)
        if data:
            servers = [_normalize_summary(s) for s in data.get("servers", [])]
            return {
                "servers": servers,
                "pagination": data.get("pagination", {}),
            }
    except Exception as exc:
        if verbose:
            print(f"  ⚠️  Smithery search failed: {exc}")

    return {"servers": [], "pagination": {}}


def _normalize_server(raw: Dict[str, Any]) -> Dict[str, Any]:
    """Normalize a Smithery server detail response into a consistent format."""
    security = raw.get("security")
    connections = raw.get("connections", [])

    # Determine transport type from connections
    transport = "unknown"
    if connections:
        first = connections[0] if isinstance(connections, list) else connections
        transport = first.get("type", "unknown")

    return {
        "qualified_name": raw.get("qualifiedName", ""),
        "display_name": raw.get("displayName", ""),
        "description": raw.get("description", ""),
        "remote": raw.get("remote", False),
        "transport": transport,
        "security_scan_passed": security.get("scanPassed", False) if isinstance(security, dict) else None,
        "tools_count": len(raw.get("tools") or []),
        "resources_count": len(raw.get("resources") or []),
        "prompts_count": len(raw.get("prompts") or []),
        "connections": connections,
        "is_smithery": True,
    }


def _normalize_summary(raw: Dict[str, Any]) -> Dict[str, Any]:
    """Normalize a Smithery server summary from list/search results."""
    return {
        "qualified_name": raw.get("qualifiedName", ""),
        "display_name": raw.get("displayName", ""),
        "description": raw.get("description", ""),
        "use_count": raw.get("useCount", 0),
        "remote": raw.get("remote", False),
        "is_smithery": True,
    }


def compute_smithery_bonus(server_info: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    """Compute scoring bonuses from Smithery registry data.

    Returns a dict with individual bonus points that can be merged
    into the trust score computation.
    """
    if not server_info:
        return {
            "verified_bonus": 0,
            "security_scan_bonus": 0,
            "popularity_bonus": 0,
            "tooling_bonus": 0,
        }

    info = server_info
    bonuses = {
        "verified_bonus": 0,
        "security_scan_bonus": 0,
        "popularity_bonus": 0,
        "tooling_bonus": 0,
    }

    # Security scan passed → +5 (supply chain confidence)
    scan = info.get("security_scan_passed")
    if scan is True:
        bonuses["security_scan_bonus"] = 5

    # Popularity (tools_count as proxy for maturity)
    tools_count = info.get("tools_count", 0)
    if tools_count >= 10:
        bonuses["popularity_bonus"] = 3
    elif tools_count >= 3:
        bonuses["popularity_bonus"] = 1

    # Tooling completeness (has tools + resources)
    resources_count = info.get("resources_count", 0)
    if tools_count > 0 and resources_count > 0:
        bonuses["tooling_bonus"] = 2

    return bonuses
