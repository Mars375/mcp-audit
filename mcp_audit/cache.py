"""
Intelligent response cache for mcp-audit network requests.

Caches GET/POST responses from npm registry, PyPI, OSV.dev, GitHub API,
and Smithery registry in a local JSON file with configurable TTL.

Default TTL: 24 hours. Cache location: ~/.cache/mcp-audit/cache.json
"""

import hashlib
import json
import os
import time
from pathlib import Path
from typing import Any, Dict, Optional, Tuple


# ── Constants ──────────────────────────────────────────────────

DEFAULT_TTL = 86400  # 24 hours in seconds
DEFAULT_CACHE_DIR = os.path.expanduser("~/.cache/mcp-audit")
DEFAULT_CACHE_FILE = "cache.json"


# ── Public API ─────────────────────────────────────────────────

class ResponseCache:
    """File-backed response cache with TTL expiry.

    Usage::

        cache = ResponseCache()          # enabled by default
        cache = ResponseCache(enabled=False)  # --no-cache

        data = cache.get_or_fetch(
            key="npm:express",
            fetch_fn=lambda: requests.get(url).json(),
        )
    """

    def __init__(
        self,
        enabled: bool = True,
        ttl: int = DEFAULT_TTL,
        cache_dir: Optional[str] = None,
        verbose: bool = False,
    ):
        self.enabled = enabled
        self.ttl = ttl
        self.cache_dir = cache_dir or DEFAULT_CACHE_DIR
        self.cache_path = os.path.join(self.cache_dir, DEFAULT_CACHE_FILE)
        self.verbose = verbose
        self._data: Optional[Dict[str, Any]] = None
        self._hits = 0
        self._misses = 0

    # ── Core API ───────────────────────────────────────────────

    def get_or_fetch(
        self,
        key: str,
        fetch_fn,
    ) -> Any:
        """Return cached value if fresh, otherwise call fetch_fn and store.

        Args:
            key: Cache key (URL, or composite key like "osv:npm:express").
            fetch_fn: Callable that returns the value to cache.

        Returns:
            The cached or freshly fetched value.
        """
        if not self.enabled:
            self._misses += 1
            return fetch_fn()

        store = self._load()

        entry = store.get(key)
        if entry is not None and not self._is_expired(entry):
            self._hits += 1
            if self.verbose:
                print(f"  💾 Cache HIT: {key[:60]}")
            return entry["value"]

        # Cache miss or expired — fetch
        self._misses += 1
        value = fetch_fn()
        store[key] = {"ts": time.time(), "value": value}
        self._save(store)

        if self.verbose:
            print(f"  🌐 Cache MISS: {key[:60]}")

        return value

    def get(self, key: str) -> Optional[Any]:
        """Return cached value if fresh, None otherwise."""
        if not self.enabled:
            return None

        store = self._load()
        entry = store.get(key)
        if entry is not None and not self._is_expired(entry):
            self._hits += 1
            return entry["value"]
        return None

    def put(self, key: str, value: Any) -> None:
        """Store a value in the cache."""
        if not self.enabled:
            return

        store = self._load()
        store[key] = {"ts": time.time(), "value": value}
        self._save(store)

    def invalidate(self, key: str) -> None:
        """Remove a specific key from the cache."""
        if not self.enabled:
            return

        store = self._load()
        store.pop(key, None)
        self._save(store)

    def clear(self) -> None:
        """Clear the entire cache."""
        self._data = {}
        if os.path.exists(self.cache_path):
            os.remove(self.cache_path)
        self._hits = 0
        self._misses = 0

    def stats(self) -> Dict[str, Any]:
        """Return cache hit/miss statistics."""
        total = self._hits + self._misses
        return {
            "hits": self._hits,
            "misses": self._misses,
            "total": total,
            "hit_rate": self._hits / total if total > 0 else 0.0,
            "enabled": self.enabled,
            "ttl": self.ttl,
        }

    def cleanup(self) -> int:
        """Remove expired entries. Returns number of entries removed."""
        if not self.enabled:
            return 0

        store = self._load()
        before = len(store)
        expired_keys = [
            k for k, v in store.items()
            if self._is_expired(v)
        ]
        for k in expired_keys:
            del store[k]

        if expired_keys:
            self._save(store)

        removed = before - len(store)
        if removed and self.verbose:
            print(f"  🧹 Cache cleanup: removed {removed} expired entries")
        return removed

    # ── Key helpers ────────────────────────────────────────────

    @staticmethod
    def make_key(method: str, url: str, body: Optional[Any] = None) -> str:
        """Build a deterministic cache key from request params.

        Args:
            method: HTTP method (GET, POST).
            url: Request URL.
            body: Optional request body (for POST).

        Returns:
            A string key like "GET:https://registry.npmjs.org/express"
            or "POST:https://api.osv.dev/v1/query:<sha256>"
        """
        key = f"{method.upper()}:{url}"
        if body is not None:
            body_str = json.dumps(body, sort_keys=True, separators=(",", ":"))
            body_hash = hashlib.sha256(body_str.encode()).hexdigest()[:16]
            key += f":{body_hash}"
        return key

    # ── Private ────────────────────────────────────────────────

    def _is_expired(self, entry: Dict[str, Any]) -> bool:
        """Check if a cache entry has expired."""
        ts = entry.get("ts", 0)
        return (time.time() - ts) > self.ttl

    def _load(self) -> Dict[str, Any]:
        """Load cache from disk."""
        if self._data is not None:
            return self._data

        if not os.path.exists(self.cache_path):
            self._data = {}
            return self._data

        try:
            with open(self.cache_path, "r") as f:
                self._data = json.load(f)
        except (json.JSONDecodeError, OSError):
            self._data = {}

        return self._data

    def _save(self, data: Dict[str, Any]) -> None:
        """Persist cache to disk."""
        os.makedirs(self.cache_dir, exist_ok=True)
        try:
            with open(self.cache_path, "w") as f:
                json.dump(data, f, separators=(",", ":"))
        except OSError:
            pass  # Non-critical: cache is optional

    # ── Integration helpers ────────────────────────────────────

    def cached_get(self, url: str, **kwargs) -> Optional[Dict[str, Any]]:
        """Cached GET request returning parsed JSON or None.

        Uses requests.get internally. Returns the .json() result.
        """
        import requests as _requests

        key = self.make_key("GET", url)

        def _fetch():
            try:
                resp = _requests.get(url, **kwargs)
                if resp.status_code == 200:
                    return resp.json()
            except Exception:
                pass
            return None

        return self.get_or_fetch(key, _fetch)

    def cached_post(self, url: str, json_body: Any, **kwargs) -> Optional[Dict[str, Any]]:
        """Cached POST request returning parsed JSON or None.

        Uses requests.post internally. Returns the .json() result.
        """
        import requests as _requests

        key = self.make_key("POST", url, json_body)

        def _fetch():
            try:
                resp = _requests.post(url, json=json_body, **kwargs)
                if resp.status_code == 200:
                    return resp.json()
            except Exception:
                pass
            return None

        return self.get_or_fetch(key, _fetch)


# ── Module-level singleton ────────────────────────────────────

_global_cache: Optional[ResponseCache] = None


def get_cache() -> ResponseCache:
    """Get the global cache instance."""
    global _global_cache
    if _global_cache is None:
        _global_cache = ResponseCache()
    return _global_cache


def init_cache(
    enabled: bool = True,
    ttl: int = DEFAULT_TTL,
    verbose: bool = False,
) -> ResponseCache:
    """Initialize the global cache singleton."""
    global _global_cache
    _global_cache = ResponseCache(enabled=enabled, ttl=ttl, verbose=verbose)
    return _global_cache
