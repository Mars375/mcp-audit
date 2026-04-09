"""
Tests for the intelligent response cache (P9).

Covers: creation, get/put, TTL expiry, key generation, cleanup,
file persistence, get_or_fetch, cached_get/cached_post, stats,
module-level singleton, --no-cache integration.
"""

import json
import os
import time
import tempfile
import unittest
from unittest.mock import patch, MagicMock

from mcp_audit.cache import (
    ResponseCache,
    DEFAULT_TTL,
    DEFAULT_CACHE_FILE,
    get_cache,
    init_cache,
    _global_cache,
)


class TestResponseCacheCore(unittest.TestCase):
    """Core cache operations: get, put, get_or_fetch."""

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.cache = ResponseCache(cache_dir=self.tmpdir, ttl=60, verbose=False)

    def tearDown(self):
        self.cache.clear()

    def test_put_and_get(self):
        self.cache.put("key1", {"data": "value1"})
        result = self.cache.get("key1")
        self.assertEqual(result, {"data": "value1"})

    def test_get_miss_returns_none(self):
        result = self.cache.get("nonexistent")
        self.assertIsNone(result)

    def test_get_or_fetch_caches_result(self):
        call_count = 0

        def fetch():
            nonlocal call_count
            call_count += 1
            return {"fetched": True}

        # First call — should fetch
        result1 = self.cache.get_or_fetch("key1", fetch)
        self.assertEqual(result1, {"fetched": True})
        self.assertEqual(call_count, 1)

        # Second call — should hit cache
        result2 = self.cache.get_or_fetch("key1", fetch)
        self.assertEqual(result2, {"fetched": True})
        self.assertEqual(call_count, 1)  # Not incremented

    def test_get_or_fetch_different_keys(self):
        self.cache.get_or_fetch("key1", lambda: "val1")
        self.cache.get_or_fetch("key2", lambda: "val2")
        self.assertEqual(self.cache.get("key1"), "val1")
        self.assertEqual(self.cache.get("key2"), "val2")

    def test_overwrite_existing_key(self):
        self.cache.put("key1", "old")
        self.cache.put("key1", "new")
        self.assertEqual(self.cache.get("key1"), "new")

    def test_invalidate_key(self):
        self.cache.put("key1", "value1")
        self.cache.invalidate("key1")
        self.assertIsNone(self.cache.get("key1"))

    def test_invalidate_nonexistent_key_no_error(self):
        self.cache.invalidate("nonexistent")  # Should not raise

    def test_clear_removes_all_entries(self):
        self.cache.put("a", 1)
        self.cache.put("b", 2)
        self.cache.clear()
        self.assertIsNone(self.cache.get("a"))
        self.assertIsNone(self.cache.get("b"))

    def test_get_or_fetch_with_none_result(self):
        """Cache should store None as a valid value (e.g., API returned nothing)."""
        call_count = 0

        def fetch():
            nonlocal call_count
            call_count += 1
            return None

        result1 = self.cache.get_or_fetch("key1", fetch)
        self.assertIsNone(result1)
        # None is a valid cache miss — function called again
        result2 = self.cache.get_or_fetch("key1", fetch)
        self.assertIsNone(result2)
        # None entries should still be re-fetched (they indicate failure)


class TestResponseCacheTTL(unittest.TestCase):
    """TTL expiry behavior."""

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()

    def tearDown(self):
        cache = ResponseCache(cache_dir=self.tmpdir)
        cache.clear()

    def test_fresh_entry_not_expired(self):
        cache = ResponseCache(cache_dir=self.tmpdir, ttl=60)
        cache.put("key1", "value1")
        self.assertIsNotNone(cache.get("key1"))

    def test_expired_entry_returns_none(self):
        cache = ResponseCache(cache_dir=self.tmpdir, ttl=1)  # 1 second TTL
        # Manually inject an expired entry
        store = cache._load()
        store["key1"] = {"ts": time.time() - 10, "value": "expired"}
        cache._save(store)
        # Force reload
        cache._data = None
        self.assertIsNone(cache.get("key1"))

    def test_get_or_fetch_refetches_after_expiry(self):
        cache = ResponseCache(cache_dir=self.tmpdir, ttl=1)
        call_count = 0

        def fetch():
            nonlocal call_count
            call_count += 1
            return f"val{call_count}"

        result1 = cache.get_or_fetch("key1", fetch)
        self.assertEqual(result1, "val1")

        # Manually expire the entry
        store = cache._load()
        store["key1"]["ts"] = time.time() - 10
        cache._save(store)
        cache._data = None

        result2 = cache.get_or_fetch("key1", fetch)
        self.assertEqual(result2, "val2")
        self.assertEqual(call_count, 2)

    def test_default_ttl_is_24h(self):
        self.assertEqual(DEFAULT_TTL, 86400)


class TestResponseCacheCleanup(unittest.TestCase):
    """Cleanup of expired entries."""

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.cache = ResponseCache(cache_dir=self.tmpdir, ttl=60)

    def tearDown(self):
        self.cache.clear()

    def test_cleanup_removes_expired_entries(self):
        store = self.cache._load()
        store["fresh"] = {"ts": time.time(), "value": "fresh"}
        store["expired"] = {"ts": time.time() - 10000, "value": "old"}
        self.cache._save(store)
        self.cache._data = None

        removed = self.cache.cleanup()
        self.assertEqual(removed, 1)
        self.assertIsNotNone(self.cache.get("fresh"))
        self.assertIsNone(self.cache.get("expired"))

    def test_cleanup_no_expired_entries(self):
        self.cache.put("key1", "value1")
        removed = self.cache.cleanup()
        self.assertEqual(removed, 0)


class TestResponseCacheDisabled(unittest.TestCase):
    """When cache is disabled (--no-cache)."""

    def test_disabled_cache_returns_none_on_get(self):
        cache = ResponseCache(enabled=False, cache_dir="/tmp/nonexist")
        self.assertIsNone(cache.get("any_key"))

    def test_disabled_cache_always_fetches(self):
        cache = ResponseCache(enabled=False, cache_dir="/tmp/nonexist")
        call_count = 0

        def fetch():
            nonlocal call_count
            call_count += 1
            return "fetched"

        cache.get_or_fetch("key1", fetch)
        cache.get_or_fetch("key1", fetch)
        self.assertEqual(call_count, 2)

    def test_disabled_put_is_noop(self):
        cache = ResponseCache(enabled=False, cache_dir="/tmp/nonexist")
        cache.put("key1", "value")  # Should not raise

    def test_disabled_stats(self):
        cache = ResponseCache(enabled=False)
        stats = cache.stats()
        self.assertFalse(stats["enabled"])

    def test_disabled_cleanup_returns_zero(self):
        cache = ResponseCache(enabled=False)
        self.assertEqual(cache.cleanup(), 0)


class TestResponseCachePersistence(unittest.TestCase):
    """File persistence behavior."""

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()

    def test_data_persists_across_instances(self):
        cache1 = ResponseCache(cache_dir=self.tmpdir, ttl=60)
        cache1.put("persist_key", "persist_value")

        # New instance, same dir
        cache2 = ResponseCache(cache_dir=self.tmpdir, ttl=60)
        self.assertEqual(cache2.get("persist_key"), "persist_value")

        cache2.clear()

    def test_cache_file_created_on_write(self):
        cache = ResponseCache(cache_dir=self.tmpdir, ttl=60)
        cache.put("key1", "val1")

        cache_path = os.path.join(self.tmpdir, DEFAULT_CACHE_FILE)
        self.assertTrue(os.path.exists(cache_path))

        # Verify JSON structure
        with open(cache_path) as f:
            data = json.load(f)
        self.assertIn("key1", data)
        self.assertIn("ts", data["key1"])
        self.assertIn("value", data["key1"])

        cache.clear()

    def test_corrupted_cache_handled_gracefully(self):
        cache_path = os.path.join(self.tmpdir, DEFAULT_CACHE_FILE)
        os.makedirs(os.path.dirname(cache_path), exist_ok=True)
        with open(cache_path, "w") as f:
            f.write("not json{{{")

        cache = ResponseCache(cache_dir=self.tmpdir, ttl=60)
        # Should not crash, starts with empty cache
        self.assertIsNone(cache.get("any"))


class TestMakeKey(unittest.TestCase):
    """Cache key generation."""

    def test_get_key(self):
        key = ResponseCache.make_key("GET", "https://registry.npmjs.org/express")
        self.assertEqual(key, "GET:https://registry.npmjs.org/express")

    def test_post_key_with_body(self):
        body = {"package": {"name": "express", "ecosystem": "npm"}}
        key = ResponseCache.make_key("POST", "https://api.osv.dev/v1/query", body)
        self.assertTrue(key.startswith("POST:https://api.osv.dev/v1/query:"))
        # Body hash is deterministic
        key2 = ResponseCache.make_key("POST", "https://api.osv.dev/v1/query", body)
        self.assertEqual(key, key2)

    def test_different_bodies_different_keys(self):
        body1 = {"package": {"name": "express"}}
        body2 = {"package": {"name": "lodash"}}
        key1 = ResponseCache.make_key("POST", "https://api.osv.dev/v1/query", body1)
        key2 = ResponseCache.make_key("POST", "https://api.osv.dev/v1/query", body2)
        self.assertNotEqual(key1, key2)

    def test_none_body_no_hash_suffix(self):
        key = ResponseCache.make_key("GET", "https://example.com", None)
        self.assertNotIn(":", key.split("://", 1)[1].split(":")[0])
        self.assertEqual(key, "GET:https://example.com")

    def test_method_case_insensitive(self):
        key = ResponseCache.make_key("get", "https://example.com")
        self.assertTrue(key.startswith("GET:"))


class TestResponseCacheStats(unittest.TestCase):
    """Cache statistics."""

    def test_initial_stats(self):
        cache = ResponseCache(cache_dir=tempfile.mkdtemp())
        stats = cache.stats()
        self.assertEqual(stats["hits"], 0)
        self.assertEqual(stats["misses"], 0)
        self.assertEqual(stats["total"], 0)
        self.assertEqual(stats["hit_rate"], 0.0)
        self.assertTrue(stats["enabled"])
        cache.clear()

    def test_stats_after_operations(self):
        cache = ResponseCache(cache_dir=tempfile.mkdtemp())
        cache.get_or_fetch("k1", lambda: "v1")  # miss
        cache.get_or_fetch("k1", lambda: "v1")  # hit
        cache.get_or_fetch("k2", lambda: "v2")  # miss

        stats = cache.stats()
        self.assertEqual(stats["hits"], 1)
        self.assertEqual(stats["misses"], 2)
        self.assertEqual(stats["total"], 3)
        self.assertAlmostEqual(stats["hit_rate"], 1 / 3)
        cache.clear()


class TestModuleSingleton(unittest.TestCase):
    """Module-level get_cache / init_cache."""

    def test_init_creates_cache(self):
        cache = init_cache(enabled=True, ttl=3600, verbose=False)
        self.assertTrue(cache.enabled)
        self.assertEqual(cache.ttl, 3600)

        # get_cache returns same instance
        cache2 = get_cache()
        self.assertIs(cache2, cache)

        # Reset
        init_cache(enabled=True, ttl=DEFAULT_TTL)

    def test_init_disabled_cache(self):
        cache = init_cache(enabled=False)
        self.assertFalse(cache.enabled)

        # Reset
        init_cache(enabled=True, ttl=DEFAULT_TTL)


class TestCachedGetPost(unittest.TestCase):
    """cached_get / cached_post integration helpers."""

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.cache = ResponseCache(cache_dir=self.tmpdir, ttl=60)

    def tearDown(self):
        self.cache.clear()

    @patch("requests.get")
    def test_cached_get_returns_json(self, mock_get):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {"name": "express", "versions": {}}
        mock_get.return_value = mock_resp

        result = self.cache.cached_get("https://registry.npmjs.org/express", timeout=10)
        self.assertEqual(result["name"], "express")

        # Second call should be cached — no new HTTP request
        result2 = self.cache.cached_get("https://registry.npmjs.org/express", timeout=10)
        self.assertEqual(result2["name"], "express")
        self.assertEqual(mock_get.call_count, 1)

    @patch("requests.get")
    def test_cached_get_non_200_returns_none(self, mock_get):
        mock_resp = MagicMock()
        mock_resp.status_code = 404
        mock_get.return_value = mock_resp

        result = self.cache.cached_get("https://example.com/notfound")
        self.assertIsNone(result)

    @patch("requests.post")
    def test_cached_post_returns_json(self, mock_post):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {"vulns": []}
        mock_post.return_value = mock_resp

        body = {"package": {"name": "express", "ecosystem": "npm"}}
        result = self.cache.cached_post("https://api.osv.dev/v1/query", body)
        self.assertEqual(result, {"vulns": []})

        # Cached — no second HTTP call
        result2 = self.cache.cached_post("https://api.osv.dev/v1/query", body)
        self.assertEqual(mock_post.call_count, 1)

    @patch("requests.get")
    def test_cached_get_exception_returns_none(self, mock_get):
        mock_get.side_effect = Exception("network error")
        result = self.cache.cached_get("https://example.com")
        self.assertIsNone(result)


class TestCacheWithVerbose(unittest.TestCase):
    """Verbose output."""

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()

    def test_verbose_hit_prints(self):
        cache = ResponseCache(cache_dir=self.tmpdir, ttl=60, verbose=True)
        cache.put("key1", "val1")

        import io
        import sys
        captured = io.StringIO()
        sys.stdout = captured
        cache.get_or_fetch("key1", lambda: "should_not_call")
        sys.stdout = sys.__stdout__
        self.assertIn("Cache HIT", captured.getvalue())
        cache.clear()

    def test_verbose_miss_prints(self):
        cache = ResponseCache(cache_dir=self.tmpdir, ttl=60, verbose=True)

        import io
        import sys
        captured = io.StringIO()
        sys.stdout = captured
        cache.get_or_fetch("key1", lambda: "val1")
        sys.stdout = sys.__stdout__
        self.assertIn("Cache MISS", captured.getvalue())
        cache.clear()


if __name__ == "__main__":
    unittest.main()
