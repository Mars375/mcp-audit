"""
Test configuration: isolate the response cache between tests.
"""

import os
import tempfile
import pytest

from mcp_audit.cache import ResponseCache, init_cache, _global_cache


@pytest.fixture(autouse=True)
def _isolate_cache():
    """Reset the global cache singleton before each test.

    Uses a temp directory so no test reads or writes to the real cache.
    """
    tmpdir = tempfile.mkdtemp(prefix="mcp-audit-test-")
    test_cache = ResponseCache(cache_dir=tmpdir, ttl=60, enabled=True)
    init_cache(enabled=True, ttl=60)
    # Override internal cache dir to temp
    import mcp_audit.cache as _cm
    _cm._global_cache = test_cache

    yield

    test_cache.clear()
    # Clean up temp dir
    try:
        os.rmdir(tmpdir)
    except OSError:
        pass
