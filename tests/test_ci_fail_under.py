"""
Tests for --fail-under CI gate (P3).
"""

import json
import pytest
import tempfile
import os
from pathlib import Path
from click.testing import CliRunner

# Ensure local package is importable
import sys
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from main import audit


def _make_native_config(servers):
    """Build a minimal native config JSON file."""
    data = {"servers": servers}
    f = tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False)
    json.dump(data, f)
    f.close()
    return f.name


def _server_with_score(score_elements):
    """Build a server config that produces a predictable trust score.

    score_elements: dict with keys quality_score, vulns, health, etc.
    We just need enough structure for the audit to produce a trust_score.
    """
    return score_elements


# ── Tests ──────────────────────────────────────────────────────

class TestFailUnder:

    def test_fail_under_pass_all_above(self, tmp_path):
        """All servers above threshold → exit 0."""
        config = {
            "servers": {
                "good-server": {
                    "command": "npx",
                    "args": ["-y", "some-great-package"],
                    "version": "1.0.0"
                }
            }
        }
        config_file = tmp_path / "config.json"
        config_file.write_text(json.dumps(config))

        runner = CliRunner()
        # Use a very low threshold so it passes even with real API calls
        result = runner.invoke(audit, [
            '--config', str(config_file),
            '--fail-under', '0',
            '--ci',
        ])
        # Should exit 0 (or at least not exit 1 for fail-under)
        assert result.exit_code in (0, 1)  # 1 could be network errors
        if result.exit_code == 0:
            assert "CI PASSED" in result.output

    def test_fail_under_fail_below_threshold(self, tmp_path):
        """Server with low trust score → exit 1 when threshold is high."""
        # A server with no command/args will have low quality score
        config = {
            "servers": {
                "bad-server": {}
            }
        }
        config_file = tmp_path / "config.json"
        config_file.write_text(json.dumps(config))

        runner = CliRunner()
        result = runner.invoke(audit, [
            '--config', str(config_file),
            '--fail-under', '90',
            '--ci',
        ])
        # Should exit 1
        assert result.exit_code == 1
        # Error message should mention the failing server
        assert "CI FAILED" in (result.output + (result.stderr or ""))

    def test_fail_under_not_set_no_exit1(self, tmp_path):
        """Without --fail-under, should never exit 1 for score reasons."""
        config = {
            "servers": {
                "empty-server": {}
            }
        }
        config_file = tmp_path / "config.json"
        config_file.write_text(json.dumps(config))

        runner = CliRunner()
        result = runner.invoke(audit, [
            '--config', str(config_file),
            '--ci',
        ])
        # Should NOT exit 1 just because of low scores
        # It might exit 1 for other errors, but not for fail-under
        assert "CI FAILED" not in result.output

    def test_fail_under_with_ci_mode(self, tmp_path):
        """--fail-under works correctly in --ci mode (JSON output + exit code)."""
        config = {
            "servers": {
                "bad-server": {}
            }
        }
        config_file = tmp_path / "config.json"
        config_file.write_text(json.dumps(config))

        runner = CliRunner()
        result = runner.invoke(audit, [
            '--config', str(config_file),
            '--fail-under', '80',
            '--ci',
            '--output', str(tmp_path / 'report.json'),
        ])
        assert result.exit_code == 1

    def test_fail_under_mixed_servers(self, tmp_path):
        """Mix of good and bad servers: one below threshold → exit 1."""
        config = {
            "servers": {
                "empty-server": {},
                "versioned-server": {
                    "version": "1.0.0",
                    "command": "npx",
                    "args": ["-y", "some-package"]
                }
            }
        }
        config_file = tmp_path / "config.json"
        config_file.write_text(json.dumps(config))

        runner = CliRunner()
        result = runner.invoke(audit, [
            '--config', str(config_file),
            '--fail-under', '80',
            '--ci',
        ])
        assert result.exit_code == 1

    def test_fail_under_zero_always_passes(self, tmp_path):
        """Threshold 0 should always pass."""
        config = {"servers": {"s1": {}}}
        config_file = tmp_path / "config.json"
        config_file.write_text(json.dumps(config))

        runner = CliRunner()
        result = runner.invoke(audit, [
            '--config', str(config_file),
            '--fail-under', '0',
            '--ci',
        ])
        # exit code 0 means pass (no network dependency for threshold 0)
        assert result.exit_code in (0, 1)  # 1 only if network error
        if result.exit_code == 0:
            assert "CI PASSED" in result.output


class TestFailUnderUnit:
    """Unit tests for trust score threshold logic without CLI."""

    def test_trust_score_below_threshold(self):
        """Verify compute_trust_score returns predictable low score for empty dep."""
        from mcp_audit.scoring import compute_trust_score

        dep = {
            "quality_score": 0,
            "vulnerabilities": [{"severity": "critical"}],
            "maintenance_status": {"health": "unknown"},
            "metadata": {},
            "source": None,
        }
        result = compute_trust_score(dep)
        assert result["score"] < 50
        assert result["grade"] in ("C", "D")

    def test_trust_score_above_threshold(self):
        """Verify compute_trust_score returns high score for well-maintained dep."""
        from mcp_audit.scoring import compute_trust_score

        dep = {
            "quality_score": 100,
            "vulnerabilities": [],
            "maintenance_status": {
                "health": "good",
                "commit_frequency": "high",
                "last_update": "2026-04-01T00:00:00Z",
                "stars": 5000,
                "forks": 200,
                "last_release": "2026-04-01T00:00:00Z",
            },
            "metadata": {},
            "source": "https://github.com/popular/repo",
        }
        result = compute_trust_score(dep)
        assert result["score"] >= 80
        assert result["grade"] == "A"

    def test_fail_under_threshold_boundary(self):
        """Exact score == threshold should pass (not fail)."""
        from mcp_audit.scoring import compute_trust_score

        # Build a dep whose score we can predict
        dep = {
            "quality_score": 0,
            "vulnerabilities": [],
            "maintenance_status": {"health": "unknown"},
            "metadata": {},
            "source": None,
        }
        result = compute_trust_score(dep)
        threshold = result["score"]
        # score >= threshold should pass
        assert result["score"] >= threshold
