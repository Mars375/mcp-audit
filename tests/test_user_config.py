"""Tests for mcp_audit.user_config — P10 user config file support."""

import os
import pytest
from pathlib import Path
from unittest.mock import patch

from mcp_audit.user_config import (
    _user_config_path,
    _project_config_path,
    _load_yaml_file,
    _validate_value,
    _validate_config,
    load_merged_config,
    apply_config_to_cli,
    generate_sample_config,
    init_config_file,
    VALID_KEYS,
    BOOL_KEYS,
    INT_KEYS,
    CHOICE_KEYS,
)


# ── _user_config_path ──────────────────────────────────────────

class TestUserConfigPath:
    def test_default(self):
        p = _user_config_path()
        assert p == Path.home() / '.config' / 'mcp-audit' / 'config.yaml'

    def test_xdg_override(self):
        with patch.dict(os.environ, {'XDG_CONFIG_HOME': '/tmp/xdg-cfg'}):
            p = _user_config_path()
            assert p == Path('/tmp/xdg-cfg/mcp-audit/config.yaml')


# ── _project_config_path ──────────────────────────────────────

class TestProjectConfigPath:
    def test_default(self):
        p = _project_config_path()
        assert p == Path.cwd() / '.mcp-audit.yaml'


# ── _load_yaml_file ────────────────────────────────────────────

class TestLoadYamlFile:
    def test_nonexistent_file(self, tmp_path):
        result = _load_yaml_file(tmp_path / 'nope.yaml')
        assert result == {}

    def test_valid_yaml(self, tmp_path):
        f = tmp_path / 'test.yaml'
        f.write_text('config: /foo/bar\nverbose: true\nfail-under: 80\n')
        result = _load_yaml_file(f)
        assert result == {'config': '/foo/bar', 'verbose': True, 'fail-under': 80}

    def test_empty_file(self, tmp_path):
        f = tmp_path / 'empty.yaml'
        f.write_text('')
        result = _load_yaml_file(f)
        assert result == {}

    def test_non_dict_yaml(self, tmp_path):
        f = tmp_path / 'list.yaml'
        f.write_text('- a\n- b\n')
        result = _load_yaml_file(f)
        assert result == {}

    def test_malformed_yaml(self, tmp_path):
        f = tmp_path / 'bad.yaml'
        f.write_text(':\n  :\n   bad: [}')
        result = _load_yaml_file(f)
        # Should not raise, return empty dict
        assert isinstance(result, dict)


# ── _validate_value ────────────────────────────────────────────

class TestValidateValue:
    def test_bool_true(self):
        assert _validate_value('verbose', True) is True

    def test_bool_string(self):
        assert _validate_value('verbose', 'true') is True
        assert _validate_value('verbose', 'yes') is True
        assert _validate_value('verbose', '1') is True
        assert _validate_value('verbose', 'false') is False  # valid bool → False

    def test_bool_false_explicit(self):
        assert _validate_value('ci', False) is False

    def test_bool_invalid(self):
        assert _validate_value('verbose', 42) is None

    def test_int_valid(self):
        assert _validate_value('fail-under', '80') == 80
        assert _validate_value('cache-ttl', 43200) == 43200

    def test_int_invalid(self):
        assert _validate_value('fail-under', 'abc') is None

    def test_choice_valid(self):
        assert _validate_value('sbom', 'cyclonedx') == 'cyclonedx'
        assert _validate_value('sbom', 'SPDX') == 'spdx'

    def test_choice_invalid(self):
        assert _validate_value('sbom', 'invalid') is None

    def test_string_valid(self):
        assert _validate_value('config', '/foo/bar') == '/foo/bar'

    def test_none_value(self):
        assert _validate_value('config', None) is None

    def test_string_invalid_type(self):
        assert _validate_value('config', 123) is None


# ── _validate_config ──────────────────────────────────────────

class TestValidateConfig:
    def test_valid_config(self):
        raw = {'config': '/foo', 'verbose': True, 'fail-under': 80}
        result = _validate_config(raw)
        assert result == raw

    def test_ignores_unknown_keys(self):
        raw = {'config': '/foo', 'unknown-key': 'bar', 'hack': True}
        result = _validate_config(raw)
        assert 'unknown-key' not in result
        assert 'hack' not in result
        assert result == {'config': '/foo'}

    def test_ignores_invalid_values(self):
        raw = {'fail-under': 'not-a-number', 'verbose': 99}
        result = _validate_config(raw)
        assert 'fail-under' not in result
        assert 'verbose' not in result
        assert result == {}

    def test_empty(self):
        assert _validate_config({}) == {}


# ── load_merged_config ────────────────────────────────────────

class TestLoadMergedConfig:
    def test_no_files(self, tmp_path):
        result = load_merged_config(
            user_path=tmp_path / 'user.yaml',
            project_path=tmp_path / 'project.yaml',
        )
        assert result == {}

    def test_user_only(self, tmp_path):
        user = tmp_path / 'user.yaml'
        user.write_text('verbose: true\nfail-under: 60\n')
        result = load_merged_config(
            user_path=user,
            project_path=tmp_path / 'project.yaml',
        )
        assert result == {'verbose': True, 'fail-under': 60}

    def test_project_only(self, tmp_path):
        project = tmp_path / 'project.yaml'
        project.write_text('ci: true\n')
        result = load_merged_config(
            user_path=tmp_path / 'user.yaml',
            project_path=project,
        )
        assert result == {'ci': True}

    def test_merge_project_overrides_user(self, tmp_path):
        user = tmp_path / 'user.yaml'
        user.write_text('verbose: false\nfail-under: 60\noutput: user-report.json\n')
        project = tmp_path / 'project.yaml'
        project.write_text('fail-under: 80\nno-cache: true\n')
        result = load_merged_config(
            user_path=user,
            project_path=project,
        )
        assert result == {
            'verbose': False,      # from user, not overridden
            'fail-under': 80,       # project overrides user
            'output': 'user-report.json',
            'no-cache': True,       # project only
        }

    def test_invalid_keys_filtered(self, tmp_path):
        user = tmp_path / 'user.yaml'
        user.write_text('config: /foo\nhack-me: evil\nfail-under: 70\n')
        result = load_merged_config(
            user_path=user,
            project_path=tmp_path / 'project.yaml',
        )
        assert 'hack-me' not in result
        assert result['config'] == '/foo'
        assert result['fail-under'] == 70


# ── apply_config_to_cli ───────────────────────────────────────

class TestApplyConfigToCli:
    def test_applies_defaults(self):
        """Simulate a Click context with default values."""
        import click

        @click.command()
        @click.option('--config', default=None)
        @click.option('--verbose', is_flag=True, default=False)
        @click.option('--fail-under', type=int, default=None)
        @click.pass_context
        def dummy(ctx, config, verbose, fail_under):
            pass

        with dummy.make_context('dummy', []) as ctx:
            cfg = {'config': '/my/config.json', 'verbose': True, 'fail-under': 75}
            apply_config_to_cli(ctx, cfg)
            assert ctx.params['config'] == '/my/config.json'
            assert ctx.params['verbose'] is True
            assert ctx.params['fail_under'] == 75

    def test_does_not_override_explicit_cli(self):
        """CLI flags should NOT be overridden by config file."""
        import click

        @click.command()
        @click.option('--config', default=None)
        @click.option('--fail-under', type=int, default=None)
        @click.pass_context
        def dummy(ctx, config, fail_under):
            pass

        with dummy.make_context('dummy', ['--fail-under', '50']) as ctx:
            cfg = {'config': '/cfg.json', 'fail-under': 90}
            apply_config_to_cli(ctx, cfg)
            assert ctx.params['config'] == '/cfg.json'  # applied (default)
            assert ctx.params['fail_under'] == 50       # NOT overridden


# ── generate_sample_config ────────────────────────────────────

class TestGenerateSampleConfig:
    def test_produces_yaml_string(self):
        sample = generate_sample_config()
        assert isinstance(sample, str)
        assert 'mcp-audit' in sample
        assert 'fail-under' in sample
        assert 'cache-ttl' in sample

    def test_is_valid_yaml(self):
        import yaml
        sample = generate_sample_config()
        # All commented out, should parse cleanly
        data = yaml.safe_load(sample)
        assert data is None or isinstance(data, dict)


# ── init_config_file ──────────────────────────────────────────

class TestInitConfigFile:
    def test_creates_file(self, tmp_path):
        target = tmp_path / 'config.yaml'
        result = init_config_file(target)
        assert result == target
        assert target.exists()
        content = target.read_text()
        assert 'mcp-audit' in content

    def test_refuses_existing(self, tmp_path):
        target = tmp_path / 'config.yaml'
        target.write_text('old')
        with pytest.raises(FileExistsError):
            init_config_file(target)

    def test_creates_parent_dirs(self, tmp_path):
        target = tmp_path / 'deep' / 'nested' / 'config.yaml'
        init_config_file(target)
        assert target.exists()

    def test_default_path(self):
        """init_config_file() without args uses user config path."""
        with patch('mcp_audit.user_config._user_config_path', return_value=Path('/tmp/test-init-cfg.yaml')):
            target = Path('/tmp/test-init-cfg.yaml')
            if target.exists():
                target.unlink()
            result = init_config_file()
            assert result == target
            assert target.exists()
            target.unlink()
