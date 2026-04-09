"""
User configuration for mcp-audit CLI defaults.

Supports two config locations (merged in priority order):
  1. Project-level: ./.mcp-audit.yaml   (highest priority)
  2. User-level:    ~/.config/mcp-audit/config.yaml

CLI flags always override file values.

Config file example::

    # ~/.config/mcp-audit/config.yaml
    config: ~/.claude/settings.json
    fail-under: 60
    cache-ttl: 43200
    verbose: true
    output: mcp-audit-report.json
    format: terminal   # terminal | json | markdown

    # ./.mcp-audit.yaml  (project overrides)
    fail-under: 80
    no-cache: true
"""

import os
from pathlib import Path
from typing import Any, Dict, Optional

import click
import yaml


# Keys that are valid in the config file
VALID_KEYS = frozenset({
    'config', 'ci', 'output', 'fail-under', 'sbom',
    'no-cache', 'cache-ttl', 'verbose', 'format',
})

# Keys that are boolean flags
BOOL_KEYS = frozenset({'ci', 'no-cache', 'verbose'})

# Keys that are integers
INT_KEYS = frozenset({'fail-under', 'cache-ttl'})

# Keys that have constrained choices
CHOICE_KEYS = {
    'sbom': ('cyclonedx', 'spdx'),
    'format': ('terminal', 'json', 'markdown'),
}


def _user_config_path() -> Path:
    """Return the user-level config path, respecting XDG_CONFIG_HOME."""
    xdg = os.environ.get('XDG_CONFIG_HOME')
    if xdg:
        return Path(xdg) / 'mcp-audit' / 'config.yaml'
    return Path.home() / '.config' / 'mcp-audit' / 'config.yaml'


def _project_config_path() -> Path:
    """Return the project-level config path (cwd)."""
    return Path.cwd() / '.mcp-audit.yaml'


def _load_yaml_file(path: Path) -> Dict[str, Any]:
    """Load a YAML file, returning an empty dict on any error."""
    if not path.exists():
        return {}
    try:
        with open(path, 'r', encoding='utf-8') as f:
            data = yaml.safe_load(f)
        if not isinstance(data, dict):
            return {}
        return data
    except Exception:
        return {}


def _validate_value(key: str, value: Any) -> Any:
    """Validate and coerce a single config value. Returns None to skip."""
    if value is None:
        return None

    if key in BOOL_KEYS:
        if isinstance(value, bool):
            return value
        if isinstance(value, str):
            return value.lower() in ('true', '1', 'yes')
        return None

    if key in INT_KEYS:
        try:
            return int(value)
        except (ValueError, TypeError):
            return None

    if key in CHOICE_KEYS:
        allowed = CHOICE_KEYS[key]
        if isinstance(value, str) and value.lower() in allowed:
            return value.lower()
        return None

    # String keys (config, output, format, etc.)
    if isinstance(value, str):
        return value
    return None


def _validate_config(raw: Dict[str, Any]) -> Dict[str, Any]:
    """Validate config dict, keeping only valid keys with valid values."""
    validated = {}
    for key, value in raw.items():
        if key not in VALID_KEYS:
            continue
        cleaned = _validate_value(key, value)
        if cleaned is not None:
            validated[key] = cleaned
    return validated


def load_merged_config(
    project_path: Optional[Path] = None,
    user_path: Optional[Path] = None,
) -> Dict[str, Any]:
    """Load and merge user + project config files.

    Priority (highest wins):
      1. Project-level config (.mcp-audit.yaml)
      2. User-level config (~/.config/mcp-audit/config.yaml)

    Returns:
        Validated and merged config dict.
    """
    if user_path is None:
        user_path = _user_config_path()
    if project_path is None:
        project_path = _project_config_path()

    user_cfg = _validate_config(_load_yaml_file(user_path))
    project_cfg = _validate_config(_load_yaml_file(project_path))

    # Merge: project overrides user
    merged = {**user_cfg, **project_cfg}
    return merged


def apply_config_to_cli(
    ctx: 'click.Context',
    config: Dict[str, Any],
) -> None:
    """Apply loaded config as defaults for Click CLI params.

    Only sets values that the user didn't explicitly pass on the CLI.
    """
    param_map = {
        'config': 'config',
        'ci': 'ci',
        'output': 'output',
        'fail-under': 'fail_under',
        'sbom': 'sbom',
        'no-cache': 'no_cache',
        'cache-ttl': 'cache_ttl',
        'verbose': 'verbose',
        'format': 'fmt',
    }

    for config_key, param_name in param_map.items():
        if config_key not in config:
            continue
        # Only set if user didn't pass the flag explicitly
        if ctx.get_parameter_source(param_name) == click.core.ParameterSource.DEFAULT:
            ctx.params[param_name] = config[config_key]


def generate_sample_config() -> str:
    """Generate a sample config YAML string."""
    return """\
# mcp-audit configuration
# Place in ~/.config/mcp-audit/config.yaml (user) or ./.mcp-audit.yaml (project)

# Path to MCP config file (auto-detected if not set)
# config: ~/.claude/settings.json

# CI mode (JSON only, no interactive prompts)
# ci: false

# Default output file for reports
# output: mcp-audit-report.json

# Minimum trust score /100 per server (exit 1 if below)
# fail-under: 60

# SBOM export format
# sbom: cyclonedx  # cyclonedx | spdx

# Disable response cache
# no-cache: false

# Cache TTL in seconds (default: 86400 = 24h)
# cache-ttl: 86400

# Default report format
# format: terminal  # terminal | json | markdown

# Verbose mode
# verbose: false
"""


def init_config_file(path: Optional[Path] = None) -> Path:
    """Create a sample config file at the given path (default: user config)."""
    if path is None:
        path = _user_config_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists():
        raise FileExistsError(f"Config file already exists: {path}")
    path.write_text(generate_sample_config(), encoding='utf-8')
    return path
