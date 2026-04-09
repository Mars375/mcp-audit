"""Tests for P12 watch mode."""

import json
from pathlib import Path

from click.testing import CliRunner

import sys
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import main
from main import audit


class TestWatchHelpers:
    def test_config_fingerprint_changes_when_file_changes(self, tmp_path):
        config_file = tmp_path / 'config.json'
        config_file.write_text('{"servers": {"demo": {}}}', encoding='utf-8')

        first = main._config_fingerprint(config_file)
        config_file.write_text('{"servers": {"demo": {}, "extra": {}}}', encoding='utf-8')
        second = main._config_fingerprint(config_file)

        assert first != second

    def test_watch_loop_reruns_on_change(self, tmp_path):
        config_file = tmp_path / 'config.json'
        config_file.write_text('{"servers": {"demo": {}}}', encoding='utf-8')

        runs = []
        state = {'tick': 0}

        def run_once():
            runs.append(config_file.read_text(encoding='utf-8'))

        def fake_sleep(_interval):
            state['tick'] += 1
            if state['tick'] == 1:
                config_file.write_text('{"servers": {"demo": {}, "changed": {}}}', encoding='utf-8')

        main._watch_loop(config_file, run_once, interval=0, max_cycles=2, sleep_fn=fake_sleep)

        assert len(runs) == 2
        assert 'changed' in runs[-1]


class TestWatchCLI:
    def test_cli_watch_delegates_to_watch_loop(self, tmp_path, monkeypatch):
        config_file = tmp_path / 'config.json'
        config_file.write_text(json.dumps({'servers': {'empty-server': {}}}), encoding='utf-8')

        captured = {}

        def fake_watch_loop(config_path, run_once, interval=1.0, verbose=False, max_cycles=None, sleep_fn=None):
            captured['config_path'] = Path(config_path)
            captured['verbose'] = verbose
            run_once()

        monkeypatch.setattr(main, '_watch_loop', fake_watch_loop)

        runner = CliRunner()
        result = runner.invoke(audit, ['--config', str(config_file), '--watch'])

        assert result.exit_code == 0
        assert captured['config_path'] == config_file
        assert "Debut de l'audit MCP..." in result.output
        assert 'Watch mode actif' not in result.output  # fake loop replaces banner
