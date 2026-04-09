#!/usr/bin/env python3
"""
MCP Audit CLI - Outil d'audit des dependances MCP

Supporte les formats de configuration :
  - Natif mcp-audit : { "servers", "tools", "resources" }
  - Claude Code     : ~/.claude/settings.json avec "mcpServers"
  - .mcp.json       : Configuration projet Claude Code

User config (optional):
  - ~/.config/mcp-audit/config.yaml  (user-level defaults)
  - ./.mcp-audit.yaml               (project-level overrides)
"""

import click
import json
import time
from pathlib import Path

from mcp_audit.audit import MCPAudit
from mcp_audit.cache import get_cache, init_cache
from mcp_audit.config import MCPConfig, find_default_config
from mcp_audit.user_config import apply_config_to_cli, load_merged_config


@click.command()
@click.option('--config', '-c', help='Chemin vers la configuration MCP')
@click.option('--ci', is_flag=True, help='Mode CI (non interactif, JSON par defaut)')
@click.option('--output', '-o', help='Fichier de sortie pour le rapport (JSON/Markdown) ou SBOM.')
@click.option('--fail-under', type=int, default=None,
              help='Score minimum /100 par serveur. Exit 1 si un serveur est en dessous.')
@click.option('--sbom', type=click.Choice(['cyclonedx', 'spdx']), default=None,
              help='Exporter un SBOM au format CycloneDX ou SPDX.')
@click.option('--no-cache', is_flag=True, help='Desactiver le cache des requetes registry.')
@click.option('--cache-ttl', type=int, default=86400,
              help='TTL du cache en secondes (defaut: 86400 = 24h).')
@click.option('--format', '-f', 'fmt', type=click.Choice(['terminal', 'json', 'markdown']), default=None,
              help='Format de sortie: terminal (defaut), json, markdown.')
@click.option('--watch', is_flag=True,
              help="Surveille le fichier de configuration MCP et relance l'audit a chaque modification.")
@click.option('--verbose', '-v', is_flag=True, help='Mode verbeux')
@click.pass_context
def audit(ctx, config, ci, output, fail_under, sbom, no_cache, cache_ttl, fmt, watch, verbose):
    """Audit les dependances MCP pour qualite, securite et maintenance.

    Format detecte automatiquement : natif, Claude Code, ou .mcp.json.
    Si --config n'est pas specifie, cherche dans les chemins par defaut.

    Options par defaut chargees depuis ~/.config/mcp-audit/config.yaml
    et ./.mcp-audit.yaml (projet). Les flags CLI ont la priorite.
    """

    file_cfg = load_merged_config()
    if file_cfg:
        apply_config_to_cli(ctx, file_cfg)
        config = ctx.params['config']
        ci = ctx.params['ci']
        output = ctx.params['output']
        fail_under = ctx.params['fail_under']
        sbom = ctx.params['sbom']
        no_cache = ctx.params['no_cache']
        cache_ttl = ctx.params['cache_ttl']
        fmt = ctx.params['fmt']
        watch = ctx.params['watch']
        verbose = ctx.params['verbose']

    config_path = _resolve_config_path(config=config, verbose=verbose)

    def run_once():
        return _run_audit_once(
            config_path=config_path,
            ci=ci,
            output=output,
            fail_under=fail_under,
            sbom=sbom,
            no_cache=no_cache,
            cache_ttl=cache_ttl,
            fmt=fmt,
            verbose=verbose,
            file_cfg=file_cfg,
            prompt_for_export=not watch,
            exit_on_error=not watch,
            exit_on_fail_under=not watch,
        )

    if watch:
        _watch_loop(config_path, run_once, verbose=verbose)
        return

    run_once()


def _resolve_config_path(config, verbose=False):
    """Resolve the effective MCP config path."""
    if config:
        return Path(config)

    config_path = find_default_config()
    if config_path is None:
        click.echo(
            "Aucun fichier de configuration trouve.\n"
            "Chemins cherches :\n"
            "  - ~/.config/mcp/config.json\n"
            "  - ~/.claude/settings.json\n"
            "  - ~/.claude.json\n"
            "  - ./.mcp.json\n"
            "Utilisez --config pour specifier un fichier.",
            err=True,
        )
        raise SystemExit(1)

    if verbose:
        click.echo(f"Configuration auto-detectee: {config_path}")
    return config_path


def _config_fingerprint(path):
    """Return a cheap fingerprint for change detection."""
    path = Path(path)
    if not path.exists():
        return (False, None, None)
    stat = path.stat()
    return (True, stat.st_mtime_ns, stat.st_size)


def _watch_loop(config_path, run_once, interval=1.0, verbose=False, max_cycles=None, sleep_fn=time.sleep):
    """Watch config file changes and re-run the audit when needed."""
    config_path = Path(config_path)
    last_seen = _config_fingerprint(config_path)

    click.echo(f"Watch mode actif: {config_path}")
    click.echo("Ctrl+C pour arreter la surveillance.")
    run_once()

    cycles = 0
    try:
        while True:
            if max_cycles is not None and cycles >= max_cycles:
                break
            sleep_fn(interval)
            cycles += 1
            current = _config_fingerprint(config_path)
            if current == last_seen:
                continue
            last_seen = current
            click.echo(f"\nChangement detecte: {config_path}")
            run_once()
    except KeyboardInterrupt:
        click.echo("\nWatch mode arrete.")


def _run_audit_once(
    config_path,
    ci,
    output,
    fail_under,
    sbom,
    no_cache,
    cache_ttl,
    fmt,
    verbose,
    file_cfg=None,
    prompt_for_export=True,
    exit_on_error=True,
    exit_on_fail_under=True,
):
    """Run one audit iteration."""
    try:
        config_path = Path(config_path)
        mcp_config = MCPConfig.load(config_path)

        if verbose:
            click.echo(f"Configuration chargee depuis: {config_path}")
            click.echo(f"Format detecte: {mcp_config.source_format}")
            click.echo(f"Serveurs: {len(mcp_config.servers)}")
            if file_cfg:
                click.echo(f"Config utilisateur: {list(file_cfg.keys())}")

        init_cache(enabled=not no_cache, ttl=cache_ttl, verbose=verbose)
        auditor = MCPAudit(mcp_config, verbose=verbose)

        click.echo("Debut de l'audit MCP...")
        audit_results = auditor.audit()

        if sbom:
            from mcp_audit.sbom import generate_sbom

            sbom_json = generate_sbom(audit_results, fmt=sbom)
            output_path = output or f"mcp-audit-sbom-{sbom}.json"
            with open(output_path, 'w', encoding='utf-8') as f:
                f.write(sbom_json)
            click.echo(f"SBOM {sbom} genere: {output_path}")
            _ci_gate(fail_under, audit_results, exit_on_fail=exit_on_fail_under)
            return True

        from mcp_audit.report import ReportGenerator

        generator = ReportGenerator(audit_results, verbose=verbose)
        effective_fmt = fmt or 'terminal'

        if effective_fmt == 'markdown':
            md_report = generator.generate_markdown_report()
            if output:
                with open(output, 'w', encoding='utf-8') as f:
                    f.write(md_report)
                click.echo(f"Rapport Markdown genere: {output}")
            else:
                click.echo(md_report)
        elif ci or effective_fmt == 'json':
            report = generator.generate_json_report()
            output_path = output or 'mcp-audit-report.json'
            with open(output_path, 'w', encoding='utf-8') as f:
                json.dump(report, f, indent=2)
            click.echo(f"Rapport JSON genere: {output_path}")
        else:
            terminal_report = generator.generate_terminal_report()
            click.echo(terminal_report)

            export_json = bool(output)
            if not output and prompt_for_export:
                export_json = click.confirm("\nExporter le rapport en JSON?")
                if export_json:
                    output = click.prompt("Nom du fichier de sortie", default='mcp-audit-report.json')

            if export_json:
                report = generator.generate_json_report()
                output_path = output or 'mcp-audit-report.json'
                with open(output_path, 'w', encoding='utf-8') as f:
                    json.dump(report, f, indent=2)
                click.echo(f"Rapport JSON genere: {output_path}")

        if verbose:
            stats = get_cache().stats()
            if stats['enabled'] and stats['total'] > 0:
                click.echo(f"Cache: {stats['hits']}/{stats['total']} hits ({stats['hit_rate']:.0%})")

        _ci_gate(fail_under, audit_results, exit_on_fail=exit_on_fail_under)
        return True

    except FileNotFoundError as e:
        click.echo(f"Erreur: {e}", err=True)
    except Exception as e:
        click.echo(f"Erreur inattendue: {e}", err=True)
        if verbose:
            import traceback
            traceback.print_exc()

    if exit_on_error:
        raise SystemExit(1)
    return False


def _ci_gate(fail_under, audit_results, exit_on_fail=True):
    """Check --fail-under threshold and exit if needed."""
    if fail_under is None:
        return False

    failed_servers = []
    for dep in audit_results['dependencies']:
        ts = dep.get('trust_score', {})
        score = ts.get('score', 0)
        if score < fail_under:
            failed_servers.append((dep['name'], score, ts.get('grade', '?')))

    if failed_servers:
        msg_lines = [
            f"CI FAILED: {len(failed_servers)} server(s) below threshold {fail_under}/100:"
        ]
        for name, score, grade in failed_servers:
            msg_lines.append(f"  - {name}: {score}/100 (grade {grade})")
        click.echo('\n'.join(msg_lines), err=True)
        if exit_on_fail:
            raise SystemExit(1)
        return True

    click.echo(f"CI PASSED: all servers >= {fail_under}/100")
    return False


if __name__ == '__main__':
    audit()
