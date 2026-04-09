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
import sys
from pathlib import Path

from mcp_audit.audit import MCPAudit
from mcp_audit.config import MCPConfig, find_default_config
from mcp_audit.cache import init_cache, get_cache
from mcp_audit.user_config import load_merged_config, apply_config_to_cli


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
@click.option('--verbose', '-v', is_flag=True, help='Mode verbeux')
@click.pass_context
def audit(ctx, config, ci, output, fail_under, sbom, no_cache, cache_ttl, fmt, verbose):
    """Audit les dependances MCP pour qualite, securite et maintenance.

    Format detecte automatiquement : natif, Claude Code, ou .mcp.json.
    Si --config n'est pas specifie, cherche dans les chemins par defaut.

    Options par defaut chargees depuis ~/.config/mcp-audit/config.yaml
    et ./.mcp-audit.yaml (projet). Les flags CLI ont la priorite.
    """

    # ── Apply user config file as defaults ──
    file_cfg = load_merged_config()
    if file_cfg:
        apply_config_to_cli(ctx, file_cfg)
        # Re-read potentially overridden params
        config = ctx.params['config']
        ci = ctx.params['ci']
        output = ctx.params['output']
        fail_under = ctx.params['fail_under']
        sbom = ctx.params['sbom']
        no_cache = ctx.params['no_cache']
        cache_ttl = ctx.params['cache_ttl']
        fmt = ctx.params['fmt']
        verbose = ctx.params['verbose']

    try:
        # Resoudre le chemin de config
        if config:
            config_path = Path(config)
        else:
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
                sys.exit(1)
            if verbose:
                click.echo(f"Configuration auto-detectee: {config_path}")

        # Charger la configuration
        mcp_config = MCPConfig.load(config_path)

        if verbose:
            click.echo(f"Configuration chargee depuis: {config_path}")
            click.echo(f"Format detecte: {mcp_config.source_format}")
            click.echo(f"Serveurs: {len(mcp_config.servers)}")
            if file_cfg:
                click.echo(f"Config utilisateur: {list(file_cfg.keys())}")

        # Initialiser le cache
        cache = init_cache(enabled=not no_cache, ttl=cache_ttl, verbose=verbose)

        # Initialiser l'audit
        auditor = MCPAudit(mcp_config, verbose=verbose)

        # Executer l'audit
        click.echo("Debut de l'audit MCP...")
        audit_results = auditor.audit()

        # ── SBOM export mode ──
        if sbom:
            from mcp_audit.sbom import generate_sbom
            sbom_json = generate_sbom(audit_results, fmt=sbom)
            output_path = output or f"mcp-audit-sbom-{sbom}.json"
            with open(output_path, 'w') as f:
                f.write(sbom_json)
            click.echo(f"SBOM {sbom} genere: {output_path}")
            # Still run CI gate if requested
            _ci_gate(fail_under, audit_results)
            return

        # Generer le rapport
        from mcp_audit.report import ReportGenerator
        generator = ReportGenerator(audit_results, verbose=verbose)

        # Resolve effective format (CLI > user config > default)
        effective_fmt = fmt or 'terminal'

        if effective_fmt == 'markdown':
            # Markdown report
            md_report = generator.generate_markdown_report()
            if output:
                with open(output, 'w') as f:
                    f.write(md_report)
                click.echo(f"Rapport Markdown genere: {output}")
            else:
                click.echo(md_report)
        elif ci or effective_fmt == 'json':
            # JSON report (CI mode or explicit --format json)
            report = generator.generate_json_report()
            output_path = output or 'mcp-audit-report.json'
            with open(output_path, 'w') as f:
                json.dump(report, f, indent=2)
            click.echo(f"Rapport JSON genere: {output_path}")
        else:
            # Mode interactif: rapport terminal + option JSON
            terminal_report = generator.generate_terminal_report()
            click.echo(terminal_report)

            # Demander si exporter en JSON
            if not output:
                export_json = click.confirm("\nExporter le rapport en JSON?")
                if export_json:
                    output = click.prompt("Nom du fichier de sortie", default='mcp-audit-report.json')
            else:
                export_json = True

            if export_json:
                report = generator.generate_json_report()
                with open(output, 'w') as f:
                    json.dump(report, f, indent=2)
                click.echo(f"Rapport JSON genere: {output}")

        # ── Cache stats ──
        if verbose:
            stats = get_cache().stats()
            if stats['enabled'] and stats['total'] > 0:
                click.echo(f"Cache: {stats['hits']}/{stats['total']} hits ({stats['hit_rate']:.0%})")

        # ── CI gate: --fail-under ──
        _ci_gate(fail_under, audit_results)

    except FileNotFoundError as e:
        click.echo(f"Erreur: {e}", err=True)
        sys.exit(1)
    except Exception as e:
        click.echo(f"Erreur inattendue: {e}", err=True)
        if verbose:
            import traceback
            traceback.print_exc()
        sys.exit(1)


def _ci_gate(fail_under, audit_results):
    """Check --fail-under threshold and exit if needed."""
    if fail_under is None:
        return
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
        sys.exit(1)
    else:
        click.echo(f"CI PASSED: all servers >= {fail_under}/100")


if __name__ == '__main__':
    audit()
