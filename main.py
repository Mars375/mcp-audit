#!/usr/bin/env python3
"""
MCP Audit CLI - Outil d'audit des dependances MCP

Supporte les formats de configuration :
  - Natif mcp-audit : { "servers", "tools", "resources" }
  - Claude Code     : ~/.claude/settings.json avec "mcpServers"
  - .mcp.json       : Configuration projet Claude Code
"""

import click
import json
import sys
from pathlib import Path

from mcp_audit.audit import MCPAudit
from mcp_audit.config import MCPConfig, find_default_config


@click.command()
@click.option('--config', '-c', help='Chemin vers la configuration MCP')
@click.option('--ci', is_flag=True, help='Mode CI (rapport JSON seulement)')
@click.option('--output', '-o', help='Fichier de sortie pour le rapport JSON')
@click.option('--verbose', '-v', is_flag=True, help='Mode verbeux')
def audit(config, ci, output, verbose):
    """Audit les dependances MCP pour qualite, securite et maintenance.

    Format detecte automatiquement : natif, Claude Code, ou .mcp.json.
    Si --config n'est pas specifie, cherche dans les chemins par defaut.
    """

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

        # Initialiser l'audit
        auditor = MCPAudit(mcp_config, verbose=verbose)

        # Executer l'audit
        click.echo("Debut de l'audit MCP...")
        audit_results = auditor.audit()

        # Generer le rapport
        from mcp_audit.report import ReportGenerator
        generator = ReportGenerator(audit_results, verbose=verbose)

        if ci:
            # Mode CI: rapport JSON seulement
            report = generator.generate_json_report()
            output_path = output or 'mcp-audit-report.json'
            with open(output_path, 'w') as f:
                json.dump(report, f, indent=2)
            click.echo(f"Rapport CI genere: {output_path}")
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

    except FileNotFoundError as e:
        click.echo(f"Erreur: {e}", err=True)
        sys.exit(1)
    except Exception as e:
        click.echo(f"Erreur inattendue: {e}", err=True)
        if verbose:
            import traceback
            traceback.print_exc()
        sys.exit(1)


if __name__ == '__main__':
    audit()
