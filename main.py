#!/usr/bin/env python3
"""
MCP Audit CLI - Outil d'audit des dépendances MCP
"""

import click
import json
import sys
from pathlib import Path

from mcp_audit.audit import MCPAudit
from mcp_audit.config import MCPConfig
from mcp_audit.report import ReportGenerator


@click.command()
@click.option('--config', '-c', help='Chemin vers la configuration MCP')
@click.option('--ci', is_flag=True, help='Mode CI (rapport JSON seulement)')
@click.option('--output', '-o', help='Fichier de sortie pour le rapport JSON')
@click.option('--verbose', '-v', is_flag=True, help='Mode verbeux')
def audit(config, ci, output, verbose):
    """Audit les dépendances MCP pour qualité, sécurité et maintenance."""
    
    try:
        # Charger la configuration MCP
        config_path = config or Path.home() / '.config' / 'mcp' / 'config.json'
        mcp_config = MCPConfig.load(config_path)
        
        if verbose:
            click.echo(f"Configuration chargée depuis: {config_path}")
        
        # Initialiser l'audit
        auditor = MCPAudit(mcp_config, verbose=verbose)
        
        # Exécuter l'audit
        click.echo("Début de l'audit MCP...")
        audit_results = auditor.audit()
        
        # Générer le rapport
        generator = ReportGenerator(audit_results, verbose=verbose)
        
        if ci:
            # Mode CI: rapport JSON seulement
            report = generator.generate_json_report()
            output_path = output or 'mcp-audit-report.json'
            with open(output_path, 'w') as f:
                json.dump(report, f, indent=2)
            click.echo(f"Rapport CI généré: {output_path}")
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
                click.echo(f"Rapport JSON généré: {output}")
    
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