"""
Génération de rapports pour MCP Audit
"""

from typing import Dict, Any
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.text import Text
import json


class ReportGenerator:
    """Générateur de rapports pour l'audit MCP."""
    
    def __init__(self, audit_results: Dict[str, Any], verbose: bool = False):
        self.results = audit_results
        self.verbose = verbose
        self.console = Console()
    
    def generate_terminal_report(self) -> str:
        """Génère un rapport formaté pour le terminal."""
        report_lines = []
        
        # Titre
        title = Text("MCP Audit Report", style="bold blue")
        report_lines.append(str(Panel(title, expand=False)))
        report_lines.append("")
        
        # Résumé
        report_lines.append(self._generate_summary())
        report_lines.append("")

        # Trust scores per server
        if self.results['dependencies']:
            report_lines.append(self._generate_trust_score_table())
            report_lines.append("")

        # Transitive deps overview
        if any(dep.get('transitive') for dep in self.results['dependencies']):
            report_lines.append(self._generate_transitive_section())
            report_lines.append("")
        
        # Dépendances
        if self.results['dependencies']:
            report_lines.append(self._generate_dependencies_table())
            report_lines.append("")
        
        # Vulnérabilités
        if self.results['vulnerabilities']:
            report_lines.append(self._generate_vulnerabilities_section())
            report_lines.append("")
        
        # Recommandations
        if self.results['recommendations']:
            report_lines.append(self._generate_recommendations_section())
        
        return "\n".join(report_lines)
    
    def generate_json_report(self) -> Dict[str, Any]:
        """Génère un rapport au format JSON."""
        return {
            'metadata': {
                'generated_at': '2026-04-07T04:07:00Z',  # TODO: utiliser datetime.now().isoformat()
                'version': '1.0.0'
            },
            'summary': self.results['summary'],
            'dependencies': self.results['dependencies'],
            'vulnerabilities': self.results['vulnerabilities'],
            'quality_issues': self.results['quality_issues'],
            'trust_scores': {
                dep['name']: dep.get('trust_score', {})
                for dep in self.results['dependencies']
            },
            'recommendations': self.results['recommendations']
        }
    
    def _generate_summary(self) -> str:
        """Génère la section de résumé."""
        summary = self.results['summary']
        
        table = Table(title="Audit Summary", show_header=True, header_style="bold magenta")
        table.add_column("Metric", style="cyan")
        table.add_column("Value", style="green")
        
        table.add_row("Total Dependencies", str(summary['total_dependencies']))
        table.add_row("Tools", str(summary['tools']))
        table.add_row("Resources", str(summary['resources']))
        table.add_row("Servers", str(summary['servers']))
        table.add_row("Vulnerabilities", str(summary['vulnerabilities']))
        table.add_row("Quality Issues", str(summary['quality_issues']))
        table.add_row("Transitive Deps", str(summary.get('transitive_deps', 0)))
        table.add_row("Transitive Vulns", str(summary.get('transitive_vulns', 0)))
        
        with self.console.capture() as capture:
            self.console.print(table)
        
        return capture.get()
    
    def _generate_trust_score_table(self) -> str:
        """Génère le tableau des scores de confiance agrégés par serveur."""
        table = Table(title="🔒 Trust Score per Server", show_header=True, header_style="bold magenta")
        table.add_column("Server", style="cyan", min_width=16)
        table.add_column("Score", justify="right")
        table.add_column("Grade", justify="center")
        table.add_column("Quality", justify="right")
        table.add_column("Security", justify="right")
        table.add_column("Maint.", justify="right")
        table.add_column("Supply", justify="right")
        table.add_column("Trans. Risk", justify="right")
        table.add_column("Vulns", justify="right")

        for dep in self.results['dependencies']:
            ts = dep.get('trust_score', {})
            score = ts.get('score', 0)
            color = ts.get('color', 'white')
            grade = ts.get('grade', '?')
            vuln_count = len(dep.get('vulnerabilities', []))

            # Transitive risk display
            transitive_penalty = ts.get('transitive_risk_penalty', 0)
            transitive_risk_score = ts.get('transitive_risk_score', None)
            if transitive_risk_score is not None:
                tr_color = "red" if transitive_risk_score > 50 else "yellow" if transitive_risk_score > 25 else "green"
                transitive_display = f"[{tr_color}]{transitive_risk_score} (-{transitive_penalty})[/]"
            else:
                transitive_display = "—"

            table.add_row(
                dep['name'],
                f"[{color}]{score}/100[/]",
                f"[{color}]{grade}[/]",
                str(ts.get('quality', 0)),
                str(ts.get('security', 0)),
                str(ts.get('maintenance', 0)),
                str(ts.get('supply_chain', 0)),
                transitive_display,
                str(vuln_count),
            )

        with self.console.capture() as capture:
            self.console.print(table)
        return capture.get()

    def _generate_transitive_section(self) -> str:
        """Generate a summary table of transitive dependency analysis."""
        table = Table(title="🔗 Transitive Dependency Analysis", show_header=True, header_style="bold magenta")
        table.add_column("Server", style="cyan", min_width=16)
        table.add_column("Ecosystem", style="yellow")
        table.add_column("Deps", justify="right")
        table.add_column("Max Depth", justify="right")
        table.add_column("Vulnerable", justify="right", style="red")
        table.add_column("Risk Score", justify="right")
        table.add_column("Tool", style="dim")

        for dep in self.results['dependencies']:
            t = dep.get('transitive')
            if not t:
                continue
            risk = t.get('risk_score', 0)
            risk_color = "red" if risk >= 50 else "yellow" if risk >= 25 else "green"
            table.add_row(
                dep['name'],
                t.get('ecosystem', '?'),
                str(t.get('total_deps', 0)),
                str(t.get('max_depth', 0)),
                str(t.get('vulnerable_deps', 0)),
                f"[{risk_color}]{risk}/100[/]",
                ', '.join(t.get('tools_used', [])),
            )

        with self.console.capture() as capture:
            self.console.print(table)
        return capture.get()

    def _generate_dependencies_table(self) -> str:
        """Génère le tableau des dépendances."""
        table = Table(title="Dependencies Analysis", show_header=True, header_style="bold magenta")
        table.add_column("Name", style="cyan")
        table.add_column("Type", style="yellow")
        table.add_column("Quality Score", style="green")
        table.add_column("Vulnerabilities", style="red")
        table.add_column("Maintenance", style="blue")
        
        for dep in self.results['dependencies']:
            quality_color = "green" if dep['quality_score'] >= 80 else "yellow" if dep['quality_score'] >= 60 else "red"
            vuln_count = len(dep['vulnerabilities'])
            maint_color = "green" if dep['maintenance_status']['health'] == 'good' else "yellow" if dep['maintenance_status']['health'] == 'warning' else "red"
            
            table.add_row(
                dep['name'],
                dep['type'],
                f"[{quality_color}]{dep['quality_score']}[/]",
                str(vuln_count),
                f"[{maint_color}]{dep['maintenance_status']['health']}[/]"
            )
        
        with self.console.capture() as capture:
            self.console.print(table)
        
        return capture.get()
    
    def _generate_vulnerabilities_section(self) -> str:
        """Génère la section des vulnérabilités."""
        vulnerabilities = self.results['vulnerabilities']
        
        text = Text("🚨 Vulnerabilities Found", style="bold red")
        panel = Panel(text, expand=False)
        
        if self.console.is_terminal:
            self.console.print(panel)
        
        for vuln in vulnerabilities:
            severity_color = {
                'critical': 'bold red',
                'high': 'red',
                'medium': 'yellow',
                'low': 'cyan'
            }.get(vuln.get('severity', 'low'), 'white')
            
            vuln_text = Text()
            vuln_text.append(f"ID: {vuln['id']}\n", style="bold")
            vuln_text.append(f"Severity: {vuln['severity']}\n", style=severity_color)
            vuln_text.append(f"Description: {vuln['description']}\n", style="white")
            vuln_text.append(f"Affected Versions: {', '.join(vuln['affected_versions'])}", style="cyan")
            
            panel = Panel(vuln_text, title=f"Dependency: {vuln.get('dependency', 'Unknown')}")
            
            if self.console.is_terminal:
                self.console.print(panel)
        
        return ""  # Le contenu est déjà affiché
    
    def _generate_recommendations_section(self) -> str:
        """Génère la section des recommandations."""
        recommendations = self.results['recommendations']
        
        text = Text("💡 Recommendations", style="bold blue")
        panel = Panel(text, expand=False)
        
        if self.console.is_terminal:
            self.console.print(panel)
        
        for rec in recommendations:
            priority_color = {
                'high': 'bold red',
                'medium': 'yellow',
                'low': 'cyan'
            }.get(rec.get('priority', 'medium'), 'white')
            
            rec_text = Text()
            rec_text.append(f"Type: {rec['type']}\n", style="bold")
            rec_text.append(f"Priority: {rec['priority']}\n", style=priority_color)
            rec_text.append(f"Message: {rec['message']}\n", style="white")
            rec_text.append(f"Dependency: {rec.get('dependency', 'All')}", style="cyan")
            
            panel = Panel(rec_text, title=f"Recommendation {rec['type']}")
            
            if self.console.is_terminal:
                self.console.print(panel)
        
        return ""  # Le contenu est déjà affiché