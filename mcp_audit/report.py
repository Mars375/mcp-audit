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
    # ── Markdown report ─────────────────────────────────────────

    def generate_markdown_report(self) -> str:
        """Génère un rapport au format Markdown."""
        lines: list[str] = []
        summary = self.results['summary']

        # Header
        lines.append("# \U0001f512 MCP Audit Report")
        lines.append("")
        from datetime import datetime, timezone
        now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        lines.append(f"> Generated: `{now}` | mcp-audit v1.0.0")
        lines.append("")

        # ── Summary ──
        lines.append("## \U0001f4ca Summary")
        lines.append("")
        lines.append("| Metric | Value |")
        lines.append("|--------|------:|")
        for label, key in [
            ("Total Dependencies", "total_dependencies"),
            ("Servers", "servers"),
            ("Tools", "tools"),
            ("Resources", "resources"),
            ("Vulnerabilities", "vulnerabilities"),
            ("Quality Issues", "quality_issues"),
            ("Transitive Deps", "transitive_deps"),
            ("Transitive Vulns", "transitive_vulns"),
        ]:
            lines.append(f"| {label} | {summary.get(key, 0)} |")
        lines.append("")

        # ── Trust scores per server ──
        deps_with_ts = [d for d in self.results['dependencies'] if d.get('trust_score')]
        if deps_with_ts:
            lines.append("## \U0001f6e1\ufe0f Trust Score per Server")
            lines.append("")
            lines.append("| Server | Score | Grade | Quality | Security | Maint. | Supply | Trans. Risk | Vulns |")
            lines.append("|--------|------:|:-----:|--------:|---------:|-------:|-------:|:-----------:|------:|")
            for dep in deps_with_ts:
                ts = dep['trust_score']
                score = ts.get('score', 0)
                badge = _score_badge(score)
                grade = ts.get('grade', '?')
                tr_score = ts.get('transitive_risk_score')
                tr_penalty = ts.get('transitive_risk_penalty', 0)
                if tr_score is not None:
                    tr_badge = _risk_badge(tr_score)
                    tr_display = f"{tr_badge} {tr_score} (\u2212{tr_penalty})"
                else:
                    tr_display = "\u2014"
                vuln_count = len(dep.get('vulnerabilities', []))
                lines.append(
                    f"| {dep['name']} "
                    f"| {badge} {score}/100 "
                    f"| {grade} "
                    f"| {ts.get('quality', 0)} "
                    f"| {ts.get('security', 0)} "
                    f"| {ts.get('maintenance', 0)} "
                    f"| {ts.get('supply_chain', 0)} "
                    f"| {tr_display} "
                    f"| {vuln_count} |"
                )
            lines.append("")

        # ── Transitive dependencies ──
        deps_with_trans = [d for d in self.results['dependencies'] if d.get('transitive')]
        if deps_with_trans:
            lines.append("## \U0001f517 Transitive Dependencies")
            lines.append("")
            lines.append("| Server | Ecosystem | Deps | Max Depth | Vulnerable | Risk Score | Tools |")
            lines.append("|--------|-----------|-----:|----------:|-----------:|:----------:|-------|")
            for dep in deps_with_trans:
                t = dep['transitive']
                risk = t.get('risk_score', 0)
                lines.append(
                    f"| {dep['name']} "
                    f"| {t.get('ecosystem', '?')} "
                    f"| {t.get('total_deps', 0)} "
                    f"| {t.get('max_depth', 0)} "
                    f"| {t.get('vulnerable_deps', 0)} "
                    f"| {_risk_badge(risk)} {risk}/100 "
                    f"| {', '.join(t.get('tools_used', []))} |"
                )
            lines.append("")

            # Detail: vulnerable sub-deps (verbose only)
            if self.verbose:
                vuln_trans = []
                for dep in deps_with_trans:
                    t = dep['transitive']
                    for sd in t.get('dependencies', []):
                        if sd.get('vulnerable'):
                            for sv in sd.get('vulnerabilities', []):
                                vuln_trans.append((dep['name'], sd['name'], sv))
                if vuln_trans:
                    lines.append("### Vulnerable Sub-Dependencies")
                    lines.append("")
                    for server, sub_name, sv in vuln_trans:
                        sev = sv.get('severity', 'unknown')
                        lines.append(
                            f"- **{sub_name}** ({server}) \u2014 "
                            f"{_severity_badge(sev)} {sv.get('id', 'N/A')}"
                        )
                    lines.append("")

        # ── Vulnerabilities ──
        vulns = self.results.get('vulnerabilities', [])
        if vulns:
            lines.append("## \U0001f6a8 Vulnerabilities")
            lines.append("")
            for vuln in vulns:
                sev = vuln.get('severity', 'low')
                lines.append(f"### {_severity_badge(sev)} {vuln.get('id', 'Unknown')}")
                lines.append("")
                lines.append(f"- **Dependency**: {vuln.get('dependency', 'Unknown')}")
                lines.append(f"- **Severity**: {_severity_badge(sev)} {sev}")
                lines.append(f"- **Description**: {vuln.get('description', 'N/A')}")
                affected = vuln.get('affected_versions', [])
                if affected:
                    lines.append(f"- **Affected Versions**: {', '.join(affected)}")
                url = vuln.get('url')
                if url:
                    lines.append(f"- **Link**: {url}")
                lines.append("")

        # ── Recommendations ──
        recs = self.results.get('recommendations', [])
        if recs:
            lines.append("## \U0001f4a1 Recommendations")
            lines.append("")
            for rec in recs:
                priority = rec.get('priority', 'medium')
                lines.append(
                    f"- {_priority_badge(priority)} **[{rec.get('type', 'info')}]** "
                    f"{rec.get('message', '')} \u2014 _{rec.get('dependency', 'All')}_"
                )
            lines.append("")

        # ── Footer ──
        lines.append("---")
        lines.append("")
        lines.append("_Generated by [mcp-audit](https://github.com/Mars375/mcp-audit)_")
        lines.append("")

        return "\n".join(lines)


def _score_badge(score: int) -> str:
    """Return a shield-style badge emoji for a trust score."""
    if score >= 80:
        return "\U0001f7e2"  # green circle
    if score >= 60:
        return "\U0001f7e1"  # yellow circle
    return "\U0001f534"  # red circle


def _risk_badge(risk: int) -> str:
    """Return a badge emoji for a risk score (higher = worse)."""
    if risk >= 50:
        return "\U0001f534"
    if risk >= 25:
        return "\U0001f7e1"
    return "\U0001f7e2"


def _severity_badge(severity: str) -> str:
    """Return a badge for vulnerability severity."""
    return {
        "critical": "\U0001f534",
        "high": "\U0001f7e0",
        "medium": "\U0001f7e1",
        "low": "\U0001f7e2",
    }.get(severity.lower(), "\u26aa")


def _priority_badge(priority: str) -> str:
    """Return a badge for recommendation priority."""
    return {
        "high": "\U0001f534",
        "medium": "\U0001f7e1",
        "low": "\U0001f7e2",
    }.get(priority.lower(), "\u26aa")
