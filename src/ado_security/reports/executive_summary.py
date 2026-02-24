"""
One-page executive summary report generator.

Outputs:
- Compact HTML summary (single page)
- CSV summary for governance tracking and BI ingestion
"""

import csv
from html import escape
from pathlib import Path
from typing import List, Tuple

from ..analyzers.governance import GovernanceReport, RiskLevel


class ExecutiveSummaryGenerator:
    """Generate one-page governance executive summaries."""

    def __init__(self, organization: str, project: str, governance_report: GovernanceReport):
        self.organization = organization
        self.project = project
        self.gov = governance_report

    def generate(self, output_base: str, fmt: str = "both") -> List[Tuple[str, str]]:
        generated: List[Tuple[str, str]] = []
        base = Path(output_base)
        base.parent.mkdir(parents=True, exist_ok=True)

        if fmt in ("html", "both"):
            html_path = str(base.with_name(f"{base.name}_executive_summary.html"))
            self._write_html(html_path)
            generated.append(("Executive Summary HTML", html_path))

        if fmt in ("csv", "both"):
            csv_path = str(base.with_name(f"{base.name}_executive_summary.csv"))
            self._write_csv(csv_path)
            generated.append(("Executive Summary CSV", csv_path))

        return generated

    def _write_html(self, output_path: str):
        g = self.gov
        score = g.score
        pass_count = sum(1 for c in g.controls if c.status == "Pass")
        warn_count = sum(1 for c in g.controls if c.status == "Warning")
        fail_count = sum(1 for c in g.controls if c.status == "Fail")
        grade_color = {"A": "#2E7D32", "B": "#388E3C", "C": "#F9A825", "D": "#EF6C00", "F": "#C62828"}.get(score.grade, "#546E7A")

        risk_rank = {RiskLevel.CRITICAL: 0, RiskLevel.HIGH: 1, RiskLevel.MEDIUM: 2, RiskLevel.LOW: 3, RiskLevel.INFO: 4}
        top_findings = sorted(g.findings, key=lambda f: risk_rank.get(f.risk_level, 9))[:8]

        measure_rows = ""
        for m in g.simple_measures:
            color = {"Good": "#2E7D32", "Watch": "#F9A825", "Risk": "#C62828"}.get(m.status, "#546E7A")
            measure_rows += (
                "<tr>"
                f"<td>{escape(m.label)}</td>"
                f"<td>{escape(m.value)}</td>"
                f"<td><span style='color:#fff;background:{color};padding:2px 8px;border-radius:10px;font-size:11px'>{escape(m.status)}</span></td>"
                f"<td>{escape(m.description)}</td>"
                "</tr>"
            )

        action_rows = ""
        for a in g.top_actions:
            action_rows += (
                "<tr>"
                f"<td>{a.priority}</td>"
                f"<td>{escape(a.risk_level)}</td>"
                f"<td>{escape(a.category)}</td>"
                f"<td>{escape(a.action)}</td>"
                f"<td>{escape(a.rationale)}</td>"
                "</tr>"
            )

        finding_rows = ""
        for f in top_findings:
            finding_rows += (
                "<tr>"
                f"<td>{escape(f.risk_level)}</td>"
                f"<td>{escape(f.category)}</td>"
                f"<td>{escape(f.title)}</td>"
                f"<td>{escape(f.affected_entity)}</td>"
                "</tr>"
            )

        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Executive Summary - {escape(self.organization)}/{escape(self.project)}</title>
<style>
body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif; margin: 0; background: #f4f6f8; color: #223; }}
.wrap {{ max-width: 1100px; margin: 0 auto; padding: 20px; }}
.header {{ background: #0B4F6C; color: #fff; padding: 20px; border-radius: 10px; }}
.header h1 {{ margin: 0; font-size: 24px; }}
.header p {{ margin: 8px 0 0; font-size: 13px; opacity: 0.95; }}
.cards {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(150px, 1fr)); gap: 12px; margin: 16px 0; }}
.card {{ background: #fff; border-radius: 10px; padding: 14px; box-shadow: 0 1px 4px rgba(0,0,0,.08); }}
.label {{ font-size: 11px; color: #607080; text-transform: uppercase; }}
.value {{ font-size: 28px; font-weight: 700; margin-top: 6px; }}
.section {{ background: #fff; border-radius: 10px; padding: 14px; box-shadow: 0 1px 4px rgba(0,0,0,.08); margin-top: 14px; }}
.section h2 {{ margin: 0 0 10px; font-size: 16px; color: #0B4F6C; }}
table {{ width: 100%; border-collapse: collapse; font-size: 13px; }}
th {{ text-align: left; background: #0B4F6C; color: #fff; padding: 8px; }}
td {{ border-bottom: 1px solid #e6eaee; padding: 8px; vertical-align: top; }}
@media (max-width: 768px) {{ .value {{ font-size: 22px; }} }}
</style>
</head>
<body>
<div class="wrap">
  <div class="header">
    <h1>Azure DevOps Governance Executive Summary</h1>
    <p>Org: {escape(self.organization)} | Project: {escape(self.project)} | Scope: {escape(g.scope_statement)} | Collection: {escape(g.collection_mode)} | Generated: {g.generated_at.strftime('%Y-%m-%d %H:%M')}</p>
  </div>
  <div class="cards">
    <div class="card"><div class="label">Grade</div><div class="value" style="color:{grade_color}">{score.grade}</div></div>
    <div class="card"><div class="label">Score</div><div class="value">{score.overall_score}</div></div>
    <div class="card"><div class="label">Findings</div><div class="value">{len(g.findings)}</div></div>
    <div class="card"><div class="label">Critical</div><div class="value" style="color:#C62828">{len(g.critical_findings)}</div></div>
    <div class="card"><div class="label">High</div><div class="value" style="color:#EF6C00">{len(g.high_findings)}</div></div>
    <div class="card"><div class="label">Controls</div><div class="value">{pass_count}/{len(g.controls)} Pass</div></div>
    <div class="card"><div class="label">Warnings</div><div class="value">{warn_count}</div></div>
    <div class="card"><div class="label">Fails</div><div class="value" style="color:#C62828">{fail_count}</div></div>
  </div>

  <div class="section">
    <h2>Simple Measures</h2>
    <table>
      <thead><tr><th>Measure</th><th>Value</th><th>Status</th><th>Interpretation</th></tr></thead>
      <tbody>{measure_rows}</tbody>
    </table>
  </div>

  <div class="section">
    <h2>Top Actions</h2>
    <table>
      <thead><tr><th>Priority</th><th>Risk</th><th>Category</th><th>Action</th><th>Rationale</th></tr></thead>
      <tbody>{action_rows}</tbody>
    </table>
  </div>

  <div class="section">
    <h2>Top Findings</h2>
    <table>
      <thead><tr><th>Risk</th><th>Category</th><th>Finding</th><th>Affected</th></tr></thead>
      <tbody>{finding_rows}</tbody>
    </table>
  </div>
</div>
</body>
</html>"""

        with open(output_path, "w", encoding="utf-8") as f:
            f.write(html)

    def _write_csv(self, output_path: str):
        g = self.gov
        score = g.score
        with open(output_path, "w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerow(["section", "key", "value", "status", "details"])

            writer.writerow(["summary", "organization", self.organization, "", ""])
            writer.writerow(["summary", "project", self.project, "", ""])
            writer.writerow(["summary", "scope_statement", g.scope_statement, "", ""])
            writer.writerow(["summary", "collection_mode", g.collection_mode, "", ""])
            writer.writerow(["summary", "governance_grade", score.grade, "", ""])
            writer.writerow(["summary", "governance_score", score.overall_score, "", ""])
            writer.writerow(["summary", "total_findings", len(g.findings), "", ""])
            writer.writerow(["summary", "critical_findings", len(g.critical_findings), "", ""])
            writer.writerow(["summary", "high_findings", len(g.high_findings), "", ""])

            for m in g.simple_measures:
                writer.writerow(["measure", m.label, m.value, m.status, m.description])

            for a in g.top_actions:
                writer.writerow(["action", f"P{a.priority}", a.action, a.risk_level, f"{a.category} | {a.rationale}"])

            for c in g.controls:
                writer.writerow(["control", c.control_id, c.control_name, c.status, f"score={round(c.score,1)}"])

            risk_rank = {RiskLevel.CRITICAL: 0, RiskLevel.HIGH: 1, RiskLevel.MEDIUM: 2, RiskLevel.LOW: 3, RiskLevel.INFO: 4}
            for finding in sorted(g.findings, key=lambda x: risk_rank.get(x.risk_level, 9))[:15]:
                writer.writerow([
                    "finding",
                    finding.title,
                    finding.affected_entity,
                    finding.risk_level,
                    f"{finding.category} | {finding.recommendation}",
                ])
