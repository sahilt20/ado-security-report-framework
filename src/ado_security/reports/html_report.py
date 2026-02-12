"""
Azure DevOps Data Governance HTML Dashboard Report.

Generates an interactive HTML dashboard with Chart.js visualizations,
sortable tables, and a modern responsive design.
"""

import json
import logging
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional

from ..models import PermissionState, SecurityGroup, User, Permission
from ..collectors.permissions import GranularPermissions
from ..analyzers.governance import (
    GovernanceAnalyzer,
    GovernanceReport,
    RiskLevel,
)
from ..analyzers.matrix import FullPermissionReport
from ..analyzers.inheritance import InheritanceAnalyzer

logger = logging.getLogger(__name__)


class HTMLReportGenerator:
    """Generates an interactive HTML governance dashboard."""

    def __init__(
        self,
        organization: str,
        project: str,
        groups: List[SecurityGroup],
        users: List[User],
        permissions: GranularPermissions,
        permission_report: Optional[FullPermissionReport] = None,
        inheritance_analyzer: Optional[InheritanceAnalyzer] = None,
    ):
        self.organization = organization
        self.project = project
        self.groups = groups
        self.users = users
        self.permissions = permissions
        self.permission_report = permission_report
        self.inheritance_analyzer = inheritance_analyzer

        gov = GovernanceAnalyzer(
            groups=groups, users=users, granular_permissions=permissions,
            organization=organization, project=project,
        )
        self.gov: GovernanceReport = gov.analyze()

    def generate(self, output_path: str) -> str:
        Path(output_path).parent.mkdir(parents=True, exist_ok=True)
        html = self._render()
        with open(output_path, "w", encoding="utf-8") as f:
            f.write(html)
        logger.info(f"HTML report saved to {output_path}")
        return output_path

    # ------------------------------------------------------------------
    # Data helpers
    # ------------------------------------------------------------------

    def _risk_color(self, risk: str) -> str:
        return {
            RiskLevel.CRITICAL: "#FF0000",
            RiskLevel.HIGH: "#FF6600",
            RiskLevel.MEDIUM: "#FFB800",
            RiskLevel.LOW: "#2196F3",
            RiskLevel.INFO: "#9E9E9E",
        }.get(risk, "#9E9E9E")

    def _grade_color(self, grade: str) -> str:
        return {"A": "#28A745", "B": "#5CB85C", "C": "#FFC107", "D": "#FF9800", "F": "#DC3545"}.get(grade, "#666")

    def _status_color(self, status: str) -> str:
        return {"Pass": "#28A745", "Warning": "#FFC107", "Fail": "#DC3545"}.get(status, "#9E9E9E")

    # ------------------------------------------------------------------
    # Render
    # ------------------------------------------------------------------

    def _render(self) -> str:
        g = self.gov
        score = g.score

        # Prepare chart data
        findings_by_risk = json.dumps({
            "labels": [RiskLevel.CRITICAL, RiskLevel.HIGH, RiskLevel.MEDIUM, RiskLevel.LOW, RiskLevel.INFO],
            "data": [g.findings_by_risk.get(r, 0) for r in [RiskLevel.CRITICAL, RiskLevel.HIGH, RiskLevel.MEDIUM, RiskLevel.LOW, RiskLevel.INFO]],
            "colors": ["#FF0000", "#FF6600", "#FFB800", "#2196F3", "#9E9E9E"],
        })

        perms_by_service = json.dumps({
            "labels": list(g.permissions_by_service.keys()),
            "data": list(g.permissions_by_service.values()),
        })

        score_radar = json.dumps({
            "labels": ["Access Control", "Least Privilege", "Separation of Duties", "Audit & Compliance", "Lifecycle Mgmt"],
            "data": [
                round(score.access_control_score, 1),
                round(score.least_privilege_score, 1),
                round(score.separation_of_duties_score, 1),
                round(score.audit_compliance_score, 1),
                round(score.lifecycle_management_score, 1),
            ],
        })

        controls_data = json.dumps({
            "labels": [c.control_name for c in g.controls],
            "scores": [round(c.score, 1) for c in g.controls],
            "colors": [self._status_color(c.status) for c in g.controls],
        })

        access_levels: Dict[str, int] = {}
        for u in self.users:
            access_levels[u.access_level] = access_levels.get(u.access_level, 0) + 1
        access_data = json.dumps({
            "labels": list(access_levels.keys()),
            "data": list(access_levels.values()),
        })

        group_members = json.dumps({
            "labels": [gr.display_name for gr in self.groups],
            "data": [gr.member_count or len(gr.members) for gr in self.groups],
        })

        # Permission distribution
        perm_dist = json.dumps({
            "labels": ["Allow (Direct)", "Allow (Inherited)", "Deny"],
            "data": [
                max(0, g.allow_permissions - g.inherited_permissions),
                g.inherited_permissions,
                g.deny_permissions,
            ],
            "colors": ["#28A745", "#0078D4", "#DC3545"],
        })

        # Findings table rows
        risk_order = {RiskLevel.CRITICAL: 0, RiskLevel.HIGH: 1, RiskLevel.MEDIUM: 2, RiskLevel.LOW: 3, RiskLevel.INFO: 4}
        sorted_findings = sorted(g.findings, key=lambda f: risk_order.get(f.risk_level, 5))
        findings_rows = ""
        for i, f in enumerate(sorted_findings):
            rc = self._risk_color(f.risk_level)
            findings_rows += f"""
            <tr>
                <td>{i+1}</td>
                <td><span class="badge" style="background:{rc};color:#fff">{f.risk_level}</span></td>
                <td>{f.category}</td>
                <td><strong>{f.title}</strong></td>
                <td>{f.affected_entity}</td>
                <td class="desc">{f.description}</td>
                <td class="desc">{f.recommendation}</td>
            </tr>"""

        # Controls table
        controls_rows = ""
        for c in g.controls:
            sc = self._status_color(c.status)
            controls_rows += f"""
            <tr>
                <td>{c.control_id}</td>
                <td>{c.control_name}</td>
                <td>{c.category}</td>
                <td><span class="badge" style="background:{sc};color:#fff">{c.status}</span></td>
                <td>{round(c.score,1)}</td>
                <td>{c.description}</td>
            </tr>"""

        # Users table
        users_rows = ""
        for u in self.users:
            status_cls = "active" if u.is_active else "inactive"
            users_rows += f"""
            <tr class="{status_cls}">
                <td>{u.display_name}</td>
                <td>{u.mail_address}</td>
                <td>{u.access_level}</td>
                <td>{"Active" if u.is_active else "Inactive"}</td>
                <td>{u.last_accessed.strftime('%Y-%m-%d') if u.last_accessed else 'Never'}</td>
            </tr>"""

        # Groups table
        groups_rows = ""
        for gr in self.groups:
            groups_rows += f"""
            <tr>
                <td>{gr.display_name}</td>
                <td><span class="badge badge-sm" style="background:{'#0078D4' if gr.group_type=='Default' else '#1B3A5C'};color:#fff">{gr.group_type}</span></td>
                <td>{gr.member_count or len(gr.members)}</td>
                <td>{gr.origin}</td>
                <td class="desc">{gr.description}</td>
            </tr>"""

        grade_color = self._grade_color(score.grade)

        return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Azure DevOps Data Governance Report - {self.organization}/{self.project}</title>
<script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.0/dist/chart.umd.min.js"></script>
<style>
* {{ margin: 0; padding: 0; box-sizing: border-box; }}
body {{ font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; background: #f0f2f5; color: #333; }}
.header {{ background: linear-gradient(135deg, #1B3A5C 0%, #0078D4 100%); color: #fff; padding: 30px 40px; }}
.header h1 {{ font-size: 28px; margin-bottom: 5px; }}
.header p {{ opacity: 0.85; font-size: 14px; }}
.container {{ max-width: 1400px; margin: 0 auto; padding: 20px; }}
.nav {{ background: #fff; border-radius: 8px; margin-bottom: 20px; padding: 10px 20px; box-shadow: 0 2px 4px rgba(0,0,0,0.08); display: flex; flex-wrap: wrap; gap: 8px; }}
.nav a {{ text-decoration: none; color: #1B3A5C; padding: 8px 16px; border-radius: 6px; font-size: 13px; font-weight: 500; transition: all 0.2s; }}
.nav a:hover, .nav a.active {{ background: #0078D4; color: #fff; }}
.section {{ display: none; }}
.section.active {{ display: block; }}
.cards {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(180px, 1fr)); gap: 16px; margin-bottom: 24px; }}
.card {{ background: #fff; border-radius: 10px; padding: 20px; box-shadow: 0 2px 8px rgba(0,0,0,0.06); text-align: center; }}
.card .label {{ font-size: 12px; color: #666; text-transform: uppercase; letter-spacing: 0.5px; }}
.card .value {{ font-size: 32px; font-weight: 700; margin: 8px 0 0; }}
.card.grade .value {{ font-size: 48px; }}
.chart-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(420px, 1fr)); gap: 20px; margin-bottom: 24px; }}
.chart-box {{ background: #fff; border-radius: 10px; padding: 20px; box-shadow: 0 2px 8px rgba(0,0,0,0.06); }}
.chart-box h3 {{ font-size: 15px; color: #1B3A5C; margin-bottom: 12px; }}
.chart-box canvas {{ max-height: 320px; }}
table {{ width: 100%; border-collapse: collapse; font-size: 13px; }}
th {{ background: #1B3A5C; color: #fff; padding: 10px 12px; text-align: left; font-weight: 600; position: sticky; top: 0; }}
td {{ padding: 8px 12px; border-bottom: 1px solid #e8e8e8; }}
tr:nth-child(even) {{ background: #f8f9fa; }}
tr:hover {{ background: #e8f4fd; }}
tr.inactive td {{ opacity: 0.6; }}
.badge {{ display: inline-block; padding: 3px 10px; border-radius: 12px; font-size: 11px; font-weight: 600; }}
.badge-sm {{ font-size: 10px; padding: 2px 8px; }}
.table-container {{ background: #fff; border-radius: 10px; padding: 20px; box-shadow: 0 2px 8px rgba(0,0,0,0.06); margin-bottom: 24px; overflow-x: auto; }}
.table-container h3 {{ font-size: 15px; color: #1B3A5C; margin-bottom: 12px; }}
.desc {{ max-width: 300px; font-size: 12px; }}
.score-bar {{ height: 8px; background: #e0e0e0; border-radius: 4px; overflow: hidden; margin-top: 4px; }}
.score-bar-fill {{ height: 100%; border-radius: 4px; }}
@media (max-width: 768px) {{
    .chart-grid {{ grid-template-columns: 1fr; }}
    .cards {{ grid-template-columns: repeat(2, 1fr); }}
}}
</style>
</head>
<body>
<div class="header">
    <h1>Azure DevOps Data Governance Report</h1>
    <p>Organization: {self.organization} &bull; Project: {self.project} &bull; Generated: {g.generated_at.strftime('%Y-%m-%d %H:%M')}</p>
</div>

<div class="container">
<div class="nav">
    <a href="#" onclick="showSection('dashboard')" class="active" id="nav-dashboard">Dashboard</a>
    <a href="#" onclick="showSection('scores')" id="nav-scores">Governance Scores</a>
    <a href="#" onclick="showSection('controls')" id="nav-controls">Compliance Controls</a>
    <a href="#" onclick="showSection('findings')" id="nav-findings">Risk Findings ({len(g.findings)})</a>
    <a href="#" onclick="showSection('users')" id="nav-users">Users ({len(self.users)})</a>
    <a href="#" onclick="showSection('groups')" id="nav-groups">Groups ({len(self.groups)})</a>
    <a href="#" onclick="showSection('permissions')" id="nav-permissions">Permissions</a>
</div>

<!-- ==================== DASHBOARD ==================== -->
<div id="dashboard" class="section active">
<div class="cards">
    <div class="card grade">
        <div class="label">Governance Grade</div>
        <div class="value" style="color:{grade_color}">{score.grade}</div>
    </div>
    <div class="card">
        <div class="label">Overall Score</div>
        <div class="value" style="color:#0078D4">{score.overall_score}</div>
        <div class="score-bar"><div class="score-bar-fill" style="width:{score.overall_score}%;background:{grade_color}"></div></div>
    </div>
    <div class="card">
        <div class="label">Total Users</div>
        <div class="value">{g.total_users}</div>
    </div>
    <div class="card">
        <div class="label">Active Users</div>
        <div class="value" style="color:#28A745">{g.active_users}</div>
    </div>
    <div class="card">
        <div class="label">Admin Users</div>
        <div class="value" style="color:{'#DC3545' if g.admin_users > 3 else '#0078D4'}">{g.admin_users}</div>
    </div>
    <div class="card">
        <div class="label">External Users</div>
        <div class="value" style="color:{'#FFC107' if g.external_users > 0 else '#28A745'}">{g.external_users}</div>
    </div>
    <div class="card">
        <div class="label">Security Groups</div>
        <div class="value">{g.total_groups}</div>
    </div>
    <div class="card">
        <div class="label">Total Permissions</div>
        <div class="value">{g.total_permissions}</div>
    </div>
    <div class="card">
        <div class="label">Critical Findings</div>
        <div class="value" style="color:#FF0000">{len(g.critical_findings)}</div>
    </div>
    <div class="card">
        <div class="label">High Findings</div>
        <div class="value" style="color:#FF6600">{len(g.high_findings)}</div>
    </div>
</div>

<div class="chart-grid">
    <div class="chart-box"><h3>Findings by Risk Level</h3><canvas id="chartFindingsRisk"></canvas></div>
    <div class="chart-box"><h3>Permissions by Service</h3><canvas id="chartPermsByService"></canvas></div>
    <div class="chart-box"><h3>Permission Distribution</h3><canvas id="chartPermDist"></canvas></div>
    <div class="chart-box"><h3>Access Level Distribution</h3><canvas id="chartAccessLevels"></canvas></div>
    <div class="chart-box"><h3>Members per Group</h3><canvas id="chartGroupMembers"></canvas></div>
    <div class="chart-box"><h3>Governance Score Radar</h3><canvas id="chartRadar"></canvas></div>
</div>
</div>

<!-- ==================== SCORES ==================== -->
<div id="scores" class="section">
<div class="cards">
    <div class="card"><div class="label">Access Control</div><div class="value">{round(score.access_control_score,1)}</div><div class="score-bar"><div class="score-bar-fill" style="width:{score.access_control_score}%;background:#0078D4"></div></div></div>
    <div class="card"><div class="label">Least Privilege</div><div class="value">{round(score.least_privilege_score,1)}</div><div class="score-bar"><div class="score-bar-fill" style="width:{score.least_privilege_score}%;background:#0078D4"></div></div></div>
    <div class="card"><div class="label">Separation of Duties</div><div class="value">{round(score.separation_of_duties_score,1)}</div><div class="score-bar"><div class="score-bar-fill" style="width:{score.separation_of_duties_score}%;background:#0078D4"></div></div></div>
    <div class="card"><div class="label">Audit & Compliance</div><div class="value">{round(score.audit_compliance_score,1)}</div><div class="score-bar"><div class="score-bar-fill" style="width:{score.audit_compliance_score}%;background:#0078D4"></div></div></div>
    <div class="card"><div class="label">Lifecycle Management</div><div class="value">{round(score.lifecycle_management_score,1)}</div><div class="score-bar"><div class="score-bar-fill" style="width:{score.lifecycle_management_score}%;background:#0078D4"></div></div></div>
</div>
<div class="chart-grid">
    <div class="chart-box"><h3>Score Radar</h3><canvas id="chartRadar2"></canvas></div>
    <div class="chart-box"><h3>Compliance Control Scores</h3><canvas id="chartControlScores"></canvas></div>
</div>
</div>

<!-- ==================== CONTROLS ==================== -->
<div id="controls" class="section">
<div class="table-container">
    <h3>Compliance Controls Assessment</h3>
    <table>
        <thead><tr><th>ID</th><th>Control</th><th>Category</th><th>Status</th><th>Score</th><th>Description</th></tr></thead>
        <tbody>{controls_rows}</tbody>
    </table>
</div>
</div>

<!-- ==================== FINDINGS ==================== -->
<div id="findings" class="section">
<div class="table-container">
    <h3>All Risk Findings ({len(sorted_findings)})</h3>
    <table>
        <thead><tr><th>#</th><th>Risk</th><th>Category</th><th>Title</th><th>Entity</th><th>Description</th><th>Recommendation</th></tr></thead>
        <tbody>{findings_rows}</tbody>
    </table>
</div>
</div>

<!-- ==================== USERS ==================== -->
<div id="users" class="section">
<div class="chart-grid">
    <div class="chart-box"><h3>Access Level Distribution</h3><canvas id="chartAccessLevels2"></canvas></div>
    <div class="chart-box"><h3>User Status</h3><canvas id="chartUserStatus"></canvas></div>
</div>
<div class="table-container">
    <h3>Users ({len(self.users)})</h3>
    <table>
        <thead><tr><th>Name</th><th>Email</th><th>Access Level</th><th>Status</th><th>Last Access</th></tr></thead>
        <tbody>{users_rows}</tbody>
    </table>
</div>
</div>

<!-- ==================== GROUPS ==================== -->
<div id="groups" class="section">
<div class="chart-grid">
    <div class="chart-box"><h3>Members per Group</h3><canvas id="chartGroupMembers2"></canvas></div>
    <div class="chart-box"><h3>Group Types</h3><canvas id="chartGroupTypes"></canvas></div>
</div>
<div class="table-container">
    <h3>Security Groups ({len(self.groups)})</h3>
    <table>
        <thead><tr><th>Name</th><th>Type</th><th>Members</th><th>Origin</th><th>Description</th></tr></thead>
        <tbody>{groups_rows}</tbody>
    </table>
</div>
</div>

<!-- ==================== PERMISSIONS ==================== -->
<div id="permissions" class="section">
<div class="chart-grid">
    <div class="chart-box"><h3>Permissions by Service</h3><canvas id="chartPermsByService2"></canvas></div>
    <div class="chart-box"><h3>Permission Distribution</h3><canvas id="chartPermDist2"></canvas></div>
</div>
</div>

<script>
const findingsRisk = {findings_by_risk};
const permsByService = {perms_by_service};
const scoreRadar = {score_radar};
const controlsData = {controls_data};
const accessData = {access_data};
const groupMembers = {group_members};
const permDist = {perm_dist};

function showSection(id) {{
    document.querySelectorAll('.section').forEach(s => s.classList.remove('active'));
    document.querySelectorAll('.nav a').forEach(a => a.classList.remove('active'));
    document.getElementById(id).classList.add('active');
    document.getElementById('nav-'+id).classList.add('active');
}}

// --- Charts ---
const chartOpts = {{ responsive: true, maintainAspectRatio: false, plugins: {{ legend: {{ position: 'bottom' }} }} }};

function pie(ctx, labels, data, colors) {{
    new Chart(ctx, {{ type: 'doughnut', data: {{ labels, datasets: [{{ data, backgroundColor: colors }}] }}, options: chartOpts }});
}}
function bar(ctx, labels, data, color, label) {{
    new Chart(ctx, {{ type: 'bar', data: {{ labels, datasets: [{{ label: label||'Count', data, backgroundColor: color||'#0078D4' }}] }}, options: {{ ...chartOpts, scales: {{ y: {{ beginAtZero: true }} }} }} }});
}}

// Dashboard charts
pie('chartFindingsRisk', findingsRisk.labels, findingsRisk.data, findingsRisk.colors);
bar('chartPermsByService', permsByService.labels, permsByService.data, '#0078D4', 'Permissions');
pie('chartPermDist', permDist.labels, permDist.data, permDist.colors);
pie('chartAccessLevels', accessData.labels, accessData.data, ['#0078D4','#28A745','#FFC107','#DC3545','#9E9E9E','#FF6600']);
bar('chartGroupMembers', groupMembers.labels, groupMembers.data, '#1B3A5C', 'Members');

// Radar
function radar(ctx) {{
    new Chart(ctx, {{
        type: 'radar',
        data: {{
            labels: scoreRadar.labels,
            datasets: [{{ label: 'Score', data: scoreRadar.data, backgroundColor: 'rgba(0,120,212,0.2)', borderColor: '#0078D4', pointBackgroundColor: '#0078D4' }}]
        }},
        options: {{ ...chartOpts, scales: {{ r: {{ beginAtZero: true, max: 100 }} }} }}
    }});
}}
radar('chartRadar');

// Scores tab
radar('chartRadar2');
new Chart('chartControlScores', {{
    type: 'bar',
    data: {{ labels: controlsData.labels, datasets: [{{ label: 'Score', data: controlsData.scores, backgroundColor: controlsData.colors }}] }},
    options: {{ ...chartOpts, indexAxis: 'y', scales: {{ x: {{ beginAtZero: true, max: 100 }} }} }}
}});

// Users tab
pie('chartAccessLevels2', accessData.labels, accessData.data, ['#0078D4','#28A745','#FFC107','#DC3545','#9E9E9E','#FF6600']);
pie('chartUserStatus', ['Active','Inactive'], [{g.active_users},{g.inactive_users}], ['#28A745','#DC3545']);

// Groups tab
bar('chartGroupMembers2', groupMembers.labels, groupMembers.data, '#1B3A5C', 'Members');
pie('chartGroupTypes', ['Default','Custom'], [{g.default_groups},{g.custom_groups}], ['#0078D4','#1B3A5C']);

// Permissions tab
bar('chartPermsByService2', permsByService.labels, permsByService.data, '#0078D4', 'Permissions');
pie('chartPermDist2', permDist.labels, permDist.data, permDist.colors);
</script>
</body>
</html>"""
