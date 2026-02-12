"""
Azure DevOps Data Governance Excel Report Generator.

Generates comprehensive Excel reports with:
- Executive summary dashboard with governance scores
- Visual charts (bar, pie, radar) with proper non-overlapping layout
- Permission details showing resource display names
- Compliance control status
- Risk findings with color-coded severity
- Full user/group/permission details
"""

import logging
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Any

from openpyxl import Workbook
from openpyxl.styles import (
    Font, PatternFill, Alignment, Border, Side,
)
from openpyxl.chart import (
    BarChart, PieChart, RadarChart, Reference,
)
from openpyxl.chart.label import DataLabelList
from openpyxl.chart.series import DataPoint
from openpyxl.utils import get_column_letter

from ..models import (
    Permission,
    PermissionState,
    SecurityGroup,
    User,
)
from ..collectors.namespaces import ServiceNamespaces
from ..collectors.permissions import GranularPermissions
from ..analyzers.matrix import FullPermissionReport
from ..analyzers.inheritance import InheritanceAnalyzer
from ..analyzers.governance import (
    GovernanceAnalyzer,
    GovernanceReport,
    GovernanceFinding,
    RiskLevel,
)

logger = logging.getLogger(__name__)


# --- Color Palette ---
class Colors:
    PRIMARY = "1B3A5C"
    PRIMARY_LIGHT = "2E5984"
    ACCENT = "0078D4"
    ACCENT_LIGHT = "50A0E6"
    SUCCESS = "28A745"
    WARNING = "FFC107"
    DANGER = "DC3545"
    INFO = "17A2B8"
    CRITICAL = "FF0000"
    HIGH = "FF6600"
    MEDIUM = "FFB800"
    LOW = "2196F3"
    INFO_RISK = "9E9E9E"
    ALLOW = "C6EFCE"
    ALLOW_TEXT = "006100"
    DENY = "FFC7CE"
    DENY_TEXT = "9C0006"
    INHERITED = "D6E4F0"
    INHERITED_TEXT = "1F4E79"
    NOT_SET = "F2F2F2"
    WHITE = "FFFFFF"
    LIGHT_GRAY = "F5F5F5"
    GRAY = "E0E0E0"
    DARK_GRAY = "666666"
    BLACK = "000000"
    HEADER_BG = "1B3A5C"
    HEADER_FG = "FFFFFF"
    ROW_ALT = "F0F4F8"
    GRADE_A = "28A745"
    GRADE_B = "5CB85C"
    GRADE_C = "FFC107"
    GRADE_D = "FF9800"
    GRADE_F = "DC3545"


def _hf():
    return Font(name="Calibri", bold=True, color=Colors.HEADER_FG, size=11)

def _hfill():
    return PatternFill(start_color=Colors.HEADER_BG, end_color=Colors.HEADER_BG, fill_type="solid")

def _tfont(sz=16):
    return Font(name="Calibri", bold=True, color=Colors.PRIMARY, size=sz)

def _border():
    s = Side(style="thin", color=Colors.GRAY)
    return Border(left=s, right=s, top=s, bottom=s)

def _center():
    return Alignment(horizontal="center", vertical="center")

SEVERITY_FILLS = {
    RiskLevel.CRITICAL: PatternFill(start_color=Colors.CRITICAL, end_color=Colors.CRITICAL, fill_type="solid"),
    RiskLevel.HIGH: PatternFill(start_color=Colors.HIGH, end_color=Colors.HIGH, fill_type="solid"),
    RiskLevel.MEDIUM: PatternFill(start_color=Colors.MEDIUM, end_color=Colors.MEDIUM, fill_type="solid"),
    RiskLevel.LOW: PatternFill(start_color=Colors.LOW, end_color=Colors.LOW, fill_type="solid"),
    RiskLevel.INFO: PatternFill(start_color=Colors.INFO_RISK, end_color=Colors.INFO_RISK, fill_type="solid"),
}

PERM_STATE_FILLS = {
    PermissionState.ALLOW: PatternFill(start_color=Colors.ALLOW, end_color=Colors.ALLOW, fill_type="solid"),
    PermissionState.DENY: PatternFill(start_color=Colors.DENY, end_color=Colors.DENY, fill_type="solid"),
    PermissionState.INHERITED_ALLOW: PatternFill(start_color=Colors.INHERITED, end_color=Colors.INHERITED, fill_type="solid"),
    PermissionState.INHERITED_DENY: PatternFill(start_color=Colors.DENY, end_color=Colors.DENY, fill_type="solid"),
    PermissionState.NOT_SET: PatternFill(start_color=Colors.NOT_SET, end_color=Colors.NOT_SET, fill_type="solid"),
}

PERM_STATE_FONTS = {
    PermissionState.ALLOW: Font(color=Colors.ALLOW_TEXT, bold=True),
    PermissionState.DENY: Font(color=Colors.DENY_TEXT, bold=True),
    PermissionState.INHERITED_ALLOW: Font(color=Colors.INHERITED_TEXT),
    PermissionState.INHERITED_DENY: Font(color=Colors.DENY_TEXT),
    PermissionState.NOT_SET: Font(color=Colors.DARK_GRAY),
}

STATUS_FILLS = {
    "Pass": PatternFill(start_color=Colors.ALLOW, end_color=Colors.ALLOW, fill_type="solid"),
    "Fail": PatternFill(start_color=Colors.DENY, end_color=Colors.DENY, fill_type="solid"),
    "Warning": PatternFill(start_color="FFF3CD", end_color="FFF3CD", fill_type="solid"),
    "N/A": PatternFill(start_color=Colors.NOT_SET, end_color=Colors.NOT_SET, fill_type="solid"),
}


class ExcelReportGenerator:
    """Generates a multi-sheet Excel Data Governance report."""

    def __init__(
        self,
        organization: str,
        project: str,
        groups: List[SecurityGroup],
        users: List[User],
        namespaces: ServiceNamespaces,
        permissions: GranularPermissions,
        permission_report: Optional[FullPermissionReport] = None,
        inheritance_analyzer: Optional[InheritanceAnalyzer] = None,
    ):
        self.organization = organization
        self.project = project
        self.groups = groups
        self.users = users
        self.namespaces = namespaces
        self.permissions = permissions
        self.permission_report = permission_report
        self.inheritance_analyzer = inheritance_analyzer

        gov = GovernanceAnalyzer(
            groups=groups, users=users, granular_permissions=permissions,
            organization=organization, project=project,
        )
        self.gov: GovernanceReport = gov.analyze()
        self.wb: Optional[Workbook] = None

    def generate(self, output_path: str) -> str:
        Path(output_path).parent.mkdir(parents=True, exist_ok=True)
        self.wb = Workbook()
        self.wb.remove(self.wb.active)

        self._create_executive_summary()
        self._create_scoring_methodology()
        self._create_governance_score()
        self._create_compliance_controls()
        self._create_risk_findings()
        self._create_groups_overview()
        self._create_group_members()
        self._create_users_overview()
        self._create_namespace_inventory()
        self._create_service_permission_sheets()
        self._create_permission_matrix()
        self._create_inheritance_analysis()
        self._create_recommendations()

        self.wb.save(output_path)
        logger.info(f"Report saved to {output_path}")
        return output_path

    # ---- Helpers ----

    def _write_headers(self, ws, row, headers, widths=None):
        for c, h in enumerate(headers, 1):
            cell = ws.cell(row=row, column=c, value=h)
            cell.font = _hf()
            cell.fill = _hfill()
            cell.alignment = _center()
            cell.border = _border()
        if widths:
            for c, w in enumerate(widths, 1):
                ws.column_dimensions[get_column_letter(c)].width = w

    def _write_row(self, ws, row, vals, bold=False, alt=False):
        for c, v in enumerate(vals, 1):
            cell = ws.cell(row=row, column=c, value=v)
            cell.font = Font(name="Calibri", size=10, bold=bold)
            cell.border = _border()
            cell.alignment = Alignment(vertical="center", wrap_text=True)
            if alt:
                cell.fill = PatternFill(start_color=Colors.ROW_ALT, end_color=Colors.ROW_ALT, fill_type="solid")

    def _write_title(self, ws, row, col, text, sz=16):
        ws.cell(row=row, column=col, value=text).font = _tfont(sz)

    def _metric_card(self, ws, row, col, label, value, color=Colors.ACCENT):
        c1 = ws.cell(row=row, column=col, value=label)
        c1.font = Font(name="Calibri", size=9, color=Colors.DARK_GRAY)
        c1.alignment = Alignment(horizontal="center")
        c2 = ws.cell(row=row + 1, column=col, value=value)
        c2.font = Font(name="Calibri", size=18, bold=True, color=color)
        c2.alignment = Alignment(horizontal="center")
        for r in (row, row + 1):
            ws.cell(row=r, column=col).fill = PatternFill(start_color="F0F4F8", end_color="F0F4F8", fill_type="solid")
            ws.cell(row=r, column=col).border = _border()

    def _grade_color(self, score_val):
        if score_val >= 90: return Colors.GRADE_A
        if score_val >= 80: return Colors.GRADE_B
        if score_val >= 70: return Colors.GRADE_C
        if score_val >= 60: return Colors.GRADE_D
        return Colors.GRADE_F

    # ---- Sheet 1: Executive Summary ----

    def _create_executive_summary(self):
        ws = self.wb.create_sheet("Executive Summary")
        ws.sheet_properties.tabColor = Colors.PRIMARY
        gr = self.gov

        self._write_title(ws, 1, 1, "Azure DevOps Project-Level Data Governance Report", 20)
        ws.merge_cells("A1:J1")
        sub = ws.cell(row=2, column=1,
            value=f"Organization: {self.organization}  |  Project: {self.project}  |  Scope: Project Admin  |  Generated: {gr.generated_at.strftime('%Y-%m-%d %H:%M')}")
        sub.font = Font(name="Calibri", size=10, color=Colors.DARK_GRAY)
        ws.merge_cells("A2:J2")

        # Grade + score
        row = 4
        gc = self._grade_color(gr.score.overall_score)
        ws.cell(row=row, column=1, value="GOVERNANCE GRADE").font = Font(name="Calibri", size=9, color=Colors.DARK_GRAY, bold=True)
        g_cell = ws.cell(row=row + 1, column=1, value=gr.score.grade)
        g_cell.font = Font(name="Calibri", size=36, bold=True, color=gc)
        g_cell.alignment = _center()
        ws.merge_cells(f"A{row+1}:A{row+2}")

        ws.cell(row=row, column=2, value="OVERALL SCORE").font = Font(name="Calibri", size=9, color=Colors.DARK_GRAY, bold=True)
        s_cell = ws.cell(row=row + 1, column=2, value=f"{gr.score.overall_score}/100")
        s_cell.font = Font(name="Calibri", size=20, bold=True, color=Colors.PRIMARY)
        s_cell.alignment = _center()
        ws.merge_cells(f"B{row+1}:B{row+2}")

        # Key metrics
        row = 8
        ws.cell(row=row, column=1, value="KEY METRICS").font = Font(name="Calibri", size=12, bold=True, color=Colors.PRIMARY)
        row = 9
        metrics = [
            ("Total Users", gr.total_users, Colors.ACCENT),
            ("Active Users", gr.active_users, Colors.SUCCESS),
            ("Inactive Users", gr.inactive_users, Colors.WARNING if gr.inactive_users > 0 else Colors.SUCCESS),
            ("Admin Users", gr.admin_users, Colors.DANGER if gr.admin_users > 3 else Colors.ACCENT),
            ("External Users", gr.external_users, Colors.WARNING if gr.external_users > 0 else Colors.SUCCESS),
            ("Total Groups", gr.total_groups, Colors.ACCENT),
            ("Empty Groups", gr.empty_groups, Colors.WARNING if gr.empty_groups > 0 else Colors.SUCCESS),
            ("Total Permissions", gr.total_permissions, Colors.ACCENT),
            ("Stale Users", gr.stale_users, Colors.DANGER if gr.stale_users > 0 else Colors.SUCCESS),
            ("Overprivileged", gr.overprivileged_users, Colors.DANGER if gr.overprivileged_users > 0 else Colors.SUCCESS),
        ]
        for i, (lbl, val, clr) in enumerate(metrics):
            self._metric_card(ws, row, i + 1, lbl, val, clr)

        # Findings summary table - left side (cols A-C, rows 12-18)
        row = 12
        ws.cell(row=row, column=1, value="FINDINGS SUMMARY").font = Font(name="Calibri", size=12, bold=True, color=Colors.PRIMARY)
        row = 13
        self._write_headers(ws, row, ["Risk Level", "Count", "Description"], [18, 12, 35])
        risk_order = [RiskLevel.CRITICAL, RiskLevel.HIGH, RiskLevel.MEDIUM, RiskLevel.LOW, RiskLevel.INFO]
        for i, risk in enumerate(risk_order):
            cnt = gr.findings_by_risk.get(risk, 0)
            r = row + 1 + i
            self._write_row(ws, r, [risk, cnt, f"{risk}-level governance findings"])
            ws.cell(row=r, column=1).fill = SEVERITY_FILLS.get(risk, PatternFill())
            if risk in (RiskLevel.CRITICAL, RiskLevel.HIGH):
                ws.cell(row=r, column=1).font = Font(name="Calibri", size=10, bold=True, color=Colors.WHITE)

        # Pie chart: findings by risk - right of summary table
        pie = PieChart()
        pie.title = "Findings by Risk Level"
        pie.style = 10
        pie.width = 14
        pie.height = 10
        cats = Reference(ws, min_col=1, min_row=row + 1, max_row=row + 5)
        vals = Reference(ws, min_col=2, min_row=row + 1, max_row=row + 5)
        pie.add_data(vals, titles_from_data=False)
        pie.set_categories(cats)
        for idx, c in enumerate([Colors.CRITICAL, Colors.HIGH, Colors.MEDIUM, Colors.LOW, Colors.INFO_RISK]):
            pt = DataPoint(idx=idx)
            pt.graphicalProperties.solidFill = c
            pie.series[0].data_points.append(pt)
        pie.dataLabels = DataLabelList()
        pie.dataLabels.showPercent = True
        pie.dataLabels.showVal = True
        ws.add_chart(pie, "E12")

        # Permissions by service - table below findings (row 20+)
        row = 20
        ws.cell(row=row, column=1, value="PERMISSIONS BY SERVICE").font = Font(name="Calibri", size=12, bold=True, color=Colors.PRIMARY)
        row = 21
        self._write_headers(ws, row, ["Service", "Permissions", "Risk"], [22, 14, 14])
        services = sorted(gr.permissions_by_service.items(), key=lambda x: x[1], reverse=True)
        for i, (svc, cnt) in enumerate(services):
            r = row + 1 + i
            risk = gr.risk_by_service.get(svc, "Info")
            self._write_row(ws, r, [svc, cnt, risk], alt=i % 2 == 1)
            rf = SEVERITY_FILLS.get(risk)
            if rf:
                ws.cell(row=r, column=3).fill = rf
                if risk in (RiskLevel.CRITICAL, RiskLevel.HIGH):
                    ws.cell(row=r, column=3).font = Font(color=Colors.WHITE, bold=True)

        # Bar chart: perms by service - right side, below pie chart
        end_svc_row = row + len(services)
        if services:
            bar = BarChart()
            bar.type = "col"
            bar.style = 10
            bar.title = "Permissions by Service Area"
            bar.y_axis.title = "Count"
            bar.width = 18
            bar.height = 10
            d = Reference(ws, min_col=2, min_row=row, max_row=end_svc_row)
            ca = Reference(ws, min_col=1, min_row=row + 1, max_row=end_svc_row)
            bar.add_data(d, titles_from_data=True)
            bar.set_categories(ca)
            bar.series[0].graphicalProperties.solidFill = Colors.ACCENT
            ws.add_chart(bar, f"E{max(23, end_svc_row + 2)}")

        # Permission distribution - below service table
        perm_dist_row = end_svc_row + 2
        ws.cell(row=perm_dist_row, column=1, value="PERMISSION DISTRIBUTION").font = Font(name="Calibri", size=12, bold=True, color=Colors.PRIMARY)
        perm_dist_row += 1
        self._write_headers(ws, perm_dist_row, ["State", "Count"], [20, 15])
        allow_direct = max(0, gr.allow_permissions - gr.inherited_permissions)
        states_data = [
            ("Allow (Direct)", allow_direct),
            ("Allow (Inherited)", gr.inherited_permissions),
            ("Deny", gr.deny_permissions),
            ("Direct Assignments", gr.direct_permissions),
        ]
        for i, (lbl, cnt) in enumerate(states_data):
            self._write_row(ws, perm_dist_row + 1 + i, [lbl, cnt])

        ws.column_dimensions["A"].width = 22
        ws.column_dimensions["B"].width = 18
        ws.column_dimensions["C"].width = 18

    # ---- Sheet: Scoring Methodology ----

    def _create_scoring_methodology(self):
        ws = self.wb.create_sheet("Scoring Methodology")
        ws.sheet_properties.tabColor = "5B9BD5"
        gr = self.gov

        self._write_title(ws, 1, 1, "Scoring Methodology & Grading Logic", 18)
        ws.merge_cells("A1:H1")
        ws.cell(row=2, column=1,
            value="How the governance grade is calculated, what each dimension measures, and how control scores work."
        ).font = Font(name="Calibri", size=10, color=Colors.DARK_GRAY, italic=True)
        ws.merge_cells("A2:H2")

        # ----- Section 1: Grade Scale -----
        row = 4
        ws.cell(row=row, column=1, value="GRADE SCALE").font = Font(name="Calibri", size=12, bold=True, color=Colors.PRIMARY)
        row += 1
        self._write_headers(ws, row, ["Grade", "Score Range", "Description"],
                            widths=[10, 16, 55])
        grade_rows = [
            ("A", "90 - 100", "Excellent. Project follows security best practices with minimal findings."),
            ("B", "80 - 89", "Good. Minor improvements recommended; no critical or high-risk issues."),
            ("C", "70 - 79", "Fair. Several governance gaps identified that should be addressed."),
            ("D", "60 - 69", "Poor. Significant issues present; immediate remediation recommended."),
            ("F", "0 - 59", "Failing. Critical governance deficiencies; urgent action required."),
        ]
        grade_colors = {
            "A": Colors.GRADE_A, "B": Colors.GRADE_B,
            "C": Colors.GRADE_C, "D": Colors.GRADE_D, "F": Colors.GRADE_F,
        }
        for g_letter, g_range, g_desc in grade_rows:
            row += 1
            c = ws.cell(row=row, column=1, value=g_letter)
            c.font = Font(name="Calibri", size=14, bold=True, color=grade_colors.get(g_letter, Colors.PRIMARY))
            c.alignment = _center()
            ws.cell(row=row, column=2, value=g_range).alignment = _center()
            ws.cell(row=row, column=3, value=g_desc)

        # ----- Section 2: Overall Score Formula -----
        row += 2
        ws.cell(row=row, column=1, value="OVERALL SCORE FORMULA").font = Font(name="Calibri", size=12, bold=True, color=Colors.PRIMARY)
        ws.merge_cells(start_row=row, start_column=1, end_row=row, end_column=3)
        row += 1
        ws.cell(row=row, column=1,
            value="Overall Score  =  (Access Control x 25%)  +  (Least Privilege x 25%)  +  (Separation of Duties x 15%)  +  (Audit & Compliance x 20%)  +  (Lifecycle Management x 15%)"
        ).font = Font(name="Calibri", size=10, bold=True)
        ws.merge_cells(start_row=row, start_column=1, end_row=row, end_column=8)

        # ----- Section 3: Governance Dimensions -----
        row += 2
        ws.cell(row=row, column=1, value="GOVERNANCE DIMENSIONS").font = Font(name="Calibri", size=12, bold=True, color=Colors.PRIMARY)
        row += 1
        self._write_headers(ws, row, ["Dimension", "Weight", "Measures", "Source Controls", "Your Score"],
                            widths=[24, 10, 55, 32, 14])

        dimensions = [
            (
                "Access Control", "25%",
                "Admin user count, external user access, empty groups, branch policy bypasses, large groups",
                "GOV-001, GOV-004, GOV-005, GOV-008",
                f"{gr.score.access_control_score:.1f}",
            ),
            (
                "Least Privilege", "25%",
                "Overprivileged users, high-risk permissions on custom groups, pipeline destructive perms, license waste, broad contributor access",
                "GOV-002, GOV-007, GOV-009, GOV-010",
                f"{gr.score.least_privilege_score:.1f}",
            ),
            (
                "Separation of Duties", "15%",
                "Users with combined Build + Release admin, admins with multiple critical roles",
                "GOV-006",
                f"{gr.score.separation_of_duties_score:.1f}",
            ),
            (
                "Audit & Compliance", "20%",
                "Total finding density (Critical: -15 pts each, High: -8 pts each, Medium/Low: -2 pts each)",
                "Finding density formula",
                f"{gr.score.audit_compliance_score:.1f}",
            ),
            (
                "Lifecycle Management", "15%",
                "Stale/inactive accounts still having project access",
                "GOV-003",
                f"{gr.score.lifecycle_management_score:.1f}",
            ),
        ]
        for dim_name, weight, measures, source, score_val in dimensions:
            row += 1
            ws.cell(row=row, column=1, value=dim_name).font = Font(name="Calibri", bold=True)
            ws.cell(row=row, column=2, value=weight).alignment = _center()
            ws.cell(row=row, column=3, value=measures)
            ws.cell(row=row, column=4, value=source)
            sc = ws.cell(row=row, column=5, value=float(score_val))
            sc.alignment = _center()
            sc.number_format = "0.0"
            if float(score_val) >= 80:
                sc.font = Font(color=Colors.ALLOW_TEXT, bold=True)
            elif float(score_val) >= 60:
                sc.font = Font(color=Colors.MEDIUM, bold=True)
            else:
                sc.font = Font(color=Colors.DENY_TEXT, bold=True)

        # ----- Section 4: Compliance Controls Detail -----
        row += 2
        ws.cell(row=row, column=1, value="COMPLIANCE CONTROL SCORING").font = Font(name="Calibri", size=12, bold=True, color=Colors.PRIMARY)
        row += 1
        self._write_headers(ws, row,
            ["Control ID", "Control Name", "Category", "Pass Criteria (Score 100)", "Warning Criteria", "Fail Criteria", "Your Status", "Your Score"],
            widths=[12, 30, 20, 38, 38, 38, 14, 12])

        control_criteria = [
            ("GOV-001", "Administrative Access Control", "Access Control",
             "Admin users <= 3", "Admin users 4-5 (score 60)", "Admin users > 5 (score 20)"),
            ("GOV-002", "Least Privilege Enforcement", "Least Privilege",
             "0 overprivileged users", "1-2 overprivileged (score 60)", "> 2 overprivileged (score 30)"),
            ("GOV-003", "Stale Account Management", "Lifecycle Mgmt",
             "0 stale accounts", "1-2 stale (score 60)", "> 2 stale (score 30)"),
            ("GOV-004", "External User Access Control", "Access Control",
             "0 external users", "1-3 external (score 50-70)", "External user has admin (score 0)"),
            ("GOV-005", "Security Group Hygiene", "Access Control",
             "0 empty groups", "1-2 empty groups (score 70)", "> 2 empty groups (score 40)"),
            ("GOV-006", "Separation of Duties", "Separation of Duties",
             "No SoD findings", "Non-critical SoD findings (score 70)", "Critical/High SoD (score 30)"),
            ("GOV-007", "High-Risk Permission Control", "Least Privilege",
             "No high-risk findings", "1-3 high-risk findings (score 60)", "> 3 high-risk findings (score 30)"),
            ("GOV-008", "Branch Policy Enforcement", "Branch Policy",
             "No bypass findings", "Low/Med bypass findings (score 70)", "Custom groups bypass policies (score 30)"),
            ("GOV-009", "Pipeline Security Controls", "Pipeline Security",
             "No destructive findings", "Low/Med destructive findings (score 65)", "Custom groups have destructive perms (score 30)"),
            ("GOV-010", "License Optimization", "License Optimization",
             "No license findings", "Stakeholder mismatches (score 75)", "Premium licenses on inactive users (score 40)"),
        ]

        # Map control IDs to actual results
        ctrl_by_id = {c.control_id: c for c in gr.controls}
        for cid, cname, ccat, pass_c, warn_c, fail_c in control_criteria:
            row += 1
            ws.cell(row=row, column=1, value=cid).font = Font(name="Calibri", bold=True)
            ws.cell(row=row, column=2, value=cname)
            ws.cell(row=row, column=3, value=ccat)
            ws.cell(row=row, column=4, value=pass_c)
            ws.cell(row=row, column=5, value=warn_c)
            ws.cell(row=row, column=6, value=fail_c)
            ctrl = ctrl_by_id.get(cid)
            if ctrl:
                sc = ws.cell(row=row, column=7, value=ctrl.status)
                sc.alignment = _center()
                if ctrl.status in STATUS_FILLS:
                    sc.fill = STATUS_FILLS[ctrl.status]
                sv = ws.cell(row=row, column=8, value=ctrl.score)
                sv.alignment = _center()
                sv.number_format = "0"
            else:
                ws.cell(row=row, column=7, value="N/A").alignment = _center()
                ws.cell(row=row, column=8, value="-").alignment = _center()

        # ----- Section 5: Audit & Compliance Scoring -----
        row += 2
        ws.cell(row=row, column=1, value="AUDIT & COMPLIANCE SCORING").font = Font(name="Calibri", size=12, bold=True, color=Colors.PRIMARY)
        row += 1
        ws.cell(row=row, column=1,
            value="Audit & Compliance is calculated from finding density rather than specific controls:"
        ).font = Font(name="Calibri", size=10, italic=True)
        ws.merge_cells(start_row=row, start_column=1, end_row=row, end_column=6)
        row += 1
        self._write_headers(ws, row, ["Finding Severity", "Point Deduction Per Finding", "Your Count", "Points Lost"],
                            widths=[22, 30, 14, 14])
        crit_count = len(gr.critical_findings)
        high_count = len(gr.high_findings)
        other_count = len(gr.findings) - crit_count - high_count
        audit_data = [
            ("Critical", 15, crit_count),
            ("High", 8, high_count),
            ("Medium / Low / Info", 2, other_count),
        ]
        total_lost = 0
        for sev, deduction, count in audit_data:
            row += 1
            ws.cell(row=row, column=1, value=sev).font = Font(name="Calibri", bold=True)
            ws.cell(row=row, column=2, value=f"-{deduction} points per finding").alignment = _center()
            ws.cell(row=row, column=3, value=count).alignment = _center()
            lost = deduction * count
            total_lost += lost
            ws.cell(row=row, column=4, value=lost).alignment = _center()
        row += 1
        ws.cell(row=row, column=1, value="TOTAL").font = Font(name="Calibri", bold=True)
        ws.cell(row=row, column=2, value=f"Base: 100 - {total_lost} = {max(0, 100 - total_lost)}").font = Font(bold=True)
        ws.merge_cells(start_row=row, start_column=2, end_row=row, end_column=3)
        sv = ws.cell(row=row, column=4, value=gr.score.audit_compliance_score)
        sv.alignment = _center()
        sv.font = Font(name="Calibri", bold=True, size=12)
        sv.number_format = "0.0"

        # ----- Section 6: Risk Level Definitions -----
        row += 2
        ws.cell(row=row, column=1, value="RISK LEVEL DEFINITIONS").font = Font(name="Calibri", size=12, bold=True, color=Colors.PRIMARY)
        row += 1
        self._write_headers(ws, row, ["Risk Level", "Description", "Example"],
                            widths=[14, 50, 50])
        risk_defs = [
            ("Critical", "Immediate security threat; exploitable with high business impact.", "External user has Project Administrator role"),
            ("High", "Significant governance gap that should be fixed within days.", "Custom group can bypass branch policies; user in both Build + Release admin"),
            ("Medium", "Moderate issue that should be addressed in the next sprint.", "Broad write access across 6+ resources; premium license on inactive user"),
            ("Low", "Minor improvement opportunity; address during regular reviews.", "Stakeholder users in contributor groups; groups with 10-20 members"),
            ("Info", "Informational only; no action required unless relevant.", "Permission inheritance observations"),
        ]
        for rlevel, rdesc, rexample in risk_defs:
            row += 1
            c = ws.cell(row=row, column=1, value=rlevel)
            c.alignment = _center()
            c.font = Font(name="Calibri", bold=True, color="FFFFFF")
            if rlevel in SEVERITY_FILLS:
                c.fill = SEVERITY_FILLS[rlevel]
            ws.cell(row=row, column=2, value=rdesc)
            ws.cell(row=row, column=3, value=rexample).font = Font(name="Calibri", italic=True, color=Colors.DARK_GRAY)

        # ----- Section 7: Permission State Legend -----
        row += 2
        ws.cell(row=row, column=1, value="PERMISSION STATE LEGEND").font = Font(name="Calibri", size=12, bold=True, color=Colors.PRIMARY)
        row += 1
        self._write_headers(ws, row, ["State", "Meaning"],
                            widths=[20, 60])
        state_defs = [
            ("Allow", "Explicitly granted at this scope."),
            ("Deny", "Explicitly denied at this scope (overrides allow)."),
            ("Inherited Allow", "Granted via parent group or higher scope."),
            ("Inherited Deny", "Denied via parent group or higher scope."),
            ("Not Set", "No explicit grant or denial; effectively no access unless inherited."),
        ]
        for sname, smeaning in state_defs:
            row += 1
            st_enum = {
                "Allow": PermissionState.ALLOW,
                "Deny": PermissionState.DENY,
                "Inherited Allow": PermissionState.INHERITED_ALLOW,
                "Inherited Deny": PermissionState.INHERITED_DENY,
                "Not Set": PermissionState.NOT_SET,
            }.get(sname)
            c = ws.cell(row=row, column=1, value=sname)
            c.alignment = _center()
            if st_enum in PERM_STATE_FILLS:
                c.fill = PERM_STATE_FILLS[st_enum]
            if st_enum in PERM_STATE_FONTS:
                c.font = PERM_STATE_FONTS[st_enum]
            ws.cell(row=row, column=2, value=smeaning)

    # ---- Sheet 2: Governance Score ----

    def _create_governance_score(self):
        ws = self.wb.create_sheet("Governance Score")
        ws.sheet_properties.tabColor = Colors.ACCENT
        score = self.gov.score

        self._write_title(ws, 1, 1, "Governance Score Breakdown", 16)
        ws.merge_cells("A1:F1")

        row = 3
        categories = [
            ("Access Control", score.access_control_score),
            ("Least Privilege", score.least_privilege_score),
            ("Separation of Duties", score.separation_of_duties_score),
            ("Audit & Compliance", score.audit_compliance_score),
            ("Lifecycle Management", score.lifecycle_management_score),
            ("OVERALL", score.overall_score),
        ]

        self._write_headers(ws, row, ["Governance Area", "Score", "Grade", "Status"], [30, 12, 10, 20])
        for i, (cat, sc) in enumerate(categories):
            r = row + 1 + i
            grade = "A" if sc >= 90 else "B" if sc >= 80 else "C" if sc >= 70 else "D" if sc >= 60 else "F"
            status = "Excellent" if sc >= 90 else "Good" if sc >= 80 else "Needs Improvement" if sc >= 70 else "At Risk" if sc >= 60 else "Critical"
            self._write_row(ws, r, [cat, round(sc, 1), grade, status], bold=(cat == "OVERALL"))
            gc = self._grade_color(sc)
            ws.cell(row=r, column=2).font = Font(name="Calibri", size=11, bold=True, color=gc)
            ws.cell(row=r, column=3).font = Font(name="Calibri", size=11, bold=True, color=gc)

        # Radar data in columns F-G
        radar_row = row
        for i, (cat, sc) in enumerate(categories[:-1]):
            ws.cell(row=radar_row + 1 + i, column=6, value=cat)
            ws.cell(row=radar_row + 1 + i, column=7, value=round(sc, 1))
        ws.cell(row=radar_row, column=7, value="Score")

        radar = RadarChart()
        radar.type = "filled"
        radar.title = "Governance Score Radar"
        radar.style = 10
        radar.width = 16
        radar.height = 12
        ca = Reference(ws, min_col=6, min_row=radar_row + 1, max_row=radar_row + 5)
        d = Reference(ws, min_col=7, min_row=radar_row, max_row=radar_row + 5)
        radar.add_data(d, titles_from_data=True)
        radar.set_categories(ca)
        radar.series[0].graphicalProperties.solidFill = Colors.ACCENT_LIGHT
        ws.add_chart(radar, "A12")

        # Bar chart below radar
        bar = BarChart()
        bar.type = "col"
        bar.style = 10
        bar.title = "Score by Governance Area"
        bar.y_axis.title = "Score (0-100)"
        bar.y_axis.scaling.max = 100
        bar.y_axis.scaling.min = 0
        bar.width = 16
        bar.height = 10
        d2 = Reference(ws, min_col=7, min_row=radar_row, max_row=radar_row + 5)
        ca2 = Reference(ws, min_col=6, min_row=radar_row + 1, max_row=radar_row + 5)
        bar.add_data(d2, titles_from_data=True)
        bar.set_categories(ca2)
        bar.series[0].graphicalProperties.solidFill = Colors.PRIMARY_LIGHT
        ws.add_chart(bar, "A28")

        ws.column_dimensions["F"].width = 25
        ws.column_dimensions["G"].width = 12

    # ---- Sheet 3: Compliance Controls ----

    def _create_compliance_controls(self):
        ws = self.wb.create_sheet("Compliance Controls")
        ws.sheet_properties.tabColor = "28A745"
        gr = self.gov

        self._write_title(ws, 1, 1, "Compliance Control Assessment", 16)
        ws.merge_cells("A1:G1")

        row = 3
        headers = ["Control ID", "Control Name", "Category", "Description", "Status", "Score", "Action Required"]
        widths = [14, 30, 20, 45, 12, 10, 40]
        self._write_headers(ws, row, headers, widths)

        for i, ctrl in enumerate(gr.controls):
            r = row + 1 + i
            action = "" if ctrl.status == "Pass" else "Review and remediate findings"
            self._write_row(ws, r, [
                ctrl.control_id, ctrl.control_name, ctrl.category,
                ctrl.description, ctrl.status, round(ctrl.score, 1), action,
            ], alt=i % 2 == 1)
            sf = STATUS_FILLS.get(ctrl.status)
            if sf:
                ws.cell(row=r, column=5).fill = sf

        # Status chart below table
        cr = row + len(gr.controls) + 2
        pass_c = sum(1 for c in gr.controls if c.status == "Pass")
        warn_c = sum(1 for c in gr.controls if c.status == "Warning")
        fail_c = sum(1 for c in gr.controls if c.status == "Fail")

        ws.cell(row=cr, column=1, value="Status"); ws.cell(row=cr, column=2, value="Count")
        for j, (lbl, cnt) in enumerate([("Pass", pass_c), ("Warning", warn_c), ("Fail", fail_c)]):
            ws.cell(row=cr + 1 + j, column=1, value=lbl)
            ws.cell(row=cr + 1 + j, column=2, value=cnt)

        pie = PieChart()
        pie.title = "Control Status Distribution"
        pie.style = 10; pie.width = 14; pie.height = 10
        ca = Reference(ws, min_col=1, min_row=cr + 1, max_row=cr + 3)
        d = Reference(ws, min_col=2, min_row=cr + 1, max_row=cr + 3)
        pie.add_data(d, titles_from_data=False)
        pie.set_categories(ca)
        for idx, c in enumerate([Colors.SUCCESS, Colors.WARNING, Colors.DANGER]):
            pt = DataPoint(idx=idx); pt.graphicalProperties.solidFill = c
            pie.series[0].data_points.append(pt)
        pie.dataLabels = DataLabelList()
        pie.dataLabels.showPercent = True; pie.dataLabels.showVal = True
        ws.add_chart(pie, f"D{cr}")

    # ---- Sheet 4: Risk Findings ----

    def _create_risk_findings(self):
        ws = self.wb.create_sheet("Risk Findings")
        ws.sheet_properties.tabColor = Colors.DANGER
        gr = self.gov

        self._write_title(ws, 1, 1, "Governance Risk Findings", 16)
        ws.merge_cells("A1:H1")

        row = 3
        headers = ["#", "Risk Level", "Category", "Title", "Affected Entity", "Entity Type", "Description", "Recommendation"]
        widths = [5, 14, 22, 35, 25, 12, 50, 45]
        self._write_headers(ws, row, headers, widths)

        ro = {RiskLevel.CRITICAL: 0, RiskLevel.HIGH: 1, RiskLevel.MEDIUM: 2, RiskLevel.LOW: 3, RiskLevel.INFO: 4}
        sorted_f = sorted(gr.findings, key=lambda f: ro.get(f.risk_level, 5))

        for i, f in enumerate(sorted_f):
            r = row + 1 + i
            self._write_row(ws, r, [
                i + 1, f.risk_level, f.category, f.title,
                f.affected_entity, f.entity_type, f.description, f.recommendation,
            ], alt=i % 2 == 1)
            sf = SEVERITY_FILLS.get(f.risk_level)
            if sf:
                ws.cell(row=r, column=2).fill = sf
                if f.risk_level in (RiskLevel.CRITICAL, RiskLevel.HIGH):
                    ws.cell(row=r, column=2).font = Font(color=Colors.WHITE, bold=True)

        # Category chart - below table
        cat_row = row + len(sorted_f) + 2
        ws.cell(row=cat_row, column=1, value="Category"); ws.cell(row=cat_row, column=2, value="Count")
        cat_data = sorted(gr.findings_by_category.items(), key=lambda x: x[1], reverse=True)
        for j, (cat, cnt) in enumerate(cat_data):
            ws.cell(row=cat_row + 1 + j, column=1, value=cat)
            ws.cell(row=cat_row + 1 + j, column=2, value=cnt)

        if cat_data:
            bar = BarChart()
            bar.type = "col"; bar.style = 10; bar.title = "Findings by Category"
            bar.y_axis.title = "Count"; bar.width = 16; bar.height = 10
            d = Reference(ws, min_col=2, min_row=cat_row, max_row=cat_row + len(cat_data))
            ca = Reference(ws, min_col=1, min_row=cat_row + 1, max_row=cat_row + len(cat_data))
            bar.add_data(d, titles_from_data=True); bar.set_categories(ca)
            bar.series[0].graphicalProperties.solidFill = Colors.PRIMARY_LIGHT
            ws.add_chart(bar, f"D{cat_row}")

    # ---- Sheet 5: Groups Overview ----

    def _create_groups_overview(self):
        ws = self.wb.create_sheet("Groups Overview")
        ws.sheet_properties.tabColor = Colors.ACCENT
        self._write_title(ws, 1, 1, "Security Groups Overview", 14)
        ws.merge_cells("A1:G1")

        row = 3
        self._write_headers(ws, row, ["Group Name", "Type", "Origin", "Members", "Description", "Principal Name"],
                            [28, 12, 10, 10, 45, 40])
        for i, g in enumerate(self.groups):
            r = row + 1 + i
            self._write_row(ws, r, [
                g.display_name, g.group_type, g.origin,
                g.member_count or len(g.members), g.description, g.principal_name,
            ], alt=i % 2 == 1)

        # Charts below table
        cr = row + len(self.groups) + 2
        custom = sum(1 for g in self.groups if g.group_type == "Custom")
        default = len(self.groups) - custom
        ws.cell(row=cr, column=1, value="Type"); ws.cell(row=cr, column=2, value="Count")
        ws.cell(row=cr + 1, column=1, value="Default"); ws.cell(row=cr + 1, column=2, value=default)
        ws.cell(row=cr + 2, column=1, value="Custom"); ws.cell(row=cr + 2, column=2, value=custom)

        pie = PieChart()
        pie.title = "Group Types"; pie.style = 10; pie.width = 12; pie.height = 9
        ca = Reference(ws, min_col=1, min_row=cr + 1, max_row=cr + 2)
        d = Reference(ws, min_col=2, min_row=cr + 1, max_row=cr + 2)
        pie.add_data(d, titles_from_data=False); pie.set_categories(ca)
        for idx, c in enumerate([Colors.ACCENT, Colors.PRIMARY_LIGHT]):
            pt = DataPoint(idx=idx); pt.graphicalProperties.solidFill = c
            pie.series[0].data_points.append(pt)
        pie.dataLabels = DataLabelList(); pie.dataLabels.showPercent = True
        ws.add_chart(pie, f"A{cr}")

        # Members bar chart - to the right
        mcr = cr
        ws.cell(row=mcr, column=5, value="Group"); ws.cell(row=mcr, column=6, value="Members")
        for j, g in enumerate(self.groups):
            ws.cell(row=mcr + 1 + j, column=5, value=g.display_name)
            ws.cell(row=mcr + 1 + j, column=6, value=g.member_count or len(g.members))
        ws.column_dimensions["E"].width = 25; ws.column_dimensions["F"].width = 12

        bar = BarChart()
        bar.type = "col"; bar.style = 10; bar.title = "Members per Group"
        bar.y_axis.title = "Count"; bar.width = 16; bar.height = 10
        d = Reference(ws, min_col=6, min_row=mcr, max_row=mcr + len(self.groups))
        ca = Reference(ws, min_col=5, min_row=mcr + 1, max_row=mcr + len(self.groups))
        bar.add_data(d, titles_from_data=True); bar.set_categories(ca)
        bar.series[0].graphicalProperties.solidFill = Colors.ACCENT
        ws.add_chart(bar, f"E{cr + max(3, len(self.groups)) + 1}")

    # ---- Sheet 6: Group Members ----

    def _create_group_members(self):
        ws = self.wb.create_sheet("Group Members")
        ws.sheet_properties.tabColor = Colors.ACCENT
        self._write_title(ws, 1, 1, "Group Membership Details", 14)
        ws.merge_cells("A1:F1")

        row = 3
        self._write_headers(ws, row, ["Group", "Member Name", "Member Type", "Principal Name", "Active", "Origin"],
                            [25, 25, 12, 35, 10, 10])
        r = row
        for g in self.groups:
            if not g.members:
                r += 1
                self._write_row(ws, r, [g.display_name, "(no members)", "", "", "", ""])
                ws.cell(row=r, column=2).font = Font(name="Calibri", size=10, italic=True, color=Colors.DARK_GRAY)
                continue
            for m in g.members:
                r += 1
                self._write_row(ws, r, [
                    g.display_name, m.display_name, m.member_type,
                    m.principal_name, "Yes" if m.is_active else "No", m.origin,
                ], alt=(r - row) % 2 == 1)
                if not m.is_active:
                    ws.cell(row=r, column=5).fill = PatternFill(start_color="FFC7CE", end_color="FFC7CE", fill_type="solid")

    # ---- Sheet 7: Users Overview ----

    def _create_users_overview(self):
        ws = self.wb.create_sheet("Users Overview")
        ws.sheet_properties.tabColor = Colors.INFO
        self._write_title(ws, 1, 1, "Users & Access Levels", 14)
        ws.merge_cells("A1:H1")

        row = 3
        headers = ["User Name", "Email", "Access Level", "License", "Active", "Origin", "Created", "Last Accessed"]
        widths = [22, 30, 20, 22, 10, 10, 14, 14]
        self._write_headers(ws, row, headers, widths)

        for i, u in enumerate(self.users):
            r = row + 1 + i
            self._write_row(ws, r, [
                u.display_name, u.mail_address, u.access_level, u.license_display_name,
                "Yes" if u.is_active else "No", u.origin,
                u.date_created.strftime("%Y-%m-%d") if u.date_created else "",
                u.last_accessed.strftime("%Y-%m-%d") if u.last_accessed else "Never",
            ], alt=i % 2 == 1)
            if not u.is_active:
                ws.cell(row=r, column=5).fill = PatternFill(start_color="FFC7CE", end_color="FFC7CE", fill_type="solid")

        # Access level chart
        ac: Dict[str, int] = {}
        for u in self.users:
            ac[u.access_level] = ac.get(u.access_level, 0) + 1
        cr = row + len(self.users) + 2
        ws.cell(row=cr, column=1, value="Access Level"); ws.cell(row=cr, column=2, value="Count")
        for j, (al, cnt) in enumerate(sorted(ac.items())):
            ws.cell(row=cr + 1 + j, column=1, value=al)
            ws.cell(row=cr + 1 + j, column=2, value=cnt)

        if ac:
            pie = PieChart()
            pie.title = "Access Level Distribution"; pie.style = 10; pie.width = 14; pie.height = 10
            ca = Reference(ws, min_col=1, min_row=cr + 1, max_row=cr + len(ac))
            d = Reference(ws, min_col=2, min_row=cr + 1, max_row=cr + len(ac))
            pie.add_data(d, titles_from_data=False); pie.set_categories(ca)
            pie.dataLabels = DataLabelList(); pie.dataLabels.showPercent = True; pie.dataLabels.showVal = True
            ws.add_chart(pie, f"A{cr}")

        # Active vs Inactive - to the right
        bar_row = cr
        ws.cell(row=bar_row, column=5, value="Status"); ws.cell(row=bar_row, column=6, value="Count")
        ws.cell(row=bar_row + 1, column=5, value="Active"); ws.cell(row=bar_row + 1, column=6, value=self.gov.active_users)
        ws.cell(row=bar_row + 2, column=5, value="Inactive"); ws.cell(row=bar_row + 2, column=6, value=self.gov.inactive_users)

        bar = BarChart()
        bar.type = "col"; bar.style = 10; bar.title = "User Status"
        bar.width = 12; bar.height = 8
        d = Reference(ws, min_col=6, min_row=bar_row, max_row=bar_row + 2)
        ca = Reference(ws, min_col=5, min_row=bar_row + 1, max_row=bar_row + 2)
        bar.add_data(d, titles_from_data=True); bar.set_categories(ca)
        bar.series[0].graphicalProperties.solidFill = Colors.ACCENT
        ws.add_chart(bar, f"E{cr + max(len(ac), 2) + 2}")

    # ---- Sheet 8: Namespaces ----

    def _create_namespace_inventory(self):
        ws = self.wb.create_sheet("Security Namespaces")
        ws.sheet_properties.tabColor = Colors.PRIMARY_LIGHT
        self._write_title(ws, 1, 1, "Security Namespace Inventory", 14)
        ws.merge_cells("A1:F1")

        row = 3
        self._write_headers(ws, row, ["Service Area", "Namespace Name", "Display Name", "Description", "Actions Count", "Hierarchical"],
                            [16, 22, 22, 40, 14, 14])
        all_ns = []
        for svc, ns_list in [
            ("Project", self.namespaces.project), ("Boards", self.namespaces.boards),
            ("Repos", self.namespaces.repos), ("Pipelines", self.namespaces.pipelines),
            ("Release", self.namespaces.release), ("Test Plans", self.namespaces.test_plans),
            ("Artifacts", self.namespaces.artifacts), ("Analytics", self.namespaces.analytics),
            ("Security", self.namespaces.security),
        ]:
            for ns in ns_list:
                all_ns.append((svc, ns))

        for i, (svc, ns) in enumerate(all_ns):
            r = row + 1 + i
            self._write_row(ws, r, [
                svc, ns.name, ns.display_name, ns.description,
                len(ns.actions), "Yes" if ns.is_hierarchical else "No",
            ], alt=i % 2 == 1)

    # ---- Sheet 9+: Per-Service Permissions (with resource display names) ----

    def _create_service_permission_sheets(self):
        for svc in self.permissions.all_services():
            sp = self.permissions.get_by_service(svc)
            if sp.permissions:
                self._create_svc_perm_sheet(svc, sp.permissions)

    def _create_svc_perm_sheet(self, svc: str, perms: List[Permission]):
        safe = f"Perms - {svc}"[:31]
        ws = self.wb.create_sheet(safe)
        ws.sheet_properties.tabColor = Colors.PRIMARY_LIGHT

        self._write_title(ws, 1, 1, f"{svc} Permissions", 14)
        ws.merge_cells("A1:H1")

        row = 3
        headers = ["Identity", "Namespace", "Permission", "State", "Inherited", "Resource", "Resource Token", "Source"]
        widths = [25, 20, 30, 18, 12, 25, 30, 20]
        self._write_headers(ws, row, headers, widths)

        for i, p in enumerate(perms):
            r = row + 1 + i
            state_str = p.state.value.replace("_", " ").title()
            self._write_row(ws, r, [
                p.identity_name, p.namespace_name, p.permission_name,
                state_str, "Yes" if p.is_inherited else "No",
                p.resource_label, p.resource_token, p.source,
            ], alt=i % 2 == 1)
            sf = PERM_STATE_FILLS.get(p.state)
            sff = PERM_STATE_FONTS.get(p.state)
            if sf: ws.cell(row=r, column=4).fill = sf
            if sff: ws.cell(row=r, column=4).font = sff

    # ---- Sheet: Permission Matrix (Heatmap) ----

    def _create_permission_matrix(self):
        ws = self.wb.create_sheet("Permission Matrix")
        ws.sheet_properties.tabColor = Colors.PRIMARY
        self._write_title(ws, 1, 1, "User-Permission Heatmap Matrix", 14)
        ws.merge_cells("A1:H1")

        if not self.permission_report or not self.permission_report.matrices:
            ws.cell(row=3, column=1, value="No permission matrix data available.")
            return

        cur = 3
        for svc_name, svc_matrix in self.permission_report.matrices.items():
            matrix = svc_matrix.matrix
            if not matrix.permissions:
                continue

            ws.cell(row=cur, column=1, value=f"{svc_name} Permissions").font = Font(
                name="Calibri", size=12, bold=True, color=Colors.PRIMARY)
            cur += 1

            # Header
            hcell = ws.cell(row=cur, column=1, value="User / Permission")
            hcell.font = _hf(); hcell.fill = _hfill(); hcell.border = _border()
            ws.column_dimensions["A"].width = 22

            for pi, pn in enumerate(matrix.permissions):
                col = pi + 2
                cell = ws.cell(row=cur, column=col, value=pn)
                cell.font = _hf(); cell.fill = _hfill()
                cell.alignment = Alignment(horizontal="center", text_rotation=45, wrap_text=True)
                cell.border = _border()
                ws.column_dimensions[get_column_letter(col)].width = 14
            cur += 1

            for un in matrix.users:
                up = matrix.matrix.get(un, {})
                if not up: continue
                ws.cell(row=cur, column=1, value=un).font = Font(name="Calibri", size=10, bold=True)
                ws.cell(row=cur, column=1).border = _border()
                for pi, pn in enumerate(matrix.permissions):
                    col = pi + 2
                    cell = ws.cell(row=cur, column=col)
                    cell.border = _border(); cell.alignment = _center()
                    entry = up.get(pn)
                    if entry:
                        cell.value = entry.state.value.replace("_", " ").upper()
                        sf = PERM_STATE_FILLS.get(entry.state)
                        sff = PERM_STATE_FONTS.get(entry.state)
                        if sf: cell.fill = sf
                        if sff: cell.font = sff
                    else:
                        cell.value = "-"
                        cell.fill = PERM_STATE_FILLS[PermissionState.NOT_SET]
                        cell.font = Font(color=Colors.DARK_GRAY)
                cur += 1
            cur += 2

        # Summary chart
        chart_row = cur + 1
        ws.cell(row=chart_row, column=1, value="User").font = Font(bold=True)
        ws.cell(row=chart_row, column=2, value="Allow").font = Font(bold=True)
        ws.cell(row=chart_row, column=3, value="Deny").font = Font(bold=True)
        ws.cell(row=chart_row, column=4, value="Inherited").font = Font(bold=True)

        user_totals: Dict[str, Dict[str, int]] = {}
        for sn, sm in self.permission_report.matrices.items():
            for un, summary in sm.summary.items():
                if un not in user_totals:
                    user_totals[un] = {"allow": 0, "deny": 0, "inherited": 0}
                for k in ("allow", "deny", "inherited"):
                    user_totals[un][k] += summary.get(k, 0)

        data_users = [u for u in user_totals if any(v > 0 for v in user_totals[u].values())]
        for j, uname in enumerate(data_users):
            r = chart_row + 1 + j
            ws.cell(row=r, column=1, value=uname)
            ws.cell(row=r, column=2, value=user_totals[uname]["allow"])
            ws.cell(row=r, column=3, value=user_totals[uname]["deny"])
            ws.cell(row=r, column=4, value=user_totals[uname]["inherited"])

        if data_users:
            bar = BarChart()
            bar.type = "col"; bar.grouping = "stacked"; bar.style = 10
            bar.title = "Permission Distribution per User"
            bar.y_axis.title = "Count"; bar.x_axis.title = "User"
            bar.width = 20; bar.height = 12
            ca = Reference(ws, min_col=1, min_row=chart_row + 1, max_row=chart_row + len(data_users))
            for ci, (cn, clr) in enumerate([(2, Colors.SUCCESS), (3, Colors.DANGER), (4, Colors.ACCENT)]):
                d = Reference(ws, min_col=cn, min_row=chart_row, max_row=chart_row + len(data_users))
                bar.add_data(d, titles_from_data=True)
                bar.series[ci].graphicalProperties.solidFill = clr
            bar.set_categories(ca)
            ws.add_chart(bar, f"F{chart_row}")

    # ---- Sheet: Inheritance Analysis ----

    def _create_inheritance_analysis(self):
        ws = self.wb.create_sheet("Inheritance Analysis")
        ws.sheet_properties.tabColor = Colors.PRIMARY_LIGHT
        self._write_title(ws, 1, 1, "Permission Inheritance Analysis", 14)
        ws.merge_cells("A1:H1")

        if not self.inheritance_analyzer:
            ws.cell(row=3, column=1, value="No inheritance analysis data available.")
            return

        row = 3
        self._write_headers(ws, row, ["User", "Service", "Direct Perms", "Inherited Perms", "Deny Count", "Source Groups"],
                            [22, 18, 16, 18, 12, 40])
        r = row
        total_direct = 0
        total_inherited = 0

        for user in self.users:
            reports = self.inheritance_analyzer.get_service_inheritance_report(user.descriptor)
            for svc_name, sir in reports.items():
                r += 1
                source_groups = set()
                for ps in sir.permissions:
                    if ps.source_group:
                        source_groups.add(ps.source_group)
                self._write_row(ws, r, [
                    user.display_name, svc_name, sir.direct_count,
                    sir.inherited_count, sir.deny_count,
                    ", ".join(source_groups) if source_groups else "Direct only",
                ], alt=(r - row) % 2 == 1)
                total_direct += sir.direct_count
                total_inherited += sir.inherited_count
                if sir.deny_count > 0:
                    ws.cell(row=r, column=5).fill = PatternFill(start_color=Colors.DENY, end_color=Colors.DENY, fill_type="solid")

        # Pie chart
        cr = r + 2
        ws.cell(row=cr, column=1, value="Type"); ws.cell(row=cr, column=2, value="Count")
        ws.cell(row=cr + 1, column=1, value="Direct"); ws.cell(row=cr + 1, column=2, value=total_direct)
        ws.cell(row=cr + 2, column=1, value="Inherited"); ws.cell(row=cr + 2, column=2, value=total_inherited)

        pie = PieChart()
        pie.title = "Direct vs Inherited Permissions"; pie.style = 10; pie.width = 14; pie.height = 10
        ca = Reference(ws, min_col=1, min_row=cr + 1, max_row=cr + 2)
        d = Reference(ws, min_col=2, min_row=cr + 1, max_row=cr + 2)
        pie.add_data(d, titles_from_data=False); pie.set_categories(ca)
        for idx, c in enumerate([Colors.ACCENT, Colors.PRIMARY_LIGHT]):
            pt = DataPoint(idx=idx); pt.graphicalProperties.solidFill = c
            pie.series[0].data_points.append(pt)
        pie.dataLabels = DataLabelList(); pie.dataLabels.showPercent = True; pie.dataLabels.showVal = True
        ws.add_chart(pie, f"A{cr}")

        # Conflicts - placed to the right of pie chart
        conflicts = self.inheritance_analyzer.find_permission_conflicts()
        if conflicts:
            ccr = cr
            ws.cell(row=ccr, column=5, value="PERMISSION CONFLICTS").font = Font(
                name="Calibri", size=12, bold=True, color=Colors.DANGER)
            ccr += 1
            for ci, ch in enumerate(["User", "Namespace", "Permission", "Conflicting States"]):
                cell = ws.cell(row=ccr, column=5 + ci, value=ch)
                cell.font = _hf(); cell.fill = _hfill(); cell.border = _border()
            ws.column_dimensions["E"].width = 22
            ws.column_dimensions["F"].width = 20
            ws.column_dimensions["G"].width = 25
            ws.column_dimensions["H"].width = 45

            for i, conf in enumerate(conflicts):
                rr = ccr + 1 + i
                states_str = "; ".join(f"{s['source']}: {s['state']}" for s in conf.get("sources", []))
                ws.cell(row=rr, column=5, value=conf["user"]).border = _border()
                ws.cell(row=rr, column=6, value=conf["namespace"]).border = _border()
                ws.cell(row=rr, column=7, value=conf["permission"]).border = _border()
                ws.cell(row=rr, column=8, value=states_str).border = _border()
                for cc in range(5, 9):
                    ws.cell(row=rr, column=cc).fill = PatternFill(start_color="FFF3CD", end_color="FFF3CD", fill_type="solid")

    # ---- Sheet: Recommendations ----

    def _create_recommendations(self):
        ws = self.wb.create_sheet("Recommendations")
        ws.sheet_properties.tabColor = Colors.SUCCESS
        gr = self.gov

        self._write_title(ws, 1, 1, "Prioritized Recommendations", 16)
        ws.merge_cells("A1:F1")
        ws.cell(row=2, column=1,
                value=f"Based on governance analysis of {self.organization}/{self.project}").font = Font(
            name="Calibri", size=10, color=Colors.DARK_GRAY)

        row = 4
        self._write_headers(ws, row, ["Priority", "Category", "Recommendation", "Impact", "Effort", "Status"],
                            [10, 22, 55, 12, 12, 12])

        recs = self._generate_recommendations()
        for i, rec in enumerate(recs):
            r = row + 1 + i
            self._write_row(ws, r, [
                rec["priority"], rec["category"], rec["recommendation"],
                rec["impact"], rec["effort"], "Open",
            ], alt=i % 2 == 1)
            if rec["priority"] == 1:
                ws.cell(row=r, column=1).fill = PatternFill(start_color=Colors.CRITICAL, end_color=Colors.CRITICAL, fill_type="solid")
                ws.cell(row=r, column=1).font = Font(color=Colors.WHITE, bold=True)
            elif rec["priority"] == 2:
                ws.cell(row=r, column=1).fill = PatternFill(start_color=Colors.HIGH, end_color=Colors.HIGH, fill_type="solid")
                ws.cell(row=r, column=1).font = Font(color=Colors.WHITE, bold=True)
            elif rec["priority"] == 3:
                ws.cell(row=r, column=1).fill = PatternFill(start_color=Colors.MEDIUM, end_color=Colors.MEDIUM, fill_type="solid")

        if recs:
            ic: Dict[str, int] = {}
            for rec in recs:
                ic[rec["impact"]] = ic.get(rec["impact"], 0) + 1
            cr = row + len(recs) + 2
            ws.cell(row=cr, column=1, value="Impact"); ws.cell(row=cr, column=2, value="Count")
            for j, (imp, cnt) in enumerate(sorted(ic.items())):
                ws.cell(row=cr + 1 + j, column=1, value=imp)
                ws.cell(row=cr + 1 + j, column=2, value=cnt)

            bar = BarChart()
            bar.type = "col"; bar.style = 10; bar.title = "Recommendations by Impact"
            bar.width = 14; bar.height = 10
            d = Reference(ws, min_col=2, min_row=cr, max_row=cr + len(ic))
            ca = Reference(ws, min_col=1, min_row=cr + 1, max_row=cr + len(ic))
            bar.add_data(d, titles_from_data=True); bar.set_categories(ca)
            bar.series[0].graphicalProperties.solidFill = Colors.ACCENT
            ws.add_chart(bar, f"D{cr}")

    def _generate_recommendations(self) -> List[Dict]:
        recs = []
        seen = set()
        rp = {RiskLevel.CRITICAL: 1, RiskLevel.HIGH: 2, RiskLevel.MEDIUM: 3, RiskLevel.LOW: 4, RiskLevel.INFO: 5}

        for f in sorted(self.gov.findings, key=lambda x: rp.get(x.risk_level, 5)):
            key = (f.category, f.recommendation)
            if key in seen:
                continue
            seen.add(key)
            p = rp.get(f.risk_level, 5)
            impact = "Critical" if p <= 1 else "High" if p <= 2 else "Medium" if p <= 3 else "Low"
            effort = "Low" if any(w in f.recommendation for w in ("Remove", "Review")) else "Medium"
            recs.append({"priority": p, "category": f.category, "recommendation": f.recommendation,
                         "impact": impact, "effort": effort})
        return recs
