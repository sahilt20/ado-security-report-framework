"""
Azure DevOps Data Governance Excel Report Generator.

Generates comprehensive Excel reports with:
- Executive summary dashboard with governance scores
- Visual charts (bar, pie, radar, heatmaps)
- Permission matrices with conditional formatting
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
    numbers, NamedStyle,
)
from openpyxl.chart import (
    BarChart, PieChart, RadarChart, Reference,
    BarChart3D,
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
    RISK_COLORS,
)

logger = logging.getLogger(__name__)


# --- Color Palette ---
class Colors:
    # Brand
    PRIMARY = "1B3A5C"
    PRIMARY_LIGHT = "2E5984"
    ACCENT = "0078D4"  # Azure blue
    ACCENT_LIGHT = "50A0E6"

    # Status
    SUCCESS = "28A745"
    WARNING = "FFC107"
    DANGER = "DC3545"
    INFO = "17A2B8"

    # Severity
    CRITICAL = "FF0000"
    HIGH = "FF6600"
    MEDIUM = "FFB800"
    LOW = "2196F3"
    INFO_RISK = "9E9E9E"

    # Permission states
    ALLOW = "C6EFCE"
    ALLOW_TEXT = "006100"
    DENY = "FFC7CE"
    DENY_TEXT = "9C0006"
    INHERITED = "D6E4F0"
    INHERITED_TEXT = "1F4E79"
    NOT_SET = "F2F2F2"

    # General
    WHITE = "FFFFFF"
    LIGHT_GRAY = "F5F5F5"
    GRAY = "E0E0E0"
    DARK_GRAY = "666666"
    BLACK = "000000"
    HEADER_BG = "1B3A5C"
    HEADER_FG = "FFFFFF"
    ROW_ALT = "F0F4F8"

    # Grades
    GRADE_A = "28A745"
    GRADE_B = "5CB85C"
    GRADE_C = "FFC107"
    GRADE_D = "FF9800"
    GRADE_F = "DC3545"


# --- Reusable Styles ---
def _header_font():
    return Font(name="Calibri", bold=True, color=Colors.HEADER_FG, size=11)

def _header_fill():
    return PatternFill(start_color=Colors.HEADER_BG, end_color=Colors.HEADER_BG, fill_type="solid")

def _title_font(size=16):
    return Font(name="Calibri", bold=True, color=Colors.PRIMARY, size=size)

def _thin_border():
    side = Side(style="thin", color=Colors.GRAY)
    return Border(left=side, right=side, top=side, bottom=side)

def _wrap_alignment():
    return Alignment(wrap_text=True, vertical="top")

def _center_alignment():
    return Alignment(horizontal="center", vertical="center")


# --- Severity fills ---
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
    """
    Generates a multi-sheet Excel Data Governance report for Azure DevOps.

    Sheets:
    1.  Executive Summary  - Governance dashboard with scores and charts
    2.  Governance Score    - Detailed score breakdown with radar chart
    3.  Compliance Controls - Control check results
    4.  Risk Findings       - All governance findings sorted by severity
    5.  Groups Overview     - Security groups with membership
    6.  Group Members       - Detailed group membership
    7.  Users Overview      - All users with access levels
    8.  Security Namespaces - Namespace inventory
    9.  Perms - <Service>   - Per-service permission details
    10. Permission Matrix   - User x Permission heatmap
    11. Inheritance Analysis - Permission inheritance breakdown
    12. Recommendations     - Prioritized action items
    """

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

        # Run governance analysis
        gov_analyzer = GovernanceAnalyzer(
            groups=groups,
            users=users,
            granular_permissions=permissions,
            organization=organization,
            project=project,
        )
        self.gov_report: GovernanceReport = gov_analyzer.analyze()
        self.wb: Optional[Workbook] = None

    def generate(self, output_path: str) -> str:
        """Generate the complete Excel report."""
        Path(output_path).parent.mkdir(parents=True, exist_ok=True)

        self.wb = Workbook()
        # Remove default sheet
        self.wb.remove(self.wb.active)

        # Build sheets
        self._create_executive_summary()
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

    # ==================================================================
    # Helper: write a header row
    # ==================================================================
    def _write_header_row(self, ws, row: int, headers: List[str], widths: Optional[List[int]] = None):
        for col_idx, header in enumerate(headers, 1):
            cell = ws.cell(row=row, column=col_idx, value=header)
            cell.font = _header_font()
            cell.fill = _header_fill()
            cell.alignment = _center_alignment()
            cell.border = _thin_border()
        if widths:
            for col_idx, w in enumerate(widths, 1):
                ws.column_dimensions[get_column_letter(col_idx)].width = w

    def _write_data_row(self, ws, row: int, values: List[Any], bold: bool = False, alt: bool = False):
        for col_idx, val in enumerate(values, 1):
            cell = ws.cell(row=row, column=col_idx, value=val)
            cell.font = Font(name="Calibri", size=10, bold=bold)
            cell.border = _thin_border()
            cell.alignment = Alignment(vertical="center", wrap_text=True)
            if alt:
                cell.fill = PatternFill(start_color=Colors.ROW_ALT, end_color=Colors.ROW_ALT, fill_type="solid")

    def _write_title(self, ws, row: int, col: int, text: str, size: int = 16):
        cell = ws.cell(row=row, column=col, value=text)
        cell.font = _title_font(size)

    def _write_metric_card(self, ws, row: int, col: int, label: str, value, color: str = Colors.ACCENT):
        """Write a metric card (label + large value)."""
        label_cell = ws.cell(row=row, column=col, value=label)
        label_cell.font = Font(name="Calibri", size=9, color=Colors.DARK_GRAY)
        label_cell.alignment = Alignment(horizontal="center")

        value_cell = ws.cell(row=row + 1, column=col, value=value)
        value_cell.font = Font(name="Calibri", size=18, bold=True, color=color)
        value_cell.alignment = Alignment(horizontal="center")

        # Light background
        for r in (row, row + 1):
            ws.cell(row=r, column=col).fill = PatternFill(
                start_color="F0F4F8", end_color="F0F4F8", fill_type="solid"
            )
            ws.cell(row=r, column=col).border = _thin_border()

    # ==================================================================
    # Sheet 1: Executive Summary
    # ==================================================================
    def _create_executive_summary(self):
        ws = self.wb.create_sheet("Executive Summary")
        ws.sheet_properties.tabColor = Colors.PRIMARY
        gr = self.gov_report

        # Title
        self._write_title(ws, 1, 1, "Azure DevOps Data Governance Report", 20)
        ws.merge_cells("A1:J1")

        # Subtitle
        sub = ws.cell(row=2, column=1, value=f"Organization: {self.organization}  |  Project: {self.project}  |  Generated: {gr.generated_at.strftime('%Y-%m-%d %H:%M')}")
        sub.font = Font(name="Calibri", size=10, color=Colors.DARK_GRAY)
        ws.merge_cells("A2:J2")

        # --- Governance Grade ---
        row = 4
        grade_color = {
            "A": Colors.GRADE_A, "B": Colors.GRADE_B, "C": Colors.GRADE_C,
            "D": Colors.GRADE_D, "F": Colors.GRADE_F,
        }.get(gr.score.grade, Colors.DARK_GRAY)

        ws.cell(row=row, column=1, value="GOVERNANCE GRADE").font = Font(name="Calibri", size=9, color=Colors.DARK_GRAY, bold=True)
        grade_cell = ws.cell(row=row + 1, column=1, value=gr.score.grade)
        grade_cell.font = Font(name="Calibri", size=36, bold=True, color=grade_color)
        grade_cell.alignment = Alignment(horizontal="center", vertical="center")
        ws.merge_cells(f"A{row+1}:A{row+2}")

        ws.cell(row=row, column=2, value="OVERALL SCORE").font = Font(name="Calibri", size=9, color=Colors.DARK_GRAY, bold=True)
        score_cell = ws.cell(row=row + 1, column=2, value=f"{gr.score.overall_score}/100")
        score_cell.font = Font(name="Calibri", size=20, bold=True, color=Colors.PRIMARY)
        score_cell.alignment = Alignment(horizontal="center", vertical="center")
        ws.merge_cells(f"B{row+1}:B{row+2}")

        # --- Key Metrics Row ---
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
        ]
        for i, (label, val, color) in enumerate(metrics):
            self._write_metric_card(ws, row, i + 1, label, val, color)

        # --- Findings Summary ---
        row = 12
        ws.cell(row=row, column=1, value="FINDINGS SUMMARY").font = Font(name="Calibri", size=12, bold=True, color=Colors.PRIMARY)
        row = 13
        self._write_header_row(ws, row, ["Risk Level", "Count", "Description"], [18, 12, 50])
        risk_order = [RiskLevel.CRITICAL, RiskLevel.HIGH, RiskLevel.MEDIUM, RiskLevel.LOW, RiskLevel.INFO]
        for i, risk in enumerate(risk_order):
            count = gr.findings_by_risk.get(risk, 0)
            r = row + 1 + i
            self._write_data_row(ws, r, [risk, count, f"{risk}-level governance findings"])
            ws.cell(row=r, column=1).fill = SEVERITY_FILLS.get(risk, PatternFill())
            if risk in (RiskLevel.CRITICAL, RiskLevel.HIGH):
                ws.cell(row=r, column=1).font = Font(name="Calibri", size=10, bold=True, color=Colors.WHITE)

        # --- Pie Chart: Findings by Risk Level ---
        chart_data_start = row
        pie = PieChart()
        pie.title = "Findings by Risk Level"
        pie.style = 10
        pie.width = 16
        pie.height = 12
        cats = Reference(ws, min_col=1, min_row=row + 1, max_row=row + len(risk_order))
        vals = Reference(ws, min_col=2, min_row=row + 1, max_row=row + len(risk_order))
        pie.add_data(vals, titles_from_data=False)
        pie.set_categories(cats)
        # Color the pie slices
        pie_colors = [Colors.CRITICAL, Colors.HIGH, Colors.MEDIUM, Colors.LOW, Colors.INFO_RISK]
        for idx, c in enumerate(pie_colors):
            pt = DataPoint(idx=idx)
            pt.graphicalProperties.solidFill = c
            pie.series[0].data_points.append(pt)
        pie.dataLabels = DataLabelList()
        pie.dataLabels.showPercent = True
        pie.dataLabels.showVal = True
        ws.add_chart(pie, "E12")

        # --- Bar Chart: Permissions by Service ---
        row = 20
        ws.cell(row=row, column=1, value="PERMISSIONS BY SERVICE").font = Font(name="Calibri", size=12, bold=True, color=Colors.PRIMARY)
        row = 21
        self._write_header_row(ws, row, ["Service", "Permission Count", "Risk Level"], [22, 18, 14])
        services = sorted(gr.permissions_by_service.items(), key=lambda x: x[1], reverse=True)
        for i, (svc, count) in enumerate(services):
            r = row + 1 + i
            risk = gr.risk_by_service.get(svc, "Info")
            self._write_data_row(ws, r, [svc, count, risk], alt=i % 2 == 1)
            risk_fill = SEVERITY_FILLS.get(risk)
            if risk_fill:
                ws.cell(row=r, column=3).fill = risk_fill
                if risk in (RiskLevel.CRITICAL, RiskLevel.HIGH):
                    ws.cell(row=r, column=3).font = Font(color=Colors.WHITE, bold=True)

        if services:
            bar = BarChart()
            bar.type = "col"
            bar.style = 10
            bar.title = "Permissions by Service Area"
            bar.y_axis.title = "Permission Count"
            bar.x_axis.title = "Service"
            bar.width = 20
            bar.height = 12
            data_ref = Reference(ws, min_col=2, min_row=row, max_row=row + len(services))
            cats_ref = Reference(ws, min_col=1, min_row=row + 1, max_row=row + len(services))
            bar.add_data(data_ref, titles_from_data=True)
            bar.set_categories(cats_ref)
            bar.series[0].graphicalProperties.solidFill = Colors.ACCENT
            ws.add_chart(bar, "E20")

        # --- Permission State Distribution ---
        row = 21 + len(services) + 2
        ws.cell(row=row, column=1, value="PERMISSION DISTRIBUTION").font = Font(name="Calibri", size=12, bold=True, color=Colors.PRIMARY)
        row += 1
        self._write_header_row(ws, row, ["State", "Count"], [20, 15])
        states = [
            ("Allow (Direct)", gr.allow_permissions - gr.inherited_permissions),
            ("Allow (Inherited)", gr.inherited_permissions),
            ("Deny", gr.deny_permissions),
        ]
        for i, (label, count) in enumerate(states):
            r = row + 1 + i
            if count < 0:
                count = 0
            self._write_data_row(ws, r, [label, count])

        if any(c > 0 for _, c in states):
            pie2 = PieChart()
            pie2.title = "Permission State Distribution"
            pie2.style = 10
            pie2.width = 14
            pie2.height = 10
            cats2 = Reference(ws, min_col=1, min_row=row + 1, max_row=row + len(states))
            vals2 = Reference(ws, min_col=2, min_row=row + 1, max_row=row + len(states))
            pie2.add_data(vals2, titles_from_data=False)
            pie2.set_categories(cats2)
            dist_colors = [Colors.SUCCESS, Colors.ACCENT, Colors.DANGER]
            for idx, c in enumerate(dist_colors):
                pt = DataPoint(idx=idx)
                pt.graphicalProperties.solidFill = c
                pie2.series[0].data_points.append(pt)
            pie2.dataLabels = DataLabelList()
            pie2.dataLabels.showPercent = True
            ws.add_chart(pie2, f"D{row}")

        # Column widths
        ws.column_dimensions["A"].width = 22
        ws.column_dimensions["B"].width = 18
        ws.column_dimensions["C"].width = 18

    # ==================================================================
    # Sheet 2: Governance Score
    # ==================================================================
    def _create_governance_score(self):
        ws = self.wb.create_sheet("Governance Score")
        ws.sheet_properties.tabColor = Colors.ACCENT
        score = self.gov_report.score

        self._write_title(ws, 1, 1, "Governance Score Breakdown", 16)
        ws.merge_cells("A1:F1")

        # Score cards
        row = 3
        categories = [
            ("Access Control", score.access_control_score),
            ("Least Privilege", score.least_privilege_score),
            ("Separation of Duties", score.separation_of_duties_score),
            ("Audit & Compliance", score.audit_compliance_score),
            ("Lifecycle Management", score.lifecycle_management_score),
            ("OVERALL", score.overall_score),
        ]

        self._write_header_row(ws, row, ["Governance Area", "Score", "Grade", "Status"], [30, 12, 10, 20])
        for i, (cat, sc) in enumerate(categories):
            r = row + 1 + i
            grade = "A" if sc >= 90 else "B" if sc >= 80 else "C" if sc >= 70 else "D" if sc >= 60 else "F"
            status = "Excellent" if sc >= 90 else "Good" if sc >= 80 else "Needs Improvement" if sc >= 70 else "At Risk" if sc >= 60 else "Critical"
            bold = cat == "OVERALL"
            self._write_data_row(ws, r, [cat, round(sc, 1), grade, status], bold=bold)
            # Color the score cell
            color = Colors.GRADE_A if sc >= 90 else Colors.GRADE_B if sc >= 80 else Colors.GRADE_C if sc >= 70 else Colors.GRADE_D if sc >= 60 else Colors.GRADE_F
            ws.cell(row=r, column=2).font = Font(name="Calibri", size=11, bold=True, color=color)
            ws.cell(row=r, column=3).font = Font(name="Calibri", size=11, bold=True, color=color)

        # Radar chart for score dimensions
        # Data for radar: we write them in hidden cols
        radar_row = row
        for i, (cat, sc) in enumerate(categories[:-1]):  # exclude overall
            ws.cell(row=radar_row + 1 + i, column=6, value=cat)
            ws.cell(row=radar_row + 1 + i, column=7, value=round(sc, 1))

        ws.cell(row=radar_row, column=7, value="Score")

        radar = RadarChart()
        radar.type = "filled"
        radar.title = "Governance Score Radar"
        radar.style = 10
        radar.width = 18
        radar.height = 14

        cats_ref = Reference(ws, min_col=6, min_row=radar_row + 1, max_row=radar_row + len(categories) - 1)
        data_ref = Reference(ws, min_col=7, min_row=radar_row, max_row=radar_row + len(categories) - 1)
        radar.add_data(data_ref, titles_from_data=True)
        radar.set_categories(cats_ref)
        radar.series[0].graphicalProperties.solidFill = Colors.ACCENT_LIGHT
        ws.add_chart(radar, "A12")

        # Bar chart comparison
        bar = BarChart()
        bar.type = "col"
        bar.style = 10
        bar.title = "Score by Governance Area"
        bar.y_axis.title = "Score (0-100)"
        bar.y_axis.scaling.max = 100
        bar.y_axis.scaling.min = 0
        bar.width = 18
        bar.height = 12

        data_ref2 = Reference(ws, min_col=7, min_row=radar_row, max_row=radar_row + len(categories) - 1)
        cats_ref2 = Reference(ws, min_col=6, min_row=radar_row + 1, max_row=radar_row + len(categories) - 1)
        bar.add_data(data_ref2, titles_from_data=True)
        bar.set_categories(cats_ref2)
        bar.series[0].graphicalProperties.solidFill = Colors.PRIMARY_LIGHT
        ws.add_chart(bar, "A28")

        ws.column_dimensions["F"].width = 25
        ws.column_dimensions["G"].width = 12

    # ==================================================================
    # Sheet 3: Compliance Controls
    # ==================================================================
    def _create_compliance_controls(self):
        ws = self.wb.create_sheet("Compliance Controls")
        ws.sheet_properties.tabColor = "28A745"
        gr = self.gov_report

        self._write_title(ws, 1, 1, "Compliance Control Assessment", 16)
        ws.merge_cells("A1:G1")

        row = 3
        headers = ["Control ID", "Control Name", "Category", "Description", "Status", "Score", "Action Required"]
        widths = [14, 30, 20, 45, 12, 10, 40]
        self._write_header_row(ws, row, headers, widths)

        for i, ctrl in enumerate(gr.controls):
            r = row + 1 + i
            action = "" if ctrl.status == "Pass" else "Review and remediate findings"
            self._write_data_row(ws, r, [
                ctrl.control_id,
                ctrl.control_name,
                ctrl.category,
                ctrl.description,
                ctrl.status,
                round(ctrl.score, 1),
                action,
            ], alt=i % 2 == 1)
            # Status color
            status_fill = STATUS_FILLS.get(ctrl.status)
            if status_fill:
                ws.cell(row=r, column=5).fill = status_fill

        # Status distribution chart
        if gr.controls:
            chart_row = row
            pass_count = sum(1 for c in gr.controls if c.status == "Pass")
            warn_count = sum(1 for c in gr.controls if c.status == "Warning")
            fail_count = sum(1 for c in gr.controls if c.status == "Fail")

            cr = row + len(gr.controls) + 2
            ws.cell(row=cr, column=1, value="Status")
            ws.cell(row=cr, column=2, value="Count")
            for j, (label, cnt, clr) in enumerate([
                ("Pass", pass_count, Colors.SUCCESS),
                ("Warning", warn_count, Colors.WARNING),
                ("Fail", fail_count, Colors.DANGER),
            ]):
                ws.cell(row=cr + 1 + j, column=1, value=label)
                ws.cell(row=cr + 1 + j, column=2, value=cnt)

            pie = PieChart()
            pie.title = "Control Status Distribution"
            pie.style = 10
            pie.width = 14
            pie.height = 10
            cats_ref = Reference(ws, min_col=1, min_row=cr + 1, max_row=cr + 3)
            vals_ref = Reference(ws, min_col=2, min_row=cr + 1, max_row=cr + 3)
            pie.add_data(vals_ref, titles_from_data=False)
            pie.set_categories(cats_ref)
            for idx, c in enumerate([Colors.SUCCESS, Colors.WARNING, Colors.DANGER]):
                pt = DataPoint(idx=idx)
                pt.graphicalProperties.solidFill = c
                pie.series[0].data_points.append(pt)
            pie.dataLabels = DataLabelList()
            pie.dataLabels.showPercent = True
            pie.dataLabels.showVal = True
            ws.add_chart(pie, f"D{cr}")

    # ==================================================================
    # Sheet 4: Risk Findings
    # ==================================================================
    def _create_risk_findings(self):
        ws = self.wb.create_sheet("Risk Findings")
        ws.sheet_properties.tabColor = Colors.DANGER
        gr = self.gov_report

        self._write_title(ws, 1, 1, "Governance Risk Findings", 16)
        ws.merge_cells("A1:H1")

        row = 3
        headers = ["#", "Risk Level", "Category", "Title", "Affected Entity", "Entity Type", "Description", "Recommendation"]
        widths = [5, 14, 22, 35, 25, 12, 50, 45]
        self._write_header_row(ws, row, headers, widths)

        # Sort findings: Critical > High > Medium > Low > Info
        risk_order_map = {RiskLevel.CRITICAL: 0, RiskLevel.HIGH: 1, RiskLevel.MEDIUM: 2, RiskLevel.LOW: 3, RiskLevel.INFO: 4}
        sorted_findings = sorted(gr.findings, key=lambda f: risk_order_map.get(f.risk_level, 5))

        for i, finding in enumerate(sorted_findings):
            r = row + 1 + i
            self._write_data_row(ws, r, [
                i + 1,
                finding.risk_level,
                finding.category,
                finding.title,
                finding.affected_entity,
                finding.entity_type,
                finding.description,
                finding.recommendation,
            ], alt=i % 2 == 1)
            # Severity color
            sev_fill = SEVERITY_FILLS.get(finding.risk_level)
            if sev_fill:
                ws.cell(row=r, column=2).fill = sev_fill
                if finding.risk_level in (RiskLevel.CRITICAL, RiskLevel.HIGH):
                    ws.cell(row=r, column=2).font = Font(color=Colors.WHITE, bold=True)

        # Findings by category bar chart
        cat_row = row + len(sorted_findings) + 2
        ws.cell(row=cat_row, column=1, value="Category")
        ws.cell(row=cat_row, column=2, value="Count")
        cat_data = sorted(gr.findings_by_category.items(), key=lambda x: x[1], reverse=True)
        for j, (cat, cnt) in enumerate(cat_data):
            ws.cell(row=cat_row + 1 + j, column=1, value=cat)
            ws.cell(row=cat_row + 1 + j, column=2, value=cnt)

        if cat_data:
            bar = BarChart()
            bar.type = "col"
            bar.style = 10
            bar.title = "Findings by Category"
            bar.y_axis.title = "Count"
            bar.width = 18
            bar.height = 10
            data_ref = Reference(ws, min_col=2, min_row=cat_row, max_row=cat_row + len(cat_data))
            cats_ref = Reference(ws, min_col=1, min_row=cat_row + 1, max_row=cat_row + len(cat_data))
            bar.add_data(data_ref, titles_from_data=True)
            bar.set_categories(cats_ref)
            bar.series[0].graphicalProperties.solidFill = Colors.PRIMARY_LIGHT
            ws.add_chart(bar, f"D{cat_row}")

    # ==================================================================
    # Sheet 5: Groups Overview
    # ==================================================================
    def _create_groups_overview(self):
        ws = self.wb.create_sheet("Groups Overview")
        ws.sheet_properties.tabColor = Colors.ACCENT

        self._write_title(ws, 1, 1, "Security Groups Overview", 14)
        ws.merge_cells("A1:G1")

        row = 3
        headers = ["Group Name", "Type", "Origin", "Members", "Description", "Principal Name"]
        widths = [28, 12, 10, 10, 45, 40]
        self._write_header_row(ws, row, headers, widths)

        for i, group in enumerate(self.groups):
            r = row + 1 + i
            self._write_data_row(ws, r, [
                group.display_name,
                group.group_type,
                group.origin,
                group.member_count or len(group.members),
                group.description,
                group.principal_name,
            ], alt=i % 2 == 1)

        # Group type distribution chart
        custom = sum(1 for g in self.groups if g.group_type == "Custom")
        default = len(self.groups) - custom
        cr = row + len(self.groups) + 2
        ws.cell(row=cr, column=1, value="Type")
        ws.cell(row=cr, column=2, value="Count")
        ws.cell(row=cr + 1, column=1, value="Default")
        ws.cell(row=cr + 1, column=2, value=default)
        ws.cell(row=cr + 2, column=1, value="Custom")
        ws.cell(row=cr + 2, column=2, value=custom)

        pie = PieChart()
        pie.title = "Group Types"
        pie.style = 10
        pie.width = 12
        pie.height = 9
        cats_ref = Reference(ws, min_col=1, min_row=cr + 1, max_row=cr + 2)
        vals_ref = Reference(ws, min_col=2, min_row=cr + 1, max_row=cr + 2)
        pie.add_data(vals_ref, titles_from_data=False)
        pie.set_categories(cats_ref)
        for idx, c in enumerate([Colors.ACCENT, Colors.PRIMARY_LIGHT]):
            pt = DataPoint(idx=idx)
            pt.graphicalProperties.solidFill = c
            pie.series[0].data_points.append(pt)
        pie.dataLabels = DataLabelList()
        pie.dataLabels.showPercent = True
        ws.add_chart(pie, f"D{cr}")

        # Members bar chart
        if self.groups:
            bar = BarChart()
            bar.type = "col"
            bar.style = 10
            bar.title = "Members per Group"
            bar.y_axis.title = "Member Count"
            bar.width = 18
            bar.height = 10

            mcr = cr + 5
            ws.cell(row=mcr, column=1, value="Group")
            ws.cell(row=mcr, column=2, value="Members")
            for j, g in enumerate(self.groups):
                ws.cell(row=mcr + 1 + j, column=1, value=g.display_name)
                ws.cell(row=mcr + 1 + j, column=2, value=g.member_count or len(g.members))

            data_ref = Reference(ws, min_col=2, min_row=mcr, max_row=mcr + len(self.groups))
            cats_ref = Reference(ws, min_col=1, min_row=mcr + 1, max_row=mcr + len(self.groups))
            bar.add_data(data_ref, titles_from_data=True)
            bar.set_categories(cats_ref)
            bar.series[0].graphicalProperties.solidFill = Colors.ACCENT
            ws.add_chart(bar, f"D{mcr}")

    # ==================================================================
    # Sheet 6: Group Members
    # ==================================================================
    def _create_group_members(self):
        ws = self.wb.create_sheet("Group Members")
        ws.sheet_properties.tabColor = Colors.ACCENT

        self._write_title(ws, 1, 1, "Group Membership Details", 14)
        ws.merge_cells("A1:F1")

        row = 3
        headers = ["Group", "Member Name", "Member Type", "Principal Name", "Active", "Origin"]
        widths = [25, 25, 12, 35, 10, 10]
        self._write_header_row(ws, row, headers, widths)

        r = row
        for group in self.groups:
            if not group.members:
                r += 1
                self._write_data_row(ws, r, [group.display_name, "(no members)", "", "", "", ""])
                ws.cell(row=r, column=2).font = Font(name="Calibri", size=10, italic=True, color=Colors.DARK_GRAY)
                continue
            for member in group.members:
                r += 1
                self._write_data_row(ws, r, [
                    group.display_name,
                    member.display_name,
                    member.member_type,
                    member.principal_name,
                    "Yes" if member.is_active else "No",
                    member.origin,
                ], alt=(r - row) % 2 == 1)
                if not member.is_active:
                    ws.cell(row=r, column=5).fill = PatternFill(start_color="FFC7CE", end_color="FFC7CE", fill_type="solid")

    # ==================================================================
    # Sheet 7: Users Overview
    # ==================================================================
    def _create_users_overview(self):
        ws = self.wb.create_sheet("Users Overview")
        ws.sheet_properties.tabColor = Colors.INFO

        self._write_title(ws, 1, 1, "Users & Access Levels", 14)
        ws.merge_cells("A1:H1")

        row = 3
        headers = ["User Name", "Email", "Access Level", "License", "Active", "Origin", "Created", "Last Accessed"]
        widths = [22, 30, 20, 22, 10, 10, 14, 14]
        self._write_header_row(ws, row, headers, widths)

        for i, user in enumerate(self.users):
            r = row + 1 + i
            self._write_data_row(ws, r, [
                user.display_name,
                user.mail_address,
                user.access_level,
                user.license_display_name,
                "Yes" if user.is_active else "No",
                user.origin,
                user.date_created.strftime("%Y-%m-%d") if user.date_created else "",
                user.last_accessed.strftime("%Y-%m-%d") if user.last_accessed else "Never",
            ], alt=i % 2 == 1)
            if not user.is_active:
                ws.cell(row=r, column=5).fill = PatternFill(start_color="FFC7CE", end_color="FFC7CE", fill_type="solid")

        # Access level distribution chart
        access_counts: Dict[str, int] = {}
        for u in self.users:
            access_counts[u.access_level] = access_counts.get(u.access_level, 0) + 1

        cr = row + len(self.users) + 2
        ws.cell(row=cr, column=1, value="Access Level")
        ws.cell(row=cr, column=2, value="Count")
        for j, (al, cnt) in enumerate(sorted(access_counts.items())):
            ws.cell(row=cr + 1 + j, column=1, value=al)
            ws.cell(row=cr + 1 + j, column=2, value=cnt)

        if access_counts:
            pie = PieChart()
            pie.title = "Access Level Distribution"
            pie.style = 10
            pie.width = 14
            pie.height = 10
            cats_ref = Reference(ws, min_col=1, min_row=cr + 1, max_row=cr + len(access_counts))
            vals_ref = Reference(ws, min_col=2, min_row=cr + 1, max_row=cr + len(access_counts))
            pie.add_data(vals_ref, titles_from_data=False)
            pie.set_categories(cats_ref)
            pie.dataLabels = DataLabelList()
            pie.dataLabels.showPercent = True
            pie.dataLabels.showVal = True
            ws.add_chart(pie, f"D{cr}")

        # Active vs Inactive bar
        bar_row = cr + len(access_counts) + 3
        ws.cell(row=bar_row, column=1, value="Status")
        ws.cell(row=bar_row, column=2, value="Count")
        ws.cell(row=bar_row + 1, column=1, value="Active")
        ws.cell(row=bar_row + 1, column=2, value=self.gov_report.active_users)
        ws.cell(row=bar_row + 2, column=1, value="Inactive")
        ws.cell(row=bar_row + 2, column=2, value=self.gov_report.inactive_users)

        bar = BarChart()
        bar.type = "col"
        bar.style = 10
        bar.title = "User Status"
        bar.width = 12
        bar.height = 8
        data_ref = Reference(ws, min_col=2, min_row=bar_row, max_row=bar_row + 2)
        cats_ref = Reference(ws, min_col=1, min_row=bar_row + 1, max_row=bar_row + 2)
        bar.add_data(data_ref, titles_from_data=True)
        bar.set_categories(cats_ref)
        bar.series[0].graphicalProperties.solidFill = Colors.ACCENT
        ws.add_chart(bar, f"D{bar_row}")

    # ==================================================================
    # Sheet 8: Security Namespaces
    # ==================================================================
    def _create_namespace_inventory(self):
        ws = self.wb.create_sheet("Security Namespaces")
        ws.sheet_properties.tabColor = Colors.PRIMARY_LIGHT

        self._write_title(ws, 1, 1, "Security Namespace Inventory", 14)
        ws.merge_cells("A1:F1")

        row = 3
        headers = ["Service Area", "Namespace Name", "Display Name", "Description", "Actions Count", "Hierarchical"]
        widths = [16, 22, 22, 40, 14, 14]
        self._write_header_row(ws, row, headers, widths)

        all_ns = []
        for service, ns_list in [
            ("Project", self.namespaces.project),
            ("Boards", self.namespaces.boards),
            ("Repos", self.namespaces.repos),
            ("Pipelines", self.namespaces.pipelines),
            ("Release", self.namespaces.release),
            ("Test Plans", self.namespaces.test_plans),
            ("Artifacts", self.namespaces.artifacts),
            ("Analytics", self.namespaces.analytics),
            ("Security", self.namespaces.security),
        ]:
            for ns in ns_list:
                all_ns.append((service, ns))

        for i, (service, ns) in enumerate(all_ns):
            r = row + 1 + i
            self._write_data_row(ws, r, [
                service,
                ns.name,
                ns.display_name,
                ns.description,
                len(ns.actions),
                "Yes" if ns.is_hierarchical else "No",
            ], alt=i % 2 == 1)

    # ==================================================================
    # Sheet 9+: Per-Service Permission Sheets
    # ==================================================================
    def _create_service_permission_sheets(self):
        for service in self.permissions.all_services():
            sp = self.permissions.get_by_service(service)
            if not sp.permissions:
                continue
            self._create_service_perm_sheet(service, sp.permissions)

    def _create_service_perm_sheet(self, service: str, perms: List[Permission]):
        safe_name = f"Perms - {service}"[:31]
        ws = self.wb.create_sheet(safe_name)
        ws.sheet_properties.tabColor = Colors.PRIMARY_LIGHT

        self._write_title(ws, 1, 1, f"{service} Permissions", 14)
        ws.merge_cells("A1:G1")

        row = 3
        headers = ["Identity", "Namespace", "Permission", "State", "Inherited", "Resource Token", "Source"]
        widths = [25, 20, 30, 18, 12, 30, 20]
        self._write_header_row(ws, row, headers, widths)

        for i, perm in enumerate(perms):
            r = row + 1 + i
            state_str = perm.state.value.replace("_", " ").title()
            self._write_data_row(ws, r, [
                perm.identity_name,
                perm.namespace_name,
                perm.permission_name,
                state_str,
                "Yes" if perm.is_inherited else "No",
                perm.resource_token,
                perm.source,
            ], alt=i % 2 == 1)
            # Color the state cell
            state_fill = PERM_STATE_FILLS.get(perm.state)
            state_font = PERM_STATE_FONTS.get(perm.state)
            if state_fill:
                ws.cell(row=r, column=4).fill = state_fill
            if state_font:
                ws.cell(row=r, column=4).font = state_font

    # ==================================================================
    # Sheet: Permission Matrix (Heatmap)
    # ==================================================================
    def _create_permission_matrix(self):
        ws = self.wb.create_sheet("Permission Matrix")
        ws.sheet_properties.tabColor = Colors.PRIMARY

        self._write_title(ws, 1, 1, "User-Permission Heatmap Matrix", 14)
        ws.merge_cells("A1:H1")

        if not self.permission_report or not self.permission_report.matrices:
            ws.cell(row=3, column=1, value="No permission matrix data available.")
            return

        current_row = 3
        for service_name, service_matrix in self.permission_report.matrices.items():
            matrix = service_matrix.matrix

            if not matrix.permissions:
                continue

            # Service header
            ws.cell(row=current_row, column=1, value=f"{service_name} Permissions").font = Font(
                name="Calibri", size=12, bold=True, color=Colors.PRIMARY
            )
            current_row += 1

            # Header row: blank + permission names
            ws.cell(row=current_row, column=1, value="User / Permission").font = _header_font()
            ws.cell(row=current_row, column=1).fill = _header_fill()
            ws.cell(row=current_row, column=1).border = _thin_border()
            ws.column_dimensions["A"].width = 22

            for pi, perm_name in enumerate(matrix.permissions):
                col = pi + 2
                cell = ws.cell(row=current_row, column=col, value=perm_name)
                cell.font = _header_font()
                cell.fill = _header_fill()
                cell.alignment = Alignment(horizontal="center", text_rotation=45, wrap_text=True)
                cell.border = _thin_border()
                ws.column_dimensions[get_column_letter(col)].width = 14

            current_row += 1

            # Data rows
            for ui, user_name in enumerate(matrix.users):
                user_perms = matrix.matrix.get(user_name, {})
                if not user_perms:
                    continue

                ws.cell(row=current_row, column=1, value=user_name).font = Font(name="Calibri", size=10, bold=True)
                ws.cell(row=current_row, column=1).border = _thin_border()

                for pi, perm_name in enumerate(matrix.permissions):
                    col = pi + 2
                    entry = user_perms.get(perm_name)
                    cell = ws.cell(row=current_row, column=col)
                    cell.border = _thin_border()
                    cell.alignment = _center_alignment()

                    if entry:
                        state_label = entry.state.value.replace("_", " ").upper()
                        cell.value = state_label
                        state_fill = PERM_STATE_FILLS.get(entry.state)
                        state_font = PERM_STATE_FONTS.get(entry.state)
                        if state_fill:
                            cell.fill = state_fill
                        if state_font:
                            cell.font = state_font
                    else:
                        cell.value = "-"
                        cell.fill = PERM_STATE_FILLS[PermissionState.NOT_SET]
                        cell.font = Font(color=Colors.DARK_GRAY)

                current_row += 1

            current_row += 2  # Gap between services

        # Add a summary chart - permissions per user across services
        chart_row = current_row + 1
        ws.cell(row=chart_row, column=1, value="User").font = Font(bold=True)
        ws.cell(row=chart_row, column=2, value="Allow").font = Font(bold=True)
        ws.cell(row=chart_row, column=3, value="Deny").font = Font(bold=True)
        ws.cell(row=chart_row, column=4, value="Inherited").font = Font(bold=True)

        user_totals: Dict[str, Dict[str, int]] = {}
        for service_name, sm in self.permission_report.matrices.items():
            for user_name, summary in sm.summary.items():
                if user_name not in user_totals:
                    user_totals[user_name] = {"allow": 0, "deny": 0, "inherited": 0}
                for k in ("allow", "deny", "inherited"):
                    user_totals[user_name][k] += summary.get(k, 0)

        data_users = [u for u in user_totals if any(v > 0 for v in user_totals[u].values())]
        for j, uname in enumerate(data_users):
            r = chart_row + 1 + j
            ws.cell(row=r, column=1, value=uname)
            ws.cell(row=r, column=2, value=user_totals[uname]["allow"])
            ws.cell(row=r, column=3, value=user_totals[uname]["deny"])
            ws.cell(row=r, column=4, value=user_totals[uname]["inherited"])

        if data_users:
            bar = BarChart()
            bar.type = "col"
            bar.grouping = "stacked"
            bar.title = "Permission Distribution per User"
            bar.y_axis.title = "Count"
            bar.x_axis.title = "User"
            bar.width = 22
            bar.height = 12
            bar.style = 10

            cats_ref = Reference(ws, min_col=1, min_row=chart_row + 1, max_row=chart_row + len(data_users))
            for ci, (col_name, color) in enumerate([(2, Colors.SUCCESS), (3, Colors.DANGER), (4, Colors.ACCENT)], 0):
                data_ref = Reference(ws, min_col=col_name, min_row=chart_row, max_row=chart_row + len(data_users))
                bar.add_data(data_ref, titles_from_data=True)
                bar.series[ci].graphicalProperties.solidFill = color
            bar.set_categories(cats_ref)
            ws.add_chart(bar, f"F{chart_row}")

    # ==================================================================
    # Sheet: Inheritance Analysis
    # ==================================================================
    def _create_inheritance_analysis(self):
        ws = self.wb.create_sheet("Inheritance Analysis")
        ws.sheet_properties.tabColor = Colors.PRIMARY_LIGHT

        self._write_title(ws, 1, 1, "Permission Inheritance Analysis", 14)
        ws.merge_cells("A1:H1")

        if not self.inheritance_analyzer:
            ws.cell(row=3, column=1, value="No inheritance analysis data available.")
            return

        row = 3
        headers = ["User", "Service", "Direct Permissions", "Inherited Permissions", "Deny Count", "Source Groups"]
        widths = [22, 18, 18, 20, 12, 40]
        self._write_header_row(ws, row, headers, widths)

        r = row
        total_direct = 0
        total_inherited = 0
        user_data = []

        for user in self.users:
            reports = self.inheritance_analyzer.get_service_inheritance_report(user.descriptor)
            for service_name, sir in reports.items():
                r += 1
                source_groups = set()
                for ps in sir.permissions:
                    if ps.source_group:
                        source_groups.add(ps.source_group)
                self._write_data_row(ws, r, [
                    user.display_name,
                    service_name,
                    sir.direct_count,
                    sir.inherited_count,
                    sir.deny_count,
                    ", ".join(source_groups) if source_groups else "Direct only",
                ], alt=(r - row) % 2 == 1)
                total_direct += sir.direct_count
                total_inherited += sir.inherited_count
                if sir.deny_count > 0:
                    ws.cell(row=r, column=5).fill = PatternFill(start_color=Colors.DENY, end_color=Colors.DENY, fill_type="solid")

            user_data.append((user.display_name, total_direct, total_inherited))

        # Inheritance chart
        cr = r + 2
        ws.cell(row=cr, column=1, value="Type")
        ws.cell(row=cr, column=2, value="Count")
        ws.cell(row=cr + 1, column=1, value="Direct")
        ws.cell(row=cr + 1, column=2, value=total_direct)
        ws.cell(row=cr + 2, column=1, value="Inherited")
        ws.cell(row=cr + 2, column=2, value=total_inherited)

        pie = PieChart()
        pie.title = "Direct vs Inherited Permissions"
        pie.style = 10
        pie.width = 14
        pie.height = 10
        cats_ref = Reference(ws, min_col=1, min_row=cr + 1, max_row=cr + 2)
        vals_ref = Reference(ws, min_col=2, min_row=cr + 1, max_row=cr + 2)
        pie.add_data(vals_ref, titles_from_data=False)
        pie.set_categories(cats_ref)
        for idx, c in enumerate([Colors.ACCENT, Colors.PRIMARY_LIGHT]):
            pt = DataPoint(idx=idx)
            pt.graphicalProperties.solidFill = c
            pie.series[0].data_points.append(pt)
        pie.dataLabels = DataLabelList()
        pie.dataLabels.showPercent = True
        pie.dataLabels.showVal = True
        ws.add_chart(pie, f"D{cr}")

        # Conflict detection
        conflicts = self.inheritance_analyzer.find_permission_conflicts()
        if conflicts:
            ccr = cr + 14
            ws.cell(row=ccr, column=1, value="PERMISSION CONFLICTS").font = Font(
                name="Calibri", size=12, bold=True, color=Colors.DANGER
            )
            ccr += 1
            self._write_header_row(ws, ccr, ["User", "Namespace", "Permission", "Conflicting States"], [22, 20, 25, 45])
            for i, conflict in enumerate(conflicts):
                r = ccr + 1 + i
                states_str = "; ".join(
                    f"{s['source']}: {s['state']}" for s in conflict.get("sources", [])
                )
                self._write_data_row(ws, r, [
                    conflict["user"],
                    conflict["namespace"],
                    conflict["permission"],
                    states_str,
                ])
                ws.cell(row=r, column=1).fill = PatternFill(start_color="FFF3CD", end_color="FFF3CD", fill_type="solid")

    # ==================================================================
    # Sheet: Recommendations
    # ==================================================================
    def _create_recommendations(self):
        ws = self.wb.create_sheet("Recommendations")
        ws.sheet_properties.tabColor = Colors.SUCCESS
        gr = self.gov_report

        self._write_title(ws, 1, 1, "Prioritized Recommendations", 16)
        ws.merge_cells("A1:F1")

        ws.cell(row=2, column=1,
                value=f"Based on governance analysis of {self.organization}/{self.project}").font = Font(
            name="Calibri", size=10, color=Colors.DARK_GRAY
        )

        row = 4
        headers = ["Priority", "Category", "Recommendation", "Impact", "Effort", "Status"]
        widths = [10, 22, 55, 12, 12, 12]
        self._write_header_row(ws, row, headers, widths)

        # Generate prioritized recommendations from findings
        recommendations = self._generate_recommendations()
        for i, rec in enumerate(recommendations):
            r = row + 1 + i
            self._write_data_row(ws, r, [
                rec["priority"],
                rec["category"],
                rec["recommendation"],
                rec["impact"],
                rec["effort"],
                "Open",
            ], alt=i % 2 == 1)
            # Priority color
            if rec["priority"] == 1:
                ws.cell(row=r, column=1).fill = PatternFill(start_color=Colors.CRITICAL, end_color=Colors.CRITICAL, fill_type="solid")
                ws.cell(row=r, column=1).font = Font(color=Colors.WHITE, bold=True)
            elif rec["priority"] == 2:
                ws.cell(row=r, column=1).fill = PatternFill(start_color=Colors.HIGH, end_color=Colors.HIGH, fill_type="solid")
                ws.cell(row=r, column=1).font = Font(color=Colors.WHITE, bold=True)
            elif rec["priority"] == 3:
                ws.cell(row=r, column=1).fill = PatternFill(start_color=Colors.MEDIUM, end_color=Colors.MEDIUM, fill_type="solid")

        # Summary chart
        if recommendations:
            cr = row + len(recommendations) + 2
            impact_counts: Dict[str, int] = {}
            for rec in recommendations:
                impact_counts[rec["impact"]] = impact_counts.get(rec["impact"], 0) + 1

            ws.cell(row=cr, column=1, value="Impact Level")
            ws.cell(row=cr, column=2, value="Count")
            for j, (imp, cnt) in enumerate(sorted(impact_counts.items())):
                ws.cell(row=cr + 1 + j, column=1, value=imp)
                ws.cell(row=cr + 1 + j, column=2, value=cnt)

            bar = BarChart()
            bar.type = "col"
            bar.style = 10
            bar.title = "Recommendations by Impact"
            bar.width = 14
            bar.height = 10
            data_ref = Reference(ws, min_col=2, min_row=cr, max_row=cr + len(impact_counts))
            cats_ref = Reference(ws, min_col=1, min_row=cr + 1, max_row=cr + len(impact_counts))
            bar.add_data(data_ref, titles_from_data=True)
            bar.set_categories(cats_ref)
            bar.series[0].graphicalProperties.solidFill = Colors.ACCENT
            ws.add_chart(bar, f"D{cr}")

    def _generate_recommendations(self) -> List[Dict]:
        """Generate prioritized recommendations from governance findings."""
        recs = []
        seen = set()
        gr = self.gov_report

        risk_to_priority = {
            RiskLevel.CRITICAL: 1,
            RiskLevel.HIGH: 2,
            RiskLevel.MEDIUM: 3,
            RiskLevel.LOW: 4,
            RiskLevel.INFO: 5,
        }

        for finding in sorted(
            gr.findings,
            key=lambda f: risk_to_priority.get(f.risk_level, 5)
        ):
            rec_key = (finding.category, finding.recommendation)
            if rec_key in seen:
                continue
            seen.add(rec_key)

            priority = risk_to_priority.get(finding.risk_level, 5)
            impact = "Critical" if priority <= 1 else "High" if priority <= 2 else "Medium" if priority <= 3 else "Low"
            effort = "Low" if "Remove" in finding.recommendation or "Review" in finding.recommendation else "Medium"

            recs.append({
                "priority": priority,
                "category": finding.category,
                "recommendation": finding.recommendation,
                "impact": impact,
                "effort": effort,
            })

        return recs
