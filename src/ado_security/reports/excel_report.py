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
        self._create_user_risk_profiles()
        self._create_license_access_analysis()
        self._create_groups_overview()
        self._create_group_hierarchy()
        self._create_group_members()
        self._create_users_overview()
        self._create_namespace_inventory()
        self._create_unified_permissions()
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

    # ---- Computed helpers for insights ----

    def _compute_user_insights(self) -> Dict[str, Dict]:
        """Compute per-user risk insights across all data points."""
        now = datetime.now()
        gr = self.gov
        group_map = {g.descriptor: g for g in self.groups}
        insights = {}
        for u in self.users:
            # Groups this user belongs to
            user_groups = [group_map[gd].display_name for gd in u.group_memberships if gd in group_map]
            # Count permissions for this user (via groups)
            perm_count = 0
            deny_count = 0
            high_risk_perms = 0
            services_accessed = set()
            for svc in self.permissions.all_services():
                sp = self.permissions.get_by_service(svc)
                for p in sp.permissions:
                    if p.identity_descriptor in u.group_memberships or p.identity_descriptor == u.descriptor:
                        perm_count += 1
                        services_accessed.add(svc)
                        if p.state in (PermissionState.DENY, PermissionState.INHERITED_DENY):
                            deny_count += 1
                        if p.permission_name in ("Administer", "Force push", "Bypass policies",
                                                  "Delete build pipeline", "Manage release approvers"):
                            high_risk_perms += 1
            # Risk flags
            flags = []
            is_admin = any("Administrator" in g for g in user_groups)
            if is_admin:
                flags.append("Admin")
            if not u.is_active:
                flags.append("Inactive")
            if u.origin == "aad" and u.mail_address and "external" in u.mail_address.lower():
                flags.append("External")
            if u.last_accessed:
                days = (now - u.last_accessed).days
                if days > 90:
                    flags.append(f"Stale ({days}d)")
            if high_risk_perms > 3:
                flags.append("Overprivileged")
            # Risk score
            risk_score = 0
            if is_admin: risk_score += 30
            if not u.is_active: risk_score += 20
            if "External" in flags: risk_score += 25
            if "Stale" in " ".join(flags): risk_score += 15
            risk_score += min(high_risk_perms * 5, 30)

            insights[u.descriptor] = {
                "user": u, "groups": user_groups, "perm_count": perm_count,
                "deny_count": deny_count, "high_risk_perms": high_risk_perms,
                "services": services_accessed, "flags": flags,
                "risk_score": min(risk_score, 100), "is_admin": is_admin,
            }
        return insights

    # ---- Sheet 1: Executive Summary ----

    def _create_executive_summary(self):
        ws = self.wb.create_sheet("Executive Summary")
        ws.sheet_properties.tabColor = Colors.PRIMARY
        gr = self.gov
        user_insights = self._compute_user_insights()

        self._write_title(ws, 1, 1, "Azure DevOps Project-Level Data Governance Report", 20)
        ws.merge_cells("A1:J1")
        sub = ws.cell(row=2, column=1,
            value=f"Organization: {self.organization}  |  Project: {self.project}  |  Scope: Project Admin  |  Generated: {gr.generated_at.strftime('%Y-%m-%d %H:%M')}")
        sub.font = Font(name="Calibri", size=10, color=Colors.DARK_GRAY)
        ws.merge_cells("A2:J2")

        # --- Grade + Score + Compliance Status (row 4-6) ---
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

        # Compliance control status inline
        pass_c = sum(1 for c in gr.controls if c.status == "Pass")
        warn_c = sum(1 for c in gr.controls if c.status == "Warning")
        fail_c = sum(1 for c in gr.controls if c.status == "Fail")
        for ci, (lbl, val, clr) in enumerate([
            ("Controls Passed", pass_c, Colors.SUCCESS),
            ("Warnings", warn_c, Colors.WARNING),
            ("Controls Failed", fail_c, Colors.DANGER),
            ("Total Findings", len(gr.findings), Colors.PRIMARY),
        ]):
            self._metric_card(ws, row, 3 + ci, lbl, val, clr)

        # Dimension scores inline (cols G-J, row 4-5)
        dims = [
            ("Access Control", gr.score.access_control_score),
            ("Least Privilege", gr.score.least_privilege_score),
            ("Separation of Duties", gr.score.separation_of_duties_score),
            ("Lifecycle Mgmt", gr.score.lifecycle_management_score),
        ]
        for ci, (lbl, val) in enumerate(dims):
            self._metric_card(ws, row, 7 + ci, lbl, f"{val:.0f}", self._grade_color(val))

        # --- Key Metrics (row 8-9) ---
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
            ("Custom Groups", gr.custom_groups, Colors.ACCENT),
            ("Empty Groups", gr.empty_groups, Colors.WARNING if gr.empty_groups > 0 else Colors.SUCCESS),
            ("Total Permissions", gr.total_permissions, Colors.ACCENT),
            ("Overprivileged", gr.overprivileged_users, Colors.DANGER if gr.overprivileged_users > 0 else Colors.SUCCESS),
        ]
        for i, (lbl, val, clr) in enumerate(metrics):
            self._metric_card(ws, row, i + 1, lbl, val, clr)

        # --- Security Posture Highlights (row 12) ---
        row = 12
        ws.cell(row=row, column=1, value="SECURITY POSTURE HIGHLIGHTS").font = Font(name="Calibri", size=12, bold=True, color=Colors.PRIMARY)
        row += 1
        self._write_headers(ws, row, ["Indicator", "Status", "Detail"], [30, 14, 50])
        posture_items = [
            ("Admin-to-User Ratio", f"{gr.admin_users}/{gr.total_users}",
             "Good" if gr.admin_users <= 3 else "Warning" if gr.admin_users <= 5 else "Fail",
             f"{gr.admin_users} admins for {gr.total_users} users ({gr.admin_users/max(gr.total_users,1)*100:.0f}%)"),
            ("External Access", f"{gr.external_users} users",
             "Pass" if gr.external_users == 0 else "Warning",
             "No external users" if gr.external_users == 0 else f"{gr.external_users} external users with project access"),
            ("Stale Accounts", f"{gr.stale_users} accounts",
             "Pass" if gr.stale_users == 0 else "Fail",
             "All accounts active" if gr.stale_users == 0 else f"{gr.stale_users} accounts inactive >90 days"),
            ("Group Hygiene", f"{gr.empty_groups} empty",
             "Pass" if gr.empty_groups == 0 else "Warning",
             "All groups have members" if gr.empty_groups == 0 else f"{gr.empty_groups} groups with no members"),
            ("Deny Rules", f"{gr.deny_permissions} denies",
             "Pass" if gr.deny_permissions > 0 else "Warning",
             f"{gr.deny_permissions} explicit deny rules enforced" if gr.deny_permissions > 0 else "No explicit deny rules - relying on defaults"),
            ("Direct vs Inherited", f"{gr.direct_permissions}/{gr.inherited_permissions}",
             "Pass" if gr.inherited_permissions >= gr.direct_permissions else "Warning",
             f"{gr.inherited_permissions} inherited, {gr.direct_permissions} direct assignments"),
        ]
        for i, (indicator, value, status, detail) in enumerate(posture_items):
            r = row + 1 + i
            self._write_row(ws, r, [indicator, status, detail], alt=i % 2 == 1)
            sf = STATUS_FILLS.get(status)
            if sf:
                ws.cell(row=r, column=2).fill = sf
                ws.cell(row=r, column=2).alignment = _center()

        # --- Findings by Risk + Category (row 20) ---
        row = 20
        ws.cell(row=row, column=1, value="FINDINGS BY RISK LEVEL").font = Font(name="Calibri", size=12, bold=True, color=Colors.PRIMARY)
        row = 21
        self._write_headers(ws, row, ["Risk Level", "Count", "% of Total"], [18, 10, 14])
        risk_order = [RiskLevel.CRITICAL, RiskLevel.HIGH, RiskLevel.MEDIUM, RiskLevel.LOW, RiskLevel.INFO]
        total_findings = max(len(gr.findings), 1)
        for i, risk in enumerate(risk_order):
            cnt = gr.findings_by_risk.get(risk, 0)
            r = row + 1 + i
            pct = f"{cnt / total_findings * 100:.0f}%"
            self._write_row(ws, r, [risk, cnt, pct])
            ws.cell(row=r, column=1).fill = SEVERITY_FILLS.get(risk, PatternFill())
            ws.cell(row=r, column=3).alignment = _center()
            if risk in (RiskLevel.CRITICAL, RiskLevel.HIGH):
                ws.cell(row=r, column=1).font = Font(name="Calibri", size=10, bold=True, color=Colors.WHITE)

        # Findings by category table (right of risk)
        ws.cell(row=20, column=5, value="FINDINGS BY CATEGORY").font = Font(name="Calibri", size=12, bold=True, color=Colors.PRIMARY)
        cat_data = sorted(gr.findings_by_category.items(), key=lambda x: x[1], reverse=True)
        r_cat = 21
        self._write_headers(ws, r_cat, ["", "", "", "", "Category", "Count"], [18, 10, 14, 2, 24, 10])
        for j, (cat, cnt) in enumerate(cat_data):
            ws.cell(row=r_cat + 1 + j, column=5, value=cat).border = _border()
            ws.cell(row=r_cat + 1 + j, column=6, value=cnt).border = _border()
            ws.cell(row=r_cat + 1 + j, column=6).alignment = _center()

        # Pie chart: findings by risk
        pie = PieChart()
        pie.title = "Findings by Risk Level"
        pie.style = 10; pie.width = 14; pie.height = 10
        cats_ref = Reference(ws, min_col=1, min_row=row + 1, max_row=row + 5)
        vals = Reference(ws, min_col=2, min_row=row + 1, max_row=row + 5)
        pie.add_data(vals, titles_from_data=False)
        pie.set_categories(cats_ref)
        for idx, c in enumerate([Colors.CRITICAL, Colors.HIGH, Colors.MEDIUM, Colors.LOW, Colors.INFO_RISK]):
            pt = DataPoint(idx=idx)
            pt.graphicalProperties.solidFill = c
            pie.series[0].data_points.append(pt)
        pie.dataLabels = DataLabelList()
        pie.dataLabels.showPercent = True; pie.dataLabels.showVal = True; pie.dataLabels.showCatName = True
        pie.legend.position = 'b'
        ws.add_chart(pie, "H20")

        # --- Top Risk Users (row 28) ---
        row = 28
        ws.cell(row=row, column=1, value="TOP RISK USERS").font = Font(name="Calibri", size=12, bold=True, color=Colors.PRIMARY)
        row += 1
        self._write_headers(ws, row, ["User", "Risk Score", "Flags", "Groups", "Permissions", "High-Risk Perms"],
                            [22, 12, 26, 30, 14, 16])
        risk_users = sorted(user_insights.values(), key=lambda x: x["risk_score"], reverse=True)[:8]
        for i, ui in enumerate(risk_users):
            u = ui["user"]
            r = row + 1 + i
            self._write_row(ws, r, [
                u.display_name, ui["risk_score"],
                ", ".join(ui["flags"]) if ui["flags"] else "None",
                ", ".join(ui["groups"][:3]) + ("..." if len(ui["groups"]) > 3 else ""),
                ui["perm_count"], ui["high_risk_perms"],
            ], alt=i % 2 == 1)
            # Color risk score
            sc = ws.cell(row=r, column=2)
            sc.alignment = _center()
            if ui["risk_score"] >= 60:
                sc.fill = PatternFill(start_color=Colors.DENY, end_color=Colors.DENY, fill_type="solid")
                sc.font = Font(name="Calibri", bold=True, color=Colors.DENY_TEXT)
            elif ui["risk_score"] >= 30:
                sc.fill = PatternFill(start_color="FFF3CD", end_color="FFF3CD", fill_type="solid")

        # --- Permissions by Service + Distribution (row 38) ---
        row = 38
        ws.cell(row=row, column=1, value="PERMISSIONS BY SERVICE").font = Font(name="Calibri", size=12, bold=True, color=Colors.PRIMARY)
        row += 1
        self._write_headers(ws, row, ["Service", "Total Perms", "Risk Level", "Allow", "Deny"],
                            [22, 14, 14, 10, 10])
        services = sorted(gr.permissions_by_service.items(), key=lambda x: x[1], reverse=True)
        for i, (svc, cnt) in enumerate(services):
            r = row + 1 + i
            risk = gr.risk_by_service.get(svc, "Info")
            # Count allow/deny per service
            sp = self.permissions.get_by_service(svc)
            allow_c = sum(1 for p in sp.permissions if p.state in (PermissionState.ALLOW, PermissionState.INHERITED_ALLOW))
            deny_c = sum(1 for p in sp.permissions if p.state in (PermissionState.DENY, PermissionState.INHERITED_DENY))
            self._write_row(ws, r, [svc, cnt, risk, allow_c, deny_c], alt=i % 2 == 1)
            rf = SEVERITY_FILLS.get(risk)
            if rf:
                ws.cell(row=r, column=3).fill = rf
                if risk in (RiskLevel.CRITICAL, RiskLevel.HIGH):
                    ws.cell(row=r, column=3).font = Font(color=Colors.WHITE, bold=True)
            if deny_c > 0:
                ws.cell(row=r, column=5).fill = PatternFill(start_color=Colors.DENY, end_color=Colors.DENY, fill_type="solid")

        end_svc_row = row + len(services)
        if services:
            bar = BarChart()
            bar.type = "col"; bar.style = 10
            bar.title = "Permissions by Service Area"
            bar.y_axis.title = "Count"; bar.width = 18; bar.height = 10
            d = Reference(ws, min_col=2, min_row=row, max_row=end_svc_row)
            ca = Reference(ws, min_col=1, min_row=row + 1, max_row=end_svc_row)
            bar.add_data(d, titles_from_data=True); bar.set_categories(ca)
            bar.series[0].graphicalProperties.solidFill = Colors.ACCENT
            bar.legend.position = 'b'
            ws.add_chart(bar, f"G{row}")

        # --- License Summary (right of services) ---
        lic_row = row
        ws.cell(row=lic_row - 1, column=7, value="LICENSE DISTRIBUTION").font = Font(name="Calibri", size=12, bold=True, color=Colors.PRIMARY)
        lic_dist: Dict[str, int] = {}
        for u in self.users:
            lic_dist[u.access_level] = lic_dist.get(u.access_level, 0) + 1
        for ci, hdr in enumerate(["License Type", "Users", "Active", "Inactive"]):
            cell = ws.cell(row=lic_row, column=7 + ci, value=hdr)
            cell.font = _hf(); cell.fill = _hfill(); cell.alignment = _center(); cell.border = _border()
        for j, (lic, cnt) in enumerate(sorted(lic_dist.items(), key=lambda x: x[1], reverse=True)):
            r = lic_row + 1 + j
            active_lic = sum(1 for u in self.users if u.access_level == lic and u.is_active)
            inactive_lic = cnt - active_lic
            ws.cell(row=r, column=7, value=lic).border = _border()
            ws.cell(row=r, column=8, value=cnt).border = _border()
            ws.cell(row=r, column=8).alignment = _center()
            ws.cell(row=r, column=9, value=active_lic).border = _border()
            ws.cell(row=r, column=9).alignment = _center()
            c10 = ws.cell(row=r, column=10, value=inactive_lic)
            c10.border = _border(); c10.alignment = _center()
            if inactive_lic > 0:
                c10.fill = PatternFill(start_color="FFF3CD", end_color="FFF3CD", fill_type="solid")

        ws.column_dimensions["A"].width = 22
        ws.column_dimensions["B"].width = 18
        ws.column_dimensions["C"].width = 18
        for col_letter in ["G", "H", "I", "J"]:
            ws.column_dimensions[col_letter].width = 16

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
        radar.legend.position = 'b'
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
        bar.legend.position = 'b'
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
        pie.dataLabels.showCatName = True
        pie.legend.position = 'b'
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
            bar.legend.position = 'b'
            ws.add_chart(bar, f"D{cat_row}")

    # ---- Sheet: User Risk Profiles ----

    def _create_user_risk_profiles(self):
        ws = self.wb.create_sheet("User Risk Profiles")
        ws.sheet_properties.tabColor = Colors.DANGER
        gr = self.gov
        user_insights = self._compute_user_insights()
        now = datetime.now()

        self._write_title(ws, 1, 1, "User Risk Profiles & Security Assessment", 16)
        ws.merge_cells("A1:L1")
        ws.cell(row=2, column=1,
            value="Per-user security analysis: risk score, group memberships, permission footprint, and risk indicators."
        ).font = Font(name="Calibri", size=10, color=Colors.DARK_GRAY, italic=True)
        ws.merge_cells("A2:L2")

        # Summary cards
        row = 4
        total = len(self.users)
        flagged = sum(1 for ui in user_insights.values() if ui["risk_score"] >= 30)
        high_risk = sum(1 for ui in user_insights.values() if ui["risk_score"] >= 60)
        admins = sum(1 for ui in user_insights.values() if ui["is_admin"])
        for ci, (lbl, val, clr) in enumerate([
            ("Total Users", total, Colors.ACCENT),
            ("Flagged Users", flagged, Colors.WARNING if flagged > 0 else Colors.SUCCESS),
            ("High Risk Users", high_risk, Colors.DANGER if high_risk > 0 else Colors.SUCCESS),
            ("Admin Users", admins, Colors.DANGER if admins > 3 else Colors.ACCENT),
        ]):
            self._metric_card(ws, row, ci + 1, lbl, val, clr)

        # Main table
        row = 7
        headers = ["User", "Email", "License", "Active", "Last Access", "Days Idle",
                   "Risk Score", "Risk Flags", "Groups", "Services Accessed",
                   "Total Perms", "High-Risk Perms"]
        widths = [20, 28, 18, 8, 14, 10, 12, 28, 34, 28, 12, 14]
        self._write_headers(ws, row, headers, widths)

        sorted_users = sorted(user_insights.values(), key=lambda x: x["risk_score"], reverse=True)
        for i, ui in enumerate(sorted_users):
            u = ui["user"]
            r = row + 1 + i
            if u.last_accessed:
                days_idle = (now - u.last_accessed).days
                last_str = u.last_accessed.strftime("%Y-%m-%d")
            else:
                days_idle = ""
                last_str = "No Data"
            self._write_row(ws, r, [
                u.display_name, u.mail_address, u.access_level,
                "Yes" if u.is_active else "No", last_str, days_idle,
                ui["risk_score"],
                ", ".join(ui["flags"]) if ui["flags"] else "None",
                ", ".join(ui["groups"]),
                ", ".join(sorted(ui["services"])) if ui["services"] else "None",
                ui["perm_count"], ui["high_risk_perms"],
            ], alt=i % 2 == 1)
            # Color risk score
            sc = ws.cell(row=r, column=7)
            sc.alignment = _center()
            if ui["risk_score"] >= 60:
                sc.fill = PatternFill(start_color=Colors.DENY, end_color=Colors.DENY, fill_type="solid")
                sc.font = Font(name="Calibri", bold=True, color=Colors.DENY_TEXT)
            elif ui["risk_score"] >= 30:
                sc.fill = PatternFill(start_color="FFF3CD", end_color="FFF3CD", fill_type="solid")
            # Inactive highlight
            if not u.is_active:
                ws.cell(row=r, column=4).fill = PatternFill(start_color=Colors.DENY, end_color=Colors.DENY, fill_type="solid")
            # Stale highlight
            if isinstance(days_idle, int) and days_idle > 90:
                ws.cell(row=r, column=6).fill = PatternFill(start_color=Colors.DENY, end_color=Colors.DENY, fill_type="solid")
                ws.cell(row=r, column=6).font = Font(name="Calibri", bold=True, color=Colors.DENY_TEXT)

        last_row = row + len(sorted_users)
        if sorted_users:
            ws.auto_filter.ref = f"A{row}:{get_column_letter(len(headers))}{last_row}"
            ws.freeze_panes = f"A{row + 1}"

        # Risk distribution chart
        cr = last_row + 2
        ws.cell(row=cr, column=1, value="Risk Level"); ws.cell(row=cr, column=2, value="Users")
        low_risk = sum(1 for ui in user_insights.values() if ui["risk_score"] < 30)
        med_risk = sum(1 for ui in user_insights.values() if 30 <= ui["risk_score"] < 60)
        ws.cell(row=cr + 1, column=1, value="Low Risk (0-29)"); ws.cell(row=cr + 1, column=2, value=low_risk)
        ws.cell(row=cr + 2, column=1, value="Medium Risk (30-59)"); ws.cell(row=cr + 2, column=2, value=med_risk)
        ws.cell(row=cr + 3, column=1, value="High Risk (60+)"); ws.cell(row=cr + 3, column=2, value=high_risk)

        pie = PieChart()
        pie.title = "User Risk Distribution"; pie.style = 10; pie.width = 14; pie.height = 10
        pie.legend.position = 'b'
        ca = Reference(ws, min_col=1, min_row=cr + 1, max_row=cr + 3)
        d = Reference(ws, min_col=2, min_row=cr + 1, max_row=cr + 3)
        pie.add_data(d, titles_from_data=False); pie.set_categories(ca)
        for idx, c in enumerate([Colors.SUCCESS, Colors.WARNING, Colors.DANGER]):
            pt = DataPoint(idx=idx); pt.graphicalProperties.solidFill = c
            pie.series[0].data_points.append(pt)
        pie.dataLabels = DataLabelList()
        pie.dataLabels.showPercent = True; pie.dataLabels.showVal = True; pie.dataLabels.showCatName = True
        ws.add_chart(pie, f"A{cr + 4}")

        # Risk score bar chart
        bar = BarChart()
        bar.type = "col"; bar.style = 10
        bar.title = "Risk Score by User"; bar.y_axis.title = "Risk Score"
        bar.y_axis.scaling.max = 100; bar.y_axis.scaling.min = 0
        bar.width = 20; bar.height = 12; bar.legend.position = 'b'
        # Write chart data
        ws.cell(row=cr, column=5, value="User"); ws.cell(row=cr, column=6, value="Risk Score")
        for j, ui in enumerate(sorted_users[:12]):  # Top 12
            ws.cell(row=cr + 1 + j, column=5, value=ui["user"].display_name)
            ws.cell(row=cr + 1 + j, column=6, value=ui["risk_score"])
        num_chart_users = min(len(sorted_users), 12)
        if num_chart_users:
            d2 = Reference(ws, min_col=6, min_row=cr, max_row=cr + num_chart_users)
            ca2 = Reference(ws, min_col=5, min_row=cr + 1, max_row=cr + num_chart_users)
            bar.add_data(d2, titles_from_data=True); bar.set_categories(ca2)
            bar.series[0].graphicalProperties.solidFill = Colors.PRIMARY_LIGHT
            ws.add_chart(bar, f"E{cr + 4}")

    # ---- Sheet: License & Access Analysis ----

    def _create_license_access_analysis(self):
        ws = self.wb.create_sheet("License & Access")
        ws.sheet_properties.tabColor = Colors.INFO
        now = datetime.now()

        self._write_title(ws, 1, 1, "License & Access Level Analysis", 16)
        ws.merge_cells("A1:H1")
        ws.cell(row=2, column=1,
            value="License utilization, cost optimization opportunities, and access level appropriateness analysis."
        ).font = Font(name="Calibri", size=10, color=Colors.DARK_GRAY, italic=True)
        ws.merge_cells("A2:H2")

        # License distribution summary
        row = 4
        ws.cell(row=row, column=1, value="LICENSE DISTRIBUTION").font = Font(name="Calibri", size=12, bold=True, color=Colors.PRIMARY)
        row += 1
        self._write_headers(ws, row, ["License Type", "Total Users", "Active", "Inactive", "Utilization %", "Avg Days Idle"],
                            [24, 12, 10, 10, 14, 14])
        lic_data: Dict[str, Dict] = {}
        for u in self.users:
            if u.access_level not in lic_data:
                lic_data[u.access_level] = {"total": 0, "active": 0, "inactive": 0, "idle_days": []}
            lic_data[u.access_level]["total"] += 1
            if u.is_active:
                lic_data[u.access_level]["active"] += 1
            else:
                lic_data[u.access_level]["inactive"] += 1
            if u.last_accessed:
                lic_data[u.access_level]["idle_days"].append((now - u.last_accessed).days)

        for j, (lic, data) in enumerate(sorted(lic_data.items(), key=lambda x: x[1]["total"], reverse=True)):
            r = row + 1 + j
            util = f"{data['active'] / max(data['total'], 1) * 100:.0f}%"
            avg_idle = f"{sum(data['idle_days']) / max(len(data['idle_days']), 1):.0f}" if data['idle_days'] else "-"
            self._write_row(ws, r, [lic, data["total"], data["active"], data["inactive"], util, avg_idle],
                            alt=j % 2 == 1)
            ws.cell(row=r, column=5).alignment = _center()
            ws.cell(row=r, column=6).alignment = _center()
            if data["inactive"] > 0:
                ws.cell(row=r, column=4).fill = PatternFill(start_color="FFF3CD", end_color="FFF3CD", fill_type="solid")

        lic_end = row + len(lic_data)

        # Pie chart for license distribution
        cr = lic_end + 2
        ws.cell(row=cr, column=1, value="License"); ws.cell(row=cr, column=2, value="Users")
        for j, (lic, data) in enumerate(sorted(lic_data.items())):
            ws.cell(row=cr + 1 + j, column=1, value=lic)
            ws.cell(row=cr + 1 + j, column=2, value=data["total"])
        if lic_data:
            pie = PieChart()
            pie.title = "License Type Distribution"; pie.style = 10; pie.width = 14; pie.height = 10
            pie.legend.position = 'b'
            ca = Reference(ws, min_col=1, min_row=cr + 1, max_row=cr + len(lic_data))
            d = Reference(ws, min_col=2, min_row=cr + 1, max_row=cr + len(lic_data))
            pie.add_data(d, titles_from_data=False); pie.set_categories(ca)
            pie.dataLabels = DataLabelList()
            pie.dataLabels.showPercent = True; pie.dataLabels.showVal = True; pie.dataLabels.showCatName = True
            ws.add_chart(pie, f"A{cr + len(lic_data) + 1}")

        # Optimization Opportunities
        opt_row = cr + len(lic_data) + 2
        ws.cell(row=opt_row, column=4, value="LICENSE OPTIMIZATION OPPORTUNITIES").font = Font(
            name="Calibri", size=12, bold=True, color=Colors.PRIMARY)
        opt_row += 1
        self._write_headers(ws, opt_row, ["", "", "", "User", "Current License", "Issue", "Recommendation", "Savings Potential"],
                            [0, 0, 0, 22, 20, 30, 35, 16])
        opt_count = 0
        for u in self.users:
            issues = []
            if not u.is_active and u.access_level in ("Visual Studio Enterprise", "Visual Studio Professional", "Basic"):
                issues.append(("Inactive premium license", "Downgrade to Stakeholder or remove", "High"))
            if u.last_accessed:
                days = (now - u.last_accessed).days
                if days > 60 and u.access_level in ("Visual Studio Enterprise", "Visual Studio Professional"):
                    issues.append((f"Premium license idle {days} days", "Review and potentially downgrade", "Medium"))
            # Check for stakeholder in high-perm groups
            if u.access_level == "Stakeholder":
                group_map = {g.descriptor: g for g in self.groups}
                for gd in u.group_memberships:
                    g = group_map.get(gd)
                    if g and "contributor" in g.display_name.lower():
                        issues.append(("Stakeholder in contributor group", "Upgrade license or remove from group", "Low"))
                        break
            for issue, rec, savings in issues:
                r = opt_row + 1 + opt_count
                ws.cell(row=r, column=4, value=u.display_name).border = _border()
                ws.cell(row=r, column=5, value=u.access_level).border = _border()
                ws.cell(row=r, column=6, value=issue).border = _border()
                ws.cell(row=r, column=7, value=rec).border = _border()
                c_sav = ws.cell(row=r, column=8, value=savings)
                c_sav.border = _border(); c_sav.alignment = _center()
                if savings == "High":
                    c_sav.fill = PatternFill(start_color=Colors.DENY, end_color=Colors.DENY, fill_type="solid")
                elif savings == "Medium":
                    c_sav.fill = PatternFill(start_color="FFF3CD", end_color="FFF3CD", fill_type="solid")
                opt_count += 1

        if opt_count == 0:
            ws.cell(row=opt_row + 1, column=4, value="No optimization opportunities identified.").font = Font(
                name="Calibri", italic=True, color=Colors.DARK_GRAY)

        ws.column_dimensions["D"].width = 22
        ws.column_dimensions["E"].width = 20

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
        pie.dataLabels = DataLabelList(); pie.dataLabels.showPercent = True; pie.dataLabels.showVal = True
        pie.dataLabels.showCatName = True
        pie.legend.position = 'b'
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
        bar.legend.position = 'b'
        ws.add_chart(bar, f"E{cr + max(3, len(self.groups)) + 1}")

    # ---- Sheet: Group Hierarchy & Risk ----

    def _create_group_hierarchy(self):
        ws = self.wb.create_sheet("Group Hierarchy & Risk")
        ws.sheet_properties.tabColor = Colors.PRIMARY_LIGHT
        gr = self.gov
        user_insights = self._compute_user_insights()

        self._write_title(ws, 1, 1, "Group Hierarchy, Membership & Risk Analysis", 16)
        ws.merge_cells("A1:K1")
        ws.cell(row=2, column=1,
            value="Security group risk assessment: member composition, permission coverage, nesting, and governance flags."
        ).font = Font(name="Calibri", size=10, color=Colors.DARK_GRAY, italic=True)
        ws.merge_cells("A2:K2")

        # Group risk table
        row = 4
        ws.cell(row=row, column=1, value="GROUP RISK ASSESSMENT").font = Font(
            name="Calibri", size=12, bold=True, color=Colors.PRIMARY)
        row += 1
        headers = ["Group", "Type", "Members", "Users", "Nested Groups", "Inactive Members",
                   "Permission Count", "Services", "Risk Flags", "Risk Level"]
        widths = [26, 10, 10, 8, 14, 16, 16, 28, 32, 12]
        self._write_headers(ws, row, headers, widths)

        for i, g in enumerate(self.groups):
            r = row + 1 + i
            member_count = g.member_count or len(g.members)
            user_members = [m for m in g.members if m.member_type == "user"]
            group_members = [m for m in g.members if m.member_type == "group"]
            inactive_members = [m for m in g.members if not m.is_active]

            # Count permissions for this group
            perm_count = 0
            svc_set = set()
            for svc in self.permissions.all_services():
                sp = self.permissions.get_by_service(svc)
                for p in sp.permissions:
                    if p.identity_descriptor == g.descriptor:
                        perm_count += 1
                        svc_set.add(svc)

            # Risk flags
            flags = []
            if member_count == 0:
                flags.append("Empty")
            if member_count > 15:
                flags.append("Large")
            if len(inactive_members) > 0:
                flags.append(f"{len(inactive_members)} inactive")
            if "Administrator" in g.display_name and g.group_type == "Custom":
                flags.append("Custom admin")
            if perm_count > 20:
                flags.append("High perm count")

            risk = "High" if len(flags) >= 3 else "Medium" if len(flags) >= 1 else "Low"

            self._write_row(ws, r, [
                g.display_name, g.group_type, member_count, len(user_members),
                len(group_members), len(inactive_members), perm_count,
                ", ".join(sorted(svc_set)) if svc_set else "None",
                ", ".join(flags) if flags else "No issues",
                risk,
            ], alt=i % 2 == 1)

            # Color risk level
            rc = ws.cell(row=r, column=10)
            rc.alignment = _center()
            if risk == "High":
                rc.fill = PatternFill(start_color=Colors.DENY, end_color=Colors.DENY, fill_type="solid")
                rc.font = Font(name="Calibri", bold=True, color=Colors.DENY_TEXT)
            elif risk == "Medium":
                rc.fill = PatternFill(start_color="FFF3CD", end_color="FFF3CD", fill_type="solid")
            else:
                rc.fill = PatternFill(start_color=Colors.ALLOW, end_color=Colors.ALLOW, fill_type="solid")

        last_row = row + len(self.groups)
        ws.auto_filter.ref = f"A{row}:{get_column_letter(len(headers))}{last_row}"
        ws.freeze_panes = f"A{row + 1}"

        # Group membership matrix (User -> Groups)
        mx_row = last_row + 3
        ws.cell(row=mx_row, column=1, value="USER-GROUP MEMBERSHIP MATRIX").font = Font(
            name="Calibri", size=12, bold=True, color=Colors.PRIMARY)
        mx_row += 1
        # Header row
        hcell = ws.cell(row=mx_row, column=1, value="User")
        hcell.font = _hf(); hcell.fill = _hfill(); hcell.border = _border()
        ws.column_dimensions["A"].width = 22
        for gi, g in enumerate(self.groups):
            col = gi + 2
            cell = ws.cell(row=mx_row, column=col, value=g.display_name)
            cell.font = Font(name="Calibri", size=9, bold=True, color=Colors.WHITE)
            cell.fill = _hfill()
            cell.alignment = Alignment(horizontal="center", text_rotation=45, wrap_text=True)
            cell.border = _border()
            ws.column_dimensions[get_column_letter(col)].width = 14

        group_descriptor_map = {g.descriptor: g for g in self.groups}
        for ui, u in enumerate(self.users):
            r = mx_row + 1 + ui
            ws.cell(row=r, column=1, value=u.display_name).font = Font(name="Calibri", size=10, bold=True)
            ws.cell(row=r, column=1).border = _border()
            for gi, g in enumerate(self.groups):
                col = gi + 2
                cell = ws.cell(row=r, column=col)
                cell.border = _border(); cell.alignment = _center()
                if g.descriptor in u.group_memberships:
                    cell.value = "YES"
                    cell.fill = PatternFill(start_color=Colors.ALLOW, end_color=Colors.ALLOW, fill_type="solid")
                    cell.font = Font(name="Calibri", size=9, bold=True, color=Colors.ALLOW_TEXT)
                else:
                    cell.value = ""
                    cell.fill = PatternFill(start_color=Colors.NOT_SET, end_color=Colors.NOT_SET, fill_type="solid")

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
        headers = ["User Name", "Email", "Access Level", "License", "Active", "Origin", "Created", "Last Accessed", "Days Since Access"]
        widths = [22, 30, 20, 22, 10, 10, 14, 16, 18]
        self._write_headers(ws, row, headers, widths)

        now = datetime.now()
        for i, u in enumerate(self.users):
            r = row + 1 + i
            if u.last_accessed:
                days_since = (now - u.last_accessed).days
                access_str = u.last_accessed.strftime("%Y-%m-%d")
            else:
                days_since = ""
                access_str = "No Data"
            self._write_row(ws, r, [
                u.display_name, u.mail_address, u.access_level, u.license_display_name,
                "Yes" if u.is_active else "No", u.origin,
                u.date_created.strftime("%Y-%m-%d") if u.date_created else "",
                access_str, days_since,
            ], alt=i % 2 == 1)
            if not u.is_active:
                ws.cell(row=r, column=5).fill = PatternFill(start_color="FFC7CE", end_color="FFC7CE", fill_type="solid")
            if isinstance(days_since, int) and days_since > 90:
                ws.cell(row=r, column=9).fill = PatternFill(start_color="FFC7CE", end_color="FFC7CE", fill_type="solid")
                ws.cell(row=r, column=9).font = Font(name="Calibri", size=10, bold=True, color=Colors.DENY_TEXT)
            elif isinstance(days_since, int) and days_since > 30:
                ws.cell(row=r, column=9).fill = PatternFill(start_color="FFF3CD", end_color="FFF3CD", fill_type="solid")

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
            pie.dataLabels.showCatName = True
            pie.legend.position = 'b'
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
        bar.legend.position = 'b'
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

    # ---- Sheet: Unified Permissions (All Services) ----

    def _create_unified_permissions(self):
        ws = self.wb.create_sheet("All Permissions")
        ws.sheet_properties.tabColor = Colors.PRIMARY

        self._write_title(ws, 1, 1, "All Permissions - Unified View", 16)
        ws.merge_cells("A1:I1")
        ws.cell(row=2, column=1,
            value="Filter by Service, Identity, Resource, or State using Excel auto-filters. All resource IDs resolved to display names."
        ).font = Font(name="Calibri", size=10, color=Colors.DARK_GRAY, italic=True)
        ws.merge_cells("A2:I2")

        # --- Summary cards at top ---
        all_perms = []
        for svc in self.permissions.all_services():
            sp = self.permissions.get_by_service(svc)
            for p in sp.permissions:
                all_perms.append((svc, p))

        total_allow = sum(1 for _, p in all_perms if p.state in (PermissionState.ALLOW, PermissionState.INHERITED_ALLOW))
        total_deny = sum(1 for _, p in all_perms if p.state in (PermissionState.DENY, PermissionState.INHERITED_DENY))
        total_inherited = sum(1 for _, p in all_perms if p.is_inherited)
        total_direct = len(all_perms) - total_inherited
        unique_identities = len(set(p.identity_name for _, p in all_perms))
        unique_resources = len(set(p.resource_label for _, p in all_perms))
        unique_services = len(set(s for s, _ in all_perms))

        row = 4
        for ci, (lbl, val, clr) in enumerate([
            ("Total Perms", len(all_perms), Colors.ACCENT),
            ("Allow", total_allow, Colors.SUCCESS),
            ("Deny", total_deny, Colors.DANGER if total_deny > 0 else Colors.SUCCESS),
            ("Inherited", total_inherited, Colors.ACCENT),
            ("Direct", total_direct, Colors.PRIMARY),
            ("Identities", unique_identities, Colors.ACCENT),
            ("Resources", unique_resources, Colors.ACCENT),
            ("Services", unique_services, Colors.PRIMARY),
        ]):
            self._metric_card(ws, row, ci + 1, lbl, val, clr)

        # --- Permission State Legend ---
        legend_row = row
        legend_start_col = 10
        ws.cell(row=legend_row, column=legend_start_col, value="STATE LEGEND:").font = Font(name="Calibri", size=9, bold=True, color=Colors.PRIMARY)
        legend_items = [
            ("Allow", PermissionState.ALLOW),
            ("Deny", PermissionState.DENY),
            ("Inherited Allow", PermissionState.INHERITED_ALLOW),
            ("Inherited Deny", PermissionState.INHERITED_DENY),
            ("Not Set", PermissionState.NOT_SET),
        ]
        for li, (lbl, st) in enumerate(legend_items):
            c = ws.cell(row=legend_row + 1, column=legend_start_col + li, value=lbl)
            c.fill = PERM_STATE_FILLS.get(st, PatternFill())
            c.font = PERM_STATE_FONTS.get(st, Font())
            c.alignment = _center()
            c.border = _border()
            ws.column_dimensions[get_column_letter(legend_start_col + li)].width = 16

        # --- Service color legend ---
        svc_colors = {"Repos": "D6E4F0", "Pipelines": "E2EFDA", "Release": "FCE4D6",
                      "Project": "DDEBF7", "Boards": "FFF2CC"}
        ws.cell(row=legend_row, column=legend_start_col + 5, value="SERVICE COLORS:").font = Font(name="Calibri", size=9, bold=True, color=Colors.PRIMARY)
        for si, (svc_name, svc_clr) in enumerate(svc_colors.items()):
            c = ws.cell(row=legend_row + 1, column=legend_start_col + 5 + si, value=svc_name)
            c.fill = PatternFill(start_color=svc_clr, end_color=svc_clr, fill_type="solid")
            c.alignment = _center(); c.border = _border()
            c.font = Font(name="Calibri", size=9, bold=True)
            ws.column_dimensions[get_column_letter(legend_start_col + 5 + si)].width = 12

        # --- Main permissions table ---
        row = 7
        headers = ["Service", "Identity", "Resource", "Permission", "State", "Inherited", "Resource Type", "Namespace", "Source"]
        widths = [14, 24, 28, 30, 18, 12, 16, 22, 20]
        self._write_headers(ws, row, headers, widths)

        # Sort: service, then identity, then resource
        all_perms.sort(key=lambda x: (x[0], x[1].identity_name, x[1].resource_label, x[1].permission_name))

        for i, (svc, p) in enumerate(all_perms):
            r = row + 1 + i
            state_str = p.state.value.replace("_", " ").title()
            resource_type = self._resource_type_from_token(p.resource_token)
            self._write_row(ws, r, [
                svc, p.identity_name, p.resource_label, p.permission_name,
                state_str, "Yes" if p.is_inherited else "No",
                resource_type, p.namespace_name, p.source,
            ], alt=i % 2 == 1)
            # Color-code State
            sf = PERM_STATE_FILLS.get(p.state)
            sff = PERM_STATE_FONTS.get(p.state)
            if sf:
                ws.cell(row=r, column=5).fill = sf
            if sff:
                ws.cell(row=r, column=5).font = sff
            # Color-code service
            svc_fill = svc_colors.get(svc)
            if svc_fill:
                ws.cell(row=r, column=1).fill = PatternFill(start_color=svc_fill, end_color=svc_fill, fill_type="solid")
            # Highlight high-risk permissions
            if p.permission_name in ("Administer", "Force push", "Bypass policies",
                                     "Delete build pipeline", "Manage release approvers"):
                ws.cell(row=r, column=4).fill = PatternFill(start_color="FFF3CD", end_color="FFF3CD", fill_type="solid")
                ws.cell(row=r, column=4).font = Font(name="Calibri", size=10, bold=True)

        last_data_row = row + len(all_perms)
        if all_perms:
            ws.auto_filter.ref = f"A{row}:{get_column_letter(len(headers))}{last_data_row}"
            ws.freeze_panes = f"A{row + 1}"

        # --- Summary by service ---
        summary_row = last_data_row + 3
        ws.cell(row=summary_row, column=1, value="PERMISSION SUMMARY BY SERVICE").font = Font(
            name="Calibri", size=12, bold=True, color=Colors.PRIMARY)
        summary_row += 1
        self._write_headers(ws, summary_row, ["Service", "Total", "Allow", "Deny", "Inherited", "Direct", "High-Risk"],
                            widths=[14, 10, 10, 10, 12, 10, 12])

        svc_stats: Dict[str, Dict[str, int]] = {}
        for svc, p in all_perms:
            if svc not in svc_stats:
                svc_stats[svc] = {"total": 0, "allow": 0, "deny": 0, "inherited": 0, "direct": 0, "high_risk": 0}
            svc_stats[svc]["total"] += 1
            if p.state in (PermissionState.ALLOW, PermissionState.INHERITED_ALLOW):
                svc_stats[svc]["allow"] += 1
            if p.state in (PermissionState.DENY, PermissionState.INHERITED_DENY):
                svc_stats[svc]["deny"] += 1
            if p.is_inherited:
                svc_stats[svc]["inherited"] += 1
            else:
                svc_stats[svc]["direct"] += 1
            if p.permission_name in ("Administer", "Force push", "Bypass policies",
                                     "Delete build pipeline", "Manage release approvers"):
                svc_stats[svc]["high_risk"] += 1

        svc_names_sorted = sorted(svc_stats.keys())
        for j, svc in enumerate(svc_names_sorted):
            r = summary_row + 1 + j
            st = svc_stats[svc]
            self._write_row(ws, r, [svc, st["total"], st["allow"], st["deny"], st["inherited"], st["direct"], st["high_risk"]],
                            alt=j % 2 == 1)
            if st["deny"] > 0:
                ws.cell(row=r, column=4).fill = PatternFill(start_color="FFC7CE", end_color="FFC7CE", fill_type="solid")
            if st["high_risk"] > 0:
                ws.cell(row=r, column=7).fill = PatternFill(start_color="FFF3CD", end_color="FFF3CD", fill_type="solid")

        # Stacked bar chart
        if svc_names_sorted:
            chart_data_row = summary_row
            bar = BarChart()
            bar.type = "col"; bar.grouping = "stacked"; bar.style = 10
            bar.title = "Permission Distribution by Service"
            bar.y_axis.title = "Count"; bar.x_axis.title = "Service"
            bar.width = 20; bar.height = 12; bar.legend.position = 'b'
            ca = Reference(ws, min_col=1, min_row=chart_data_row + 2, max_row=chart_data_row + len(svc_names_sorted) + 1)
            for ci, (cn, clr, _) in enumerate([(3, Colors.SUCCESS, "Allow"), (4, Colors.DANGER, "Deny"), (5, Colors.ACCENT, "Inherited")]):
                d = Reference(ws, min_col=cn, min_row=chart_data_row + 1, max_row=chart_data_row + len(svc_names_sorted) + 1)
                bar.add_data(d, titles_from_data=True)
                bar.series[ci].graphicalProperties.solidFill = clr
            bar.set_categories(ca)
            ws.add_chart(bar, f"I{summary_row}")

        # --- Resource summary ---
        res_row = summary_row + len(svc_names_sorted) + 2
        ws.cell(row=res_row, column=1, value="PERMISSIONS BY RESOURCE").font = Font(
            name="Calibri", size=12, bold=True, color=Colors.PRIMARY)
        res_row += 1
        self._write_headers(ws, res_row, ["Resource", "Service", "Identities", "Allow", "Deny", "Total"],
                            widths=[28, 14, 12, 10, 10, 10])
        res_stats: Dict[str, Dict] = {}
        for svc, p in all_perms:
            key = p.resource_label
            if key not in res_stats:
                res_stats[key] = {"service": svc, "identities": set(), "allow": 0, "deny": 0, "total": 0}
            res_stats[key]["identities"].add(p.identity_name)
            res_stats[key]["total"] += 1
            if p.state in (PermissionState.ALLOW, PermissionState.INHERITED_ALLOW):
                res_stats[key]["allow"] += 1
            if p.state in (PermissionState.DENY, PermissionState.INHERITED_DENY):
                res_stats[key]["deny"] += 1

        for j, (res, data) in enumerate(sorted(res_stats.items(), key=lambda x: x[1]["total"], reverse=True)):
            r = res_row + 1 + j
            self._write_row(ws, r, [res, data["service"], len(data["identities"]),
                                    data["allow"], data["deny"], data["total"]], alt=j % 2 == 1)
            if data["deny"] > 0:
                ws.cell(row=r, column=5).fill = PatternFill(start_color="FFC7CE", end_color="FFC7CE", fill_type="solid")

        # User distribution chart
        ucr = res_row + len(res_stats) + 2
        user_totals: Dict[str, Dict[str, int]] = {}
        if self.permission_report and self.permission_report.matrices:
            for sn, sm in self.permission_report.matrices.items():
                for un, summary in sm.summary.items():
                    if un not in user_totals:
                        user_totals[un] = {"allow": 0, "deny": 0, "inherited": 0}
                    for k in ("allow", "deny", "inherited"):
                        user_totals[un][k] += summary.get(k, 0)
        if user_totals:
            ws.cell(row=ucr, column=1, value="PERMISSION DISTRIBUTION PER USER").font = Font(
                name="Calibri", size=12, bold=True, color=Colors.PRIMARY)
            ucr += 1
            ws.cell(row=ucr, column=1, value="User").font = Font(bold=True)
            ws.cell(row=ucr, column=2, value="Allow").font = Font(bold=True)
            ws.cell(row=ucr, column=3, value="Deny").font = Font(bold=True)
            ws.cell(row=ucr, column=4, value="Inherited").font = Font(bold=True)
            data_users = [u for u in user_totals if any(v > 0 for v in user_totals[u].values())]
            for j, uname in enumerate(data_users):
                r = ucr + 1 + j
                ws.cell(row=r, column=1, value=uname)
                ws.cell(row=r, column=2, value=user_totals[uname]["allow"])
                ws.cell(row=r, column=3, value=user_totals[uname]["deny"])
                ws.cell(row=r, column=4, value=user_totals[uname]["inherited"])
            if data_users:
                bar2 = BarChart()
                bar2.type = "col"; bar2.grouping = "stacked"; bar2.style = 10
                bar2.title = "Permission Distribution per User"
                bar2.y_axis.title = "Count"; bar2.x_axis.title = "User"
                bar2.width = 20; bar2.height = 12; bar2.legend.position = 'b'
                ca2 = Reference(ws, min_col=1, min_row=ucr + 1, max_row=ucr + len(data_users))
                for ci, (cn, clr) in enumerate([(2, Colors.SUCCESS), (3, Colors.DANGER), (4, Colors.ACCENT)]):
                    d = Reference(ws, min_col=cn, min_row=ucr, max_row=ucr + len(data_users))
                    bar2.add_data(d, titles_from_data=True)
                    bar2.series[ci].graphicalProperties.solidFill = clr
                bar2.set_categories(ca2)
                ws.add_chart(bar2, f"F{ucr}")

    @staticmethod
    def _resource_type_from_token(token: str) -> str:
        """Infer human-readable resource type from an ACL token."""
        if not token:
            return "Project"
        if token.startswith("$PROJECT"):
            return "Project"
        if "repoV2" in token or "repo" in token.lower():
            return "Repository"
        if token.startswith("$RELEASE") or "release" in token.lower():
            return "Release Pipeline"
        if "ci-" in token or "cd-" in token or "build" in token.lower():
            return "Build Pipeline"
        if "wit-" in token or "area" in token.lower():
            return "Work Item Area"
        if "/" in token:
            return "Resource"
        return "Other"

    # ---- Sheet: Inheritance Analysis ----

    def _create_inheritance_analysis(self):
        ws = self.wb.create_sheet("Inheritance Analysis")
        ws.sheet_properties.tabColor = Colors.PRIMARY_LIGHT
        self._write_title(ws, 1, 1, "Permission Inheritance Analysis", 14)
        ws.merge_cells("A1:I1")
        ws.cell(row=2, column=1,
            value="Shows how each user's effective permissions are acquired - directly assigned or inherited via group membership."
        ).font = Font(name="Calibri", size=10, color=Colors.DARK_GRAY, italic=True)
        ws.merge_cells("A2:I2")

        if not self.inheritance_analyzer:
            ws.cell(row=3, column=1, value="No inheritance analysis data available.")
            return

        # --- Section 1: Summary per user per service ---
        row = 4
        ws.cell(row=row, column=1, value="USER INHERITANCE SUMMARY").font = Font(
            name="Calibri", size=12, bold=True, color=Colors.PRIMARY)
        row += 1
        self._write_headers(ws, row, ["User", "Service", "Direct Perms", "Inherited Perms", "Total", "Deny Count", "Source Groups"],
                            [22, 18, 14, 16, 10, 12, 44])
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
                total = sir.direct_count + sir.inherited_count
                self._write_row(ws, r, [
                    user.display_name, svc_name, sir.direct_count,
                    sir.inherited_count, total, sir.deny_count,
                    ", ".join(sorted(source_groups)) if source_groups else "Direct only",
                ], alt=(r - row) % 2 == 1)
                total_direct += sir.direct_count
                total_inherited += sir.inherited_count
                if sir.deny_count > 0:
                    ws.cell(row=r, column=6).fill = PatternFill(start_color=Colors.DENY, end_color=Colors.DENY, fill_type="solid")

        summary_end = r

        # --- Section 2: Detailed per-permission inheritance breakdown ---
        r += 2
        ws.cell(row=r, column=1, value="DETAILED PERMISSION INHERITANCE").font = Font(
            name="Calibri", size=12, bold=True, color=Colors.PRIMARY)
        r += 1
        detail_hdr = ["User", "Service", "Permission", "Resource", "State", "Source Type", "Source Group", "Inheritance Chain"]
        detail_widths = [22, 14, 28, 26, 18, 16, 24, 40]
        self._write_headers(ws, r, detail_hdr, detail_widths)
        detail_hdr_row = r

        for user in self.users:
            analysis = self.inheritance_analyzer.analyze_user(user.descriptor)
            all_sources = (
                analysis.direct_permissions
                + analysis.group_inherited
                + analysis.resource_inherited
            )
            if not all_sources:
                continue

            from ..collectors.namespaces import NAMESPACE_SERVICE_MAPPING
            for ps in all_sources:
                r += 1
                p = ps.permission
                svc = NAMESPACE_SERVICE_MAPPING.get(p.namespace_name, "Other")
                state_str = p.state.value.replace("_", " ").title()
                chain_str = " > ".join(ps.inheritance_chain) if ps.inheritance_chain else "-"
                self._write_row(ws, r, [
                    user.display_name, svc, p.permission_name,
                    p.resource_label, state_str,
                    ps.source_type.replace("_", " ").title(),
                    ps.source_group or "-", chain_str,
                ], alt=(r - detail_hdr_row) % 2 == 1)
                sf = PERM_STATE_FILLS.get(p.state)
                sff = PERM_STATE_FONTS.get(p.state)
                if sf:
                    ws.cell(row=r, column=5).fill = sf
                if sff:
                    ws.cell(row=r, column=5).font = sff
                # Highlight source type
                if ps.source_type == "group_inherited":
                    ws.cell(row=r, column=6).fill = PatternFill(start_color=Colors.INHERITED, end_color=Colors.INHERITED, fill_type="solid")
                elif ps.source_type == "direct":
                    ws.cell(row=r, column=6).fill = PatternFill(start_color=Colors.ALLOW, end_color=Colors.ALLOW, fill_type="solid")

        # Auto-filter on detail table
        if r > detail_hdr_row:
            ws.auto_filter.ref = f"A{detail_hdr_row}:{get_column_letter(len(detail_hdr))}{r}"
            ws.freeze_panes = f"A{detail_hdr_row + 1}"

        # --- Pie chart: Direct vs Inherited ---
        cr = r + 2
        ws.cell(row=cr, column=1, value="Type"); ws.cell(row=cr, column=2, value="Count")
        ws.cell(row=cr + 1, column=1, value="Direct"); ws.cell(row=cr + 1, column=2, value=total_direct)
        ws.cell(row=cr + 2, column=1, value="Inherited"); ws.cell(row=cr + 2, column=2, value=total_inherited)

        if total_direct > 0 or total_inherited > 0:
            pie = PieChart()
            pie.title = "Direct vs Inherited Permissions"
            pie.style = 10; pie.width = 14; pie.height = 10
            pie.legend.position = 'b'
            ca = Reference(ws, min_col=1, min_row=cr + 1, max_row=cr + 2)
            d = Reference(ws, min_col=2, min_row=cr + 1, max_row=cr + 2)
            pie.add_data(d, titles_from_data=False); pie.set_categories(ca)
            for idx, c in enumerate([Colors.ACCENT, Colors.PRIMARY_LIGHT]):
                pt = DataPoint(idx=idx); pt.graphicalProperties.solidFill = c
                pie.series[0].data_points.append(pt)
            pie.dataLabels = DataLabelList()
            pie.dataLabels.showPercent = True
            pie.dataLabels.showVal = True
            pie.dataLabels.showCatName = True
            ws.add_chart(pie, f"A{cr + 3}")

        # --- Conflicts section ---
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
            bar.legend.position = 'b'
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
