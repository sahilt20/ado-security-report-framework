"""
Azure DevOps Data Governance Analyzer.

Provides risk scoring, compliance assessment, policy violation detection,
and governance metrics for Azure DevOps security posture.
"""

import logging
from typing import Dict, List, Optional, Set, Tuple
from dataclasses import dataclass, field
from collections import defaultdict
from datetime import datetime, timedelta

from ..models import (
    Permission,
    PermissionState,
    SecurityGroup,
    User,
)
from ..collectors.permissions import GranularPermissions, ServicePermissions

logger = logging.getLogger(__name__)


# --- Risk Levels ---
class RiskLevel:
    CRITICAL = "Critical"
    HIGH = "High"
    MEDIUM = "Medium"
    LOW = "Low"
    INFO = "Info"


RISK_COLORS = {
    RiskLevel.CRITICAL: "FF0000",
    RiskLevel.HIGH: "FF6600",
    RiskLevel.MEDIUM: "FFB800",
    RiskLevel.LOW: "2196F3",
    RiskLevel.INFO: "9E9E9E",
}

RISK_SCORES = {
    RiskLevel.CRITICAL: 10,
    RiskLevel.HIGH: 7,
    RiskLevel.MEDIUM: 4,
    RiskLevel.LOW: 2,
    RiskLevel.INFO: 0,
}


# --- Governance Data Models ---

@dataclass
class GovernanceFinding:
    """A single governance finding/issue."""
    category: str  # e.g., "Access Control", "Least Privilege", "Audit"
    title: str
    description: str
    risk_level: str
    affected_entity: str  # user, group, or resource name
    entity_type: str  # "user", "group", "permission", "policy"
    recommendation: str
    details: Dict = field(default_factory=dict)


@dataclass
class ComplianceControl:
    """A compliance control check."""
    control_id: str
    control_name: str
    category: str
    description: str
    status: str = "N/A"  # "Pass", "Fail", "Warning", "N/A"
    findings: List[GovernanceFinding] = field(default_factory=list)
    score: float = 0.0  # 0-100


@dataclass
class GovernanceScore:
    """Overall governance score."""
    overall_score: float = 0.0  # 0-100
    access_control_score: float = 0.0
    least_privilege_score: float = 0.0
    separation_of_duties_score: float = 0.0
    audit_compliance_score: float = 0.0
    lifecycle_management_score: float = 0.0

    @property
    def grade(self) -> str:
        if self.overall_score >= 90:
            return "A"
        elif self.overall_score >= 80:
            return "B"
        elif self.overall_score >= 70:
            return "C"
        elif self.overall_score >= 60:
            return "D"
        return "F"


@dataclass
class GovernanceReport:
    """Complete governance report."""
    organization: str
    project: str
    generated_at: datetime = field(default_factory=datetime.now)
    score: GovernanceScore = field(default_factory=GovernanceScore)
    findings: List[GovernanceFinding] = field(default_factory=list)
    controls: List[ComplianceControl] = field(default_factory=list)

    # Summary metrics
    total_users: int = 0
    active_users: int = 0
    inactive_users: int = 0
    total_groups: int = 0
    custom_groups: int = 0
    default_groups: int = 0
    total_permissions: int = 0
    direct_permissions: int = 0
    inherited_permissions: int = 0
    allow_permissions: int = 0
    deny_permissions: int = 0
    admin_users: int = 0
    external_users: int = 0
    empty_groups: int = 0
    overprivileged_users: int = 0
    stale_users: int = 0

    # Service breakdown
    permissions_by_service: Dict[str, int] = field(default_factory=dict)
    risk_by_service: Dict[str, str] = field(default_factory=dict)

    # Findings breakdown
    findings_by_risk: Dict[str, int] = field(default_factory=dict)
    findings_by_category: Dict[str, int] = field(default_factory=dict)

    @property
    def critical_findings(self) -> List[GovernanceFinding]:
        return [f for f in self.findings if f.risk_level == RiskLevel.CRITICAL]

    @property
    def high_findings(self) -> List[GovernanceFinding]:
        return [f for f in self.findings if f.risk_level == RiskLevel.HIGH]


# --- High-risk permissions that should be flagged ---
HIGH_RISK_PERMISSIONS = {
    "Administer",
    "Force push",
    "Bypass policies",
    "Bypass policies on PR",
    "Delete project",
    "Delete repository",
    "Manage permissions",
    "Administer build permissions",
    "Administer permissions",
    "Permanently delete",
    "Destroy builds",
    "Delete build definition",
    "Delete release pipeline",
    "Delete release stage",
    "Edit policies",
}

ADMIN_GROUP_KEYWORDS = [
    "administrator",
    "admin",
    "project collection",
]


class GovernanceAnalyzer:
    """
    Analyzes Azure DevOps data governance posture.

    Performs:
    - Risk scoring per user, group, and service
    - Compliance control checks
    - Policy violation detection
    - Least privilege analysis
    - Stale account detection
    - Separation of duties checks
    """

    def __init__(
        self,
        groups: List[SecurityGroup],
        users: List[User],
        granular_permissions: GranularPermissions,
        organization: str = "",
        project: str = "",
    ):
        self.groups = groups
        self.users = users
        self.permissions = granular_permissions
        self.organization = organization
        self.project = project

        self._groups_by_descriptor = {g.descriptor: g for g in groups}
        self._users_by_descriptor = {u.descriptor: u for u in users}

        # Build user -> groups mapping
        self._user_groups: Dict[str, Set[str]] = defaultdict(set)
        for group in groups:
            for member in group.members:
                if member.member_type == "user":
                    self._user_groups[member.descriptor].add(group.descriptor)

    def analyze(self) -> GovernanceReport:
        """Run full governance analysis and return report."""
        report = GovernanceReport(
            organization=self.organization,
            project=self.project,
        )

        # Compute basic metrics
        self._compute_metrics(report)

        # Run all checks
        self._check_admin_access(report)
        self._check_least_privilege(report)
        self._check_separation_of_duties(report)
        self._check_stale_accounts(report)
        self._check_empty_groups(report)
        self._check_external_users(report)
        self._check_high_risk_permissions(report)
        self._check_permission_inheritance(report)
        self._check_deny_overrides(report)

        # Run compliance controls
        self._run_compliance_controls(report)

        # Calculate scores
        self._calculate_scores(report)

        # Build summaries
        report.findings_by_risk = self._count_by_field(report.findings, "risk_level")
        report.findings_by_category = self._count_by_field(report.findings, "category")

        return report

    # ------------------------------------------------------------------
    # Metrics
    # ------------------------------------------------------------------

    def _compute_metrics(self, report: GovernanceReport):
        report.total_users = len(self.users)
        report.active_users = sum(1 for u in self.users if u.is_active)
        report.inactive_users = report.total_users - report.active_users
        report.total_groups = len(self.groups)
        report.custom_groups = sum(1 for g in self.groups if g.group_type == "Custom")
        report.default_groups = report.total_groups - report.custom_groups
        report.empty_groups = sum(1 for g in self.groups if g.member_count == 0)

        all_perms = self.permissions.all_permissions()
        report.total_permissions = len(all_perms)
        report.direct_permissions = sum(1 for p in all_perms if not p.is_inherited)
        report.inherited_permissions = sum(1 for p in all_perms if p.is_inherited)
        report.allow_permissions = sum(
            1 for p in all_perms
            if p.state in (PermissionState.ALLOW, PermissionState.INHERITED_ALLOW)
        )
        report.deny_permissions = sum(
            1 for p in all_perms
            if p.state in (PermissionState.DENY, PermissionState.INHERITED_DENY)
        )

        # Permissions by service
        for service in self.permissions.all_services():
            sp = self.permissions.get_by_service(service)
            if sp.permissions:
                report.permissions_by_service[service] = len(sp.permissions)

        # Admin / external counts
        report.admin_users = 0
        report.external_users = 0
        for user in self.users:
            user_groups = self._user_groups.get(user.descriptor, set())
            if self._is_admin_user(user_groups):
                report.admin_users += 1
            if self._is_external_user(user):
                report.external_users += 1

    # ------------------------------------------------------------------
    # Governance Checks
    # ------------------------------------------------------------------

    def _check_admin_access(self, report: GovernanceReport):
        """Check for excessive admin access."""
        admin_count = 0
        for user in self.users:
            user_groups = self._user_groups.get(user.descriptor, set())
            if self._is_admin_user(user_groups):
                admin_count += 1
                admin_group_names = [
                    self._groups_by_descriptor[g].display_name
                    for g in user_groups
                    if g in self._groups_by_descriptor
                    and any(kw in self._groups_by_descriptor[g].display_name.lower()
                            for kw in ADMIN_GROUP_KEYWORDS)
                ]
                report.findings.append(GovernanceFinding(
                    category="Access Control",
                    title="User with Administrative Access",
                    description=f"{user.display_name} has administrative privileges via: {', '.join(admin_group_names)}",
                    risk_level=RiskLevel.HIGH if len(admin_group_names) > 1 else RiskLevel.MEDIUM,
                    affected_entity=user.display_name,
                    entity_type="user",
                    recommendation="Review if administrative access is necessary. Apply least privilege principle.",
                    details={"groups": admin_group_names, "email": user.mail_address},
                ))

        # Too many admins
        if admin_count > 3:
            report.findings.append(GovernanceFinding(
                category="Access Control",
                title="Excessive Administrator Count",
                description=f"{admin_count} users have administrative access. Best practice is 2-3 admins.",
                risk_level=RiskLevel.HIGH,
                affected_entity=f"{admin_count} admin users",
                entity_type="policy",
                recommendation="Reduce admin count to 2-3. Use JIT access for occasional admin needs.",
            ))

    def _check_least_privilege(self, report: GovernanceReport):
        """Check for overprivileged users."""
        for user in self.users:
            user_groups = self._user_groups.get(user.descriptor, set())
            user_perms = []
            for service in self.permissions.all_services():
                sp = self.permissions.get_by_service(service)
                for p in sp.permissions:
                    if p.identity_descriptor == user.descriptor or p.identity_descriptor in user_groups:
                        user_perms.append(p)

            high_risk_count = sum(
                1 for p in user_perms
                if p.permission_name in HIGH_RISK_PERMISSIONS
                and p.state in (PermissionState.ALLOW, PermissionState.INHERITED_ALLOW)
            )

            if high_risk_count >= 5:
                report.overprivileged_users += 1
                report.findings.append(GovernanceFinding(
                    category="Least Privilege",
                    title="Overprivileged User",
                    description=f"{user.display_name} has {high_risk_count} high-risk permissions.",
                    risk_level=RiskLevel.HIGH,
                    affected_entity=user.display_name,
                    entity_type="user",
                    recommendation="Review and reduce high-risk permissions. Use role-based access.",
                    details={"high_risk_count": high_risk_count},
                ))
            elif high_risk_count >= 3:
                report.overprivileged_users += 1
                report.findings.append(GovernanceFinding(
                    category="Least Privilege",
                    title="Elevated Privileges Detected",
                    description=f"{user.display_name} has {high_risk_count} high-risk permissions.",
                    risk_level=RiskLevel.MEDIUM,
                    affected_entity=user.display_name,
                    entity_type="user",
                    recommendation="Verify these privileges are required for the user's role.",
                    details={"high_risk_count": high_risk_count},
                ))

    def _check_separation_of_duties(self, report: GovernanceReport):
        """Check separation of duties violations."""
        for user in self.users:
            user_groups = self._user_groups.get(user.descriptor, set())
            group_names = set()
            for gd in user_groups:
                g = self._groups_by_descriptor.get(gd)
                if g:
                    group_names.add(g.display_name)

            # Check: Build Admin + Release Admin = SoD violation
            has_build_admin = any("build" in g.lower() and "admin" in g.lower() for g in group_names)
            has_release_admin = any("release" in g.lower() and "admin" in g.lower() for g in group_names)

            if has_build_admin and has_release_admin:
                report.findings.append(GovernanceFinding(
                    category="Separation of Duties",
                    title="Build and Release Admin Combined",
                    description=f"{user.display_name} is both Build Administrator and Release Administrator.",
                    risk_level=RiskLevel.HIGH,
                    affected_entity=user.display_name,
                    entity_type="user",
                    recommendation="Separate build and release admin roles to different users.",
                ))

            # Check: Project Admin + member of many service groups
            is_proj_admin = any("project admin" in g.lower() for g in group_names)
            if is_proj_admin and len(group_names) > 3:
                report.findings.append(GovernanceFinding(
                    category="Separation of Duties",
                    title="Admin with Multiple Role Assignments",
                    description=f"{user.display_name} is Project Admin and member of {len(group_names)} groups.",
                    risk_level=RiskLevel.MEDIUM,
                    affected_entity=user.display_name,
                    entity_type="user",
                    recommendation="Review if all group memberships are necessary for a project admin.",
                    details={"groups": list(group_names)},
                ))

    def _check_stale_accounts(self, report: GovernanceReport):
        """Check for stale/inactive accounts with permissions."""
        now = datetime.now()
        stale_threshold = now - timedelta(days=90)

        for user in self.users:
            if not user.is_active:
                user_groups = self._user_groups.get(user.descriptor, set())
                if user_groups:
                    report.stale_users += 1
                    report.findings.append(GovernanceFinding(
                        category="Lifecycle Management",
                        title="Inactive User with Group Memberships",
                        description=f"{user.display_name} is inactive but still member of {len(user_groups)} group(s).",
                        risk_level=RiskLevel.HIGH,
                        affected_entity=user.display_name,
                        entity_type="user",
                        recommendation="Remove inactive user from all security groups.",
                        details={"groups_count": len(user_groups)},
                    ))
            elif user.last_accessed and user.last_accessed < stale_threshold:
                report.stale_users += 1
                days_since = (now - user.last_accessed).days
                report.findings.append(GovernanceFinding(
                    category="Lifecycle Management",
                    title="Stale User Account",
                    description=f"{user.display_name} has not accessed the project in {days_since} days.",
                    risk_level=RiskLevel.MEDIUM,
                    affected_entity=user.display_name,
                    entity_type="user",
                    recommendation="Review if the account is still needed. Consider deactivation.",
                    details={"days_since_access": days_since},
                ))

    def _check_empty_groups(self, report: GovernanceReport):
        """Check for empty security groups."""
        for group in self.groups:
            if group.member_count == 0 and len(group.members) == 0:
                report.findings.append(GovernanceFinding(
                    category="Access Control",
                    title="Empty Security Group",
                    description=f"Group '{group.display_name}' has no members.",
                    risk_level=RiskLevel.LOW,
                    affected_entity=group.display_name,
                    entity_type="group",
                    recommendation="Remove unused groups or add appropriate members.",
                ))

    def _check_external_users(self, report: GovernanceReport):
        """Check for external/contractor users with elevated access."""
        for user in self.users:
            if self._is_external_user(user):
                user_groups = self._user_groups.get(user.descriptor, set())
                if self._is_admin_user(user_groups):
                    report.findings.append(GovernanceFinding(
                        category="Access Control",
                        title="External User with Admin Access",
                        description=f"External user {user.display_name} ({user.mail_address}) has administrative access.",
                        risk_level=RiskLevel.CRITICAL,
                        affected_entity=user.display_name,
                        entity_type="user",
                        recommendation="External users should not have administrative access. Remove immediately.",
                    ))
                elif user_groups:
                    report.findings.append(GovernanceFinding(
                        category="Access Control",
                        title="External User with Project Access",
                        description=f"External user {user.display_name} ({user.mail_address}) is in {len(user_groups)} group(s).",
                        risk_level=RiskLevel.MEDIUM,
                        affected_entity=user.display_name,
                        entity_type="user",
                        recommendation="Review external user access regularly. Apply time-bound access.",
                    ))

    def _check_high_risk_permissions(self, report: GovernanceReport):
        """Flag high-risk permission assignments."""
        all_perms = self.permissions.all_permissions()
        for perm in all_perms:
            if (perm.permission_name in HIGH_RISK_PERMISSIONS
                    and perm.state in (PermissionState.ALLOW, PermissionState.INHERITED_ALLOW)):
                # Determine who this is
                group = self._groups_by_descriptor.get(perm.identity_descriptor)
                if group and group.group_type == "Custom":
                    report.findings.append(GovernanceFinding(
                        category="Least Privilege",
                        title="High-Risk Permission on Custom Group",
                        description=f"Custom group '{group.display_name}' has '{perm.permission_name}' permission.",
                        risk_level=RiskLevel.MEDIUM,
                        affected_entity=group.display_name,
                        entity_type="group",
                        recommendation=f"Review if '{perm.permission_name}' is needed for custom group.",
                        details={"permission": perm.permission_name, "namespace": perm.namespace_name},
                    ))

    def _check_permission_inheritance(self, report: GovernanceReport):
        """Check for broken or missing inheritance."""
        all_perms = self.permissions.all_permissions()
        inherited_count = sum(1 for p in all_perms if p.is_inherited)
        direct_count = len(all_perms) - inherited_count

        if direct_count > 0 and inherited_count == 0:
            report.findings.append(GovernanceFinding(
                category="Access Control",
                title="No Permission Inheritance Detected",
                description="All permissions are directly assigned. No inheritance hierarchy detected.",
                risk_level=RiskLevel.INFO,
                affected_entity="Permission Model",
                entity_type="policy",
                recommendation="Consider using group-based permissions with inheritance for easier management.",
            ))

    def _check_deny_overrides(self, report: GovernanceReport):
        """Check for explicit deny overrides that may indicate issues."""
        all_perms = self.permissions.all_permissions()
        deny_perms = [
            p for p in all_perms
            if p.state in (PermissionState.DENY, PermissionState.INHERITED_DENY)
        ]

        if len(deny_perms) > len(all_perms) * 0.3 and len(all_perms) > 10:
            report.findings.append(GovernanceFinding(
                category="Access Control",
                title="High Deny-to-Allow Ratio",
                description=f"{len(deny_perms)} deny permissions vs {len(all_perms)} total. "
                            f"High deny ratios may indicate overly broad allows being restricted.",
                risk_level=RiskLevel.MEDIUM,
                affected_entity="Permission Model",
                entity_type="policy",
                recommendation="Consider restructuring permissions to use allow-only with least privilege.",
            ))

    # ------------------------------------------------------------------
    # Compliance Controls
    # ------------------------------------------------------------------

    def _run_compliance_controls(self, report: GovernanceReport):
        """Run compliance control checks."""
        controls = [
            self._ctrl_admin_count(report),
            self._ctrl_least_privilege(report),
            self._ctrl_stale_accounts(report),
            self._ctrl_external_access(report),
            self._ctrl_group_hygiene(report),
            self._ctrl_separation_of_duties(report),
            self._ctrl_high_risk_permissions(report),
        ]
        report.controls = controls

    def _ctrl_admin_count(self, report: GovernanceReport) -> ComplianceControl:
        ctrl = ComplianceControl(
            control_id="GOV-001",
            control_name="Administrative Access Control",
            category="Access Control",
            description="Admin access should be limited to 2-3 users.",
        )
        if report.admin_users <= 3:
            ctrl.status = "Pass"
            ctrl.score = 100
        elif report.admin_users <= 5:
            ctrl.status = "Warning"
            ctrl.score = 60
        else:
            ctrl.status = "Fail"
            ctrl.score = 20
        return ctrl

    def _ctrl_least_privilege(self, report: GovernanceReport) -> ComplianceControl:
        ctrl = ComplianceControl(
            control_id="GOV-002",
            control_name="Least Privilege Enforcement",
            category="Least Privilege",
            description="Users should not have excessive high-risk permissions.",
        )
        if report.overprivileged_users == 0:
            ctrl.status = "Pass"
            ctrl.score = 100
        elif report.overprivileged_users <= 2:
            ctrl.status = "Warning"
            ctrl.score = 60
        else:
            ctrl.status = "Fail"
            ctrl.score = 30
        return ctrl

    def _ctrl_stale_accounts(self, report: GovernanceReport) -> ComplianceControl:
        ctrl = ComplianceControl(
            control_id="GOV-003",
            control_name="Stale Account Management",
            category="Lifecycle Management",
            description="Inactive accounts should be removed promptly.",
        )
        if report.stale_users == 0:
            ctrl.status = "Pass"
            ctrl.score = 100
        elif report.stale_users <= 2:
            ctrl.status = "Warning"
            ctrl.score = 60
        else:
            ctrl.status = "Fail"
            ctrl.score = 30
        return ctrl

    def _ctrl_external_access(self, report: GovernanceReport) -> ComplianceControl:
        ctrl = ComplianceControl(
            control_id="GOV-004",
            control_name="External User Access Control",
            category="Access Control",
            description="External users should have minimal, time-bound access.",
        )
        critical_external = sum(
            1 for f in report.findings
            if f.category == "Access Control"
            and "External User with Admin" in f.title
        )
        if critical_external > 0:
            ctrl.status = "Fail"
            ctrl.score = 0
        elif report.external_users == 0:
            ctrl.status = "Pass"
            ctrl.score = 100
        elif report.external_users <= 3:
            ctrl.status = "Warning"
            ctrl.score = 70
        else:
            ctrl.status = "Warning"
            ctrl.score = 50
        return ctrl

    def _ctrl_group_hygiene(self, report: GovernanceReport) -> ComplianceControl:
        ctrl = ComplianceControl(
            control_id="GOV-005",
            control_name="Security Group Hygiene",
            category="Access Control",
            description="Groups should have members and clear purpose.",
        )
        if report.empty_groups == 0:
            ctrl.status = "Pass"
            ctrl.score = 100
        elif report.empty_groups <= 2:
            ctrl.status = "Warning"
            ctrl.score = 70
        else:
            ctrl.status = "Fail"
            ctrl.score = 40
        return ctrl

    def _ctrl_separation_of_duties(self, report: GovernanceReport) -> ComplianceControl:
        ctrl = ComplianceControl(
            control_id="GOV-006",
            control_name="Separation of Duties",
            category="Separation of Duties",
            description="Critical roles should be separated across different users.",
        )
        sod_findings = [f for f in report.findings if f.category == "Separation of Duties"]
        critical_sod = [f for f in sod_findings if f.risk_level in (RiskLevel.CRITICAL, RiskLevel.HIGH)]
        if len(critical_sod) == 0 and len(sod_findings) == 0:
            ctrl.status = "Pass"
            ctrl.score = 100
        elif len(critical_sod) == 0:
            ctrl.status = "Warning"
            ctrl.score = 70
        else:
            ctrl.status = "Fail"
            ctrl.score = 30
        return ctrl

    def _ctrl_high_risk_permissions(self, report: GovernanceReport) -> ComplianceControl:
        ctrl = ComplianceControl(
            control_id="GOV-007",
            control_name="High-Risk Permission Control",
            category="Least Privilege",
            description="High-risk permissions should be tightly controlled.",
        )
        hr_findings = [
            f for f in report.findings
            if "High-Risk Permission" in f.title or "Overprivileged" in f.title
        ]
        if len(hr_findings) == 0:
            ctrl.status = "Pass"
            ctrl.score = 100
        elif len(hr_findings) <= 3:
            ctrl.status = "Warning"
            ctrl.score = 60
        else:
            ctrl.status = "Fail"
            ctrl.score = 30
        return ctrl

    # ------------------------------------------------------------------
    # Scoring
    # ------------------------------------------------------------------

    def _calculate_scores(self, report: GovernanceReport):
        """Calculate governance scores from controls and findings."""
        score = report.score

        # Category -> controls mapping
        cat_scores: Dict[str, List[float]] = defaultdict(list)
        for ctrl in report.controls:
            cat_scores[ctrl.category].append(ctrl.score)

        def avg(lst):
            return sum(lst) / len(lst) if lst else 100.0

        score.access_control_score = avg(cat_scores.get("Access Control", [100]))
        score.least_privilege_score = avg(cat_scores.get("Least Privilege", [100]))
        score.separation_of_duties_score = avg(cat_scores.get("Separation of Duties", [100]))
        score.lifecycle_management_score = avg(cat_scores.get("Lifecycle Management", [100]))

        # Audit compliance based on finding density
        total_findings = len(report.findings)
        critical_count = len(report.critical_findings)
        high_count = len(report.high_findings)

        audit_base = 100
        audit_base -= critical_count * 15
        audit_base -= high_count * 8
        audit_base -= (total_findings - critical_count - high_count) * 2
        score.audit_compliance_score = max(0, min(100, audit_base))

        # Overall = weighted average
        score.overall_score = (
            score.access_control_score * 0.25
            + score.least_privilege_score * 0.25
            + score.separation_of_duties_score * 0.15
            + score.audit_compliance_score * 0.20
            + score.lifecycle_management_score * 0.15
        )
        score.overall_score = round(score.overall_score, 1)

        # Risk by service
        for service in self.permissions.all_services():
            sp = self.permissions.get_by_service(service)
            if not sp.permissions:
                continue
            high_risk = sum(
                1 for p in sp.permissions
                if p.permission_name in HIGH_RISK_PERMISSIONS
                and p.state in (PermissionState.ALLOW, PermissionState.INHERITED_ALLOW)
            )
            if high_risk >= 5:
                report.risk_by_service[service] = RiskLevel.HIGH
            elif high_risk >= 2:
                report.risk_by_service[service] = RiskLevel.MEDIUM
            elif high_risk >= 1:
                report.risk_by_service[service] = RiskLevel.LOW
            else:
                report.risk_by_service[service] = RiskLevel.INFO

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _is_admin_user(self, user_groups: Set[str]) -> bool:
        for gd in user_groups:
            g = self._groups_by_descriptor.get(gd)
            if g and any(kw in g.display_name.lower() for kw in ADMIN_GROUP_KEYWORDS):
                return True
        return False

    def _is_external_user(self, user: User) -> bool:
        if user.origin and user.origin.lower() not in ("aad", "vsts"):
            return True
        if user.mail_address:
            domain = user.mail_address.split("@")[-1] if "@" in user.mail_address else ""
            if "contractor" in domain.lower() or "external" in domain.lower():
                return True
        return False

    @staticmethod
    def _count_by_field(findings: List[GovernanceFinding], field_name: str) -> Dict[str, int]:
        counts: Dict[str, int] = defaultdict(int)
        for f in findings:
            counts[getattr(f, field_name)] += 1
        return dict(counts)
