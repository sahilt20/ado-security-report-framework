#!/usr/bin/env python3
"""
Generate sample Data Governance report with dummy data.

Demonstrates the full governance reporting pipeline including:
- Excel report with charts and heatmaps
- HTML interactive dashboard
- Governance scoring and compliance controls
"""

from datetime import datetime, timedelta
import random
from pathlib import Path

from src.ado_security.models import (
    SecurityGroup,
    GroupMember,
    User,
    Permission,
    PermissionState,
    SecurityNamespace,
)
from src.ado_security.collectors.namespaces import ServiceNamespaces
from src.ado_security.collectors.permissions import GranularPermissions, ServicePermissions
from src.ado_security.analyzers.matrix import PermissionMatrixBuilder
from src.ado_security.analyzers.inheritance import InheritanceAnalyzer
from src.ado_security.analyzers.governance import GovernanceAnalyzer
from src.ado_security.reports.excel_report import ExcelReportGenerator
from src.ado_security.reports.html_report import HTMLReportGenerator


def generate_dummy_groups():
    """Generate sample security groups."""
    groups = [
        SecurityGroup(
            descriptor="vssgp.Uy0xLTktMj",
            display_name="Project Administrators",
            principal_name="[MyProject]\\Project Administrators",
            origin="vsts",
            description="Members of this group can perform all operations in the project.",
        ),
        SecurityGroup(
            descriptor="vssgp.Uy0xLTktMw",
            display_name="Contributors",
            principal_name="[MyProject]\\Contributors",
            origin="vsts",
            description="Members of this group can add, modify, and delete items within the project.",
        ),
        SecurityGroup(
            descriptor="vssgp.Uy0xLTktNA",
            display_name="Readers",
            principal_name="[MyProject]\\Readers",
            origin="vsts",
            description="Members of this group have read-only access to the project.",
        ),
        SecurityGroup(
            descriptor="vssgp.Uy0xLTktNQ",
            display_name="Build Administrators",
            principal_name="[MyProject]\\Build Administrators",
            origin="vsts",
            description="Members of this group can manage build resources.",
        ),
        SecurityGroup(
            descriptor="vssgp.Uy0xLTktNg",
            display_name="Release Administrators",
            principal_name="[MyProject]\\Release Administrators",
            origin="vsts",
            description="Members of this group can manage release pipelines.",
        ),
        SecurityGroup(
            descriptor="vssgp.custom1",
            display_name="DevOps Team",
            principal_name="[MyProject]\\DevOps Team",
            origin="vsts",
            description="Custom group for DevOps engineers.",
        ),
        SecurityGroup(
            descriptor="vssgp.custom2",
            display_name="QA Team",
            principal_name="[MyProject]\\QA Team",
            origin="vsts",
            description="Custom group for QA engineers.",
        ),
        SecurityGroup(
            descriptor="vssgp.custom3",
            display_name="External Contractors",
            principal_name="[MyProject]\\External Contractors",
            origin="aad",
            description="External contractors with limited access.",
        ),
    ]

    return groups


def generate_dummy_users():
    """Generate sample users."""
    users_data = [
        ("John Smith", "john.smith@company.com", "Basic", True),
        ("Sarah Johnson", "sarah.johnson@company.com", "Visual Studio Enterprise", True),
        ("Mike Chen", "mike.chen@company.com", "Basic", True),
        ("Emily Davis", "emily.davis@company.com", "Basic", True),
        ("Alex Wilson", "alex.wilson@company.com", "Stakeholder", True),
        ("Lisa Brown", "lisa.brown@company.com", "Basic", True),
        ("David Lee", "david.lee@company.com", "Visual Studio Professional", True),
        ("Jennifer Martinez", "jennifer.martinez@company.com", "Basic", True),
        ("Robert Taylor", "robert.taylor@company.com", "Stakeholder", True),
        ("Amanda White", "amanda.white@company.com", "Basic", False),  # Inactive
        ("Chris Anderson", "chris.anderson@contractor.com", "Stakeholder", True),  # External
        ("Maria Garcia", "maria.garcia@company.com", "Basic", True),
    ]

    users = []
    for i, (name, email, access, is_active) in enumerate(users_data):
        users.append(User(
            id=f"user-{i+1}",
            descriptor=f"aad.user{i+1}",
            display_name=name,
            principal_name=email,
            mail_address=email,
            origin="aad",
            is_active=is_active,
            access_level=access,
            license_display_name=access,
            date_created=datetime.now() - timedelta(days=random.randint(30, 365)),
            last_accessed=datetime.now() - timedelta(days=random.randint(0, 30)) if is_active else None,
        ))

    return users


def assign_members_to_groups(groups, users):
    """Assign users to groups."""
    # Project Administrators
    groups[0].members = [
        GroupMember(descriptor=users[0].descriptor, display_name=users[0].display_name,
                   principal_name=users[0].principal_name, member_type="user", is_active=True),
        GroupMember(descriptor=users[1].descriptor, display_name=users[1].display_name,
                   principal_name=users[1].principal_name, member_type="user", is_active=True),
    ]
    groups[0].member_count = 2

    # Contributors
    groups[1].members = [
        GroupMember(descriptor=u.descriptor, display_name=u.display_name,
                   principal_name=u.principal_name, member_type="user", is_active=u.is_active)
        for u in users[2:8]
    ]
    groups[1].member_count = 6

    # Readers
    groups[2].members = [
        GroupMember(descriptor=u.descriptor, display_name=u.display_name,
                   principal_name=u.principal_name, member_type="user", is_active=u.is_active)
        for u in [users[4], users[8], users[10]]
    ]
    groups[2].member_count = 3

    # Build Administrators
    groups[3].members = [
        GroupMember(descriptor=users[2].descriptor, display_name=users[2].display_name,
                   principal_name=users[2].principal_name, member_type="user", is_active=True),
    ]
    groups[3].member_count = 1

    # Release Administrators
    groups[4].members = [
        GroupMember(descriptor=users[1].descriptor, display_name=users[1].display_name,
                   principal_name=users[1].principal_name, member_type="user", is_active=True),
        GroupMember(descriptor=users[2].descriptor, display_name=users[2].display_name,
                   principal_name=users[2].principal_name, member_type="user", is_active=True),
    ]
    groups[4].member_count = 2

    # DevOps Team
    groups[5].members = [
        GroupMember(descriptor=u.descriptor, display_name=u.display_name,
                   principal_name=u.principal_name, member_type="user", is_active=u.is_active)
        for u in [users[1], users[2], users[6]]
    ]
    groups[5].member_count = 3

    # QA Team
    groups[6].members = [
        GroupMember(descriptor=u.descriptor, display_name=u.display_name,
                   principal_name=u.principal_name, member_type="user", is_active=u.is_active)
        for u in [users[3], users[5], users[7]]
    ]
    groups[6].member_count = 3

    # External Contractors (empty for issue detection)
    groups[7].members = []
    groups[7].member_count = 0


def generate_dummy_namespaces():
    """Generate sample security namespaces."""
    namespaces = ServiceNamespaces()

    # Project namespace
    namespaces.project.append(SecurityNamespace(
        namespace_id="52d39943-cb85-4d7f-8fa8-c6baac873819",
        name="Project",
        display_name="Project",
        description="Security namespace for project-level permissions",
        actions=[
            {"bit": 1, "name": "GENERIC_READ", "display_name": "View project-level information"},
            {"bit": 2, "name": "GENERIC_WRITE", "display_name": "Edit project-level information"},
            {"bit": 4, "name": "DELETE", "display_name": "Delete project"},
            {"bit": 8, "name": "PUBLISH_TEST_RESULTS", "display_name": "Create test runs"},
            {"bit": 16, "name": "ADMINISTER_BUILD", "display_name": "Administer build permissions"},
            {"bit": 32, "name": "START_BUILD", "display_name": "Queue builds"},
            {"bit": 64, "name": "EDIT_BUILD_STATUS", "display_name": "Edit build quality"},
            {"bit": 128, "name": "UPDATE_BUILD", "display_name": "Update build information"},
            {"bit": 256, "name": "DELETE_TEST_RESULTS", "display_name": "Delete test runs"},
            {"bit": 512, "name": "VIEW_TEST_RESULTS", "display_name": "View test runs"},
            {"bit": 1024, "name": "MANAGE_TEST_ENVIRONMENTS", "display_name": "Manage test environments"},
            {"bit": 2048, "name": "MANAGE_TEST_CONFIGURATIONS", "display_name": "Manage test configurations"},
        ],
    ))

    # Git Repositories
    namespaces.repos.append(SecurityNamespace(
        namespace_id="2e9eb7ed-3c0a-47d4-87c1-0ffdd275fd87",
        name="Git Repositories",
        display_name="Git Repositories",
        description="Security namespace for Git repository permissions",
        is_hierarchical=True,
        actions=[
            {"bit": 1, "name": "Administer", "display_name": "Administer"},
            {"bit": 2, "name": "GenericRead", "display_name": "Read"},
            {"bit": 4, "name": "GenericContribute", "display_name": "Contribute"},
            {"bit": 8, "name": "ForcePush", "display_name": "Force push"},
            {"bit": 16, "name": "CreateBranch", "display_name": "Create branch"},
            {"bit": 32, "name": "CreateTag", "display_name": "Create tag"},
            {"bit": 64, "name": "ManageNote", "display_name": "Manage notes"},
            {"bit": 128, "name": "PolicyExempt", "display_name": "Bypass policies"},
            {"bit": 256, "name": "CreateRepository", "display_name": "Create repository"},
            {"bit": 512, "name": "DeleteRepository", "display_name": "Delete repository"},
            {"bit": 1024, "name": "RenameRepository", "display_name": "Rename repository"},
            {"bit": 2048, "name": "EditPolicies", "display_name": "Edit policies"},
            {"bit": 4096, "name": "RemoveOthersLocks", "display_name": "Remove others locks"},
            {"bit": 8192, "name": "ManagePermissions", "display_name": "Manage permissions"},
            {"bit": 16384, "name": "PullRequestContribute", "display_name": "Contribute to pull requests"},
            {"bit": 32768, "name": "PullRequestBypassPolicy", "display_name": "Bypass policies on PR"},
        ],
    ))

    # Build
    namespaces.pipelines.append(SecurityNamespace(
        namespace_id="33344d9c-fc72-4d6f-aba5-fa317101a7e9",
        name="Build",
        display_name="Build",
        description="Security namespace for build permissions",
        actions=[
            {"bit": 1, "name": "ViewBuilds", "display_name": "View builds"},
            {"bit": 2, "name": "EditBuildQuality", "display_name": "Edit build quality"},
            {"bit": 4, "name": "RetainIndefinitely", "display_name": "Retain indefinitely"},
            {"bit": 8, "name": "DeleteBuilds", "display_name": "Delete builds"},
            {"bit": 16, "name": "ManageBuildQualities", "display_name": "Manage build qualities"},
            {"bit": 32, "name": "DestroyBuilds", "display_name": "Destroy builds"},
            {"bit": 64, "name": "UpdateBuildInformation", "display_name": "Update build info"},
            {"bit": 128, "name": "QueueBuilds", "display_name": "Queue builds"},
            {"bit": 256, "name": "ManageBuildQueue", "display_name": "Manage build queue"},
            {"bit": 512, "name": "StopBuilds", "display_name": "Stop builds"},
            {"bit": 1024, "name": "ViewBuildDefinition", "display_name": "View build definition"},
            {"bit": 2048, "name": "EditBuildDefinition", "display_name": "Edit build definition"},
            {"bit": 4096, "name": "DeleteBuildDefinition", "display_name": "Delete build definition"},
            {"bit": 8192, "name": "AdministerBuildPermissions", "display_name": "Administer build permissions"},
        ],
    ))

    # Release
    namespaces.release.append(SecurityNamespace(
        namespace_id="c788c23e-1b46-4162-8f5e-d7585343b5de",
        name="ReleaseManagement",
        display_name="Release Management",
        description="Security namespace for release permissions",
        actions=[
            {"bit": 1, "name": "ViewReleaseDefinition", "display_name": "View release pipeline"},
            {"bit": 2, "name": "EditReleaseDefinition", "display_name": "Edit release pipeline"},
            {"bit": 4, "name": "DeleteReleaseDefinition", "display_name": "Delete release pipeline"},
            {"bit": 8, "name": "ManageReleaseApprovers", "display_name": "Manage approvers"},
            {"bit": 16, "name": "ManageReleases", "display_name": "Manage releases"},
            {"bit": 32, "name": "ViewReleases", "display_name": "View releases"},
            {"bit": 64, "name": "CreateReleases", "display_name": "Create releases"},
            {"bit": 128, "name": "EditReleaseEnvironment", "display_name": "Edit release stage"},
            {"bit": 256, "name": "DeleteReleaseEnvironment", "display_name": "Delete release stage"},
            {"bit": 512, "name": "AdministerReleasePermissions", "display_name": "Administer permissions"},
        ],
    ))

    # Work Items
    namespaces.boards.append(SecurityNamespace(
        namespace_id="73e71c45-d483-40d5-bdba-62fd076f7f87",
        name="WorkItemTracking",
        display_name="Work Item Tracking",
        description="Security namespace for work item permissions",
        actions=[
            {"bit": 1, "name": "GENERIC_READ", "display_name": "View work items"},
            {"bit": 2, "name": "GENERIC_WRITE", "display_name": "Edit work items"},
            {"bit": 4, "name": "CREATE_CHILDREN", "display_name": "Create child work items"},
            {"bit": 8, "name": "DELETE", "display_name": "Delete work items"},
            {"bit": 16, "name": "WORK_ITEM_MOVE", "display_name": "Move work items"},
            {"bit": 32, "name": "WORK_ITEM_PERMANENTLY_DELETE", "display_name": "Permanently delete"},
        ],
    ))

    return namespaces


def generate_dummy_permissions(groups, users):
    """Generate sample permissions."""
    permissions = GranularPermissions()

    # Project permissions
    project_perms = [
        # Admins have all project permissions
        Permission("vssgp.Uy0xLTktMj", "Project Administrators", "Project", "$PROJECT:proj1",
                  "View project-level information", 1, PermissionState.ALLOW),
        Permission("vssgp.Uy0xLTktMj", "Project Administrators", "Project", "$PROJECT:proj1",
                  "Edit project-level information", 2, PermissionState.ALLOW),
        Permission("vssgp.Uy0xLTktMj", "Project Administrators", "Project", "$PROJECT:proj1",
                  "Delete project", 4, PermissionState.ALLOW),
        # Contributors
        Permission("vssgp.Uy0xLTktMw", "Contributors", "Project", "$PROJECT:proj1",
                  "View project-level information", 1, PermissionState.ALLOW),
        Permission("vssgp.Uy0xLTktMw", "Contributors", "Project", "$PROJECT:proj1",
                  "Edit project-level information", 2, PermissionState.ALLOW),
        Permission("vssgp.Uy0xLTktMw", "Contributors", "Project", "$PROJECT:proj1",
                  "Delete project", 4, PermissionState.DENY),
        # Readers
        Permission("vssgp.Uy0xLTktNA", "Readers", "Project", "$PROJECT:proj1",
                  "View project-level information", 1, PermissionState.ALLOW),
        Permission("vssgp.Uy0xLTktNA", "Readers", "Project", "$PROJECT:proj1",
                  "Edit project-level information", 2, PermissionState.DENY),
        # External Contractors
        Permission("vssgp.custom3", "External Contractors", "Project", "$PROJECT:proj1",
                  "View project-level information", 1, PermissionState.INHERITED_ALLOW, is_inherited=True),
    ]
    permissions.project.permissions.extend(project_perms)

    # Repos permissions
    repos_perms = [
        # Admins
        Permission("vssgp.Uy0xLTktMj", "Project Administrators", "Git Repositories", "repo1",
                  "Administer", 1, PermissionState.ALLOW),
        Permission("vssgp.Uy0xLTktMj", "Project Administrators", "Git Repositories", "repo1",
                  "Read", 2, PermissionState.ALLOW),
        Permission("vssgp.Uy0xLTktMj", "Project Administrators", "Git Repositories", "repo1",
                  "Contribute", 4, PermissionState.ALLOW),
        Permission("vssgp.Uy0xLTktMj", "Project Administrators", "Git Repositories", "repo1",
                  "Force push", 8, PermissionState.ALLOW),
        Permission("vssgp.Uy0xLTktMj", "Project Administrators", "Git Repositories", "repo1",
                  "Bypass policies", 128, PermissionState.ALLOW),
        Permission("vssgp.Uy0xLTktMj", "Project Administrators", "Git Repositories", "repo1",
                  "Manage permissions", 8192, PermissionState.ALLOW),
        # Contributors
        Permission("vssgp.Uy0xLTktMw", "Contributors", "Git Repositories", "repo1",
                  "Read", 2, PermissionState.ALLOW),
        Permission("vssgp.Uy0xLTktMw", "Contributors", "Git Repositories", "repo1",
                  "Contribute", 4, PermissionState.ALLOW),
        Permission("vssgp.Uy0xLTktMw", "Contributors", "Git Repositories", "repo1",
                  "Create branch", 16, PermissionState.ALLOW),
        Permission("vssgp.Uy0xLTktMw", "Contributors", "Git Repositories", "repo1",
                  "Force push", 8, PermissionState.DENY),
        Permission("vssgp.Uy0xLTktMw", "Contributors", "Git Repositories", "repo1",
                  "Bypass policies", 128, PermissionState.DENY),
        # Readers
        Permission("vssgp.Uy0xLTktNA", "Readers", "Git Repositories", "repo1",
                  "Read", 2, PermissionState.ALLOW),
        Permission("vssgp.Uy0xLTktNA", "Readers", "Git Repositories", "repo1",
                  "Contribute", 4, PermissionState.DENY),
        # DevOps Team - special permissions
        Permission("vssgp.custom1", "DevOps Team", "Git Repositories", "repo1",
                  "Bypass policies", 128, PermissionState.ALLOW),
        Permission("vssgp.custom1", "DevOps Team", "Git Repositories", "repo1",
                  "Force push", 8, PermissionState.ALLOW),
        Permission("vssgp.custom1", "DevOps Team", "Git Repositories", "repo1",
                  "Delete repository", 512, PermissionState.ALLOW),
    ]
    permissions.repos.permissions.extend(repos_perms)

    # Pipeline permissions
    pipeline_perms = [
        # Build Admins
        Permission("vssgp.Uy0xLTktNQ", "Build Administrators", "Build", "build1",
                  "View builds", 1, PermissionState.ALLOW),
        Permission("vssgp.Uy0xLTktNQ", "Build Administrators", "Build", "build1",
                  "Queue builds", 128, PermissionState.ALLOW),
        Permission("vssgp.Uy0xLTktNQ", "Build Administrators", "Build", "build1",
                  "Edit build definition", 2048, PermissionState.ALLOW),
        Permission("vssgp.Uy0xLTktNQ", "Build Administrators", "Build", "build1",
                  "Administer build permissions", 8192, PermissionState.ALLOW),
        Permission("vssgp.Uy0xLTktNQ", "Build Administrators", "Build", "build1",
                  "Destroy builds", 32, PermissionState.ALLOW),
        # Contributors
        Permission("vssgp.Uy0xLTktMw", "Contributors", "Build", "build1",
                  "View builds", 1, PermissionState.ALLOW),
        Permission("vssgp.Uy0xLTktMw", "Contributors", "Build", "build1",
                  "Queue builds", 128, PermissionState.ALLOW),
        Permission("vssgp.Uy0xLTktMw", "Contributors", "Build", "build1",
                  "Edit build definition", 2048, PermissionState.DENY),
        # DevOps Team
        Permission("vssgp.custom1", "DevOps Team", "Build", "build1",
                  "Edit build definition", 2048, PermissionState.ALLOW),
        Permission("vssgp.custom1", "DevOps Team", "Build", "build1",
                  "Delete build definition", 4096, PermissionState.ALLOW),
    ]
    permissions.pipelines.permissions.extend(pipeline_perms)

    # Release permissions
    release_perms = [
        # Release Admins
        Permission("vssgp.Uy0xLTktNg", "Release Administrators", "ReleaseManagement", "release1",
                  "View release pipeline", 1, PermissionState.ALLOW),
        Permission("vssgp.Uy0xLTktNg", "Release Administrators", "ReleaseManagement", "release1",
                  "Edit release pipeline", 2, PermissionState.ALLOW),
        Permission("vssgp.Uy0xLTktNg", "Release Administrators", "ReleaseManagement", "release1",
                  "Manage releases", 16, PermissionState.ALLOW),
        Permission("vssgp.Uy0xLTktNg", "Release Administrators", "ReleaseManagement", "release1",
                  "Administer permissions", 512, PermissionState.ALLOW),
        Permission("vssgp.Uy0xLTktNg", "Release Administrators", "ReleaseManagement", "release1",
                  "Delete release pipeline", 4, PermissionState.ALLOW),
        # Contributors
        Permission("vssgp.Uy0xLTktMw", "Contributors", "ReleaseManagement", "release1",
                  "View releases", 32, PermissionState.ALLOW),
        Permission("vssgp.Uy0xLTktMw", "Contributors", "ReleaseManagement", "release1",
                  "Create releases", 64, PermissionState.ALLOW),
        Permission("vssgp.Uy0xLTktMw", "Contributors", "ReleaseManagement", "release1",
                  "Edit release pipeline", 2, PermissionState.DENY),
    ]
    permissions.release.permissions.extend(release_perms)

    # Boards permissions
    boards_perms = [
        # Contributors
        Permission("vssgp.Uy0xLTktMw", "Contributors", "WorkItemTracking", "wit1",
                  "View work items", 1, PermissionState.ALLOW),
        Permission("vssgp.Uy0xLTktMw", "Contributors", "WorkItemTracking", "wit1",
                  "Edit work items", 2, PermissionState.ALLOW),
        Permission("vssgp.Uy0xLTktMw", "Contributors", "WorkItemTracking", "wit1",
                  "Delete work items", 8, PermissionState.DENY),
        Permission("vssgp.Uy0xLTktMw", "Contributors", "WorkItemTracking", "wit1",
                  "Permanently delete", 32, PermissionState.DENY),
        # Readers
        Permission("vssgp.Uy0xLTktNA", "Readers", "WorkItemTracking", "wit1",
                  "View work items", 1, PermissionState.ALLOW),
        Permission("vssgp.Uy0xLTktNA", "Readers", "WorkItemTracking", "wit1",
                  "Edit work items", 2, PermissionState.DENY),
        # QA Team
        Permission("vssgp.custom2", "QA Team", "WorkItemTracking", "wit1",
                  "View work items", 1, PermissionState.ALLOW),
        Permission("vssgp.custom2", "QA Team", "WorkItemTracking", "wit1",
                  "Edit work items", 2, PermissionState.ALLOW),
        Permission("vssgp.custom2", "QA Team", "WorkItemTracking", "wit1",
                  "Create child work items", 4, PermissionState.ALLOW),
    ]
    permissions.boards.permissions.extend(boards_perms)

    return permissions


def main():
    print("Generating Azure DevOps Data Governance sample reports...")
    print()

    # Generate dummy data
    groups = generate_dummy_groups()
    users = generate_dummy_users()
    assign_members_to_groups(groups, users)
    namespaces = generate_dummy_namespaces()
    permissions = generate_dummy_permissions(groups, users)

    # Build analyzers
    matrix_builder = PermissionMatrixBuilder(groups, users, permissions)
    permission_report = matrix_builder.build_full_report()
    inheritance_analyzer = InheritanceAnalyzer(groups, users, permissions)

    # Run governance analysis
    gov_analyzer = GovernanceAnalyzer(
        groups=groups,
        users=users,
        granular_permissions=permissions,
        organization="Contoso",
        project="MyProject",
    )
    gov_report = gov_analyzer.analyze()

    # Print governance summary
    print(f"Governance Score: {gov_report.score.overall_score}/100 (Grade: {gov_report.score.grade})")
    print(f"  Access Control:       {gov_report.score.access_control_score:.1f}")
    print(f"  Least Privilege:      {gov_report.score.least_privilege_score:.1f}")
    print(f"  Separation of Duties: {gov_report.score.separation_of_duties_score:.1f}")
    print(f"  Audit & Compliance:   {gov_report.score.audit_compliance_score:.1f}")
    print(f"  Lifecycle Management: {gov_report.score.lifecycle_management_score:.1f}")
    print()
    print(f"Findings: {len(gov_report.findings)} total")
    for risk, count in sorted(gov_report.findings_by_risk.items()):
        print(f"  {risk}: {count}")
    print()

    # Generate Excel report
    output_dir = Path("reports")
    output_dir.mkdir(exist_ok=True)

    excel_path = output_dir / "sample_governance_report.xlsx"
    excel_gen = ExcelReportGenerator(
        organization="Contoso",
        project="MyProject",
        groups=groups,
        users=users,
        namespaces=namespaces,
        permissions=permissions,
        permission_report=permission_report,
        inheritance_analyzer=inheritance_analyzer,
    )
    excel_gen.generate(str(excel_path))
    print(f"Excel Report: {excel_path}")

    # Generate HTML report
    html_path = output_dir / "sample_governance_dashboard.html"
    html_gen = HTMLReportGenerator(
        organization="Contoso",
        project="MyProject",
        groups=groups,
        users=users,
        permissions=permissions,
        permission_report=permission_report,
        inheritance_analyzer=inheritance_analyzer,
    )
    html_gen.generate(str(html_path))
    print(f"HTML Dashboard: {html_path}")

    print()
    print(f"Report Contents:")
    print(f"  {len(groups)} Security Groups")
    print(f"  {len(users)} Users")
    print(f"  {len(permissions.all_permissions())} Permissions")
    print(f"  {len(gov_report.controls)} Compliance Controls")
    print(f"  {len(gov_report.findings)} Governance Findings")
    print()
    print("Excel Sheets:")
    print("  - Executive Summary (with charts)")
    print("  - Governance Score (radar + bar charts)")
    print("  - Compliance Controls (status distribution)")
    print("  - Risk Findings (sorted by severity)")
    print("  - Groups Overview (type distribution)")
    print("  - Group Members")
    print("  - Users Overview (access level chart)")
    print("  - Security Namespaces")
    print("  - Perms - Project/Repos/Pipelines/Release/Boards")
    print("  - Permission Matrix (heatmap)")
    print("  - Inheritance Analysis (direct vs inherited)")
    print("  - Recommendations (prioritized)")
    print()
    print("HTML Dashboard Sections:")
    print("  - Interactive Dashboard with Chart.js")
    print("  - Governance Scores (radar chart)")
    print("  - Compliance Controls Table")
    print("  - Risk Findings Table")
    print("  - Users & Groups with Charts")
    print("  - Permissions Analysis")


if __name__ == "__main__":
    main()
