#!/usr/bin/env python3
"""
Generate sample Project-Level Data Governance report with dummy data.

Demonstrates the full governance reporting pipeline scoped to
project-level admin permissions, including:
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
            domain="vstfs:///Framework/IdentityDomain/MyProject",
            description="Members of this group can perform all operations in the project.",
            child_groups=["vssgp.Uy0xLTktNQ", "vssgp.Uy0xLTktNg"],
        ),
        SecurityGroup(
            descriptor="vssgp.Uy0xLTktMw",
            display_name="Contributors",
            principal_name="[MyProject]\\Contributors",
            origin="vsts",
            domain="vstfs:///Framework/IdentityDomain/MyProject",
            description="Members of this group can add, modify, and delete items within the project.",
            child_groups=["vssgp.custom1", "vssgp.custom2"],
        ),
        SecurityGroup(
            descriptor="vssgp.Uy0xLTktNA",
            display_name="Readers",
            principal_name="[MyProject]\\Readers",
            origin="vsts",
            domain="vstfs:///Framework/IdentityDomain/MyProject",
            description="Members of this group have read-only access to the project.",
            child_groups=["vssgp.custom3"],
        ),
        SecurityGroup(
            descriptor="vssgp.Uy0xLTktNQ",
            display_name="Build Administrators",
            principal_name="[MyProject]\\Build Administrators",
            origin="vsts",
            domain="vstfs:///Framework/IdentityDomain/MyProject",
            description="Members of this group can manage build resources.",
            parent_groups=["vssgp.Uy0xLTktMj"],
        ),
        SecurityGroup(
            descriptor="vssgp.Uy0xLTktNg",
            display_name="Release Administrators",
            principal_name="[MyProject]\\Release Administrators",
            origin="vsts",
            domain="vstfs:///Framework/IdentityDomain/MyProject",
            description="Members of this group can manage release pipelines.",
            parent_groups=["vssgp.Uy0xLTktMj"],
        ),
        SecurityGroup(
            descriptor="vssgp.custom1",
            display_name="DevOps Team",
            principal_name="[MyProject]\\DevOps Team",
            origin="vsts",
            domain="vstfs:///Framework/IdentityDomain/MyProject",
            description="Custom group for DevOps engineers.",
            parent_groups=["vssgp.Uy0xLTktMw"],
        ),
        SecurityGroup(
            descriptor="vssgp.custom2",
            display_name="QA Team",
            principal_name="[MyProject]\\QA Team",
            origin="vsts",
            domain="vstfs:///Framework/IdentityDomain/MyProject",
            description="Custom group for QA engineers.",
            parent_groups=["vssgp.Uy0xLTktMw"],
        ),
        SecurityGroup(
            descriptor="vssgp.custom3",
            display_name="External Contractors",
            principal_name="[MyProject]\\External Contractors",
            origin="aad",
            domain="vstfs:///Framework/IdentityDomain/External",
            description="External contractors with limited access.",
            parent_groups=["vssgp.Uy0xLTktNA"],
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
            last_accessed=datetime.now() - timedelta(days=random.randint(0, 30)) if is_active else datetime.now() - timedelta(days=random.randint(120, 300)),
        ))

    return users


def _set_user_group_memberships(groups, users):
    """Set group_memberships on users based on group member assignments."""
    user_map = {u.descriptor: u for u in users}
    for g in groups:
        for m in g.members:
            if m.member_type == "user" and m.descriptor in user_map:
                user_map[m.descriptor].group_memberships.append(g.descriptor)


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


def _perm(desc, name, ns, token, perm_name, bit, state, resource_name="", **kw):
    """Helper to create Permission with resource_display_name."""
    return Permission(desc, name, ns, token, perm_name, bit, state,
                      resource_display_name=resource_name, **kw)


def generate_dummy_permissions(groups, users):
    """Generate sample permissions with realistic resource display names."""
    permissions = GranularPermissions()

    # ----------------------------------------------------------------
    # Project-level permissions
    # ----------------------------------------------------------------
    project_perms = [
        _perm("vssgp.Uy0xLTktMj", "Project Administrators", "Project", "$PROJECT:proj1",
              "View project-level information", 1, PermissionState.ALLOW, "MyProject"),
        _perm("vssgp.Uy0xLTktMj", "Project Administrators", "Project", "$PROJECT:proj1",
              "Edit project-level information", 2, PermissionState.ALLOW, "MyProject"),
        _perm("vssgp.Uy0xLTktMj", "Project Administrators", "Project", "$PROJECT:proj1",
              "Delete project", 4, PermissionState.ALLOW, "MyProject"),
        _perm("vssgp.Uy0xLTktMw", "Contributors", "Project", "$PROJECT:proj1",
              "View project-level information", 1, PermissionState.ALLOW, "MyProject"),
        _perm("vssgp.Uy0xLTktMw", "Contributors", "Project", "$PROJECT:proj1",
              "Edit project-level information", 2, PermissionState.ALLOW, "MyProject"),
        _perm("vssgp.Uy0xLTktMw", "Contributors", "Project", "$PROJECT:proj1",
              "Delete project", 4, PermissionState.DENY, "MyProject"),
        _perm("vssgp.Uy0xLTktNA", "Readers", "Project", "$PROJECT:proj1",
              "View project-level information", 1, PermissionState.ALLOW, "MyProject"),
        _perm("vssgp.Uy0xLTktNA", "Readers", "Project", "$PROJECT:proj1",
              "Edit project-level information", 2, PermissionState.DENY, "MyProject"),
        _perm("vssgp.custom3", "External Contractors", "Project", "$PROJECT:proj1",
              "View project-level information", 1, PermissionState.INHERITED_ALLOW,
              "MyProject", is_inherited=True),
    ]
    permissions.project.permissions.extend(project_perms)

    # ----------------------------------------------------------------
    # Git Repository permissions (proper repo names)
    # ----------------------------------------------------------------
    repos_perms = [
        # Admins on main-api repo
        _perm("vssgp.Uy0xLTktMj", "Project Administrators", "Git Repositories",
              "repoV2/proj1/repo-main-api", "Administer", 1, PermissionState.ALLOW,
              "main-api"),
        _perm("vssgp.Uy0xLTktMj", "Project Administrators", "Git Repositories",
              "repoV2/proj1/repo-main-api", "Read", 2, PermissionState.ALLOW,
              "main-api"),
        _perm("vssgp.Uy0xLTktMj", "Project Administrators", "Git Repositories",
              "repoV2/proj1/repo-main-api", "Contribute", 4, PermissionState.ALLOW,
              "main-api"),
        _perm("vssgp.Uy0xLTktMj", "Project Administrators", "Git Repositories",
              "repoV2/proj1/repo-main-api", "Force push", 8, PermissionState.ALLOW,
              "main-api"),
        _perm("vssgp.Uy0xLTktMj", "Project Administrators", "Git Repositories",
              "repoV2/proj1/repo-main-api", "Bypass policies", 128, PermissionState.ALLOW,
              "main-api"),
        _perm("vssgp.Uy0xLTktMj", "Project Administrators", "Git Repositories",
              "repoV2/proj1/repo-main-api", "Manage permissions", 8192, PermissionState.ALLOW,
              "main-api"),
        # Contributors on main-api
        _perm("vssgp.Uy0xLTktMw", "Contributors", "Git Repositories",
              "repoV2/proj1/repo-main-api", "Read", 2, PermissionState.ALLOW,
              "main-api"),
        _perm("vssgp.Uy0xLTktMw", "Contributors", "Git Repositories",
              "repoV2/proj1/repo-main-api", "Contribute", 4, PermissionState.ALLOW,
              "main-api"),
        _perm("vssgp.Uy0xLTktMw", "Contributors", "Git Repositories",
              "repoV2/proj1/repo-main-api", "Create branch", 16, PermissionState.ALLOW,
              "main-api"),
        _perm("vssgp.Uy0xLTktMw", "Contributors", "Git Repositories",
              "repoV2/proj1/repo-main-api", "Force push", 8, PermissionState.DENY,
              "main-api"),
        _perm("vssgp.Uy0xLTktMw", "Contributors", "Git Repositories",
              "repoV2/proj1/repo-main-api", "Bypass policies", 128, PermissionState.DENY,
              "main-api"),
        # Readers on frontend-app repo
        _perm("vssgp.Uy0xLTktNA", "Readers", "Git Repositories",
              "repoV2/proj1/repo-frontend", "Read", 2, PermissionState.ALLOW,
              "frontend-app"),
        _perm("vssgp.Uy0xLTktNA", "Readers", "Git Repositories",
              "repoV2/proj1/repo-frontend", "Contribute", 4, PermissionState.DENY,
              "frontend-app"),
        # DevOps Team on infra-config repo
        _perm("vssgp.custom1", "DevOps Team", "Git Repositories",
              "repoV2/proj1/repo-infra", "Bypass policies", 128, PermissionState.ALLOW,
              "infra-config"),
        _perm("vssgp.custom1", "DevOps Team", "Git Repositories",
              "repoV2/proj1/repo-infra", "Force push", 8, PermissionState.ALLOW,
              "infra-config"),
        _perm("vssgp.custom1", "DevOps Team", "Git Repositories",
              "repoV2/proj1/repo-infra", "Delete repository", 512, PermissionState.ALLOW,
              "infra-config"),
    ]
    permissions.repos.permissions.extend(repos_perms)

    # ----------------------------------------------------------------
    # Pipeline (Build) permissions with pipeline names
    # ----------------------------------------------------------------
    pipeline_perms = [
        _perm("vssgp.Uy0xLTktNQ", "Build Administrators", "Build",
              "proj1/ci-main-api", "View builds", 1, PermissionState.ALLOW,
              "CI - Main API"),
        _perm("vssgp.Uy0xLTktNQ", "Build Administrators", "Build",
              "proj1/ci-main-api", "Queue builds", 128, PermissionState.ALLOW,
              "CI - Main API"),
        _perm("vssgp.Uy0xLTktNQ", "Build Administrators", "Build",
              "proj1/ci-main-api", "Edit build definition", 2048, PermissionState.ALLOW,
              "CI - Main API"),
        _perm("vssgp.Uy0xLTktNQ", "Build Administrators", "Build",
              "proj1/ci-main-api", "Administer build permissions", 8192, PermissionState.ALLOW,
              "CI - Main API"),
        _perm("vssgp.Uy0xLTktNQ", "Build Administrators", "Build",
              "proj1/ci-main-api", "Destroy builds", 32, PermissionState.ALLOW,
              "CI - Main API"),
        _perm("vssgp.Uy0xLTktMw", "Contributors", "Build",
              "proj1/ci-main-api", "View builds", 1, PermissionState.ALLOW,
              "CI - Main API"),
        _perm("vssgp.Uy0xLTktMw", "Contributors", "Build",
              "proj1/ci-main-api", "Queue builds", 128, PermissionState.ALLOW,
              "CI - Main API"),
        _perm("vssgp.Uy0xLTktMw", "Contributors", "Build",
              "proj1/ci-main-api", "Edit build definition", 2048, PermissionState.DENY,
              "CI - Main API"),
        _perm("vssgp.custom1", "DevOps Team", "Build",
              "proj1/cd-infra-deploy", "Edit build definition", 2048, PermissionState.ALLOW,
              "CD - Infra Deploy"),
        _perm("vssgp.custom1", "DevOps Team", "Build",
              "proj1/cd-infra-deploy", "Delete build definition", 4096, PermissionState.ALLOW,
              "CD - Infra Deploy"),
    ]
    permissions.pipelines.permissions.extend(pipeline_perms)

    # ----------------------------------------------------------------
    # Release permissions with release pipeline names
    # ----------------------------------------------------------------
    release_perms = [
        _perm("vssgp.Uy0xLTktNg", "Release Administrators", "ReleaseManagement",
              "proj1/release-prod", "View release pipeline", 1, PermissionState.ALLOW,
              "Release - Production"),
        _perm("vssgp.Uy0xLTktNg", "Release Administrators", "ReleaseManagement",
              "proj1/release-prod", "Edit release pipeline", 2, PermissionState.ALLOW,
              "Release - Production"),
        _perm("vssgp.Uy0xLTktNg", "Release Administrators", "ReleaseManagement",
              "proj1/release-prod", "Manage releases", 16, PermissionState.ALLOW,
              "Release - Production"),
        _perm("vssgp.Uy0xLTktNg", "Release Administrators", "ReleaseManagement",
              "proj1/release-prod", "Administer permissions", 512, PermissionState.ALLOW,
              "Release - Production"),
        _perm("vssgp.Uy0xLTktNg", "Release Administrators", "ReleaseManagement",
              "proj1/release-prod", "Delete release pipeline", 4, PermissionState.ALLOW,
              "Release - Production"),
        _perm("vssgp.Uy0xLTktMw", "Contributors", "ReleaseManagement",
              "proj1/release-staging", "View releases", 32, PermissionState.ALLOW,
              "Release - Staging"),
        _perm("vssgp.Uy0xLTktMw", "Contributors", "ReleaseManagement",
              "proj1/release-staging", "Create releases", 64, PermissionState.ALLOW,
              "Release - Staging"),
        _perm("vssgp.Uy0xLTktMw", "Contributors", "ReleaseManagement",
              "proj1/release-staging", "Edit release pipeline", 2, PermissionState.DENY,
              "Release - Staging"),
    ]
    permissions.release.permissions.extend(release_perms)

    # ----------------------------------------------------------------
    # Boards (Work Item Tracking) permissions
    # ----------------------------------------------------------------
    boards_perms = [
        _perm("vssgp.Uy0xLTktMw", "Contributors", "WorkItemTracking",
              "proj1/wit-area-root", "View work items", 1, PermissionState.ALLOW,
              "Area: Root"),
        _perm("vssgp.Uy0xLTktMw", "Contributors", "WorkItemTracking",
              "proj1/wit-area-root", "Edit work items", 2, PermissionState.ALLOW,
              "Area: Root"),
        _perm("vssgp.Uy0xLTktMw", "Contributors", "WorkItemTracking",
              "proj1/wit-area-root", "Delete work items", 8, PermissionState.DENY,
              "Area: Root"),
        _perm("vssgp.Uy0xLTktMw", "Contributors", "WorkItemTracking",
              "proj1/wit-area-root", "Permanently delete", 32, PermissionState.DENY,
              "Area: Root"),
        _perm("vssgp.Uy0xLTktNA", "Readers", "WorkItemTracking",
              "proj1/wit-area-root", "View work items", 1, PermissionState.ALLOW,
              "Area: Root"),
        _perm("vssgp.Uy0xLTktNA", "Readers", "WorkItemTracking",
              "proj1/wit-area-root", "Edit work items", 2, PermissionState.DENY,
              "Area: Root"),
        _perm("vssgp.custom2", "QA Team", "WorkItemTracking",
              "proj1/wit-area-qa", "View work items", 1, PermissionState.ALLOW,
              "Area: QA Testing"),
        _perm("vssgp.custom2", "QA Team", "WorkItemTracking",
              "proj1/wit-area-qa", "Edit work items", 2, PermissionState.ALLOW,
              "Area: QA Testing"),
        _perm("vssgp.custom2", "QA Team", "WorkItemTracking",
              "proj1/wit-area-qa", "Create child work items", 4, PermissionState.ALLOW,
              "Area: QA Testing"),
    ]
    permissions.boards.permissions.extend(boards_perms)

    return permissions


def main():
    print("Generating Azure DevOps Project-Level Data Governance sample reports...")
    print("Scope: Project Administrator (no org-level access required)")
    print()

    # Generate dummy data
    groups = generate_dummy_groups()
    users = generate_dummy_users()
    assign_members_to_groups(groups, users)
    _set_user_group_memberships(groups, users)
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


if __name__ == "__main__":
    main()
