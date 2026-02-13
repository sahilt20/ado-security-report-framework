"""
Data models for Azure DevOps Security Framework.

Contains dataclasses representing security entities like groups,
users, permissions, and access control entries.
"""

from dataclasses import dataclass, field
from typing import Optional, List, Dict, Any
from datetime import datetime
from enum import Enum


class PermissionState(Enum):
    """Permission state enumeration."""
    NOT_SET = "not_set"
    ALLOW = "allow"
    DENY = "deny"
    INHERITED_ALLOW = "inherited_allow"
    INHERITED_DENY = "inherited_deny"


class AccessLevel(Enum):
    """User access level enumeration."""
    NONE = "None"
    STAKEHOLDER = "Stakeholder"
    BASIC = "Basic"
    BASIC_TEST_PLANS = "Basic + Test Plans"
    VS_PROFESSIONAL = "Visual Studio Professional"
    VS_ENTERPRISE = "Visual Studio Enterprise"


@dataclass
class SecurityNamespace:
    """Represents an Azure DevOps security namespace."""
    namespace_id: str
    name: str
    display_name: str
    description: str = ""
    is_hierarchical: bool = False
    actions: List[Dict[str, Any]] = field(default_factory=list)
    
    def get_action_by_bit(self, bit: int) -> Optional[Dict[str, Any]]:
        """Get action definition by bit value."""
        for action in self.actions:
            if action.get("bit") == bit:
                return action
        return None
    
    def decode_permissions(self, bitmask: int) -> List[str]:
        """Decode a permission bitmask to action names."""
        permissions = []
        for action in self.actions:
            bit = action.get("bit", 0)
            if bit and (bitmask & bit):
                permissions.append(action.get("name", f"Unknown({bit})"))
        return permissions


@dataclass
class SecurityGroup:
    """Represents an Azure DevOps security group."""
    descriptor: str
    display_name: str
    principal_name: str
    origin: str = "vsts"
    origin_id: str = ""
    description: str = ""
    is_cross_project: bool = False
    domain: str = ""
    mail_address: str = ""
    url: str = ""
    
    # Relationships
    member_count: int = 0
    members: List["GroupMember"] = field(default_factory=list)
    parent_groups: List[str] = field(default_factory=list)  # Descriptors
    child_groups: List[str] = field(default_factory=list)  # Descriptors
    
    @property
    def group_type(self) -> str:
        """Determine if this is a default or custom group."""
        default_groups = [
            "Project Administrators",
            "Build Administrators",
            "Contributors",
            "Readers",
            "Project Valid Users",
            "Release Administrators",
        ]
        for default in default_groups:
            if default.lower() in self.display_name.lower():
                return "Default"
        return "Custom"


@dataclass
class GroupMember:
    """Represents a member of a security group."""
    descriptor: str
    display_name: str
    principal_name: str
    member_type: str  # "user" or "group"
    origin: str = ""
    mail_address: str = ""
    is_active: bool = True


@dataclass
class User:
    """Represents an Azure DevOps user."""
    id: str
    descriptor: str
    display_name: str
    principal_name: str
    mail_address: str = ""
    origin: str = ""
    origin_id: str = ""
    domain: str = ""
    is_active: bool = True
    
    # Entitlements
    access_level: str = ""
    access_level_source: str = ""
    license_display_name: str = ""
    
    # Project membership
    project_memberships: List[str] = field(default_factory=list)
    group_memberships: List[str] = field(default_factory=list)  # Group descriptors
    
    # Dates
    date_created: Optional[datetime] = None
    last_accessed: Optional[datetime] = None


@dataclass
class AccessControlEntry:
    """Represents an Access Control Entry (ACE)."""
    identity_descriptor: str
    identity_display_name: str = ""
    allow: int = 0
    deny: int = 0
    extended_info: Dict[str, Any] = field(default_factory=dict)
    
    @property
    def inherited_allow(self) -> int:
        """Get inherited allow bitmask."""
        return self.extended_info.get("inheritedAllow", 0)
    
    @property
    def inherited_deny(self) -> int:
        """Get inherited deny bitmask."""
        return self.extended_info.get("inheritedDeny", 0)
    
    @property
    def effective_allow(self) -> int:
        """Get effective allow bitmask."""
        return self.extended_info.get("effectiveAllow", self.allow | self.inherited_allow)
    
    @property
    def effective_deny(self) -> int:
        """Get effective deny bitmask."""
        return self.extended_info.get("effectiveDeny", self.deny | self.inherited_deny)


@dataclass
class AccessControlList:
    """Represents an Access Control List (ACL)."""
    token: str
    inherit_permissions: bool = True
    aces: List[AccessControlEntry] = field(default_factory=list)
    namespace_id: str = ""
    
    def get_ace_for_identity(self, descriptor: str) -> Optional[AccessControlEntry]:
        """Get ACE for a specific identity."""
        for ace in self.aces:
            if ace.identity_descriptor == descriptor:
                return ace
        return None


@dataclass
class Permission:
    """Represents a resolved permission for a user/group on a resource."""
    identity_descriptor: str
    identity_name: str
    namespace_name: str
    resource_token: str
    permission_name: str
    permission_bit: int
    state: PermissionState
    is_inherited: bool = False
    source: str = ""  # Where the permission comes from
    resource_display_name: str = ""  # Human-readable resource name (repo name, pipeline name, etc.)

    @property
    def resource_label(self) -> str:
        """Return human-readable resource name, falling back to token."""
        if self.resource_display_name:
            return self.resource_display_name
        return self._humanize_token(self.resource_token)

    @staticmethod
    def _humanize_token(token: str) -> str:
        """Convert an Azure DevOps ACL token to a human-readable label."""
        if not token:
            return "(project-level)"
        if token.startswith("$PROJECT"):
            return "Project Root"
        if token.startswith("$RELEASE"):
            return "Release Root"
        # repoV2/<project_id>/<repo_id>
        if token.startswith("repoV2/") or token.startswith("repoV2\\"):
            parts = token.replace("\\", "/").split("/")
            if len(parts) >= 3:
                repo_id = parts[-1]
                return f"Repo: {repo_id}"
            return "All Repositories"
        # vstfs:/// URIs
        if "vstfs:///" in token:
            # Extract the last path segment as the ID
            segments = token.split("/")
            return f"Resource: {segments[-1]}" if segments else token
        # <guid>/<def_id> patterns (builds, releases)
        if "/" in token:
            parts = token.split("/")
            if len(parts) == 2:
                return f"Definition: {parts[-1]}"
            # Deeper paths like <project>/<folder>/<def>
            return f"Resource: {parts[-1]}"
        return token


@dataclass
class PermissionMatrixEntry:
    """Entry in the permission matrix."""
    state: PermissionState
    is_inherited: bool
    source_group: str = ""


@dataclass
class PermissionMatrix:
    """User-permission matrix for a namespace."""
    namespace_name: str
    users: List[str]  # User display names
    permissions: List[str]  # Permission action names
    matrix: Dict[str, Dict[str, PermissionMatrixEntry]] = field(default_factory=dict)
    
    def set_permission(
        self,
        user: str,
        permission: str,
        state: PermissionState,
        is_inherited: bool = False,
        source_group: str = "",
    ):
        """Set a permission in the matrix."""
        if user not in self.matrix:
            self.matrix[user] = {}
        self.matrix[user][permission] = PermissionMatrixEntry(
            state=state,
            is_inherited=is_inherited,
            source_group=source_group,
        )
    
    def get_permission(self, user: str, permission: str) -> Optional[PermissionMatrixEntry]:
        """Get a permission from the matrix."""
        return self.matrix.get(user, {}).get(permission)


@dataclass
class SecurityReport:
    """Container for all security report data."""
    organization: str
    project: str
    generated_at: datetime
    
    # Collected data
    namespaces: List[SecurityNamespace] = field(default_factory=list)
    groups: List[SecurityGroup] = field(default_factory=list)
    users: List[User] = field(default_factory=list)
    acls: List[AccessControlList] = field(default_factory=list)
    
    # Analyzed data
    permissions: List[Permission] = field(default_factory=list)
    matrices: Dict[str, PermissionMatrix] = field(default_factory=dict)
    
    # Summary statistics
    total_groups: int = 0
    total_users: int = 0
    total_permissions: int = 0
    issues: List[Dict[str, Any]] = field(default_factory=list)
