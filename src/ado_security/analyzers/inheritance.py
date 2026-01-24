"""
Permission Inheritance Analyzer.

Analyzes how permissions are inherited through group memberships
and resource hierarchies, distinguishing direct vs inherited permissions.
"""

import logging
from typing import Dict, List, Optional, Set, Tuple
from dataclasses import dataclass, field
from collections import defaultdict

from ..models import (
    Permission,
    PermissionState,
    SecurityGroup,
    User,
)
from ..collectors.permissions import GranularPermissions, ServicePermissions

logger = logging.getLogger(__name__)


@dataclass
class PermissionSource:
    """Describes where a permission comes from."""
    permission: Permission
    source_type: str  # "direct", "group_inherited", "resource_inherited"
    source_group: Optional[str] = None  # Group name if inherited from group
    source_resource: Optional[str] = None  # Parent resource if inherited
    inheritance_chain: List[str] = field(default_factory=list)  # Full chain


@dataclass
class InheritanceAnalysis:
    """Results of inheritance analysis for an identity."""
    identity_descriptor: str
    identity_name: str
    direct_permissions: List[PermissionSource] = field(default_factory=list)
    group_inherited: List[PermissionSource] = field(default_factory=list)
    resource_inherited: List[PermissionSource] = field(default_factory=list)
    effective_permissions: Dict[str, Dict[str, PermissionState]] = field(default_factory=dict)
    # Dict[namespace][permission_name] -> effective state


@dataclass
class ServiceInheritanceReport:
    """Inheritance report for a single service."""
    service_name: str
    direct_count: int = 0
    inherited_count: int = 0
    deny_count: int = 0
    permissions: List[PermissionSource] = field(default_factory=list)


class InheritanceAnalyzer:
    """
    Analyzes permission inheritance in Azure DevOps.
    
    Tracks:
    - Direct vs. inherited permissions
    - Group-based inheritance chains
    - Resource hierarchy inheritance
    """
    
    def __init__(
        self,
        groups: List[SecurityGroup],
        users: List[User],
        granular_permissions: GranularPermissions,
    ):
        """
        Initialize the analyzer.
        
        Args:
            groups: List of security groups with membership info
            users: List of users
            granular_permissions: Permissions organized by service
        """
        self.groups = {g.descriptor: g for g in groups}
        self.users = {u.descriptor: u for u in users}
        self.permissions = granular_permissions
        
        # Build reverse lookup: user -> groups
        self._user_groups: Dict[str, Set[str]] = defaultdict(set)
        self._build_user_group_mapping()
    
    def _build_user_group_mapping(self):
        """Build mapping of users to their group memberships."""
        for group in self.groups.values():
            for member in group.members:
                if member.member_type == "user":
                    self._user_groups[member.descriptor].add(group.descriptor)
                elif member.member_type == "group":
                    # Handle nested groups - members of child groups
                    # inherit membership in parent groups
                    self._propagate_group_membership(
                        member.descriptor,
                        group.descriptor,
                    )
    
    def _propagate_group_membership(
        self,
        child_group_descriptor: str,
        parent_group_descriptor: str,
        visited: Optional[Set[str]] = None,
    ):
        """Propagate group membership through nested groups."""
        if visited is None:
            visited = set()
        
        if child_group_descriptor in visited:
            return  # Avoid cycles
        
        visited.add(child_group_descriptor)
        
        child_group = self.groups.get(child_group_descriptor)
        if not child_group:
            return
        
        for member in child_group.members:
            if member.member_type == "user":
                self._user_groups[member.descriptor].add(parent_group_descriptor)
    
    def analyze_user(self, user_descriptor: str) -> InheritanceAnalysis:
        """
        Analyze permission inheritance for a user.
        
        Args:
            user_descriptor: User's identity descriptor
            
        Returns:
            InheritanceAnalysis with detailed breakdown
        """
        user = self.users.get(user_descriptor)
        user_name = user.display_name if user else user_descriptor
        
        analysis = InheritanceAnalysis(
            identity_descriptor=user_descriptor,
            identity_name=user_name,
        )
        
        # Get user's group memberships
        user_groups = self._user_groups.get(user_descriptor, set())
        
        # Analyze permissions from each service
        for service_name in self.permissions.all_services():
            service_perms = self.permissions.get_by_service(service_name)
            
            for perm in service_perms.permissions:
                source = self._classify_permission_source(
                    perm,
                    user_descriptor,
                    user_groups,
                )
                
                if source:
                    if source.source_type == "direct":
                        analysis.direct_permissions.append(source)
                    elif source.source_type == "group_inherited":
                        analysis.group_inherited.append(source)
                    else:
                        analysis.resource_inherited.append(source)
                    
                    # Track effective permissions
                    if perm.namespace_name not in analysis.effective_permissions:
                        analysis.effective_permissions[perm.namespace_name] = {}
                    
                    # Deny takes precedence
                    current = analysis.effective_permissions[perm.namespace_name].get(
                        perm.permission_name
                    )
                    if current in (PermissionState.DENY, PermissionState.INHERITED_DENY):
                        continue  # Keep deny
                    
                    analysis.effective_permissions[perm.namespace_name][perm.permission_name] = perm.state
        
        return analysis
    
    def _classify_permission_source(
        self,
        permission: Permission,
        user_descriptor: str,
        user_groups: Set[str],
    ) -> Optional[PermissionSource]:
        """Classify the source of a permission for a user."""
        
        # Check if permission is directly assigned to user
        if permission.identity_descriptor == user_descriptor:
            return PermissionSource(
                permission=permission,
                source_type="direct" if not permission.is_inherited else "resource_inherited",
                source_resource=permission.resource_token if permission.is_inherited else None,
            )
        
        # Check if permission is from a group the user belongs to
        if permission.identity_descriptor in user_groups:
            group = self.groups.get(permission.identity_descriptor)
            group_name = group.display_name if group else permission.identity_descriptor
            
            # Build inheritance chain
            chain = self._build_inheritance_chain(user_descriptor, permission.identity_descriptor)
            
            return PermissionSource(
                permission=permission,
                source_type="group_inherited",
                source_group=group_name,
                inheritance_chain=chain,
            )
        
        return None
    
    def _build_inheritance_chain(
        self,
        user_descriptor: str,
        target_group_descriptor: str,
    ) -> List[str]:
        """Build the inheritance chain from user to target group."""
        chain = []
        
        user = self.users.get(user_descriptor)
        if user:
            chain.append(user.display_name)
        
        target_group = self.groups.get(target_group_descriptor)
        if target_group:
            chain.append(target_group.display_name)
        
        return chain
    
    def get_service_inheritance_report(
        self,
        user_descriptor: str,
    ) -> Dict[str, ServiceInheritanceReport]:
        """
        Generate inheritance report by service for a user.
        
        Args:
            user_descriptor: User's identity descriptor
            
        Returns:
            Dict mapping service name to inheritance report
        """
        analysis = self.analyze_user(user_descriptor)
        reports: Dict[str, ServiceInheritanceReport] = {}
        
        for service_name in self.permissions.all_services():
            report = ServiceInheritanceReport(service_name=service_name)
            
            # Count permissions by type
            for source in analysis.direct_permissions:
                if NAMESPACE_SERVICE_MAPPING.get(
                    source.permission.namespace_name, "Other"
                ) == service_name:
                    report.direct_count += 1
                    if source.permission.state in (
                        PermissionState.DENY,
                        PermissionState.INHERITED_DENY,
                    ):
                        report.deny_count += 1
                    report.permissions.append(source)
            
            for source in analysis.group_inherited + analysis.resource_inherited:
                if NAMESPACE_SERVICE_MAPPING.get(
                    source.permission.namespace_name, "Other"
                ) == service_name:
                    report.inherited_count += 1
                    if source.permission.state in (
                        PermissionState.DENY,
                        PermissionState.INHERITED_DENY,
                    ):
                        report.deny_count += 1
                    report.permissions.append(source)
            
            if report.direct_count > 0 or report.inherited_count > 0:
                reports[service_name] = report
        
        return reports
    
    def find_permission_conflicts(self) -> List[Dict]:
        """
        Find conflicting permissions (both allow and deny for same permission).
        
        Returns:
            List of conflict descriptions
        """
        conflicts = []
        
        for user_descriptor in self.users.keys():
            user_groups = self._user_groups.get(user_descriptor, set())
            
            # Track permissions by (namespace, permission_name)
            perm_states: Dict[Tuple[str, str], List[Permission]] = defaultdict(list)
            
            for service_name in self.permissions.all_services():
                service_perms = self.permissions.get_by_service(service_name)
                
                for perm in service_perms.permissions:
                    if (perm.identity_descriptor == user_descriptor or
                        perm.identity_descriptor in user_groups):
                        key = (perm.namespace_name, perm.permission_name)
                        perm_states[key].append(perm)
            
            # Check for conflicts
            for (ns, perm_name), perms in perm_states.items():
                has_allow = any(
                    p.state in (PermissionState.ALLOW, PermissionState.INHERITED_ALLOW)
                    for p in perms
                )
                has_deny = any(
                    p.state in (PermissionState.DENY, PermissionState.INHERITED_DENY)
                    for p in perms
                )
                
                if has_allow and has_deny:
                    user = self.users.get(user_descriptor)
                    conflicts.append({
                        "user": user.display_name if user else user_descriptor,
                        "namespace": ns,
                        "permission": perm_name,
                        "sources": [
                            {
                                "state": p.state.value,
                                "source": p.identity_name,
                                "inherited": p.is_inherited,
                            }
                            for p in perms
                        ],
                    })
        
        return conflicts


# Import for direct use
from ..collectors.namespaces import NAMESPACE_SERVICE_MAPPING
