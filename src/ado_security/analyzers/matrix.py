"""
Permission Matrix Builder.

Builds user-permission matrices for visualization and reporting,
organized by Azure DevOps service areas.
"""

import logging
from typing import Dict, List, Optional, Set
from dataclasses import dataclass, field
from collections import defaultdict

from ..models import (
    Permission,
    PermissionState,
    PermissionMatrix,
    PermissionMatrixEntry,
    SecurityGroup,
    User,
)
from ..collectors.permissions import GranularPermissions
from ..collectors.namespaces import NAMESPACE_SERVICE_MAPPING

logger = logging.getLogger(__name__)


@dataclass
class ServiceMatrix:
    """Permission matrix for a specific service."""
    service_name: str
    matrix: PermissionMatrix
    summary: Dict[str, Dict[str, int]] = field(default_factory=dict)
    # summary[user][state_type] = count


@dataclass
class FullPermissionReport:
    """Complete permission report with matrices for all services."""
    matrices: Dict[str, ServiceMatrix] = field(default_factory=dict)
    user_summary: Dict[str, Dict[str, int]] = field(default_factory=dict)
    # user_summary[user][service] = permission_count
    
    def get_matrix(self, service: str) -> Optional[ServiceMatrix]:
        """Get matrix for a specific service."""
        return self.matrices.get(service)


class PermissionMatrixBuilder:
    """
    Builds permission matrices for users and groups.
    
    Creates heatmap-style matrices showing permissions across
    different Azure DevOps service areas.
    """
    
    def __init__(
        self,
        groups: List[SecurityGroup],
        users: List[User],
        granular_permissions: GranularPermissions,
    ):
        """
        Initialize the builder.
        
        Args:
            groups: List of security groups
            users: List of users
            granular_permissions: Permissions organized by service
        """
        self.groups = {g.descriptor: g for g in groups}
        self.users = {u.descriptor: u for u in users}
        self.user_list = users
        self.group_list = groups
        self.permissions = granular_permissions
        
        # Build user -> groups mapping
        self._user_groups: Dict[str, Set[str]] = defaultdict(set)
        self._build_user_group_mapping()
    
    def _build_user_group_mapping(self):
        """Build mapping of users to their group memberships."""
        for group in self.groups.values():
            for member in group.members:
                if member.member_type == "user":
                    self._user_groups[member.descriptor].add(group.descriptor)
    
    def build_user_matrix(self, service: str) -> ServiceMatrix:
        """
        Build user permission matrix for a specific service.
        
        Args:
            service: Service name (e.g., "Repos", "Pipelines")
            
        Returns:
            ServiceMatrix with user permissions
        """
        service_perms = self.permissions.get_by_service(service)
        
        # Get unique permission names
        permission_names = sorted(set(
            p.permission_name for p in service_perms.permissions
        ))
        
        # Get user display names
        user_names = [u.display_name for u in self.user_list]
        
        matrix = PermissionMatrix(
            namespace_name=service,
            users=user_names,
            permissions=permission_names,
        )
        
        summary: Dict[str, Dict[str, int]] = {}
        
        # Fill in matrix
        for user in self.user_list:
            user_groups = self._user_groups.get(user.descriptor, set())
            summary[user.display_name] = {"allow": 0, "deny": 0, "inherited": 0}
            
            for perm in service_perms.permissions:
                # Check if permission applies to this user
                if self._permission_applies_to_user(perm, user.descriptor, user_groups):
                    state = perm.state
                    is_inherited = perm.is_inherited or perm.identity_descriptor in user_groups
                    
                    source_group = ""
                    if perm.identity_descriptor in user_groups:
                        group = self.groups.get(perm.identity_descriptor)
                        source_group = group.display_name if group else ""
                    
                    matrix.set_permission(
                        user.display_name,
                        perm.permission_name,
                        state,
                        is_inherited,
                        source_group,
                    )
                    
                    # Update summary
                    if state in (PermissionState.DENY, PermissionState.INHERITED_DENY):
                        summary[user.display_name]["deny"] += 1
                    elif is_inherited:
                        summary[user.display_name]["inherited"] += 1
                    else:
                        summary[user.display_name]["allow"] += 1
        
        return ServiceMatrix(
            service_name=service,
            matrix=matrix,
            summary=summary,
        )
    
    def build_group_matrix(self, service: str) -> ServiceMatrix:
        """
        Build group permission matrix for a specific service.
        
        Args:
            service: Service name
            
        Returns:
            ServiceMatrix with group permissions
        """
        service_perms = self.permissions.get_by_service(service)
        
        # Get unique permission names
        permission_names = sorted(set(
            p.permission_name for p in service_perms.permissions
        ))
        
        # Get group display names
        group_names = [g.display_name for g in self.group_list]
        
        matrix = PermissionMatrix(
            namespace_name=service,
            users=group_names,  # Using 'users' field for groups too
            permissions=permission_names,
        )
        
        summary: Dict[str, Dict[str, int]] = {}
        
        # Fill in matrix
        for group in self.group_list:
            summary[group.display_name] = {"allow": 0, "deny": 0, "inherited": 0}
            
            for perm in service_perms.permissions:
                if perm.identity_descriptor == group.descriptor:
                    matrix.set_permission(
                        group.display_name,
                        perm.permission_name,
                        perm.state,
                        perm.is_inherited,
                    )
                    
                    # Update summary
                    if perm.state in (PermissionState.DENY, PermissionState.INHERITED_DENY):
                        summary[group.display_name]["deny"] += 1
                    elif perm.is_inherited:
                        summary[group.display_name]["inherited"] += 1
                    else:
                        summary[group.display_name]["allow"] += 1
        
        return ServiceMatrix(
            service_name=service,
            matrix=matrix,
            summary=summary,
        )
    
    def build_full_report(self) -> FullPermissionReport:
        """
        Build complete permission report with all service matrices.
        
        Returns:
            FullPermissionReport with matrices for all services
        """
        report = FullPermissionReport()
        
        for service in self.permissions.all_services():
            service_perms = self.permissions.get_by_service(service)
            
            if service_perms.permissions:
                matrix = self.build_user_matrix(service)
                report.matrices[service] = matrix
        
        # Build user summary
        for user in self.user_list:
            report.user_summary[user.display_name] = {}
            
            for service, matrix in report.matrices.items():
                count = 0
                user_perms = matrix.matrix.matrix.get(user.display_name, {})
                for entry in user_perms.values():
                    if entry.state != PermissionState.NOT_SET:
                        count += 1
                
                report.user_summary[user.display_name][service] = count
        
        return report
    
    def _permission_applies_to_user(
        self,
        permission: Permission,
        user_descriptor: str,
        user_groups: Set[str],
    ) -> bool:
        """Check if a permission applies to a user."""
        return (
            permission.identity_descriptor == user_descriptor or
            permission.identity_descriptor in user_groups
        )
    
    def get_user_permissions_summary(
        self,
        user_descriptor: str,
    ) -> Dict[str, Dict[str, int]]:
        """
        Get permission summary by service for a user.
        
        Args:
            user_descriptor: User's identity descriptor
            
        Returns:
            Dict[service][state_type] = count
        """
        user = self.users.get(user_descriptor)
        if not user:
            return {}
        
        user_groups = self._user_groups.get(user_descriptor, set())
        summary: Dict[str, Dict[str, int]] = {}
        
        for service in self.permissions.all_services():
            service_perms = self.permissions.get_by_service(service)
            summary[service] = {"allow": 0, "deny": 0, "inherited": 0, "total": 0}
            
            for perm in service_perms.permissions:
                if self._permission_applies_to_user(perm, user_descriptor, user_groups):
                    summary[service]["total"] += 1
                    
                    if perm.state in (PermissionState.DENY, PermissionState.INHERITED_DENY):
                        summary[service]["deny"] += 1
                    elif perm.is_inherited or perm.identity_descriptor in user_groups:
                        summary[service]["inherited"] += 1
                    else:
                        summary[service]["allow"] += 1
        
        return summary
    
    def get_permission_heatmap_data(self) -> Dict:
        """
        Get data formatted for heatmap visualization.
        
        Returns:
            Dict with heatmap data structure
        """
        heatmap = {
            "services": [],
            "users": [u.display_name for u in self.user_list],
            "data": [],  # [service_idx][user_idx] = permission_count
        }
        
        for service in self.permissions.all_services():
            service_perms = self.permissions.get_by_service(service)
            if not service_perms.permissions:
                continue
            
            heatmap["services"].append(service)
            service_data = []
            
            for user in self.user_list:
                user_groups = self._user_groups.get(user.descriptor, set())
                count = sum(
                    1 for p in service_perms.permissions
                    if self._permission_applies_to_user(p, user.descriptor, user_groups)
                )
                service_data.append(count)
            
            heatmap["data"].append(service_data)
        
        return heatmap
