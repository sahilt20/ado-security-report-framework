"""
Groups and Membership collector.

Collects all security groups and their members at the project level,
including nested group relationships.
"""

import logging
from typing import Dict, List, Optional, Set
from collections import defaultdict

from ..client import AzureDevOpsClient
from ..models import SecurityGroup, GroupMember

logger = logging.getLogger(__name__)


class GroupsCollector:
    """
    Collects security groups and memberships from Azure DevOps.
    
    Uses the Graph API to enumerate all groups and their members
    within a project scope.
    """
    
    def __init__(self, client: AzureDevOpsClient):
        """
        Initialize the collector.
        
        Args:
            client: Azure DevOps API client
        """
        self.client = client
        self._groups_cache: Dict[str, SecurityGroup] = {}
        self._processed_groups: Set[str] = set()
    
    def collect(self, include_members: bool = True) -> List[SecurityGroup]:
        """
        Collect all security groups in the project.
        
        Args:
            include_members: Whether to also collect group members
            
        Returns:
            List of SecurityGroup objects with membership info
        """
        logger.info(f"Collecting security groups for project: {self.client.project}")
        
        # Get project scope descriptor
        scope_descriptor = self.client.get_project_descriptor()
        
        if not scope_descriptor:
            logger.warning("Could not get project scope descriptor, collecting org-wide groups")
            groups = self._collect_all_groups()
        else:
            groups = self._collect_project_groups(scope_descriptor)
        
        # Collect members for each group
        if include_members:
            for group in groups:
                self._collect_group_members(group)
        
        # Build parent-child relationships
        self._build_group_hierarchy(groups)
        
        logger.info(f"Collected {len(groups)} groups")
        return groups
    
    def _collect_project_groups(self, scope_descriptor: str) -> List[SecurityGroup]:
        """Collect groups within project scope."""
        groups = []
        
        try:
            # Get groups in project scope
            for group_data in self.client.vssps_get_paginated(
                "_apis/graph/groups",
                scopeDescriptor=scope_descriptor,
            ):
                group = self._parse_group(group_data)
                groups.append(group)
                self._groups_cache[group.descriptor] = group
        except Exception as e:
            logger.warning(f"Error collecting project groups: {e}")
            # Fallback to all groups
            return self._collect_all_groups()
        
        return groups
    
    def _collect_all_groups(self) -> List[SecurityGroup]:
        """Collect all groups in the organization."""
        groups = []
        
        for group_data in self.client.vssps_get_paginated("_apis/graph/groups"):
            group = self._parse_group(group_data)
            groups.append(group)
            self._groups_cache[group.descriptor] = group
        
        return groups
    
    def _collect_group_members(self, group: SecurityGroup):
        """
        Collect members of a specific group.
        
        Args:
            group: SecurityGroup to collect members for
        """
        if group.descriptor in self._processed_groups:
            return
        
        self._processed_groups.add(group.descriptor)
        
        try:
            # Get direct members (direction=down)
            response = self.client.vssps_get(
                f"_apis/graph/memberships/{group.descriptor}",
                direction="down",
            )
            
            member_links = response.get("value", [])
            
            for link in member_links:
                member_descriptor = link.get("memberDescriptor", "")
                
                if not member_descriptor:
                    continue
                
                # Determine if member is a user or group
                if self._is_user_descriptor(member_descriptor):
                    member = self._get_user_details(member_descriptor)
                    if member:
                        group.members.append(member)
                else:
                    # It's a nested group
                    member = self._get_group_as_member(member_descriptor)
                    if member:
                        group.members.append(member)
                        group.child_groups.append(member_descriptor)
            
            group.member_count = len(group.members)
            
        except Exception as e:
            logger.warning(f"Error collecting members for {group.display_name}: {e}")
    
    def _get_user_details(self, descriptor: str) -> Optional[GroupMember]:
        """Get user details by descriptor."""
        try:
            response = self.client.vssps_get(f"_apis/graph/users/{descriptor}")
            
            if not response:
                return None
            
            return GroupMember(
                descriptor=descriptor,
                display_name=response.get("displayName", "Unknown"),
                principal_name=response.get("principalName", ""),
                member_type="user",
                origin=response.get("origin", ""),
                mail_address=response.get("mailAddress", ""),
                is_active=True,
            )
        except Exception as e:
            logger.debug(f"Could not get user details for {descriptor}: {e}")
            return None
    
    def _get_group_as_member(self, descriptor: str) -> Optional[GroupMember]:
        """Get group details as a member entry."""
        # Check cache first
        if descriptor in self._groups_cache:
            group = self._groups_cache[descriptor]
            return GroupMember(
                descriptor=descriptor,
                display_name=group.display_name,
                principal_name=group.principal_name,
                member_type="group",
                origin=group.origin,
            )
        
        # Fetch from API
        try:
            response = self.client.vssps_get(f"_apis/graph/groups/{descriptor}")
            
            if not response:
                return None
            
            return GroupMember(
                descriptor=descriptor,
                display_name=response.get("displayName", "Unknown Group"),
                principal_name=response.get("principalName", ""),
                member_type="group",
                origin=response.get("origin", ""),
            )
        except Exception as e:
            logger.debug(f"Could not get group details for {descriptor}: {e}")
            return None
    
    def _build_group_hierarchy(self, groups: List[SecurityGroup]):
        """Build parent-child group relationships."""
        descriptor_to_group = {g.descriptor: g for g in groups}
        
        for group in groups:
            for child_descriptor in group.child_groups:
                if child_descriptor in descriptor_to_group:
                    child_group = descriptor_to_group[child_descriptor]
                    if group.descriptor not in child_group.parent_groups:
                        child_group.parent_groups.append(group.descriptor)
    
    def _parse_group(self, data: Dict) -> SecurityGroup:
        """Parse group data from API response."""
        return SecurityGroup(
            descriptor=data.get("descriptor", ""),
            display_name=data.get("displayName", "Unknown"),
            principal_name=data.get("principalName", ""),
            origin=data.get("origin", "vsts"),
            origin_id=data.get("originId", ""),
            description=data.get("description", ""),
            is_cross_project=data.get("isCrossProject", False),
            domain=data.get("domain", ""),
            mail_address=data.get("mailAddress", ""),
            url=data.get("url", ""),
        )
    
    def _is_user_descriptor(self, descriptor: str) -> bool:
        """Check if a descriptor belongs to a user (vs a group)."""
        # User descriptors typically contain specific patterns
        # Groups usually have patterns like "vssgp." or contain "Group"
        return "aad." in descriptor.lower() or "msa." in descriptor.lower()
    
    def get_group_by_descriptor(self, descriptor: str) -> Optional[SecurityGroup]:
        """Get a group from cache by descriptor."""
        return self._groups_cache.get(descriptor)
    
    def get_all_users_in_groups(self) -> List[GroupMember]:
        """Extract all unique users from all groups."""
        seen_descriptors = set()
        users = []
        
        for group in self._groups_cache.values():
            for member in group.members:
                if member.member_type == "user" and member.descriptor not in seen_descriptors:
                    seen_descriptors.add(member.descriptor)
                    users.append(member)
        
        return users
    
    def get_user_group_memberships(self, user_descriptor: str) -> List[SecurityGroup]:
        """Get all groups a user belongs to (including nested)."""
        direct_groups = []
        
        for group in self._groups_cache.values():
            for member in group.members:
                if member.descriptor == user_descriptor:
                    direct_groups.append(group)
                    break
        
        # TODO: Expand to include inherited memberships through nested groups
        return direct_groups
