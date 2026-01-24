"""
User Entitlements collector.

Collects all users with their access levels, licenses, and project memberships.
"""

import logging
from typing import Dict, List, Optional
from datetime import datetime

from ..client import AzureDevOpsClient
from ..models import User

logger = logging.getLogger(__name__)


class UsersCollector:
    """
    Collects user entitlements from Azure DevOps.
    
    Uses the Member Entitlement Management API to get detailed
    user information including access levels and licenses.
    """
    
    def __init__(self, client: AzureDevOpsClient, include_disabled: bool = False):
        """
        Initialize the collector.
        
        Args:
            client: Azure DevOps API client
            include_disabled: Whether to include disabled/inactive users
        """
        self.client = client
        self.include_disabled = include_disabled
        self._users_cache: Dict[str, User] = {}
    
    def collect(self) -> List[User]:
        """
        Collect all user entitlements.
        
        Returns:
            List of User objects with entitlement info
        """
        logger.info("Collecting user entitlements...")
        
        users = []
        
        try:
            # Use Member Entitlement Management API
            for user_data in self.client.vsaex_get_paginated(
                "_apis/userentitlements",
                api_version="7.1-preview.3",
            ):
                user = self._parse_user_entitlement(user_data)
                
                if user:
                    # Filter disabled users if needed
                    if not self.include_disabled and not user.is_active:
                        continue
                    
                    users.append(user)
                    self._users_cache[user.id] = user
                    self._users_cache[user.descriptor] = user
        
        except Exception as e:
            logger.warning(f"Error collecting user entitlements: {e}")
            # Fallback to Graph API users
            users = self._collect_graph_users()
        
        logger.info(f"Collected {len(users)} users")
        return users
    
    def _collect_graph_users(self) -> List[User]:
        """Fallback: collect users from Graph API."""
        users = []
        
        try:
            for user_data in self.client.vssps_get_paginated("_apis/graph/users"):
                user = self._parse_graph_user(user_data)
                if user:
                    users.append(user)
                    self._users_cache[user.descriptor] = user
        except Exception as e:
            logger.error(f"Error collecting users from Graph API: {e}")
        
        return users
    
    def _parse_user_entitlement(self, data: Dict) -> Optional[User]:
        """Parse user from Member Entitlement Management API response."""
        user_data = data.get("user", {})
        access_level_data = data.get("accessLevel", {})
        
        if not user_data:
            return None
        
        # Parse dates
        date_created = None
        last_accessed = None
        
        if data.get("dateCreated"):
            try:
                date_created = datetime.fromisoformat(
                    data["dateCreated"].replace("Z", "+00:00")
                )
            except (ValueError, TypeError):
                pass
        
        if data.get("lastAccessedDate"):
            try:
                last_accessed = datetime.fromisoformat(
                    data["lastAccessedDate"].replace("Z", "+00:00")
                )
            except (ValueError, TypeError):
                pass
        
        # Determine active status
        is_active = data.get("status", "") == "active"
        
        # Parse project memberships
        project_memberships = []
        for proj in data.get("projectEntitlements", []):
            proj_ref = proj.get("projectRef", {})
            if proj_ref.get("name"):
                project_memberships.append(proj_ref["name"])
        
        return User(
            id=data.get("id", ""),
            descriptor=user_data.get("descriptor", ""),
            display_name=user_data.get("displayName", "Unknown"),
            principal_name=user_data.get("principalName", ""),
            mail_address=user_data.get("mailAddress", ""),
            origin=user_data.get("origin", ""),
            origin_id=user_data.get("originId", ""),
            domain=user_data.get("domain", ""),
            is_active=is_active,
            access_level=access_level_data.get("accountLicenseType", ""),
            access_level_source=access_level_data.get("assignmentSource", ""),
            license_display_name=access_level_data.get("licenseDisplayName", ""),
            project_memberships=project_memberships,
            date_created=date_created,
            last_accessed=last_accessed,
        )
    
    def _parse_graph_user(self, data: Dict) -> Optional[User]:
        """Parse user from Graph API response."""
        return User(
            id=data.get("originId", data.get("descriptor", "")),
            descriptor=data.get("descriptor", ""),
            display_name=data.get("displayName", "Unknown"),
            principal_name=data.get("principalName", ""),
            mail_address=data.get("mailAddress", ""),
            origin=data.get("origin", ""),
            origin_id=data.get("originId", ""),
            domain=data.get("domain", ""),
            is_active=True,  # Graph API doesn't provide status
        )
    
    def get_user_by_descriptor(self, descriptor: str) -> Optional[User]:
        """Get a user from cache by descriptor."""
        return self._users_cache.get(descriptor)
    
    def get_user_by_id(self, user_id: str) -> Optional[User]:
        """Get a user from cache by ID."""
        return self._users_cache.get(user_id)
    
    def get_users_by_access_level(self, access_level: str) -> List[User]:
        """Get all users with a specific access level."""
        return [
            user for user in self._users_cache.values()
            if user.access_level.lower() == access_level.lower()
        ]
    
    def get_access_level_summary(self) -> Dict[str, int]:
        """Get summary of users by access level."""
        summary: Dict[str, int] = {}
        
        for user in self._users_cache.values():
            level = user.license_display_name or user.access_level or "Unknown"
            summary[level] = summary.get(level, 0) + 1
        
        return summary
