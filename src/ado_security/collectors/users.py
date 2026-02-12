"""
User collector for project-level scope.

Collects users within the project using the Teams API (project-scoped),
with optional fallback to the Member Entitlement Management API.
A project-level admin does NOT have access to org-wide user entitlements,
so we enumerate users via project teams and Graph API user lookups.
"""

import logging
from typing import Dict, List, Optional
from datetime import datetime

from ..client import AzureDevOpsClient
from ..models import User

logger = logging.getLogger(__name__)


class UsersCollector:
    """
    Collects users within the project scope.

    Strategy (project-admin friendly):
    1. List all teams in the project  (Teams REST API)
    2. For each team, list members     (Team Members REST API)
    3. Enrich user details via Graph API (user descriptor lookup)

    Optionally falls back to Member Entitlement Management API (org-level)
    if the PAT has org-level permissions.
    """

    def __init__(self, client: AzureDevOpsClient, include_disabled: bool = False):
        self.client = client
        self.include_disabled = include_disabled
        self._users_cache: Dict[str, User] = {}

    def collect(self) -> List[User]:
        """
        Collect all users in the project.

        Returns:
            List of User objects.
        """
        logger.info(f"Collecting users for project: {self.client.project}")

        # Primary: project-scoped collection via Teams API
        users = self._collect_project_team_members()

        if users:
            logger.info(f"Collected {len(users)} users via project Teams API")
            return users

        # Fallback: try org-level entitlements API (may fail for project admins)
        logger.info("Teams API returned no users, trying entitlements API fallback...")
        users = self._collect_via_entitlements()

        if users:
            logger.info(f"Collected {len(users)} users via entitlements API")
            return users

        # Last resort: Graph API users
        logger.info("Falling back to Graph API users...")
        users = self._collect_graph_users()
        logger.info(f"Collected {len(users)} users via Graph API")
        return users

    # ------------------------------------------------------------------
    # Project-scoped collection (primary)
    # ------------------------------------------------------------------

    def _collect_project_team_members(self) -> List[User]:
        """Collect users by enumerating project teams and their members."""
        seen_ids: Dict[str, User] = {}

        try:
            teams = self.client.get_project_teams()
        except Exception as e:
            logger.warning(f"Could not list project teams: {e}")
            return []

        for team in teams:
            team_id = team.get("id", "")
            team_name = team.get("name", "Unknown Team")
            if not team_id:
                continue

            try:
                members = self.client.get_team_members(team_id)
            except Exception as e:
                logger.warning(f"Could not get members for team '{team_name}': {e}")
                continue

            for member_entry in members:
                identity = member_entry.get("identity", {})
                uid = identity.get("id", "")
                if not uid or uid in seen_ids:
                    # Already seen – just note the team membership
                    if uid in seen_ids:
                        seen_ids[uid].project_memberships.append(team_name)
                    continue

                is_active = identity.get("isActive", True) if "isActive" in identity else True
                if not self.include_disabled and not is_active:
                    continue

                user = User(
                    id=uid,
                    descriptor=identity.get("descriptor", uid),
                    display_name=identity.get("displayName", "Unknown"),
                    principal_name=identity.get("uniqueName", ""),
                    mail_address=identity.get("uniqueName", ""),
                    origin="aad",
                    is_active=is_active,
                    project_memberships=[team_name],
                )

                # Try to enrich with Graph API details
                self._enrich_user_details(user)

                seen_ids[uid] = user
                self._users_cache[uid] = user
                self._users_cache[user.descriptor] = user

        return list(seen_ids.values())

    def _enrich_user_details(self, user: User):
        """Try to enrich user with Graph/entitlement details."""
        if not user.descriptor:
            return

        try:
            response = self.client.vssps_get(f"_apis/graph/users/{user.descriptor}")
            if response:
                user.origin = response.get("origin", user.origin)
                user.origin_id = response.get("originId", "")
                user.domain = response.get("domain", "")
                user.mail_address = response.get("mailAddress", user.mail_address)
                user.principal_name = response.get("principalName", user.principal_name)
        except Exception:
            pass  # Graph lookup is best-effort

    # ------------------------------------------------------------------
    # Org-level fallback (requires org permissions)
    # ------------------------------------------------------------------

    def _collect_via_entitlements(self) -> List[User]:
        """Fallback: collect via Member Entitlement Management API (org-level)."""
        users = []
        try:
            for user_data in self.client.vsaex_get_paginated(
                "_apis/userentitlements",
                api_version="7.1-preview.3",
            ):
                user = self._parse_user_entitlement(user_data)
                if user:
                    if not self.include_disabled and not user.is_active:
                        continue
                    # Filter to only users in the current project
                    if self.client.project.lower() in [
                        p.lower() for p in user.project_memberships
                    ]:
                        users.append(user)
                        self._users_cache[user.id] = user
                        self._users_cache[user.descriptor] = user
        except Exception as e:
            logger.debug(f"Entitlements API not accessible (expected for project admins): {e}")
        return users

    def _collect_graph_users(self) -> List[User]:
        """Last-resort fallback: collect users from Graph API."""
        users = []
        try:
            scope = self.client.get_project_descriptor()
            params = {"scopeDescriptor": scope} if scope else {}
            for user_data in self.client.vssps_get_paginated(
                "_apis/graph/users", **params,
            ):
                user = self._parse_graph_user(user_data)
                if user:
                    users.append(user)
                    self._users_cache[user.descriptor] = user
        except Exception as e:
            logger.error(f"Error collecting users from Graph API: {e}")
        return users

    # ------------------------------------------------------------------
    # Parsers
    # ------------------------------------------------------------------

    def _parse_user_entitlement(self, data: Dict) -> Optional[User]:
        """Parse user from Member Entitlement Management API response."""
        user_data = data.get("user", {})
        access_level_data = data.get("accessLevel", {})

        if not user_data:
            return None

        date_created = self._parse_date(data.get("dateCreated"))
        last_accessed = self._parse_date(data.get("lastAccessedDate"))

        is_active = data.get("status", "") == "active"

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
            is_active=True,
        )

    @staticmethod
    def _parse_date(value: Optional[str]) -> Optional[datetime]:
        if not value:
            return None
        try:
            return datetime.fromisoformat(value.replace("Z", "+00:00"))
        except (ValueError, TypeError):
            return None

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def get_user_by_descriptor(self, descriptor: str) -> Optional[User]:
        return self._users_cache.get(descriptor)

    def get_user_by_id(self, user_id: str) -> Optional[User]:
        return self._users_cache.get(user_id)

    def get_users_by_access_level(self, access_level: str) -> List[User]:
        return [
            u for u in self._users_cache.values()
            if u.access_level.lower() == access_level.lower()
        ]

    def get_access_level_summary(self) -> Dict[str, int]:
        summary: Dict[str, int] = {}
        for user in self._users_cache.values():
            level = user.license_display_name or user.access_level or "Unknown"
            summary[level] = summary.get(level, 0) + 1
        return summary
