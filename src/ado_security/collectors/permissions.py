"""
Permissions and ACL collector.

Collects Access Control Lists and entries for all security namespaces,
with granular permission details organized by Azure DevOps service areas.
"""

import logging
from typing import Dict, List, Optional, Set
from dataclasses import dataclass, field
from collections import defaultdict

from ..client import AzureDevOpsClient
from ..models import (
    AccessControlList,
    AccessControlEntry,
    Permission,
    PermissionState,
    SecurityNamespace,
)
from .namespaces import NamespacesCollector, NAMESPACE_SERVICE_MAPPING

logger = logging.getLogger(__name__)


@dataclass
class ServicePermissions:
    """Permissions organized by service area."""
    service_name: str
    permissions: List[Permission] = field(default_factory=list)
    acls: List[AccessControlList] = field(default_factory=list)
    
    def get_permissions_for_identity(self, descriptor: str) -> List[Permission]:
        """Get all permissions for a specific identity."""
        return [p for p in self.permissions if p.identity_descriptor == descriptor]


@dataclass
class GranularPermissions:
    """All permissions organized by service."""
    project: ServicePermissions = field(default_factory=lambda: ServicePermissions("Project"))
    boards: ServicePermissions = field(default_factory=lambda: ServicePermissions("Boards"))
    repos: ServicePermissions = field(default_factory=lambda: ServicePermissions("Repos"))
    pipelines: ServicePermissions = field(default_factory=lambda: ServicePermissions("Pipelines"))
    release: ServicePermissions = field(default_factory=lambda: ServicePermissions("Release"))
    test_plans: ServicePermissions = field(default_factory=lambda: ServicePermissions("Test Plans"))
    artifacts: ServicePermissions = field(default_factory=lambda: ServicePermissions("Artifacts"))
    analytics: ServicePermissions = field(default_factory=lambda: ServicePermissions("Analytics"))
    security: ServicePermissions = field(default_factory=lambda: ServicePermissions("Security"))
    service_connections: ServicePermissions = field(default_factory=lambda: ServicePermissions("Service Connections"))
    library: ServicePermissions = field(default_factory=lambda: ServicePermissions("Library"))
    environments: ServicePermissions = field(default_factory=lambda: ServicePermissions("Environments"))
    other: ServicePermissions = field(default_factory=lambda: ServicePermissions("Other"))
    
    def get_by_service(self, service: str) -> ServicePermissions:
        """Get permissions for a specific service."""
        service_map = {
            "Project": self.project,
            "Boards": self.boards,
            "Repos": self.repos,
            "Pipelines": self.pipelines,
            "Release": self.release,
            "Test Plans": self.test_plans,
            "Artifacts": self.artifacts,
            "Analytics": self.analytics,
            "Security": self.security,
            "Service Connections": self.service_connections,
            "Library": self.library,
            "Environments": self.environments,
            "Other": self.other,
        }
        return service_map.get(service, self.other)
    
    def all_services(self) -> List[str]:
        """Get list of all service names."""
        return [
            "Project", "Boards", "Repos", "Pipelines", "Release",
            "Test Plans", "Artifacts", "Analytics", "Security",
            "Service Connections", "Library", "Environments"
        ]
    
    def all_permissions(self) -> List[Permission]:
        """Get all permissions across all services."""
        all_perms = []
        for service in self.all_services():
            all_perms.extend(self.get_by_service(service).permissions)
        all_perms.extend(self.other.permissions)
        return all_perms


class PermissionsCollector:
    """
    Collects permissions (ACLs/ACEs) from Azure DevOps.
    
    Retrieves Access Control Lists for security namespaces and
    decodes permission bitmasks to human-readable format.
    """
    
    def __init__(
        self,
        client: AzureDevOpsClient,
        namespaces_collector: NamespacesCollector,
    ):
        """
        Initialize the collector.
        
        Args:
            client: Azure DevOps API client
            namespaces_collector: Collector with namespace information
        """
        self.client = client
        self.namespaces_collector = namespaces_collector
        self._identity_cache: Dict[str, str] = {}  # descriptor -> display name
        self._acls_cache: Dict[str, List[AccessControlList]] = {}
    
    def collect(
        self,
        namespaces: Optional[List[str]] = None,
    ) -> List[AccessControlList]:
        """
        Collect ACLs for specified namespaces.
        
        Args:
            namespaces: List of namespace names to collect (None = all)
            
        Returns:
            List of AccessControlList objects
        """
        logger.info("Collecting permissions...")
        
        all_acls = []
        project_id = self.client.get_project_id()
        
        # Get namespaces to query
        if namespaces:
            ns_list = [
                self.namespaces_collector.get_namespace(ns)
                for ns in namespaces
            ]
            ns_list = [ns for ns in ns_list if ns]
        else:
            ns_list = list(self.namespaces_collector._namespaces_cache.values())
        
        for namespace in ns_list:
            try:
                acls = self._collect_namespace_acls(namespace, project_id)
                all_acls.extend(acls)
                self._acls_cache[namespace.name] = acls
            except Exception as e:
                logger.warning(f"Error collecting ACLs for {namespace.name}: {e}")
        
        logger.info(f"Collected {len(all_acls)} ACLs")
        return all_acls
    
    def collect_by_service(
        self,
        namespaces: Optional[List[str]] = None,
    ) -> GranularPermissions:
        """
        Collect and organize permissions by Azure DevOps service.
        
        Args:
            namespaces: List of namespace names to collect (None = all)
            
        Returns:
            GranularPermissions with permissions organized by service
        """
        acls = self.collect(namespaces)
        granular = GranularPermissions()
        project_id = self.client.get_project_id()
        
        for acl in acls:
            namespace = self.namespaces_collector.get_namespace(acl.namespace_id)
            if not namespace:
                continue
            
            service_name = NAMESPACE_SERVICE_MAPPING.get(namespace.name, "Other")
            service_perms = granular.get_by_service(service_name)
            service_perms.acls.append(acl)
            
            # Decode permissions for each ACE
            for ace in acl.aces:
                permissions = self._decode_ace_permissions(ace, namespace, acl.token)
                service_perms.permissions.extend(permissions)
        
        return granular
    
    def _collect_namespace_acls(
        self,
        namespace: SecurityNamespace,
        project_id: str,
    ) -> List[AccessControlList]:
        """Collect ACLs for a specific namespace."""
        acls = []
        
        # Build token for project scope
        # Token format varies by namespace
        token = self._build_project_token(namespace.name, project_id)
        
        try:
            response = self.client.core_get(
                f"_apis/accesscontrollists/{namespace.namespace_id}",
                token=token,
                includeExtendedInfo="true",
                recurse="true",
            )
            
            for acl_data in response.get("value", []):
                acl = self._parse_acl(acl_data, namespace.namespace_id)
                acls.append(acl)
        
        except Exception as e:
            logger.debug(f"Could not get ACLs for {namespace.name} with token {token}: {e}")
            
            # Try without token (get all ACLs in namespace)
            try:
                response = self.client.core_get(
                    f"_apis/accesscontrollists/{namespace.namespace_id}",
                    includeExtendedInfo="true",
                )
                
                for acl_data in response.get("value", []):
                    # Filter by project if possible
                    acl_token = acl_data.get("token", "")
                    if project_id in acl_token or not acl_token:
                        acl = self._parse_acl(acl_data, namespace.namespace_id)
                        acls.append(acl)
            except Exception as e2:
                logger.debug(f"Could not get ACLs for {namespace.name}: {e2}")
        
        return acls
    
    def _build_project_token(self, namespace_name: str, project_id: str) -> str:
        """Build the appropriate token for a namespace."""
        # Token formats vary by namespace type
        token_formats = {
            "Project": f"$PROJECT:vstfs:///Classification/TeamProject/{project_id}",
            "Git Repositories": f"repoV2/{project_id}",
            "Build": f"{project_id}",
            "ReleaseManagement": f"{project_id}",
            "WorkItemTracking": f"/{project_id}",
            "CSS": f"vstfs:///Classification/Node/{project_id}",
            "Iteration": f"vstfs:///Classification/Node/{project_id}",
        }
        
        return token_formats.get(namespace_name, project_id)
    
    def _parse_acl(self, data: Dict, namespace_id: str) -> AccessControlList:
        """Parse ACL from API response."""
        aces = []
        aces_dict = data.get("acesDictionary", {})
        
        for descriptor, ace_data in aces_dict.items():
            ace = AccessControlEntry(
                identity_descriptor=descriptor,
                identity_display_name=self._resolve_identity(descriptor),
                allow=ace_data.get("allow", 0),
                deny=ace_data.get("deny", 0),
                extended_info=ace_data.get("extendedInfo", {}),
            )
            aces.append(ace)
        
        return AccessControlList(
            token=data.get("token", ""),
            inherit_permissions=data.get("inheritPermissions", True),
            aces=aces,
            namespace_id=namespace_id,
        )
    
    def _decode_ace_permissions(
        self,
        ace: AccessControlEntry,
        namespace: SecurityNamespace,
        token: str,
    ) -> List[Permission]:
        """Decode an ACE into individual Permission objects."""
        permissions = []
        
        for action in namespace.actions:
            bit = action.get("bit", 0)
            if not bit:
                continue
            
            action_name = action.get("display_name") or action.get("name", f"Unknown({bit})")
            
            # Determine permission state
            state = PermissionState.NOT_SET
            is_inherited = False
            
            # Check explicit deny first (deny takes precedence)
            if ace.deny & bit:
                state = PermissionState.DENY
            elif ace.allow & bit:
                state = PermissionState.ALLOW
            # Check inherited
            elif ace.inherited_deny & bit:
                state = PermissionState.INHERITED_DENY
                is_inherited = True
            elif ace.inherited_allow & bit:
                state = PermissionState.INHERITED_ALLOW
                is_inherited = True
            else:
                continue  # Not set, skip
            
            permissions.append(Permission(
                identity_descriptor=ace.identity_descriptor,
                identity_name=ace.identity_display_name,
                namespace_name=namespace.name,
                resource_token=token,
                permission_name=action_name,
                permission_bit=bit,
                state=state,
                is_inherited=is_inherited,
            ))
        
        return permissions
    
    def _resolve_identity(self, descriptor: str) -> str:
        """Resolve an identity descriptor to display name."""
        if descriptor in self._identity_cache:
            return self._identity_cache[descriptor]
        
        try:
            # Try to resolve via identity API
            response = self.client.vssps_get(
                "_apis/identities",
                descriptors=descriptor,
            )
            
            identities = response.get("value", [])
            if identities:
                display_name = identities[0].get(
                    "providerDisplayName",
                    identities[0].get("displayName", descriptor)
                )
                self._identity_cache[descriptor] = display_name
                return display_name
        
        except Exception:
            pass
        
        self._identity_cache[descriptor] = descriptor
        return descriptor
    
    def get_permissions_for_identity(
        self,
        descriptor: str,
        service: Optional[str] = None,
    ) -> List[Permission]:
        """
        Get all permissions for a specific identity.
        
        Args:
            descriptor: Identity descriptor
            service: Optional service filter (e.g., "Repos", "Pipelines")
            
        Returns:
            List of Permission objects
        """
        permissions = []
        
        for namespace_name, acls in self._acls_cache.items():
            if service:
                ns_service = NAMESPACE_SERVICE_MAPPING.get(namespace_name, "Other")
                if ns_service != service:
                    continue
            
            namespace = self.namespaces_collector.get_namespace(namespace_name)
            if not namespace:
                continue
            
            for acl in acls:
                ace = acl.get_ace_for_identity(descriptor)
                if ace:
                    permissions.extend(
                        self._decode_ace_permissions(ace, namespace, acl.token)
                    )
        
        return permissions
    
    def get_identity_permissions_by_service(
        self,
        descriptor: str,
    ) -> Dict[str, List[Permission]]:
        """
        Get permissions for an identity organized by service.
        
        Args:
            descriptor: Identity descriptor
            
        Returns:
            Dict mapping service name to list of permissions
        """
        result: Dict[str, List[Permission]] = defaultdict(list)
        
        for service in GranularPermissions().all_services():
            perms = self.get_permissions_for_identity(descriptor, service)
            if perms:
                result[service] = perms
        
        return dict(result)
