"""
Security Namespaces collector.

Collects all security namespaces and their permission definitions,
organized by Azure DevOps service areas.
"""

import logging
from typing import Dict, List, Optional
from dataclasses import dataclass, field

from ..client import AzureDevOpsClient
from ..models import SecurityNamespace

logger = logging.getLogger(__name__)


# Mapping of namespace names to Azure DevOps service areas
NAMESPACE_SERVICE_MAPPING = {
    # Project Level
    "Project": "Project",
    "Tagging": "Project",
    
    # Boards / Work Items
    "WorkItemTracking": "Boards",
    "WorkItemTrackingAdministration": "Boards",
    "WorkItemTrackingProvision": "Boards",
    "WorkItemQueryFolders": "Boards",
    "CSS": "Boards",  # Area paths
    "Iteration": "Boards",  # Sprints
    "Process": "Boards",
    
    # Repos / Git
    "Git Repositories": "Repos",
    "GitRepositories": "Repos",
    "VersionControlItems": "Repos",
    "VersionControlItems2": "Repos",
    
    # Pipelines / Build
    "Build": "Pipelines",
    "BuildAdministration": "Pipelines",
    
    # Release
    "ReleaseManagement": "Release",
    "ReleaseManagement2": "Release",
    
    # Test Plans
    "TestManagement": "Test Plans",
    
    # Artifacts
    "Packaging": "Artifacts",
    
    # Analytics
    "Analytics": "Analytics",
    "AnalyticsViews": "Analytics",
    
    # Identity / Security
    "Identity": "Security",
    "Security": "Security",
    "Server": "Security",
    
    # Service Connections / Endpoints
    "ServiceEndpoints": "Service Connections",
    "DistributedTask": "Service Connections",
    
    # Library (Variable Groups, Secure Files)
    "Library": "Library",
    
    # Environment
    "Environment": "Environments",
}


@dataclass
class ServiceNamespaces:
    """Namespaces organized by service area."""
    project: List[SecurityNamespace] = field(default_factory=list)
    boards: List[SecurityNamespace] = field(default_factory=list)
    repos: List[SecurityNamespace] = field(default_factory=list)
    pipelines: List[SecurityNamespace] = field(default_factory=list)
    release: List[SecurityNamespace] = field(default_factory=list)
    test_plans: List[SecurityNamespace] = field(default_factory=list)
    artifacts: List[SecurityNamespace] = field(default_factory=list)
    analytics: List[SecurityNamespace] = field(default_factory=list)
    security: List[SecurityNamespace] = field(default_factory=list)
    service_connections: List[SecurityNamespace] = field(default_factory=list)
    library: List[SecurityNamespace] = field(default_factory=list)
    environments: List[SecurityNamespace] = field(default_factory=list)
    other: List[SecurityNamespace] = field(default_factory=list)
    
    def get_by_service(self, service: str) -> List[SecurityNamespace]:
        """Get namespaces for a specific service."""
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
            "Service Connections", "Library", "Environments", "Other"
        ]


class NamespacesCollector:
    """
    Collects security namespaces from Azure DevOps.
    
    Security namespaces define the permission structure for different
    areas of Azure DevOps (repos, builds, work items, etc.).
    """
    
    def __init__(self, client: AzureDevOpsClient):
        """
        Initialize the collector.
        
        Args:
            client: Azure DevOps API client
        """
        self.client = client
        self._namespaces_cache: Dict[str, SecurityNamespace] = {}
    
    def collect(self) -> List[SecurityNamespace]:
        """
        Collect all security namespaces.
        
        Returns:
            List of SecurityNamespace objects
        """
        logger.info("Collecting security namespaces...")
        
        response = self.client.core_get("_apis/securitynamespaces")
        namespaces = []
        
        for ns_data in response.get("value", []):
            namespace = self._parse_namespace(ns_data)
            namespaces.append(namespace)
            self._namespaces_cache[namespace.namespace_id] = namespace
            self._namespaces_cache[namespace.name] = namespace
        
        logger.info(f"Collected {len(namespaces)} security namespaces")
        return namespaces
    
    def collect_by_service(self) -> ServiceNamespaces:
        """
        Collect and organize namespaces by Azure DevOps service.
        
        Returns:
            ServiceNamespaces with namespaces organized by service area
        """
        all_namespaces = self.collect()
        organized = ServiceNamespaces()
        
        for ns in all_namespaces:
            service = NAMESPACE_SERVICE_MAPPING.get(ns.name, "Other")
            
            if service == "Project":
                organized.project.append(ns)
            elif service == "Boards":
                organized.boards.append(ns)
            elif service == "Repos":
                organized.repos.append(ns)
            elif service == "Pipelines":
                organized.pipelines.append(ns)
            elif service == "Release":
                organized.release.append(ns)
            elif service == "Test Plans":
                organized.test_plans.append(ns)
            elif service == "Artifacts":
                organized.artifacts.append(ns)
            elif service == "Analytics":
                organized.analytics.append(ns)
            elif service == "Security":
                organized.security.append(ns)
            elif service == "Service Connections":
                organized.service_connections.append(ns)
            elif service == "Library":
                organized.library.append(ns)
            elif service == "Environments":
                organized.environments.append(ns)
            else:
                organized.other.append(ns)
        
        return organized
    
    def get_namespace(self, namespace_id_or_name: str) -> Optional[SecurityNamespace]:
        """
        Get a namespace by ID or name from cache.
        
        Args:
            namespace_id_or_name: Namespace ID (GUID) or name
            
        Returns:
            SecurityNamespace or None if not found
        """
        return self._namespaces_cache.get(namespace_id_or_name)
    
    def _parse_namespace(self, data: Dict) -> SecurityNamespace:
        """Parse namespace data from API response."""
        actions = []
        for action in data.get("actions", []):
            actions.append({
                "bit": action.get("bit", 0),
                "name": action.get("name", ""),
                "display_name": action.get("displayName", action.get("name", "")),
                "namespace_id": data.get("namespaceId", ""),
            })
        
        return SecurityNamespace(
            namespace_id=data.get("namespaceId", ""),
            name=data.get("name", ""),
            display_name=data.get("displayName", data.get("name", "")),
            description=data.get("description", ""),
            is_hierarchical=data.get("structureValue", 0) == 1,
            actions=sorted(actions, key=lambda x: x.get("bit", 0)),
        )
    
    def get_service_for_namespace(self, namespace_name: str) -> str:
        """
        Get the service area for a namespace.
        
        Args:
            namespace_name: Name of the namespace
            
        Returns:
            Service area name (e.g., "Repos", "Pipelines")
        """
        return NAMESPACE_SERVICE_MAPPING.get(namespace_name, "Other")
