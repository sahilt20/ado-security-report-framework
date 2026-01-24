"""
Azure DevOps REST API Client.

Provides authenticated access to Azure DevOps APIs with:
- PAT authentication
- Rate limiting
- Retry logic with exponential backoff
- Pagination handling
"""

import time
import logging
from typing import Optional, Dict, Any, List, Generator
from urllib.parse import urljoin, urlencode

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

from .config import Config


logger = logging.getLogger(__name__)


class AzureDevOpsClient:
    """
    Azure DevOps REST API client.
    
    Supports multiple API domains:
    - dev.azure.com - Core APIs
    - vssps.dev.azure.com - Graph/Identity APIs
    - vsaex.dev.azure.com - User Entitlements APIs
    """
    
    API_VERSION = "7.1-preview.1"
    
    # Base URLs for different API domains
    CORE_URL = "https://dev.azure.com/{org}"
    VSSPS_URL = "https://vssps.dev.azure.com/{org}"
    VSAEX_URL = "https://vsaex.dev.azure.com/{org}"
    
    def __init__(self, config: Config):
        """
        Initialize the Azure DevOps client.
        
        Args:
            config: Configuration object with org, project, and PAT
        """
        self.config = config
        self.organization = config.organization
        self.project = config.project
        self.pat = config.pat
        self.timeout = config.options.timeout
        self.rate_limit = config.options.rate_limit
        
        self._last_request_time = 0
        self._session = self._create_session()
        
        # Cache for frequently used data
        self._project_id: Optional[str] = None
        self._project_descriptor: Optional[str] = None
    
    def _create_session(self) -> requests.Session:
        """Create a requests session with retry logic."""
        session = requests.Session()
        
        # Set up authentication
        session.auth = ("", self.pat)
        
        # Set up retry strategy
        retry_strategy = Retry(
            total=3,
            backoff_factor=1,
            status_forcelist=[429, 500, 502, 503, 504],
            allowed_methods=["GET", "POST", "PUT", "PATCH"],
        )
        
        adapter = HTTPAdapter(max_retries=retry_strategy)
        session.mount("https://", adapter)
        session.mount("http://", adapter)
        
        # Set default headers
        session.headers.update({
            "Content-Type": "application/json",
            "Accept": "application/json",
        })
        
        return session
    
    def _rate_limit_wait(self):
        """Enforce rate limiting between requests."""
        if self.rate_limit <= 0:
            return
        
        min_interval = 1.0 / self.rate_limit
        elapsed = time.time() - self._last_request_time
        
        if elapsed < min_interval:
            time.sleep(min_interval - elapsed)
        
        self._last_request_time = time.time()
    
    def _build_url(
        self,
        base_url: str,
        path: str,
        api_version: Optional[str] = None,
        **query_params,
    ) -> str:
        """
        Build a complete API URL.
        
        Args:
            base_url: Base URL template (e.g., CORE_URL)
            path: API path
            api_version: API version override
            **query_params: Query parameters
            
        Returns:
            Complete URL string
        """
        url = base_url.format(org=self.organization)
        url = urljoin(url + "/", path.lstrip("/"))
        
        # Add API version
        query_params["api-version"] = api_version or self.API_VERSION
        
        # Filter out None values
        query_params = {k: v for k, v in query_params.items() if v is not None}
        
        if query_params:
            url += "?" + urlencode(query_params)
        
        return url
    
    def _request(
        self,
        method: str,
        base_url: str,
        path: str,
        api_version: Optional[str] = None,
        data: Optional[Dict] = None,
        **query_params,
    ) -> Dict[str, Any]:
        """
        Make an API request.
        
        Args:
            method: HTTP method
            base_url: Base URL template
            path: API path
            api_version: API version override
            data: Request body for POST/PUT
            **query_params: Query parameters
            
        Returns:
            Response JSON as dictionary
            
        Raises:
            requests.HTTPError: On API errors
        """
        self._rate_limit_wait()
        
        url = self._build_url(base_url, path, api_version, **query_params)
        
        logger.debug(f"{method} {url}")
        
        response = self._session.request(
            method,
            url,
            json=data,
            timeout=self.timeout,
        )
        
        # Handle 404 gracefully
        if response.status_code == 404:
            logger.warning(f"Resource not found: {url}")
            return {}
        
        response.raise_for_status()
        
        if response.content:
            return response.json()
        return {}
    
    def get(
        self,
        base_url: str,
        path: str,
        api_version: Optional[str] = None,
        **query_params,
    ) -> Dict[str, Any]:
        """Make a GET request."""
        return self._request("GET", base_url, path, api_version, **query_params)
    
    def post(
        self,
        base_url: str,
        path: str,
        data: Optional[Dict] = None,
        api_version: Optional[str] = None,
        **query_params,
    ) -> Dict[str, Any]:
        """Make a POST request."""
        return self._request("POST", base_url, path, api_version, data, **query_params)
    
    def get_paginated(
        self,
        base_url: str,
        path: str,
        api_version: Optional[str] = None,
        page_size: int = 100,
        **query_params,
    ) -> Generator[Dict[str, Any], None, None]:
        """
        Get paginated results.
        
        Handles continuation tokens and yields individual items.
        
        Args:
            base_url: Base URL template
            path: API path
            api_version: API version override
            page_size: Items per page
            **query_params: Query parameters
            
        Yields:
            Individual items from paginated responses
        """
        continuation_token = None
        
        while True:
            params = {**query_params, "$top": page_size}
            if continuation_token:
                params["continuationToken"] = continuation_token
            
            response = self.get(base_url, path, api_version, **params)
            
            # Handle different response formats
            items = response.get("value", response.get("members", []))
            
            for item in items:
                yield item
            
            # Check for more pages
            continuation_token = response.get("continuationToken")
            if not continuation_token or not items:
                break
    
    # Convenience methods for specific API domains
    
    def core_get(self, path: str, **kwargs) -> Dict[str, Any]:
        """GET request to core API (dev.azure.com)."""
        return self.get(self.CORE_URL, path, **kwargs)
    
    def vssps_get(self, path: str, **kwargs) -> Dict[str, Any]:
        """GET request to VSSPS API (vssps.dev.azure.com)."""
        return self.get(self.VSSPS_URL, path, **kwargs)
    
    def vsaex_get(self, path: str, **kwargs) -> Dict[str, Any]:
        """GET request to VSAEX API (vsaex.dev.azure.com)."""
        return self.get(self.VSAEX_URL, path, **kwargs)
    
    def core_get_paginated(self, path: str, **kwargs) -> Generator[Dict, None, None]:
        """Paginated GET from core API."""
        return self.get_paginated(self.CORE_URL, path, **kwargs)
    
    def vssps_get_paginated(self, path: str, **kwargs) -> Generator[Dict, None, None]:
        """Paginated GET from VSSPS API."""
        return self.get_paginated(self.VSSPS_URL, path, **kwargs)
    
    def vsaex_get_paginated(self, path: str, **kwargs) -> Generator[Dict, None, None]:
        """Paginated GET from VSAEX API."""
        return self.get_paginated(self.VSAEX_URL, path, **kwargs)
    
    # Project-related helpers
    
    def get_project_id(self) -> str:
        """Get the project ID."""
        if self._project_id:
            return self._project_id
        
        response = self.core_get(f"_apis/projects/{self.project}")
        self._project_id = response.get("id", "")
        return self._project_id
    
    def get_project_descriptor(self) -> str:
        """Get the project's scope descriptor for Graph API calls."""
        if self._project_descriptor:
            return self._project_descriptor
        
        project_id = self.get_project_id()
        response = self.vssps_get(f"_apis/graph/descriptors/{project_id}")
        self._project_descriptor = response.get("value", "")
        return self._project_descriptor
    
    def validate_connection(self) -> bool:
        """
        Validate the connection to Azure DevOps.
        
        Returns:
            True if connection is valid
            
        Raises:
            Exception with details if connection fails
        """
        try:
            response = self.core_get(f"_apis/projects/{self.project}")
            if response.get("id"):
                logger.info(f"Connected to project: {response.get('name')}")
                return True
            raise ValueError("Project not found or access denied")
        except requests.HTTPError as e:
            if e.response.status_code == 401:
                raise ValueError("Authentication failed. Check your PAT token.")
            elif e.response.status_code == 403:
                raise ValueError("Access denied. PAT may lack required permissions.")
            raise
