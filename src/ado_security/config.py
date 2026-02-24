"""
Configuration management for Azure DevOps Security Framework.

Supports:
- YAML configuration files
- Environment variable references (${VAR_NAME})
- CLI argument overrides
"""

import os
import re
import yaml
from dataclasses import dataclass, field
from typing import Optional, List, Dict, Any
from pathlib import Path


@dataclass
class OutputConfig:
    """Output configuration settings."""
    path: str = "./reports"
    filename: str = "security_report_{timestamp}.xlsx"


@dataclass
class OptionsConfig:
    """Report options configuration."""
    include_inherited: bool = True
    include_disabled_users: bool = False
    allow_org_fallback: bool = False
    namespaces: List[str] = field(default_factory=lambda: [
        "Project",
        "Git Repositories",
        "Build",
        "ReleaseManagement",
        "AnalyticsViews",
        "Workitems",
        "Identity",
        "Iteration",
        "CSS",
    ])
    rate_limit: int = 10
    timeout: int = 30
    governance_thresholds: Dict[str, Any] = field(default_factory=dict)


@dataclass
class Config:
    """Main configuration container."""
    organization: str
    project: str
    pat: str
    output: OutputConfig = field(default_factory=OutputConfig)
    options: OptionsConfig = field(default_factory=OptionsConfig)

    @classmethod
    def from_dict(cls, data: dict) -> "Config":
        """Create Config from dictionary."""
        output_data = data.get("output", {})
        options_data = data.get("options", {})
        
        output = OutputConfig(
            path=output_data.get("path", "./reports"),
            filename=output_data.get("filename", "security_report_{timestamp}.xlsx"),
        )
        
        options = OptionsConfig(
            include_inherited=options_data.get("include_inherited", True),
            include_disabled_users=options_data.get("include_disabled_users", False),
            allow_org_fallback=options_data.get("allow_org_fallback", False),
            namespaces=options_data.get("namespaces", OptionsConfig().namespaces),
            rate_limit=options_data.get("rate_limit", 10),
            timeout=options_data.get("timeout", 30),
            governance_thresholds=options_data.get("governance_thresholds", {}),
        )
        
        return cls(
            organization=data["organization"],
            project=data["project"],
            pat=data["pat"],
            output=output,
            options=options,
        )


def expand_env_vars(value: str) -> str:
    """
    Expand environment variable references in a string.
    
    Supports ${VAR_NAME} syntax.
    """
    if not isinstance(value, str):
        return value
    
    pattern = r'\$\{([^}]+)\}'
    
    def replace_env(match):
        var_name = match.group(1)
        env_value = os.environ.get(var_name)
        if env_value is None:
            raise ValueError(f"Environment variable '{var_name}' is not set")
        return env_value
    
    return re.sub(pattern, replace_env, value)


def expand_env_vars_recursive(obj):
    """Recursively expand environment variables in a data structure."""
    if isinstance(obj, dict):
        return {k: expand_env_vars_recursive(v) for k, v in obj.items()}
    elif isinstance(obj, list):
        return [expand_env_vars_recursive(item) for item in obj]
    elif isinstance(obj, str):
        return expand_env_vars(obj)
    return obj


def load_config(config_path: Optional[str] = None, **kwargs) -> Config:
    """
    Load configuration from file and/or arguments.
    
    Priority (highest to lowest):
    1. Explicit kwargs
    2. Config file
    3. Defaults
    
    Args:
        config_path: Path to YAML configuration file
        **kwargs: Override configuration values
        
    Returns:
        Config object
    """
    config_data = {}
    
    # Load from file if provided
    if config_path:
        path = Path(config_path)
        if not path.exists():
            raise FileNotFoundError(f"Configuration file not found: {config_path}")
        
        with open(path, "r") as f:
            config_data = yaml.safe_load(f) or {}
        
        # Expand environment variables
        config_data = expand_env_vars_recursive(config_data)
    
    # Override with kwargs
    for key, value in kwargs.items():
        if value is not None:
            if key in ("organization", "project", "pat"):
                config_data[key] = value
            elif key == "output_path":
                config_data.setdefault("output", {})["path"] = value
            elif key == "output_filename":
                config_data.setdefault("output", {})["filename"] = value
    
    # Validate required fields
    required_fields = ["organization", "project", "pat"]
    missing = [f for f in required_fields if not config_data.get(f)]
    if missing:
        raise ValueError(f"Missing required configuration: {', '.join(missing)}")
    
    return Config.from_dict(config_data)
