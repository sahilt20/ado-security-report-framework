# Azure DevOps Security Report Framework

A production-ready Python framework for generating comprehensive security reports from Azure DevOps projects.

## Features

- **Comprehensive Security Analysis**: Groups, users, permissions, access levels
- **Permission Matrix**: Visual user-permission heatmap
- **Inheritance Tracking**: Distinguish inherited vs. directly applied permissions
- **Excel Reports**: Professional multi-sheet reports with conditional formatting
- **Project Admin Focused**: Designed for project-level security auditing

## Installation

```bash
pip install -r requirements.txt
```

## Quick Start

### Using CLI
```bash
# Using command line arguments
python main.py --org "your-org" --project "your-project" --pat "your-pat" --output report.xlsx

# Using config file
python main.py --config config.yaml

# Generate specific sections only
python main.py --org "your-org" --project "your-project" --pat "your-pat" \
    --sections groups,users,permissions
```

### Using Config File

Create a `config.yaml`:
```yaml
organization: "your-organization"
project: "your-project"
pat: "${ADO_PAT}"  # Environment variable reference

output:
  path: "./reports"
  filename: "security_report_{timestamp}.xlsx"

options:
  include_inherited: true
  include_disabled_users: false
```

## PAT Permissions Required

Your Personal Access Token needs the following scopes:
- `vso.graph` - Read graph information
- `vso.security_manage` - Read security information  
- `vso.project` - Read project information
- `vso.identity` - Read identity information

## Report Sheets

| Sheet | Description |
|-------|-------------|
| Summary | Report metadata and totals |
| Groups | Security groups with member counts |
| Group Members | Detailed group membership |
| Users | Users with access levels |
| Security Namespaces | Available permission namespaces |
| Permissions by Group | Group permission assignments |
| Permissions by User | User effective permissions |
| User Permission Matrix | User × Permission heatmap |
| Inheritance Analysis | Inherited vs direct permissions |
| Potential Issues | Security concerns and recommendations |

## License

MIT
