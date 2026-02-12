# Azure DevOps Project-Level Data Governance Report Framework

A production-ready Python framework for generating comprehensive **data governance reports** scoped to a single Azure DevOps project. Requires only **Project Administrator** access (no organization-level admin needed).

Provides risk scoring, compliance controls, visual charts, permission heatmaps, and actionable recommendations.

## Access Scope

This framework is designed for **Project-level Administrators**:
- Collects users via project Teams API (not org-wide entitlements)
- Collects groups via project-scoped Graph API (not org-wide groups)
- Collects permissions via project-scoped ACL tokens
- Does NOT require `vso.entitlements` (org-level) scope
- PAT only needs project-level read permissions

## Features

- **Data Governance Analysis**: Risk scoring, compliance controls, policy violation detection
- **Governance Scoring**: Overall score (A-F grade) across 5 governance dimensions
- **Compliance Controls**: 10 automated compliance checks with Pass/Warning/Fail status
- **Risk Findings**: Categorized findings with Critical/High/Medium/Low severity
- **Permission Matrix**: Visual user-permission heatmap with conditional formatting
- **Inheritance Tracking**: Direct vs inherited permissions with conflict detection
- **Branch Policy Checks**: Detects policy bypass permissions on non-admin groups
- **Pipeline Security**: Flags destructive pipeline permissions
- **License Optimization**: Identifies wasted premium licenses on inactive users
- **Visual Charts**: Bar, pie, radar, and stacked charts in Excel; interactive Chart.js in HTML
- **Dual Output**: Professional Excel workbook (12+ sheets) AND interactive HTML dashboard
- **Separation of Duties**: Detects combined admin roles and overprivileged accounts
- **Lifecycle Management**: Stale account detection, inactive user flagging

## Installation

```bash
pip install -r requirements.txt
```

## Quick Start

### Generate Sample Report (No Azure DevOps Access Needed)

```bash
python generate_sample_report.py
```

This generates both Excel and HTML reports in `reports/` with dummy data demonstrating all features.

### Using CLI with Azure DevOps

```bash
# Both Excel + HTML (default)
python main.py --org "your-org" --project "your-project" --pat "your-pat"

# Excel only
python main.py --org "your-org" --project "your-project" --pat "your-pat" --format excel

# HTML dashboard only
python main.py --org "your-org" --project "your-project" --pat "your-pat" --format html

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
  filename: "governance_report_{timestamp}.xlsx"

options:
  include_inherited: true
  include_disabled_users: false
```

## PAT Permissions Required

Your Personal Access Token needs the following **project-level** scopes:
- `vso.graph` - Read graph information (project-scoped groups and users)
- `vso.security_manage` - Read security information (project ACLs)
- `vso.project` - Read project information (teams, members)
- `vso.identity` - Read identity information (resolve descriptors)

**Note**: Organization-level scopes like `vso.entitlements` are NOT required.
The framework automatically uses project-scoped APIs accessible to Project Administrators.

## Governance Dimensions

| Dimension | What It Measures |
|-----------|-----------------|
| Access Control | Admin count, external users, empty groups |
| Least Privilege | Overprivileged users, high-risk permissions on custom groups |
| Separation of Duties | Combined Build+Release admin, admin with multiple roles |
| Audit & Compliance | Finding density, critical/high risk findings |
| Lifecycle Management | Stale accounts, inactive users with permissions |

## Compliance Controls

| ID | Control | Description |
|----|---------|-------------|
| GOV-001 | Administrative Access Control | Admin access limited to 2-3 users |
| GOV-002 | Least Privilege Enforcement | No excessive high-risk permissions |
| GOV-003 | Stale Account Management | Inactive accounts removed promptly |
| GOV-004 | External User Access Control | External users have minimal access |
| GOV-005 | Security Group Hygiene | Groups have members and clear purpose |
| GOV-006 | Separation of Duties | Critical roles separated across users |
| GOV-007 | High-Risk Permission Control | High-risk permissions tightly controlled |
| GOV-008 | Branch Policy Enforcement | Branch policy bypasses limited to admins |
| GOV-009 | Pipeline Security Controls | Destructive pipeline permissions controlled |
| GOV-010 | License Optimization | No wasted premium licenses on inactive users |

## Excel Report Sheets

| Sheet | Description |
|-------|-------------|
| Executive Summary | Governance dashboard with grade, scores, key metrics, and charts |
| Governance Score | Score breakdown with radar chart and bar chart |
| Compliance Controls | Control assessment results with status distribution chart |
| Risk Findings | All findings sorted by severity with category chart |
| Groups Overview | Security groups with type distribution and members chart |
| Group Members | Detailed group membership listing |
| Users Overview | Users with access levels, activity status, and distribution charts |
| Security Namespaces | Namespace inventory by service area |
| Perms - \<Service\> | Per-service permission details with state coloring |
| Permission Matrix | User x Permission heatmap with stacked bar chart |
| Inheritance Analysis | Direct vs inherited permissions with conflict detection |
| Recommendations | Prioritized action items by impact |

## HTML Dashboard

The HTML report provides an interactive dashboard with:
- **Navigation tabs**: Dashboard, Scores, Controls, Findings, Users, Groups, Permissions
- **Chart.js visualizations**: Doughnut, bar, radar, and horizontal bar charts
- **Responsive design**: Works on desktop and mobile
- **Sortable tables**: All data tables with hover highlighting
- **No server required**: Opens directly in any browser

## Architecture

```
src/ado_security/
  analyzers/
    governance.py    # Risk scoring, compliance, policy checks
    matrix.py        # Permission matrix builder
    inheritance.py   # Inheritance analyzer
  collectors/
    namespaces.py    # Security namespaces
    groups.py        # Groups and membership
    users.py         # User entitlements
    permissions.py   # ACLs and permissions
  reports/
    excel_report.py  # Excel report with charts
    html_report.py   # HTML interactive dashboard
  client.py          # Azure DevOps API client
  config.py          # Configuration management
  models.py          # Data models
```

## License

MIT
