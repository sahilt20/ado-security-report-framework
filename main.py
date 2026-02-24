#!/usr/bin/env python3
"""
Azure DevOps Project-Level Data Governance Report Framework - CLI Entry Point.

Generates comprehensive data governance reports scoped to a single
Azure DevOps project. Requires Project Administrator access only
(does NOT require organization-level admin).

Usage:
    python main.py --org "myorg" --project "myproject" --pat $PAT
    python main.py --config config.yaml
    python main.py --org "myorg" --project "myproject" --pat $PAT --format html
"""

import argparse
import logging
import sys
from datetime import datetime
from pathlib import Path

from src.ado_security.config import load_config
from src.ado_security.client import AzureDevOpsClient
from src.ado_security.collectors import (
    GroupsCollector,
    UsersCollector,
    PermissionsCollector,
    NamespacesCollector,
)
from src.ado_security.analyzers import (
    InheritanceAnalyzer,
    PermissionMatrixBuilder,
    GovernanceAnalyzer,
)
from src.ado_security.reports import ExcelReportGenerator, HTMLReportGenerator
from src.ado_security.reports import ExecutiveSummaryGenerator


# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    handlers=[
        logging.StreamHandler(sys.stdout),
    ],
)
logger = logging.getLogger(__name__)


def parse_arguments():
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(
        description="Generate Azure DevOps project-level Data Governance reports (Project Admin scope)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Excel report (default)
  python main.py --org myorg --project myproject --pat $PAT

  # HTML dashboard
  python main.py --org myorg --project myproject --pat $PAT --format html

  # Both formats
  python main.py --org myorg --project myproject --pat $PAT --format both

  # Using config file
  python main.py --config config.yaml
        """,
    )

    parser.add_argument(
        "--config", "-c",
        help="Path to YAML configuration file",
    )

    parser.add_argument(
        "--org", "--organization",
        dest="organization",
        help="Azure DevOps organization name",
    )

    parser.add_argument(
        "--project", "-p",
        help="Azure DevOps project name",
    )

    parser.add_argument(
        "--pat",
        help="Personal Access Token",
    )

    parser.add_argument(
        "--output", "-o",
        help="Output file path (without extension)",
        default=None,
    )

    parser.add_argument(
        "--format", "-f",
        choices=["excel", "html", "both"],
        default="both",
        help="Output format: excel, html, or both (default: both)",
    )

    parser.add_argument(
        "--sections",
        help="Comma-separated list of sections to include (groups,users,permissions)",
        default="all",
    )

    parser.add_argument(
        "--include-disabled",
        action="store_true",
        help="Include disabled/inactive users in report",
    )

    parser.add_argument(
        "--allow-org-fallback",
        action="store_true",
        help="Allow org-level user entitlement fallback (disabled by default to keep project-level scope)",
    )

    parser.add_argument(
        "--verbose", "-v",
        action="store_true",
        help="Enable verbose logging",
    )

    parser.add_argument(
        "--executive-summary-format",
        choices=["html", "csv", "both", "none"],
        default="both",
        help="Generate one-page executive summary format(s): html, csv, both, or none (default: both)",
    )

    return parser.parse_args()


def main():
    """Main entry point."""
    args = parse_arguments()

    # Set logging level
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    try:
        # Load configuration
        config = load_config(
            config_path=args.config,
            organization=args.organization,
            project=args.project,
            pat=args.pat,
        )

        logger.info(f"Starting project-level data governance report for {config.organization}/{config.project}")
        logger.info("Scope: Project Administrator (no org-level access required)")

        # Create API client
        client = AzureDevOpsClient(config)

        # Validate connection
        logger.info("Validating connection...")
        client.validate_connection()

        # Determine sections to collect
        sections = args.sections.lower().split(",") if args.sections != "all" else None

        # Collect security namespaces
        logger.info("Collecting security namespaces...")
        namespaces_collector = NamespacesCollector(client)
        namespaces = namespaces_collector.collect()
        service_namespaces = namespaces_collector.collect_by_service()

        # Collect groups
        groups = []
        if sections is None or "groups" in sections:
            logger.info("Collecting security groups...")
            groups_collector = GroupsCollector(client)
            groups = groups_collector.collect(include_members=True)

        # Collect users
        users = []
        users_collection_mode = "not_collected"
        project_scope_only = True
        if sections is None or "users" in sections:
            logger.info("Collecting users...")
            users_collector = UsersCollector(
                client,
                include_disabled=args.include_disabled or config.options.include_disabled_users,
                allow_org_fallback=args.allow_org_fallback or config.options.allow_org_fallback,
            )
            users = users_collector.collect()
            users_collection_mode = users_collector.collection_mode
            project_scope_only = not users_collector.used_org_fallback
            logger.info(f"User collection mode: {users_collection_mode}")

        # Collect permissions
        granular_permissions = None
        if sections is None or "permissions" in sections:
            logger.info("Collecting permissions...")
            permissions_collector = PermissionsCollector(client, namespaces_collector)
            granular_permissions = permissions_collector.collect_by_service(
                namespaces=config.options.namespaces if config.options.namespaces else None
            )

        # Build permission matrices
        permission_report = None
        inheritance_analyzer = None

        if granular_permissions and groups and users:
            logger.info("Building permission matrices...")
            matrix_builder = PermissionMatrixBuilder(groups, users, granular_permissions)
            permission_report = matrix_builder.build_full_report()

            logger.info("Analyzing permission inheritance...")
            inheritance_analyzer = InheritanceAnalyzer(groups, users, granular_permissions)

        # Run governance analysis
        governance_thresholds = config.options.governance_thresholds or {}
        if granular_permissions and groups and users:
            logger.info("Running governance analysis...")
            gov_analyzer = GovernanceAnalyzer(
                groups=groups,
                users=users,
                granular_permissions=granular_permissions,
                organization=config.organization,
                project=config.project,
                collection_mode=users_collection_mode,
                project_scope_only=project_scope_only,
                measure_thresholds=governance_thresholds,
            )
            gov_report = gov_analyzer.analyze()
            logger.info(f"Governance Score: {gov_report.score.overall_score}/100 (Grade: {gov_report.score.grade})")
            logger.info(f"Findings: {len(gov_report.findings)} total, "
                        f"{len(gov_report.critical_findings)} critical, "
                        f"{len(gov_report.high_findings)} high")

        # Generate output path
        output_base = args.output
        if not output_base:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = config.output.filename.format(timestamp=timestamp)
            # Strip extension for base path
            filename_base = filename.rsplit(".", 1)[0] if "." in filename else filename
            output_base = str(Path(config.output.path) / filename_base)

        output_format = args.format
        generated_files = []

        # Generate one-page executive summary
        if (
            args.executive_summary_format != "none"
            and granular_permissions and groups and users
        ):
            logger.info("Generating one-page executive summary...")
            summary_gen = ExecutiveSummaryGenerator(
                organization=config.organization,
                project=config.project,
                governance_report=gov_report,
            )
            generated_files.extend(
                summary_gen.generate(output_base, fmt=args.executive_summary_format)
            )

        # Generate Excel report
        if output_format in ("excel", "both"):
            excel_path = f"{output_base}.xlsx"
            logger.info("Generating Excel governance report...")
            excel_gen = ExcelReportGenerator(
                organization=config.organization,
                project=config.project,
                groups=groups,
                users=users,
                namespaces=service_namespaces,
                permissions=granular_permissions or __import__(
                    "src.ado_security.collectors.permissions",
                    fromlist=["GranularPermissions"]
                ).GranularPermissions(),
                permission_report=permission_report,
                inheritance_analyzer=inheritance_analyzer,
                collection_mode=users_collection_mode,
                project_scope_only=project_scope_only,
                measure_thresholds=governance_thresholds,
            )
            excel_gen.generate(excel_path)
            generated_files.append(("Excel", excel_path))

        # Generate HTML report
        if output_format in ("html", "both"):
            html_path = f"{output_base}.html"
            logger.info("Generating HTML governance dashboard...")
            html_gen = HTMLReportGenerator(
                organization=config.organization,
                project=config.project,
                groups=groups,
                users=users,
                permissions=granular_permissions or __import__(
                    "src.ado_security.collectors.permissions",
                    fromlist=["GranularPermissions"]
                ).GranularPermissions(),
                permission_report=permission_report,
                inheritance_analyzer=inheritance_analyzer,
                collection_mode=users_collection_mode,
                project_scope_only=project_scope_only,
                measure_thresholds=governance_thresholds,
            )
            html_gen.generate(html_path)
            generated_files.append(("HTML", html_path))

        # Print summary
        logger.info("=" * 60)
        logger.info("Report generation complete!")
        for fmt, path in generated_files:
            logger.info(f"{fmt} Report: {path}")
        logger.info("=" * 60)

        print(f"\nProject-Level Data Governance Report Generated Successfully!")
        print(f"Organization: {config.organization} | Project: {config.project} | Scope: Project Admin")
        print(f"\nGenerated Reports:")
        for fmt, path in generated_files:
            print(f"  {fmt}: {path}")
        print(f"\nSummary:")
        print(f"  Groups: {len(groups)}")
        print(f"  Users: {len(users)}")
        print(f"  Security Namespaces: {len(namespaces)}")
        if granular_permissions:
            total_perms = len(granular_permissions.all_permissions())
            print(f"  Total Permissions: {total_perms}")
        if granular_permissions and groups and users:
            print(f"  Governance Score: {gov_report.score.overall_score}/100 (Grade: {gov_report.score.grade})")
            print(f"  Findings: {len(gov_report.findings)} total")

        return 0

    except ValueError as e:
        logger.error(f"Configuration error: {e}")
        print(f"\nError: {e}")
        return 1

    except Exception as e:
        logger.exception(f"Unexpected error: {e}")
        print(f"\nError: {e}")
        return 1


if __name__ == "__main__":
    sys.exit(main())
