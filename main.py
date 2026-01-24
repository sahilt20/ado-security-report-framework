#!/usr/bin/env python3
"""
Azure DevOps Security Report Framework - CLI Entry Point.

Generates comprehensive security reports for Azure DevOps projects.

Usage:
    python main.py --org "myorg" --project "myproject" --pat $PAT
    python main.py --config config.yaml
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
)
from src.ado_security.reports import ExcelReportGenerator


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
        description="Generate Azure DevOps security reports",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Using command line arguments
  python main.py --org myorg --project myproject --pat $PAT

  # Using config file
  python main.py --config config.yaml

  # Specify output file
  python main.py --org myorg --project myproject --pat $PAT --output report.xlsx
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
        help="Output Excel file path",
        default=None,
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
        "--verbose", "-v",
        action="store_true",
        help="Enable verbose logging",
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
        
        logger.info(f"Starting security report for {config.organization}/{config.project}")
        
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
        if sections is None or "users" in sections:
            logger.info("Collecting users...")
            users_collector = UsersCollector(
                client,
                include_disabled=args.include_disabled or config.options.include_disabled_users,
            )
            users = users_collector.collect()
        
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
        
        # Generate output path
        output_path = args.output
        if not output_path:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = config.output.filename.format(timestamp=timestamp)
            output_path = str(Path(config.output.path) / filename)
        
        # Generate Excel report
        logger.info("Generating Excel report...")
        report_generator = ExcelReportGenerator(
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
        )
        
        output_file = report_generator.generate(output_path)
        
        logger.info("=" * 60)
        logger.info("Report generation complete!")
        logger.info(f"Output file: {output_file}")
        logger.info("=" * 60)
        
        # Print summary
        print(f"\n✅ Security report generated successfully!")
        print(f"📊 Report: {output_file}")
        print(f"\n📈 Summary:")
        print(f"   • Groups: {len(groups)}")
        print(f"   • Users: {len(users)}")
        print(f"   • Security Namespaces: {len(namespaces)}")
        
        if granular_permissions:
            total_perms = len(granular_permissions.all_permissions())
            print(f"   • Total Permissions: {total_perms}")
        
        return 0
        
    except ValueError as e:
        logger.error(f"Configuration error: {e}")
        print(f"\n❌ Error: {e}")
        return 1
        
    except Exception as e:
        logger.exception(f"Unexpected error: {e}")
        print(f"\n❌ Error: {e}")
        return 1


if __name__ == "__main__":
    sys.exit(main())
