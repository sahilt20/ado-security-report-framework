"""Reports package for Azure DevOps Data Governance Framework."""

from .excel_report import ExcelReportGenerator
from .html_report import HTMLReportGenerator

__all__ = [
    "ExcelReportGenerator",
    "HTMLReportGenerator",
]
