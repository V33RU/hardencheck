"""Report generation modules."""

from hardencheck.reports.grading import classify_binary, calculate_grade
from hardencheck.reports.text_report import generate_text_summary
from hardencheck.reports.csv_report import generate_csv_summary
from hardencheck.reports.html_report import generate_html_report
from hardencheck.reports.json_report import generate_json_report
from hardencheck.reports.cyclonedx_sbom import generate_cyclonedx_sbom
from hardencheck.reports.spdx_sbom import generate_spdx_sbom

__all__ = [
    "classify_binary",
    "calculate_grade",
    "generate_text_summary",
    "generate_csv_summary",
    "generate_html_report",
    "generate_json_report",
    "generate_cyclonedx_sbom",
    "generate_spdx_sbom",
]
