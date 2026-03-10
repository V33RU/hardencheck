from typing import Dict, List

from hardencheck.models import BinaryAnalysis
from hardencheck.core.base import BaseAnalyzer


class ASLRSummaryGenerator(BaseAnalyzer):
    """Generate summary of ASLR analysis across all binaries."""

    def generate_aslr_summary(self, binaries: List[BinaryAnalysis]) -> Dict:
        """Generate summary of ASLR analysis across all binaries."""
        summary = {
            "total_pie_binaries": 0,
            "analyzed": 0,
            "by_rating": {
                "excellent": 0, "good": 0, "moderate": 0,
                "weak": 0, "ineffective": 0, "not_applicable": 0
            },
            "common_issues": {},
            "arch_distribution": {},
            "avg_effective_entropy": 0,
            "min_effective_entropy": float('inf'),
            "max_effective_entropy": 0,
            "recommendations": set()
        }

        entropy_values = []

        for binary in binaries:
            if binary.aslr_analysis:
                analysis = binary.aslr_analysis
                summary["analyzed"] += 1

                if analysis.is_pie:
                    summary["total_pie_binaries"] += 1

                rating_key = analysis.rating.name.lower()
                if rating_key in summary["by_rating"]:
                    summary["by_rating"][rating_key] += 1

                arch = analysis.arch
                summary["arch_distribution"][arch] = summary["arch_distribution"].get(arch, 0) + 1

                for issue in analysis.issues:
                    issue_key = issue.split(" - ")[0] if " - " in issue else issue[:50]
                    summary["common_issues"][issue_key] = summary["common_issues"].get(issue_key, 0) + 1

                if analysis.effective_entropy > 0:
                    entropy_values.append(analysis.effective_entropy)
                    summary["min_effective_entropy"] = min(summary["min_effective_entropy"], analysis.effective_entropy)
                    summary["max_effective_entropy"] = max(summary["max_effective_entropy"], analysis.effective_entropy)

                for rec in analysis.recommendations:
                    summary["recommendations"].add(rec)

        if entropy_values:
            summary["avg_effective_entropy"] = sum(entropy_values) / len(entropy_values)
        else:
            summary["min_effective_entropy"] = 0

        summary["recommendations"] = list(summary["recommendations"])
        summary["common_issues"] = dict(sorted(summary["common_issues"].items(), key=lambda x: -x[1])[:10])

        return summary
