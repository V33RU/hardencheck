import csv
from pathlib import Path

from hardencheck.models import ScanResult
from hardencheck.reports.grading import classify_binary


def generate_csv_summary(result: ScanResult, output_path: Path):
    """Generate a CSV summary of binary hardening results for CI tooling."""
    with output_path.open("w", encoding="utf-8", newline="") as f:
        writer = csv.writer(f)
        writer.writerow([
            "path",
            "filename",
            "type",
            "classification",
            "aslr_rating",
            "nx",
            "canary",
            "pie",
            "relro",
            "fortify",
            "stripped",
            "stack_clash",
            "cfi",
            "textrel",
            "rpath",
            "confidence",
        ])

        for b in sorted(result.binaries, key=lambda x: x.path):
            classification = classify_binary(b)
            aslr_rating = b.aslr_analysis.rating.value if b.aslr_analysis else "N/A"
            writer.writerow([
                str(b.path),
                b.filename,
                b.binary_type.value,
                classification,
                aslr_rating,
                b.nx,
                b.canary,
                b.pie,
                b.relro,
                b.fortify,
                b.stripped,
                b.stack_clash,
                b.cfi,
                b.textrel,
                b.rpath,
                b.confidence,
            ])
