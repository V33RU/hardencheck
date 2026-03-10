from pathlib import Path

from hardencheck.models import ScanResult
from hardencheck.reports.grading import classify_binary, calculate_grade


def generate_text_summary(result: ScanResult, output_path: Path):
    """Generate a plain-text summary of binary hardening results.

    This is intended for quick human/CI consumption without HTML/JSON.
    """
    lines = []
    grade, score = calculate_grade(result.binaries)

    header = (
        f"HardenCheck Summary\n"
        f"Target: {result.target}\n"
        f"Grade: {grade} ({score})\n"
        f"Total binaries: {len(result.binaries)}\n"
        f"Generated: {result.scan_time}\n"
        f"\n"
        f"{'TYPE':<12} {'CLASS':<10} {'ASLR':<12} {'NX':<3} {'CAN':<3} "
        f"{'PIE':<3} {'RELRO':<6} {'FORT':<4} {'STRIP':<5} PATH\n"
        f"{'-'*90}"
    )
    lines.append(header)

    for b in sorted(result.binaries, key=lambda x: x.path):
        classification = classify_binary(b)
        aslr_rating = b.aslr_analysis.rating.value if b.aslr_analysis else "N/A"

        def flag(v):
            if v is True:
                return "Y"
            if v is False:
                return "N"
            return "-"

        line = (
            f"{b.binary_type.value:<12} "
            f"{classification:<10} "
            f"{aslr_rating:<12} "
            f"{flag(b.nx):<3} "
            f"{flag(b.canary):<3} "
            f"{flag(b.pie):<3} "
            f"{(b.relro or '-'):6.6} "
            f"{flag(b.fortify):<4} "
            f"{flag(b.stripped):<5} "
            f"{b.path}"
        )
        lines.append(line)

    output_path.write_text("\n".join(lines), encoding="utf-8")
