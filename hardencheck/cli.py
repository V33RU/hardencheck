import argparse
import os
import sys
from pathlib import Path

from hardencheck.constants.core import VERSION
from hardencheck.scanner import HardenCheck
from hardencheck.reports.html_report import generate_html_report
from hardencheck.reports.json_report import generate_json_report
from hardencheck.reports.text_report import generate_text_summary
from hardencheck.reports.csv_report import generate_csv_summary
from hardencheck.reports.cyclonedx_sbom import generate_cyclonedx_sbom
from hardencheck.reports.spdx_sbom import generate_spdx_sbom


def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description="HardenCheck v1.0 - Firmware Binary Security Analyzer with ASLR Entropy Analysis & SBOM",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s /path/to/firmware
  %(prog)s /path/to/firmware -o report.html --json
  %(prog)s /path/to/firmware -t 8 -v --slim
  %(prog)s /path/to/firmware --sbom cyclonedx       # CycloneDX 1.5 SBOM
  %(prog)s /path/to/firmware --sbom spdx             # SPDX 2.3 SBOM
  %(prog)s /path/to/firmware --sbom all --json       # Both SBOMs + JSON report

Required Tools:
  apt install radare2 devscripts pax-utils elfutils binutils

Scoring Model:
  NX=15, Canary=15, PIE=15, RELRO=15, Fortify=10,
  StackClash=10, CFI=10, Stripped=5, NoTEXTREL=5, NoRPATH=5
  Grade: A>=90, B>=80, C>=70, D>=60, F<60
        """
    )

    parser.add_argument("target", help="Firmware directory to scan")
    parser.add_argument("-o", "--output", default="hardencheck_report.html",
                        help="Output HTML report path (default: hardencheck_report.html)")
    parser.add_argument("-t", "--threads", type=int, default=4,
                        help="Number of analysis threads (default: 4)")
    parser.add_argument("-v", "--verbose", action="store_true",
                        help="Enable verbose output")
    parser.add_argument("--json", action="store_true",
                        help="Also generate JSON report")
    parser.add_argument("--slim", action="store_true",
                        help="Generate slim HTML report (no CSS, smaller size)")
    parser.add_argument("--extended", action="store_true",
                        help="Enable extended checks (Stack Clash, CFI) - requires hardening-check tool")
    parser.add_argument("--sbom", choices=["cyclonedx", "spdx", "all"], default=None,
                        help="Generate SBOM: cyclonedx (CycloneDX 1.5), spdx (SPDX 2.3), or all")
    parser.add_argument("--summary", choices=["text", "csv"], default=None,
                        help="Generate a plain-text or CSV summary of binary hardening results")
    parser.add_argument("--fail-on-grade", choices=["A", "B", "C", "D", "F"], metavar="GRADE", default=None,
                        help="Exit with code 1 if overall grade is below GRADE (e.g. --fail-on-grade B fails for C/D/F). For CI.")
    parser.add_argument("--include", action="append", metavar="GLOB", default=None,
                        help="Only scan paths matching GLOB (relative to target). Can be repeated. Example: --include 'bin/*' --include 'usr/sbin/*'")
    parser.add_argument("--exclude", action="append", metavar="GLOB", default=None,
                        help="Skip paths matching GLOB (relative to target). Can be repeated. Example: --exclude 'usr/lib/*'")
    parser.add_argument("-q", "--quiet", action="store_true",
                        help="Suppress banner and progress output; only print report paths (for CI/scripting)")
    parser.add_argument("--nvd-api-key", default="",
                        help="NVD API key for faster CVE lookups (50 req/30s vs 5 req/30s). Also reads NVD_API_KEY env var.")
    parser.add_argument("--skip-cve-lookup", action="store_true",
                        help="Skip live CVE correlation (use static checks only)")
    parser.add_argument("--no-cve-cache", action="store_true",
                        help="Disable CVE response caching")
    parser.add_argument("--cve-cache-dir", default=None,
                        help="Custom CVE cache directory (default: ~/.cache/hardencheck/cve_cache)")
    parser.add_argument("--version", action="version",
                        version=f"HardenCheck v{VERSION}")

    args = parser.parse_args()

    target = Path(args.target)
    if not target.exists():
        print(f"Error: Target directory not found: {target}")
        sys.exit(1)
    if not target.is_dir():
        print(f"Error: Target must be a directory: {target}")
        sys.exit(1)

    try:
        nvd_key = args.nvd_api_key or os.environ.get("NVD_API_KEY", "")
        scanner = HardenCheck(
            target,
            threads=args.threads,
            verbose=args.verbose,
            extended=args.extended,
            include_patterns=args.include,
            exclude_patterns=args.exclude,
            quiet=args.quiet,
            nvd_api_key=nvd_key,
            skip_cve_lookup=args.skip_cve_lookup,
            cve_cache_enabled=not args.no_cve_cache,
            cve_cache_dir=Path(args.cve_cache_dir) if args.cve_cache_dir else None,
        )
        result = scanner.scan()

        output_path = Path(args.output)
        generate_html_report(result, output_path, slim=args.slim, extended=args.extended)
        print(f"[+] HTML Report: {output_path}")

        if args.json:
            json_path = output_path.with_suffix(".json")
            generate_json_report(result, json_path)
            print(f"[+] JSON Report: {json_path}")

        # Summary outputs for CI / quick inspection
        if args.summary:
            base = output_path.with_suffix("")
            if args.summary == "text":
                summary_path = Path(f"{base}_summary.txt")
                generate_text_summary(result, summary_path)
                print(f"[+] Text summary: {summary_path}")
            elif args.summary == "csv":
                summary_path = Path(f"{base}_summary.csv")
                generate_csv_summary(result, summary_path)
                print(f"[+] CSV summary: {summary_path}")

        # SBOM generation
        if args.sbom and result.sbom:
            sbom_base = output_path.with_suffix("")

            if args.sbom in ("cyclonedx", "all"):
                cdx_path = Path(f"{sbom_base}_sbom_cyclonedx.json")
                generate_cyclonedx_sbom(result.sbom, cdx_path)
                print(f"[+] CycloneDX 1.5 SBOM: {cdx_path}")

            if args.sbom in ("spdx", "all"):
                spdx_path = Path(f"{sbom_base}_sbom_spdx.json")
                generate_spdx_sbom(result.sbom, spdx_path)
                print(f"[+] SPDX 2.3 SBOM: {spdx_path}")

    except KeyboardInterrupt:
        print("\n[!] Scan interrupted by user")
        sys.exit(130)
    except Exception as e:
        print(f"\n[!] Error: {e}")
        if args.verbose:
            import traceback
            traceback.print_exc()
        sys.exit(1)
