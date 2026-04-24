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
from hardencheck.reports.sarif_report import generate_sarif_report
from hardencheck.reports.vex import generate_vex_report


def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description=f"HardenCheck v{VERSION} - Firmware Binary Security Analyzer with ASLR Entropy Analysis & SBOM",
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

    parser.add_argument("target", nargs="+",
                        help="Firmware directory to scan. Pass multiple paths to scan a multi-partition image "
                             "(e.g. boot + rootfs + data) in one run.")
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
    parser.add_argument("--sarif", action="store_true",
                        help="Also generate SARIF 2.1.0 report for GitHub code-scanning")
    parser.add_argument("--vex", action="store_true",
                        help="Also generate CycloneDX VEX 1.5 report (CVE triage state with reachability)")
    parser.add_argument("--yara-rules", metavar="DIR", default=None,
                        help="Directory of YARA rules (.yar/.yara) to run against firmware. Requires `yara` CLI.")
    parser.add_argument("--only", action="append", metavar="STEP", default=None,
                        help="Only run listed analyzer steps (repeatable). Steps: daemons, dependencies, "
                             "banned-functions, credentials, certificates, config, aslr, sbom, cve, crypto, "
                             "signing, service-privileges, kernel, update, security-tests, pqc, "
                             "reachability, taint, yara")
    parser.add_argument("--skip", action="append", metavar="STEP", default=None,
                        help="Skip listed analyzer steps (repeatable). See --only for valid step names.")
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

    target_paths = [Path(t) for t in args.target]
    for tp in target_paths:
        if not tp.exists():
            print(f"Error: Target directory not found: {tp}")
            sys.exit(1)
        if not tp.is_dir():
            print(f"Error: Target must be a directory: {tp}")
            sys.exit(1)
    target = target_paths[0]
    extra_roots = target_paths[1:]

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
            only_steps=args.only,
            skip_steps=args.skip,
            extra_roots=extra_roots,
            yara_rules_dir=Path(args.yara_rules) if args.yara_rules else None,
        )
        result = scanner.scan()

        output_path = Path(args.output)
        generate_html_report(result, output_path, slim=args.slim, extended=args.extended)
        print(f"[+] HTML Report: {output_path}")

        if args.json:
            json_path = output_path.with_suffix(".json")
            generate_json_report(result, json_path)
            print(f"[+] JSON Report: {json_path}")

        if args.sarif:
            sarif_path = output_path.with_suffix(".sarif")
            generate_sarif_report(result, sarif_path)
            print(f"[+] SARIF Report: {sarif_path}")

        if args.vex:
            vex_path = Path(f"{output_path.with_suffix('')}_vex.json")
            generate_vex_report(result, vex_path)
            print(f"[+] CycloneDX VEX 1.5: {vex_path}")

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
