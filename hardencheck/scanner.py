from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from pathlib import Path
from typing import List, Optional

from hardencheck.models import (
    ScanResult, CVECorrelationSummary,
    FirmwareSigningInfo, KernelHardeningInfo, UpdateMechanismInfo,
)
from hardencheck.constants.core import BANNER
from hardencheck.core.context import ScanContext
from hardencheck.analyzers.file_discovery import FileDiscovery
from hardencheck.analyzers.firmware_profile import FirmwareProfiler
from hardencheck.analyzers.binary_analysis import BinaryAnalyzer
from hardencheck.analyzers.daemon_detection import DaemonDetector
from hardencheck.analyzers.banned_functions import BannedFunctionScanner
from hardencheck.analyzers.credential_scanner import CredentialScanner
from hardencheck.analyzers.certificate_scanner import CertificateScanner
from hardencheck.analyzers.config_scanner import ConfigScanner
from hardencheck.analyzers.security_testing import SecurityTester
from hardencheck.analyzers.crypto_binary import CryptoBinaryDetector
from hardencheck.analyzers.firmware_signing import FirmwareSigningAnalyzer
from hardencheck.analyzers.service_privileges import ServicePrivilegeAnalyzer
from hardencheck.analyzers.kernel_hardening import KernelHardeningAnalyzer
from hardencheck.analyzers.update_mechanism import UpdateMechanismAnalyzer
from hardencheck.analyzers.aslr_summary import ASLRSummaryGenerator
from hardencheck.analyzers.sbom_generator import SBOMGenerator
from hardencheck.analyzers.pqc_readiness import PQCReadinessAnalyzer
from hardencheck.analyzers.cve_correlator import CVECorrelator
from hardencheck.reports.grading import classify_binary, calculate_grade


class HardenCheck:
    """Firmware security analyzer."""

    # Optional analyzer steps that can be toggled via --only / --skip.
    # "binaries" is always required (downstream steps depend on it).
    OPTIONAL_STEPS = {
        "daemons", "dependencies", "banned-functions", "credentials",
        "certificates", "config", "aslr", "sbom", "cve", "crypto",
        "signing", "service-privileges", "kernel", "update",
        "security-tests", "pqc",
    }

    def __init__(self, target: Path, threads: int = 4, verbose: bool = False, extended: bool = False,
                 include_patterns: Optional[List[str]] = None, exclude_patterns: Optional[List[str]] = None,
                 quiet: bool = False, nvd_api_key: str = "", skip_cve_lookup: bool = False,
                 cve_cache_enabled: bool = True, cve_cache_dir: Optional[Path] = None,
                 only_steps: Optional[List[str]] = None, skip_steps: Optional[List[str]] = None):
        """Initialize scanner.

        Args:
            target: Path to firmware directory
            threads: Number of analysis threads
            verbose: Enable verbose output
            extended: Enable extended checks (Stack Clash, CFI)
            include_patterns: If set, only scan paths matching any of these globs (relative to target)
            exclude_patterns: If set, skip paths matching any of these globs (relative to target)
            quiet: If True, suppress banner and progress output (for CI/scripting)
            nvd_api_key: NVD API key for faster rate limits
            skip_cve_lookup: Skip live CVE correlation
            cve_cache_enabled: Enable CVE response caching
            cve_cache_dir: Custom CVE cache directory
        """
        self.ctx = ScanContext(
            target=target,
            threads=threads,
            verbose=verbose,
            extended=extended,
            include_patterns=include_patterns,
            exclude_patterns=exclude_patterns,
            quiet=quiet,
        )
        self.quiet = self.ctx.quiet
        self.skip_cve_lookup = skip_cve_lookup

        only_set = {s.strip().lower() for s in (only_steps or []) if s.strip()}
        skip_set = {s.strip().lower() for s in (skip_steps or []) if s.strip()}
        if only_set:
            self.enabled_steps = only_set & self.OPTIONAL_STEPS
        else:
            self.enabled_steps = self.OPTIONAL_STEPS - skip_set

        # Instantiate analyzers
        self.file_discovery = FileDiscovery(self.ctx)
        self.firmware_profiler = FirmwareProfiler(self.ctx)
        self.binary_analyzer = BinaryAnalyzer(self.ctx)
        self.daemon_detector = DaemonDetector(self.ctx)
        self.banned_scanner = BannedFunctionScanner(self.ctx)
        self.credential_scanner = CredentialScanner(self.ctx)
        self.certificate_scanner = CertificateScanner(self.ctx)
        self.config_scanner = ConfigScanner(self.ctx)
        self.security_tester = SecurityTester(self.ctx)
        self.crypto_detector = CryptoBinaryDetector(self.ctx)
        self.firmware_signing_analyzer = FirmwareSigningAnalyzer(self.ctx)
        self.service_privilege_analyzer = ServicePrivilegeAnalyzer(self.ctx)
        self.kernel_hardening_analyzer = KernelHardeningAnalyzer(self.ctx)
        self.update_mechanism_analyzer = UpdateMechanismAnalyzer(self.ctx)
        self.aslr_summary_generator = ASLRSummaryGenerator(self.ctx)
        self.sbom_generator = SBOMGenerator(self.ctx)
        self.pqc_analyzer = PQCReadinessAnalyzer(self.ctx)
        self.cve_correlator = CVECorrelator(
            self.ctx,
            nvd_api_key=nvd_api_key,
            cache_enabled=cve_cache_enabled,
            cache_dir=cve_cache_dir,
        )

    @property
    def target(self):
        return self.ctx.target

    @property
    def tools(self):
        return self.ctx.tools

    @property
    def threads(self):
        return self.ctx.threads

    def _enabled(self, step: str) -> bool:
        return step in self.enabled_steps

    def scan(self) -> ScanResult:
        """Execute complete security scan."""
        start_time = datetime.now()

        if not self.quiet:
            print(BANNER)
            print(f"  Target:  {self.target}")
            print(f"  Started: {start_time.strftime('%Y-%m-%d %H:%M:%S')}")
            print("=" * 55)
            print()

            print("[*] Tools detected:")
            for name, cmd in self.tools.items():
                print(f"    + {name}: {cmd}")
            missing = {"rabin2", "hardening-check", "scanelf", "readelf", "file", "strings"} - set(self.tools.keys())
            if missing:
                print(f"    - Missing: {', '.join(missing)}")
            print()

            print("[1/18] Discovering files...")
        binaries_raw, sources, configs = self.file_discovery.find_files()
        if not self.quiet:
            print(f"      ELF binaries: {len(binaries_raw)}")
            print(f"      Source files: {len(sources)}")
            print(f"      Config files: {len(configs)}")
            print()

        if not self.quiet:
            print("[2/18] Analyzing firmware profile...")
        profile = self.firmware_profiler.detect_firmware_profile(binaries_raw)
        if not self.quiet:
            print(f"      Type: {profile.fw_type}")
            arch_str = profile.arch
            if profile.bits != "Unknown":
                arch_str += f" {profile.bits}-bit"
            if profile.endian != "Unknown":
                arch_str += f" {profile.endian}"
            print(f"      Arch: {arch_str}")
            print(f"      Libc: {profile.libc}")
            if profile.kernel != "Unknown":
                print(f"      Kernel: {profile.kernel}")
            if profile.filesystem != "Unknown":
                print(f"      Filesystem: {profile.filesystem}")
            if profile.compression != "Unknown":
                print(f"      Compression: {profile.compression}")
            if profile.bootloader != "Unknown":
                print(f"      Bootloader: {profile.bootloader}")
            if profile.init_system != "Unknown":
                print(f"      Init System: {profile.init_system}")
            if profile.package_manager not in ("Unknown", "None (static firmware)"):
                print(f"      Package Mgr: {profile.package_manager}")
            if profile.ssl_library != "Unknown":
                print(f"      SSL/TLS: {profile.ssl_library}")
            if profile.web_server != "None":
                print(f"      Web Server: {profile.web_server}")
            if profile.ssh_server != "None":
                print(f"      SSH Server: {profile.ssh_server}")
            print(f"      Total Size: {profile.total_size_mb} MB | Files: {profile.total_files} | Symlinks: {profile.symlinks}")
            if profile.busybox_applets > 0:
                print(f"      BusyBox: {profile.busybox_applets} applets")
            if profile.kernel_modules > 0:
                print(f"      Kernel Modules: {profile.kernel_modules}")
            if profile.setuid_files:
                print(f"      Setuid: {len(profile.setuid_files)} files")
            if profile.setgid_files:
                print(f"      Setgid: {len(profile.setgid_files)} files")
            print()

        if not self.quiet:
            print("[3/18] Analyzing binary hardening + ASLR entropy...")
        analyzed_binaries = []

        BATCH_SIZE = 50
        total_binaries = len(binaries_raw)

        for batch_start in range(0, total_binaries, BATCH_SIZE):
            batch_end = min(batch_start + BATCH_SIZE, total_binaries)
            batch = binaries_raw[batch_start:batch_end]

            with ThreadPoolExecutor(max_workers=self.threads) as executor:
                futures = {
                    executor.submit(self.binary_analyzer.analyze_binary, path, btype): path
                    for path, btype in batch
                }
                for future in as_completed(futures):
                    try:
                        result = future.result()
                        analyzed_binaries.append(result)
                    except Exception as e:
                        if self.ctx.verbose:
                            print(f"      Analysis error: {e}")

            if total_binaries > 100 and not self.quiet:
                print(f"      Progress: {len(analyzed_binaries)}/{total_binaries}")

        secured = sum(1 for b in analyzed_binaries if classify_binary(b) == "SECURED")
        partial = sum(1 for b in analyzed_binaries if classify_binary(b) == "PARTIAL")
        insecure = sum(1 for b in analyzed_binaries if classify_binary(b) == "INSECURE")
        if not self.quiet:
            print(f"      Analyzed: {len(analyzed_binaries)}")
            print(f"      Secured: {secured}, Partial: {partial}, Insecure: {insecure}")
            aslr_count = sum(1 for b in analyzed_binaries if b.aslr_analysis and b.aslr_analysis.is_pie)
            print(f"      PIE binaries with ASLR analysis: {aslr_count}")
            print()

            print("[4/18] Detecting network services/daemons...")
        daemons = self.daemon_detector.detect_daemons(analyzed_binaries) if self._enabled("daemons") else []
        if not self.quiet:
            if not self._enabled("daemons"):
                print("      Skipped (--skip daemons)")
            elif daemons:
                for daemon in daemons[:5]:
                    ver_str = f" v{daemon.version}" if daemon.version != "Unknown" else ""
                    print(f"      [{daemon.risk}] {daemon.name} ({daemon.binary}{ver_str})")
                if len(daemons) > 5:
                    print(f"      ... and {len(daemons) - 5} more")
            else:
                print("      No daemons detected")
            print()

            print("[5/18] Analyzing dependency chain...")
        dep_risks = self.binary_analyzer.analyze_dependencies(analyzed_binaries) if self._enabled("dependencies") else []
        if not self.quiet:
            if dep_risks:
                for risk in dep_risks[:3]:
                    print(f"      {risk.library}: {risk.issue}")
                if len(dep_risks) > 3:
                    print(f"      ... and {len(dep_risks) - 3} more")
            else:
                print("      No insecure dependencies")
            print()

            print("[6/18] Scanning for banned functions...")
        if self._enabled("banned-functions"):
            banned_binary = self.banned_scanner.scan_banned_functions_binary(analyzed_binaries)
            banned_source = self.banned_scanner.scan_banned_functions_source(sources)
        else:
            banned_binary, banned_source = [], []
        banned_all = banned_binary + banned_source
        if not self.quiet:
            print(f"      Found: {len(banned_all)} ({len(banned_binary)} binary, {len(banned_source)} source)")
            print()

            print("[7/18] Scanning for credentials and certificates...")
        credentials = self.credential_scanner.scan_credentials(configs, sources) if self._enabled("credentials") else []
        certificates = self.certificate_scanner.scan_certificates() if self._enabled("certificates") else []
        if not self.quiet:
            print(f"      Credentials: {len(credentials)} findings")
            print(f"      Certificates: {len(certificates)} files")
            print()

            print("[8/18] Scanning configuration files...")
        config_issues = self.config_scanner.scan_configurations(configs) if self._enabled("config") else []
        if not self.quiet:
            print(f"      Config issues: {len(config_issues)}")
            print()

            print("[9/18] Generating ASLR entropy summary...")
        aslr_summary = self.aslr_summary_generator.generate_aslr_summary(analyzed_binaries) if self._enabled("aslr") else {"analyzed": 0, "avg_effective_entropy": 0.0, "by_rating": {"excellent": 0, "good": 0, "weak": 0, "ineffective": 0}}
        if not self.quiet:
            if aslr_summary["analyzed"] > 0:
                print(f"      Average effective entropy: {aslr_summary['avg_effective_entropy']:.1f} bits")
                print(f"      Ratings: Excellent={aslr_summary['by_rating']['excellent']}, "
                      f"Good={aslr_summary['by_rating']['good']}, "
                      f"Weak={aslr_summary['by_rating']['weak']}, "
                      f"Ineffective={aslr_summary['by_rating']['ineffective']}")
            print()

            print("[10/18] Generating SBOM (Software Bill of Materials)...")
        sbom = self.sbom_generator.generate_sbom(analyzed_binaries, profile) if self._enabled("sbom") else None
        if not self.quiet and sbom is None:
            print("      Skipped (--skip sbom)")
        if not self.quiet and sbom is not None:
            print(f"      Components: {sbom.total_components} ({sbom.total_applications} apps, {sbom.total_libraries} libs)")
            print(f"      With version: {sbom.components_with_version}/{sbom.total_components}")
            print(f"      With CPE:     {sbom.components_with_cpe}/{sbom.total_components}")
            print(f"      Dependency links: {len(sbom.dependency_tree)}")
            if sbom.package_manager_source:
                print(f"      Package source: {sbom.package_manager_source}")
            print()

            print("[11/18] Correlating SBOM with live CVE databases...")
        cve_correlation_summary = CVECorrelationSummary(enabled=False)
        live_cve_findings = []
        if not self.skip_cve_lookup and sbom and self._enabled("cve"):
            live_cve_findings = self.cve_correlator.correlate_cves(sbom)
            stats = self.cve_correlator.get_stats()
            cve_correlation_summary = CVECorrelationSummary(
                enabled=True,
                components_queried=stats["components_queried"],
                unique_cpes_queried=stats["unique_cpes_queried"],
                cache_hits=stats["cache_hits"],
                api_calls=stats["api_calls"],
                api_errors=stats["api_errors"],
                cves_found=stats["cves_found"],
                api_available=stats["api_available"],
                duration_seconds=stats["duration_seconds"],
                data_sources=stats["data_sources"],
            )
            if not self.quiet:
                print(f"      CVEs found: {len(live_cve_findings)}")
                print(f"      API calls: {stats['api_calls']} (cache hits: {stats['cache_hits']})")
                if not stats["api_available"]:
                    print("      WARNING: API unreachable, using static checks only")
        else:
            if not self.quiet:
                print("      Skipped (--skip-cve-lookup or no SBOM)")
        if not self.quiet:
            print()

            print("[12/18] Detecting cryptographic binaries...")
        crypto_binaries = self.crypto_detector.detect_cryptographic_binaries(analyzed_binaries) if self._enabled("crypto") else []
        if not self.quiet:
            if crypto_binaries:
                print(f"      Found: {len(crypto_binaries)} cryptographic utilities")
                for cb in crypto_binaries[:5]:
                    risk_icon = "🔴" if cb.risk_level == "HIGH" else "🟡" if cb.risk_level == "MEDIUM" else "🟢"
                    print(f"        {risk_icon} [{cb.risk_level}] {cb.name} ({cb.purpose})")
                if len(crypto_binaries) > 5:
                    print(f"        ... and {len(crypto_binaries) - 5} more")
            else:
                print("      No cryptographic binaries detected")
            print()

            print("[13/18] Analyzing firmware signing & secure boot...")
        firmware_signing = self.firmware_signing_analyzer.detect_firmware_signing() if self._enabled("signing") else FirmwareSigningInfo()
        if not self.quiet:
            if firmware_signing.is_signed:
                print(f"      Signed: Yes ({firmware_signing.signing_method})")
                print(f"      Secure Boot: {'Enabled' if firmware_signing.secure_boot_enabled else 'Disabled'}")
                if firmware_signing.signature_files:
                    print(f"      Signature files: {len(firmware_signing.signature_files)}")
            else:
                print("      Signed: No")
                print("      ⚠️  Firmware is not signed")
            if firmware_signing.issues:
                for issue in firmware_signing.issues[:3]:
                    print(f"        - {issue}")
            print()

            print("[14/18] Analyzing service privileges...")
        service_privileges = self.service_privilege_analyzer.detect_service_privileges(analyzed_binaries, daemons) if self._enabled("service-privileges") else []
        if not self.quiet:
            if service_privileges:
                root_services = [s for s in service_privileges if s.runs_as_root]
                print(f"      Services analyzed: {len(service_privileges)}")
                print(f"      Running as root: {len(root_services)}")
                if root_services:
                    print(f"      ⚠️  High-risk root services:")
                    for svc in root_services[:5]:
                        print(f"        - {svc.service_name} ({svc.binary_path})")
                isolated = sum(1 for s in service_privileges if s.namespace_isolation or s.chroot_jail)
                print(f"      With isolation: {isolated}")
            else:
                print("      No service configurations found")
            print()

            print("[15/18] Analyzing kernel hardening...")
        kernel_hardening = self.kernel_hardening_analyzer.detect_kernel_hardening() if self._enabled("kernel") else KernelHardeningInfo()
        if not self.quiet:
            if kernel_hardening.config_available:
                print(f"      Config source: {kernel_hardening.config_source}")
                print(f"      Hardening score: {kernel_hardening.hardening_score}/100")
                features = []
                if kernel_hardening.kaslr_enabled:
                    features.append("KASLR")
                if kernel_hardening.smep_enabled or kernel_hardening.pxn_enabled:
                    features.append("SMEP/PXN")
                if kernel_hardening.smap_enabled:
                    features.append("SMAP")
                if kernel_hardening.stack_protector:
                    features.append("Stack Protector")
                if kernel_hardening.fortify_source:
                    features.append("FORTIFY_SOURCE")
                print(f"      Enabled features: {', '.join(features) if features else 'None'}")
                if kernel_hardening.issues:
                    print(f"      Issues: {len(kernel_hardening.issues)}")
            else:
                print("      Kernel config not found")
            print()

            print("[16/18] Analyzing update mechanism...")
        update_mechanism = self.update_mechanism_analyzer.detect_update_mechanism(analyzed_binaries) if self._enabled("update") else UpdateMechanismInfo()
        if not self.quiet:
            if update_mechanism.update_system != "Unknown":
                print(f"      Update system: {update_mechanism.update_system}")
                print(f"      HTTPS: {'Yes' if update_mechanism.uses_https else 'No'}")
                print(f"      Signed: {'Yes' if update_mechanism.uses_signing else 'No'}")
                print(f"      Rollback protection: {'Yes' if update_mechanism.has_rollback_protection else 'No'}")
                if update_mechanism.issues:
                    risk_icon = "🔴" if update_mechanism.risk_level == "HIGH" else "🟡"
                    print(f"      {risk_icon} Risk level: {update_mechanism.risk_level}")
                    for issue in update_mechanism.issues[:3]:
                        print(f"        - {issue}")
            else:
                print("      Update mechanism not detected")
            print()

            print("[17/18] Running security tests...")
        security_tests = []
        if self._enabled("security-tests"):
            weak_crypto_findings = self.security_tester.test_weak_crypto(configs, analyzed_binaries)
            security_tests.extend(weak_crypto_findings)
            covered_components = {f.component.lower() for f in live_cve_findings}
            cve_findings = self.security_tester.test_cve_vulnerabilities(sbom, skip_components=covered_components) if sbom else []
            security_tests.extend(cve_findings)
            default_creds_findings = self.security_tester.test_default_credentials(configs, daemons)
            security_tests.extend(default_creds_findings)
        security_tests.extend(live_cve_findings)
        if not self.quiet:
            print(f"      Security test findings: {len(security_tests)}")
            if security_tests:
                weak_crypto_count = sum(1 for f in security_tests if f.test_type == "weak_crypto")
                static_cve_count = sum(1 for f in security_tests if f.test_type == "cve")
                live_cve_count = sum(1 for f in security_tests if f.test_type == "live_cve")
                creds_count = sum(1 for f in security_tests if f.test_type == "default_creds")
                print(f"        - Weak crypto: {weak_crypto_count}")
                print(f"        - Static CVE checks: {static_cve_count}")
                print(f"        - Live CVE findings: {live_cve_count}")
                print(f"        - Default credentials: {creds_count}")
            print()

            print("[18/18] Analyzing post-quantum crypto readiness...")
        if self._enabled("pqc"):
            pqc_readiness = self.pqc_analyzer.analyze_pqc_readiness(analyzed_binaries)
        else:
            pqc_readiness = {"overall_readiness": "UNKNOWN", "summary": {"total_crypto_binaries": 0, "pqc_ready": 0, "hybrid": 0, "vulnerable_only": 0, "deprecated": 0}}
        if not self.quiet:
            pqc_summary = pqc_readiness.get("summary", {})
            total_pqc = pqc_summary.get("total_crypto_binaries", 0)
            if total_pqc > 0:
                readiness_icon = {"READY": "\U0001f7e2", "HYBRID": "\U0001f7e1", "NOT_READY": "\U0001f7e0", "CRITICAL": "\U0001f534"}.get(pqc_readiness["overall_readiness"], "\u26aa")
                print(f"      {readiness_icon} Overall: {pqc_readiness['overall_readiness']}")
                print(f"      Crypto binaries: {total_pqc}")
                print(f"      PQC Ready: {pqc_summary.get('pqc_ready', 0)}, Hybrid: {pqc_summary.get('hybrid', 0)}, "
                      f"Vulnerable: {pqc_summary.get('vulnerable_only', 0)}, Deprecated: {pqc_summary.get('deprecated', 0)}")
            else:
                print("      No cryptographic algorithm usage detected")
            print()

        duration = (datetime.now() - start_time).total_seconds()

        all_tools = {"rabin2", "hardening-check", "scanelf", "readelf", "file", "strings", "openssl"}
        missing_tools = list(all_tools - set(self.tools.keys()))

        grade, score = calculate_grade(analyzed_binaries)
        if not self.quiet:
            print(f"""{'=' * 65}
  SCAN COMPLETE
{'=' * 65}
  Grade: {grade} (Score: {score}/110)

  Binaries:     {len(analyzed_binaries)} ({secured} secured, {partial} partial, {insecure} insecure)
  ASLR Analysis:{aslr_summary['analyzed']} PIE binaries analyzed
  Daemons:      {len(daemons)} detected
  Dependencies: {len(dep_risks)} risks
  Banned Funcs: {len(banned_all)} hits
  Credentials:  {len(credentials)} findings
  Certificates: {len(certificates)} files
  Config Issues:{len(config_issues)} findings
  Crypto Binaries:{len(crypto_binaries)} detected
  Firmware Signing:{'Yes' if firmware_signing.is_signed else 'No'} | Secure Boot:{'Yes' if firmware_signing.secure_boot_enabled else 'No'}
  Service Privileges:{len(service_privileges)} analyzed ({sum(1 for s in service_privileges if s.runs_as_root)} as root)
  Kernel Hardening:{kernel_hardening.hardening_score}/100
  Update Mechanism:{update_mechanism.update_system} ({update_mechanism.risk_level} risk)
  Security Tests:{len(security_tests)} findings
  Live CVE:     {cve_correlation_summary.cves_found} CVEs ({cve_correlation_summary.api_calls} API calls, {cve_correlation_summary.cache_hits} cached)
  PQC Readiness:{pqc_readiness['overall_readiness']} ({pqc_summary.get('total_crypto_binaries', 0)} crypto binaries)
  SBOM:         {sbom.total_components if sbom else 0} components ({sbom.components_with_cpe if sbom else 0} with CPE)

  Duration: {duration:.1f}s
{'=' * 65}
""")

        return ScanResult(
            target=str(self.target),
            scan_time=start_time.isoformat(),
            duration=duration,
            tools=self.tools,
            profile=profile,
            daemons=daemons,
            binaries=analyzed_binaries,
            banned_functions=banned_all,
            dependency_risks=dep_risks,
            credentials=credentials,
            certificates=certificates,
            config_issues=config_issues,
            security_tests=security_tests,
            crypto_binaries=crypto_binaries,
            firmware_signing=firmware_signing,
            service_privileges=service_privileges,
            kernel_hardening=kernel_hardening,
            update_mechanism=update_mechanism,
            aslr_summary=aslr_summary,
            missing_tools=missing_tools,
            sbom=sbom,
            pqc_readiness=pqc_readiness,
            cve_correlation=cve_correlation_summary,
        )
