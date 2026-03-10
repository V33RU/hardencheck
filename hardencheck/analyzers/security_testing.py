import re
from pathlib import Path
from typing import List, Optional

from hardencheck.models import Severity, BinaryAnalysis, Daemon, SBOMResult, SecurityTestFinding
from hardencheck.constants.security import WEAK_CRYPTO_PATTERNS, VULNERABLE_VERSIONS
from hardencheck.core.base import BaseAnalyzer
from hardencheck.core.utils import safe_read_file, version_compare


class SecurityTester(BaseAnalyzer):
    """Run security tests against firmware components."""

    def test_weak_crypto(self, config_files: List[Path], binaries: List[BinaryAnalysis]) -> List[SecurityTestFinding]:
        """Test for weak cryptographic configurations and deprecated protocols."""
        findings = []

        for filepath in config_files:
            content = safe_read_file(filepath, max_size=256 * 1024)
            if not content:
                continue

            try:
                rel_path = str(filepath.relative_to(self.target))
            except ValueError:
                rel_path = str(filepath)

            for pattern, issue, severity in WEAK_CRYPTO_PATTERNS:
                if re.search(pattern, content, re.IGNORECASE):
                    findings.append(SecurityTestFinding(
                        test_type="weak_crypto",
                        component=filepath.name,
                        issue=issue,
                        severity=severity,
                        affected_path=rel_path,
                        recommendation="Update to modern TLS 1.2+ and remove deprecated ciphers"
                    ))

        for binary in binaries:
            if "ssl" in binary.filename.lower() or "crypto" in binary.filename.lower():
                if "openssl" in binary.filename.lower() or "libssl" in binary.filename.lower():
                    ver = self._extract_version(self.target / binary.path)
                    if ver and ver != "Unknown":
                        for lib_name, vuln_versions in VULNERABLE_VERSIONS.items():
                            if lib_name in binary.filename.lower():
                                for version_range, cve_info in vuln_versions.items():
                                    if version_range.startswith("<"):
                                        max_version = version_range[1:]
                                        if version_compare(ver, max_version) < 0:
                                            findings.append(SecurityTestFinding(
                                                test_type="weak_crypto",
                                                component=lib_name,
                                                version=ver,
                                                issue=f"Vulnerable version detected: {version_range}",
                                                severity=Severity.HIGH,
                                                details=cve_info,
                                                affected_path=str(binary.path),
                                                recommendation=f"Upgrade {lib_name} to version >= {max_version}"
                                            ))

        return findings

    def test_cve_vulnerabilities(self, sbom: Optional[SBOMResult]) -> List[SecurityTestFinding]:
        """Test detected components against known vulnerable versions."""
        findings = []

        if not sbom:
            return findings

        for component in sbom.components:
            if component.version == "Unknown" or not component.version:
                continue

            comp_name_lower = component.name.lower()
            for lib_name, vuln_versions in VULNERABLE_VERSIONS.items():
                if lib_name in comp_name_lower:
                    for version_range, cve_info in vuln_versions.items():
                        if version_range.startswith("<"):
                            max_version = version_range[1:]
                            if version_compare(component.version, max_version) < 0:
                                findings.append(SecurityTestFinding(
                                    test_type="cve",
                                    component=component.name,
                                    version=component.version,
                                    issue=f"Potentially vulnerable version: {version_range}",
                                    severity=Severity.HIGH,
                                    details=cve_info,
                                    cve_id="Multiple CVEs",
                                    affected_path=component.path,
                                    recommendation=f"Upgrade {component.name} to version >= {max_version}"
                                ))
                    break

        return findings

    def test_default_credentials(self, config_files: List[Path], daemons: List[Daemon]) -> List[SecurityTestFinding]:
        """Test for default credentials in configuration files."""
        findings = []

        for filepath in config_files:
            content = safe_read_file(filepath, max_size=256 * 1024)
            if not content:
                continue

            try:
                rel_path = str(filepath.relative_to(self.target))
            except ValueError:
                rel_path = str(filepath)

            default_patterns = [
                (r'(?i)(?:user|username|login)\s*[=:]\s*["\']?(?:admin|root|guest)["\']?', "Default username detected"),
                (r'(?i)(?:pass|password|pwd)\s*[=:]\s*["\']?(?:admin|password|1234|root|toor|pass)["\']?', "Weak/default password detected"),
                (r'(?i)admin\s*[=:]\s*["\']?admin["\']?', "Default admin:admin credentials"),
                (r'(?i)root\s*[=:]\s*["\']?(?:root|toor|"")["\']?', "Default root credentials"),
            ]

            for pattern, issue_desc in default_patterns:
                matches = re.finditer(pattern, content)
                for match in matches:
                    line_num = content[:match.start()].count('\n') + 1
                    snippet = content[max(0, match.start()-20):match.end()+20].replace('\n', ' ')

                    findings.append(SecurityTestFinding(
                        test_type="default_creds",
                        component=filepath.name,
                        issue=issue_desc,
                        severity=Severity.HIGH,
                        details=f"Line {line_num}: {snippet}",
                        affected_path=rel_path,
                        recommendation="Change default credentials immediately"
                    ))

        for daemon in daemons:
            daemon_name_lower = daemon.name.lower()
            if daemon_name_lower in ["telnetd", "httpd", "uhttpd", "lighttpd", "nginx", "apache"]:
                findings.append(SecurityTestFinding(
                    test_type="default_creds",
                    component=daemon.name,
                    version=daemon.version,
                    issue="Service detected - test for default credentials",
                    severity=Severity.MEDIUM,
                    details=f"Service {daemon.name} may have default credentials",
                    affected_path=daemon.path,
                    recommendation=f"Test {daemon.name} for default credentials before deployment"
                ))

        return findings
