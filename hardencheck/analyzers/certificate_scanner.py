import os
import re
from datetime import datetime
from pathlib import Path
from typing import List, Optional

from hardencheck.models import Severity, CertificateFinding
from hardencheck.constants.config import CERT_EXTENSIONS
from hardencheck.constants.core import MAX_RECURSION_DEPTH
from hardencheck.core.base import BaseAnalyzer


class CertificateScanner(BaseAnalyzer):
    """Scan for certificate and key files."""

    def scan_certificates(self) -> List[CertificateFinding]:
        """Scan for certificate and key files with content verification."""
        findings = []

        for root, dirs, files in os.walk(self.target):
            depth = root.count(os.sep) - str(self.target).count(os.sep)
            if depth > MAX_RECURSION_DEPTH:
                dirs[:] = []
                continue
            dirs[:] = [d for d in dirs if not d.startswith(".")]

            for filename in files:
                filepath = Path(root) / filename
                suffix = filepath.suffix.lower()

                if suffix not in CERT_EXTENSIONS:
                    continue

                try:
                    rel_path = str(filepath.relative_to(self.target))
                except ValueError:
                    rel_path = str(filepath)

                if suffix == ".key" or "private" in filename.lower():
                    try:
                        with open(filepath, 'rb') as f:
                            header = f.read(100)
                        if b"-----BEGIN" in header and b"PRIVATE KEY-----" in header:
                            findings.append(CertificateFinding(
                                file=rel_path,
                                file_type="Private Key",
                                issue="Private key (PEM) found in firmware",
                                severity=Severity.HIGH
                            ))
                        elif b"-----BEGIN" in header and b"KEY-----" in header:
                            findings.append(CertificateFinding(
                                file=rel_path,
                                file_type="Private Key",
                                issue="Key file (PEM) found in firmware",
                                severity=Severity.MEDIUM
                            ))
                        elif suffix == ".key":
                            findings.append(CertificateFinding(
                                file=rel_path,
                                file_type="Unknown Key Format",
                                issue="File with .key extension (verify manually)",
                                severity=Severity.LOW
                            ))
                    except (OSError, PermissionError):
                        pass

                elif suffix in {".pem", ".crt", ".cer"}:
                    try:
                        with open(filepath, 'rb') as f:
                            header = f.read(100)
                        if b"-----BEGIN" not in header:
                            continue

                        if b"PRIVATE KEY-----" in header:
                            findings.append(CertificateFinding(
                                file=rel_path,
                                file_type="Private Key",
                                issue="Private key in PEM file",
                                severity=Severity.HIGH
                            ))
                        else:
                            issue = self._analyze_certificate(filepath)
                            if issue:
                                findings.append(CertificateFinding(
                                    file=rel_path,
                                    file_type="Certificate",
                                    issue=issue,
                                    severity=Severity.MEDIUM
                                ))
                    except (OSError, PermissionError):
                        pass

                elif suffix in {".p12", ".pfx"}:
                    findings.append(CertificateFinding(
                        file=rel_path,
                        file_type="PKCS12 Bundle",
                        issue="PKCS12 bundle (may contain private key)",
                        severity=Severity.MEDIUM
                    ))
                    findings.append(CertificateFinding(
                        file=rel_path,
                        file_type="PKCS12 Bundle",
                        issue="PKCS12 bundle with private key",
                        severity=Severity.HIGH
                    ))

        return findings[:50]

    def _analyze_certificate(self, filepath: Path) -> Optional[str]:
        """Analyze certificate for issues."""
        if "openssl" not in self.tools:
            return None

        ret, out, _ = self._run_command(
            [self.tools["openssl"], "x509", "-in", str(filepath), "-noout", "-text"],
            timeout=10
        )

        if ret != 0:
            return None

        issues = []

        if "Issuer:" in out and "Subject:" in out:
            issuer_match = re.search(r"Issuer:\s*(.+)", out)
            subject_match = re.search(r"Subject:\s*(.+)", out)
            if issuer_match and subject_match:
                if issuer_match.group(1).strip() == subject_match.group(1).strip():
                    issues.append("self-signed")

        if "RSA Public-Key:" in out:
            key_match = re.search(r"RSA Public-Key:\s*\((\d+) bit\)", out)
            if key_match:
                key_size = int(key_match.group(1))
                if key_size < 2048:
                    issues.append(f"weak key ({key_size}-bit)")

        if "Not After :" in out:
            expiry_match = re.search(r"Not After :\s*(.+)", out)
            if expiry_match:
                try:
                    expiry_str = expiry_match.group(1).strip()
                    year_match = re.search(r"\b(20\d{2})\b", expiry_str)
                    if year_match:
                        expiry_year = int(year_match.group(1))
                        if expiry_year < datetime.now().year:
                            issues.append("expired")
                except (ValueError, AttributeError):
                    pass

        return ", ".join(issues) if issues else None
