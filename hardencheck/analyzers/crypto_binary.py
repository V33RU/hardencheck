from typing import List

from hardencheck.models import BinaryType, BinaryAnalysis, CryptographicBinary
from hardencheck.constants.crypto import CRYPTO_BINARY_PATTERNS
from hardencheck.core.base import BaseAnalyzer


class CryptoBinaryDetector(BaseAnalyzer):
    """Detect security-sensitive cryptographic utility binaries."""

    def detect_cryptographic_binaries(self, binaries: List[BinaryAnalysis]) -> List[CryptographicBinary]:
        """Detect security-sensitive cryptographic utility binaries."""
        crypto_binaries = []

        for binary in binaries:
            filename_lower = binary.filename.lower()

            for pattern, (purpose, risk_level, recommendation) in CRYPTO_BINARY_PATTERNS.items():
                if pattern in filename_lower:
                    security_flags = {
                        "nx": binary.nx,
                        "pie": binary.pie,
                        "canary": binary.canary,
                        "relro": binary.relro,
                        "fortify": binary.fortify,
                        "stripped": binary.stripped,
                    }

                    filepath = self.target / binary.path
                    has_network = self._has_network_symbols(filepath)

                    version = self._extract_version(filepath)

                    issues = []
                    if binary.nx is False:
                        issues.append("No NX protection - code execution risk")
                    if binary.pie is False and binary.binary_type == BinaryType.EXECUTABLE:
                        issues.append("No PIE - ASLR bypass possible")
                    if binary.canary is False:
                        issues.append("No stack canary - buffer overflow risk")
                    if binary.relro != "full":
                        issues.append(f"RELRO: {binary.relro} - GOT overwrite risk")
                    if has_network and purpose in ("decrypt", "encrypt"):
                        issues.append("Network-enabled crypto binary - potential key exposure")

                    final_risk = risk_level
                    if issues and risk_level == "MEDIUM":
                        if any("CRITICAL" in i or "No NX" in i for i in issues):
                            final_risk = "HIGH"
                    elif purpose == "decrypt" and issues:
                        final_risk = "HIGH"

                    crypto_binaries.append(CryptographicBinary(
                        name=binary.filename,
                        path=str(binary.path),
                        binary_type=binary.binary_type,
                        version=version,
                        purpose=purpose,
                        has_network=has_network,
                        security_flags=security_flags,
                        risk_level=final_risk,
                        issues=issues,
                        recommendation=recommendation
                    ))
                    break

        return crypto_binaries
