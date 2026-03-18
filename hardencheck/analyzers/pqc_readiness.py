import re
from typing import Dict, List, Optional

from hardencheck.models import BinaryAnalysis
from hardencheck.constants.pqc import (
    QUANTUM_VULNERABLE_ALGOS,
    PQC_ALGORITHM_PATTERNS,
    PQC_HYBRID_PATTERNS,
    PQC_READY_LIBRARIES,
    PQC_READINESS_LEVELS,
)
from hardencheck.core.base import BaseAnalyzer


class PQCReadinessAnalyzer(BaseAnalyzer):
    """Analyze firmware binaries for post-quantum cryptography readiness."""

    def analyze_pqc_readiness(self, binaries: List[BinaryAnalysis]) -> dict:
        """Scan binaries for quantum-vulnerable and PQC algorithm usage.

        Returns dict with overall_readiness, summary, findings, recommendations.
        """
        findings = []

        for binary in binaries:
            filepath = self.target / binary.path
            if not filepath.exists():
                continue

            strings_output = self._get_strings(filepath)
            if not strings_output:
                continue

            vuln_algos = self._detect_vulnerable_algos(strings_output)
            pqc_algos = self._detect_pqc_algos(strings_output)
            has_hybrid = self._detect_hybrid(strings_output)
            crypto_lib, crypto_version = self._detect_crypto_library(strings_output)

            if not vuln_algos and not pqc_algos:
                continue

            has_network = self._has_network_symbols(filepath)
            readiness, risk_level = self._classify_readiness(
                vuln_algos, pqc_algos, has_hybrid, has_network
            )
            issues = self._build_issues(vuln_algos, pqc_algos, crypto_lib, crypto_version, has_network)
            recommendation = self._build_recommendation(readiness, crypto_lib, crypto_version)

            findings.append({
                "binary": binary.filename,
                "path": str(binary.path),
                "crypto_library": crypto_lib,
                "crypto_version": crypto_version,
                "vulnerable_algorithms": [a for a, _ in vuln_algos],
                "pqc_algorithms": pqc_algos,
                "has_hybrid": has_hybrid,
                "has_network": has_network,
                "readiness": readiness,
                "risk_level": risk_level,
                "issues": issues,
                "recommendation": recommendation,
            })

        summary = self._build_summary(findings)
        overall = self._overall_readiness(findings)
        recommendations = self._global_recommendations(findings, overall)

        return {
            "overall_readiness": overall,
            "summary": summary,
            "findings": findings,
            "recommendations": recommendations,
        }

    def _get_strings(self, filepath) -> str:
        if "strings" not in self.tools:
            return ""
        ret, out, _ = self._run_command(
            [self.tools["strings"], "-n", "4", str(filepath)], timeout=15
        )
        return out if ret == 0 else ""

    def _detect_vulnerable_algos(self, strings_output: str) -> List[tuple]:
        """Returns list of (algo_name, severity) for quantum-vulnerable algorithms found."""
        found = []
        for algo_name, info in QUANTUM_VULNERABLE_ALGOS.items():
            for pattern in info["patterns"]:
                if pattern in strings_output:
                    found.append((algo_name, info["severity"]))
                    break
        return found

    def _detect_pqc_algos(self, strings_output: str) -> List[str]:
        """Returns list of PQC algorithm names detected."""
        found = []
        for algo_name, info in PQC_ALGORITHM_PATTERNS.items():
            for pattern in info["patterns"]:
                if pattern in strings_output:
                    found.append(algo_name)
                    break
        return found

    def _detect_hybrid(self, strings_output: str) -> bool:
        """Check if hybrid classical+PQC mode is detected."""
        for pattern in PQC_HYBRID_PATTERNS:
            if pattern in strings_output:
                return True
        return False

    def _detect_crypto_library(self, strings_output: str) -> tuple:
        """Detect crypto library and version. Returns (lib_name, version)."""
        for lib_name, info in PQC_READY_LIBRARIES.items():
            for pattern in info["patterns"]:
                if pattern in strings_output:
                    version = "Unknown"
                    for vp in info.get("version_patterns", []):
                        match = re.search(vp, strings_output)
                        if match:
                            version = match.group(1)
                            break
                    return lib_name, version
        return "Unknown", "Unknown"

    def _classify_readiness(self, vuln_algos, pqc_algos, has_hybrid, has_network):
        """Classify PQC readiness and risk level for a single binary."""
        has_deprecated = any(sev == "CRITICAL" for _, sev in vuln_algos)
        has_vuln = len(vuln_algos) > 0
        has_pqc = len(pqc_algos) > 0

        if has_deprecated:
            readiness = "CRITICAL"
            risk_level = "CRITICAL"
        elif has_pqc and not has_vuln:
            readiness = "READY"
            risk_level = "LOW"
        elif has_pqc or has_hybrid:
            readiness = "HYBRID"
            risk_level = "MEDIUM" if has_network else "LOW"
        elif has_vuln and has_network:
            readiness = "NOT_READY"
            risk_level = "HIGH"
        elif has_vuln:
            readiness = "NOT_READY"
            risk_level = "MEDIUM"
        else:
            readiness = "NOT_READY"
            risk_level = "LOW"

        return readiness, risk_level

    def _build_issues(self, vuln_algos, pqc_algos, crypto_lib, crypto_version, has_network):
        """Build issue descriptions for a finding."""
        issues = []
        for algo, sev in vuln_algos:
            desc = QUANTUM_VULNERABLE_ALGOS[algo]["description"]
            issues.append(f"[{sev}] {algo}: {desc}")

        if has_network and vuln_algos and not pqc_algos:
            issues.append("Network-exposed binary using only quantum-vulnerable crypto")

        if crypto_lib != "Unknown":
            lib_info = PQC_READY_LIBRARIES.get(crypto_lib, {})
            min_ver = lib_info.get("min_pqc_version", "99.99.99")
            if crypto_version != "Unknown":
                if self._version_lt(crypto_version, min_ver):
                    issues.append(f"{crypto_lib} {crypto_version} does not support PQC (need >= {min_ver})")
            note = lib_info.get("pqc_note", "")
            if "No PQC" in note:
                issues.append(f"{crypto_lib}: {note}")

        return issues

    def _build_recommendation(self, readiness, crypto_lib, crypto_version):
        """Build recommendation string for a finding."""
        if readiness == "READY":
            return "PQC algorithms detected - ensure hybrid mode for interoperability"
        if readiness == "HYBRID":
            return "Hybrid mode active - good transition strategy, ensure PQC-only path available"
        if readiness == "CRITICAL":
            return "Replace deprecated algorithms immediately (DSA/DES/MD5) and adopt PQC"

        if crypto_lib == "OpenSSL":
            return "Upgrade to OpenSSL 3.5+ and enable oqsprovider for ML-KEM/ML-DSA support"
        if crypto_lib == "wolfSSL":
            return "Upgrade to wolfSSL 5.5+ for ML-KEM and ML-DSA support"
        if crypto_lib == "libsodium":
            return "libsodium has no PQC support - consider adding liboqs for PQC"
        if crypto_lib == "mbedTLS":
            return "mbedTLS PQC support planned for 4.0+ - consider liboqs as interim"
        return "Integrate liboqs or upgrade crypto library to a PQC-capable version"

    def _version_lt(self, v1: str, v2: str) -> bool:
        """Compare two version strings. Returns True if v1 < v2."""
        try:
            parts1 = [int(x) for x in v1.split(".")]
            parts2 = [int(x) for x in v2.split(".")]
            while len(parts1) < len(parts2):
                parts1.append(0)
            while len(parts2) < len(parts1):
                parts2.append(0)
            return parts1 < parts2
        except (ValueError, AttributeError):
            # Cannot parse version — do not assume it is older/vulnerable
            return False

    def _build_summary(self, findings):
        """Build summary counters."""
        return {
            "total_crypto_binaries": len(findings),
            "pqc_ready": sum(1 for f in findings if f["readiness"] == "READY"),
            "hybrid": sum(1 for f in findings if f["readiness"] == "HYBRID"),
            "vulnerable_only": sum(1 for f in findings if f["readiness"] == "NOT_READY"),
            "deprecated": sum(1 for f in findings if f["readiness"] == "CRITICAL"),
        }

    def _overall_readiness(self, findings):
        """Determine overall PQC readiness across all binaries."""
        if not findings:
            return "NOT_READY"
        if any(f["readiness"] == "CRITICAL" for f in findings):
            return "CRITICAL"
        readiness_set = {f["readiness"] for f in findings}
        if readiness_set == {"READY"}:
            return "READY"
        if "READY" in readiness_set or "HYBRID" in readiness_set:
            return "HYBRID"
        return "NOT_READY"

    def _global_recommendations(self, findings, overall):
        """Generate global recommendations based on all findings."""
        recs = []
        if overall == "CRITICAL":
            recs.append("URGENT: Replace deprecated algorithms (DSA, DES, MD5) - these are broken even without quantum computers")
        if overall in ("NOT_READY", "CRITICAL"):
            recs.append("Adopt NIST PQC standards: ML-KEM (FIPS 203) for key exchange, ML-DSA (FIPS 204) for signatures")

        libs = {f["crypto_library"] for f in findings if f["crypto_library"] != "Unknown"}
        if "OpenSSL" in libs:
            openssl_versions = [f["crypto_version"] for f in findings if f["crypto_library"] == "OpenSSL" and f["crypto_version"] != "Unknown"]
            if openssl_versions and all(self._version_lt(v, "3.5.0") for v in openssl_versions):
                recs.append("Upgrade OpenSSL to 3.5+ for native PQC provider support")
        if "libsodium" in libs:
            recs.append("libsodium does not support PQC - add liboqs alongside for post-quantum key exchange")

        if overall != "READY":
            recs.append("Consider hybrid key exchange (classical + PQC) during migration for backward compatibility")
            recs.append("Prioritize PQC migration for network-facing services (TLS, SSH, VPN)")

        vuln_algo_set = set()
        for f in findings:
            for algo in f["vulnerable_algorithms"]:
                vuln_algo_set.add(algo)
        if "RSA" in vuln_algo_set:
            recs.append("Replace RSA key exchange with ML-KEM (Kyber) for quantum-safe key encapsulation")
        if "ECDSA" in vuln_algo_set or "Ed25519" in vuln_algo_set:
            recs.append("Replace ECDSA/Ed25519 signatures with ML-DSA (Dilithium) for quantum-safe signing")

        return recs
