"""Live CVE correlation using NVD and OSV APIs.

Queries real vulnerability databases using SBOM component CPE/PURL data
to find CVEs with CVSS scores affecting exact firmware versions.
"""
import json
import hashlib
import ssl
import time
import urllib.request
import urllib.error
import urllib.parse
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple

from hardencheck.models import Severity, SBOMResult, SBOMComponent, SecurityTestFinding
from hardencheck.core.base import BaseAnalyzer
from hardencheck.core.utils import version_compare


class CVECorrelator(BaseAnalyzer):
    """Correlate SBOM components with live CVE databases (NVD + OSV)."""

    NVD_API_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    OSV_API_BASE = "https://api.osv.dev/v1/query"
    DEFAULT_CACHE_DIR = Path.home() / ".cache" / "hardencheck" / "cve_cache"
    CACHE_TTL_SECONDS = 86400  # 24 hours
    REQUEST_TIMEOUT = 15

    def __init__(self, ctx, nvd_api_key: str = "",
                 cache_enabled: bool = True,
                 cache_dir: Optional[Path] = None):
        super().__init__(ctx)
        self.nvd_api_key = nvd_api_key
        self.cache_enabled = cache_enabled
        self.cache_dir = cache_dir or self.DEFAULT_CACHE_DIR
        self.rate_limit_window = 30.0
        self.rate_limit_max = 50 if nvd_api_key else 5
        self._request_timestamps: List[float] = []
        self._stats = {
            "components_queried": 0,
            "unique_cpes_queried": 0,
            "cache_hits": 0,
            "api_calls": 0,
            "api_errors": 0,
            "cves_found": 0,
            "api_available": True,
            "duration_seconds": 0.0,
            "data_sources": [],
        }
        self._seen_cve_ids: Set[str] = set()

        # Ensure cache directory exists
        if self.cache_enabled:
            try:
                self.cache_dir.mkdir(parents=True, exist_ok=True)
            except OSError:
                self.cache_enabled = False

    def correlate_cves(self, sbom: SBOMResult) -> List[SecurityTestFinding]:
        """Correlate SBOM components against NVD and OSV databases.

        Args:
            sbom: SBOM result containing components with CPE/PURL data

        Returns:
            List of SecurityTestFinding with test_type="live_cve"
        """
        start = time.monotonic()
        findings: List[SecurityTestFinding] = []

        if not sbom or not sbom.components:
            return findings

        # Filter to components with version info
        versioned = [c for c in sbom.components
                     if c.version and c.version != "Unknown"]
        self._stats["components_queried"] = len(versioned)

        # Deduplicate by CPE base (vendor:product:version)
        cpe_groups: Dict[str, List[SBOMComponent]] = {}
        purl_only: List[SBOMComponent] = []

        for comp in versioned:
            if comp.cpe:
                # Extract vendor:product:version from CPE
                key = self._cpe_key(comp.cpe)
                if key not in cpe_groups:
                    cpe_groups[key] = []
                cpe_groups[key].append(comp)
            elif comp.purl:
                purl_only.append(comp)

        self._stats["unique_cpes_queried"] = len(cpe_groups)

        # Query NVD for CPE-based components
        for cpe_key, components in cpe_groups.items():
            cpe_string = components[0].cpe
            nvd_findings = self._query_nvd_cached(cpe_string, components)
            findings.extend(nvd_findings)

            if not self._stats["api_available"]:
                break

        if findings:
            self._add_source("NVD")

        # Query OSV for PURL-only components (no CPE mapping)
        for comp in purl_only:
            if not self._stats["api_available"]:
                break
            osv_findings = self._query_osv_cached(comp)
            findings.extend(osv_findings)

        if purl_only and self._stats["api_available"]:
            self._add_source("OSV")

        self._stats["cves_found"] = len(findings)
        self._stats["duration_seconds"] = round(time.monotonic() - start, 2)

        return findings

    def get_stats(self) -> dict:
        """Return correlation statistics."""
        return dict(self._stats)

    # ── NVD API ──────────────────────────────────────────────────────────

    def _query_nvd_cached(self, cpe: str, components: List[SBOMComponent]) -> List[SecurityTestFinding]:
        """Query NVD with caching."""
        cache_key = self._cache_key(f"nvd:{cpe}")

        # Check cache
        cached = self._cache_get(cache_key)
        if cached is not None:
            self._stats["cache_hits"] += 1
            return self._parse_nvd_response(cached, components)

        # Rate limit then query
        self._rate_limit_wait()
        data = self._nvd_request(cpe)
        if data is None:
            return []

        self._stats["api_calls"] += 1
        self._cache_put(cache_key, data)
        return self._parse_nvd_response(data, components)

    def _nvd_request(self, cpe: str) -> Optional[dict]:
        """Make NVD API v2.0 request."""
        params = {
            "cpeName": cpe,
            "resultsPerPage": "50",
        }
        url = f"{self.NVD_API_BASE}?{urllib.parse.urlencode(params)}"

        headers = {"User-Agent": "HardenCheck/1.0"}
        if self.nvd_api_key:
            headers["apiKey"] = self.nvd_api_key

        return self._make_request(url, headers=headers)

    def _parse_nvd_response(self, data: dict, components: List[SBOMComponent]) -> List[SecurityTestFinding]:
        """Parse NVD API response into SecurityTestFindings."""
        findings = []
        vulnerabilities = data.get("vulnerabilities", [])

        for vuln_entry in vulnerabilities:
            cve_data = vuln_entry.get("cve", {})
            cve_id = cve_data.get("id", "")

            if not cve_id or cve_id in self._seen_cve_ids:
                continue

            # Extract English description
            description = ""
            for desc in cve_data.get("descriptions", []):
                if desc.get("lang") == "en":
                    description = desc.get("value", "")
                    break

            # Extract CVSS v3.1 score (fall back to v3.0, then v2)
            cvss_score, cvss_vector, cvss_severity = self._extract_cvss(cve_data)

            # Verify version is in affected range
            if not self._verify_version_affected(cve_data, components):
                continue

            severity = self._cvss_to_severity(cvss_score)
            self._seen_cve_ids.add(cve_id)

            # Create finding for each affected component path
            comp = components[0]
            truncated_desc = description[:200] + "..." if len(description) > 200 else description

            findings.append(SecurityTestFinding(
                test_type="live_cve",
                component=comp.name,
                version=comp.version,
                issue=truncated_desc,
                severity=severity,
                details=f"CVSS: {cvss_score} ({cvss_severity}) | Vector: {cvss_vector}",
                recommendation=f"Upgrade {comp.name} to a patched version. See https://nvd.nist.gov/vuln/detail/{cve_id}",
                cve_id=cve_id,
                affected_path=comp.path,
            ))

        return findings

    def _extract_cvss(self, cve_data: dict) -> Tuple[float, str, str]:
        """Extract CVSS score, vector, and severity from CVE data."""
        metrics = cve_data.get("metrics", {})

        # Try CVSS v3.1 first
        for metric_key in ("cvssMetricV31", "cvssMetricV30"):
            metric_list = metrics.get(metric_key, [])
            if metric_list:
                cvss_data = metric_list[0].get("cvssData", {})
                return (
                    cvss_data.get("baseScore", 0.0),
                    cvss_data.get("vectorString", ""),
                    cvss_data.get("baseSeverity", "UNKNOWN"),
                )

        # Fall back to CVSS v2
        v2_list = metrics.get("cvssMetricV2", [])
        if v2_list:
            cvss_data = v2_list[0].get("cvssData", {})
            return (
                cvss_data.get("baseScore", 0.0),
                cvss_data.get("vectorString", ""),
                cvss_data.get("baseSeverity", "UNKNOWN"),
            )

        return (0.0, "", "UNKNOWN")

    def _verify_version_affected(self, cve_data: dict, components: List[SBOMComponent]) -> bool:
        """Verify that the component version falls within the CVE's affected range."""
        configurations = cve_data.get("configurations", [])
        if not configurations:
            # No configuration data — trust the CPE match from NVD
            return True

        comp_version = components[0].version

        for config in configurations:
            for node in config.get("nodes", []):
                for cpe_match in node.get("cpeMatch", []):
                    if not cpe_match.get("vulnerable", False):
                        continue

                    # Check version range
                    v_start_inc = cpe_match.get("versionStartIncluding", "")
                    v_start_exc = cpe_match.get("versionStartExcluding", "")
                    v_end_inc = cpe_match.get("versionEndIncluding", "")
                    v_end_exc = cpe_match.get("versionEndExcluding", "")

                    # If no version constraints, it matches all versions
                    if not any([v_start_inc, v_start_exc, v_end_inc, v_end_exc]):
                        # Check if CPE has exact version match
                        criteria = cpe_match.get("criteria", "")
                        parts = criteria.split(":")
                        if len(parts) >= 6 and parts[5] not in ("*", "-"):
                            return parts[5] == comp_version
                        return True

                    # Check start bound
                    if v_start_inc and version_compare(comp_version, v_start_inc) < 0:
                        continue
                    if v_start_exc and version_compare(comp_version, v_start_exc) <= 0:
                        continue

                    # Check end bound
                    if v_end_inc and version_compare(comp_version, v_end_inc) > 0:
                        continue
                    if v_end_exc and version_compare(comp_version, v_end_exc) >= 0:
                        continue

                    return True

        return False

    # ── OSV API ──────────────────────────────────────────────────────────

    def _query_osv_cached(self, component: SBOMComponent) -> List[SecurityTestFinding]:
        """Query OSV with caching."""
        cache_key = self._cache_key(f"osv:{component.purl}:{component.version}")

        cached = self._cache_get(cache_key)
        if cached is not None:
            self._stats["cache_hits"] += 1
            return self._parse_osv_response(cached, component)

        self._rate_limit_wait()
        data = self._osv_request(component)
        if data is None:
            return []

        self._stats["api_calls"] += 1
        self._cache_put(cache_key, data)
        return self._parse_osv_response(data, component)

    def _osv_request(self, component: SBOMComponent) -> Optional[dict]:
        """Make OSV API request."""
        body = json.dumps({
            "package": {"purl": component.purl},
            "version": component.version,
        }).encode("utf-8")

        headers = {
            "Content-Type": "application/json",
            "User-Agent": "HardenCheck/1.0",
        }

        return self._make_request(self.OSV_API_BASE, method="POST",
                                  data=body, headers=headers)

    def _parse_osv_response(self, data: dict, component: SBOMComponent) -> List[SecurityTestFinding]:
        """Parse OSV API response into SecurityTestFindings."""
        findings = []
        vulns = data.get("vulns", [])

        for vuln in vulns:
            vuln_id = vuln.get("id", "")
            if not vuln_id or vuln_id in self._seen_cve_ids:
                continue

            summary = vuln.get("summary", vuln.get("details", ""))[:200]
            cvss_score = 0.0
            cvss_vector = ""

            # Extract CVSS from severity array
            for sev in vuln.get("severity", []):
                if sev.get("type") == "CVSS_V3":
                    cvss_vector = sev.get("score", "")
                    # Parse score from vector string
                    cvss_score = self._parse_cvss_from_vector(cvss_vector)
                    break

            severity = self._cvss_to_severity(cvss_score) if cvss_score > 0 else Severity.MEDIUM
            self._seen_cve_ids.add(vuln_id)

            cvss_display = f"CVSS: {cvss_score}" if cvss_score > 0 else "CVSS: N/A"

            findings.append(SecurityTestFinding(
                test_type="live_cve",
                component=component.name,
                version=component.version,
                issue=summary,
                severity=severity,
                details=f"{cvss_display} | Vector: {cvss_vector}" if cvss_vector else cvss_display,
                recommendation=f"Upgrade {component.name}. See https://osv.dev/vulnerability/{vuln_id}",
                cve_id=vuln_id,
                affected_path=component.path,
            ))

        return findings

    def _parse_cvss_from_vector(self, vector: str) -> float:
        """Parse approximate base score from CVSS v3 vector string.

        This is a simplified parser — NVD provides exact scores, OSV sometimes
        only provides the vector string. Falls back to 0.0 if unparseable.
        """
        if not vector or not vector.startswith("CVSS:3"):
            return 0.0

        # Map attack complexity and impact metrics to approximate score
        parts = {}
        for segment in vector.split("/"):
            if ":" in segment:
                key, val = segment.split(":", 1)
                parts[key] = val

        # Rough scoring based on key metrics
        base = 5.0
        if parts.get("AV") == "N":
            base += 1.5
        elif parts.get("AV") == "A":
            base += 0.5

        if parts.get("AC") == "L":
            base += 1.0

        if parts.get("C") == "H" or parts.get("I") == "H" or parts.get("A") == "H":
            base += 2.0
        elif parts.get("C") == "L" or parts.get("I") == "L" or parts.get("A") == "L":
            base += 0.5

        if parts.get("PR") == "N":
            base += 0.5

        return min(base, 10.0)

    # ── HTTP Client ──────────────────────────────────────────────────────

    def _make_request(self, url: str, method: str = "GET",
                      data: Optional[bytes] = None,
                      headers: Optional[dict] = None) -> Optional[dict]:
        """Make HTTP request and return parsed JSON, or None on error."""
        try:
            ctx = ssl.create_default_context()
            req = urllib.request.Request(url, data=data, method=method)
            if headers:
                for key, val in headers.items():
                    req.add_header(key, val)

            with urllib.request.urlopen(req, timeout=self.REQUEST_TIMEOUT,
                                        context=ctx) as resp:
                body = resp.read()
                return json.loads(body)

        except urllib.error.HTTPError as e:
            if e.code == 403:
                self._log(f"NVD API rate limited (403). Waiting...")
                time.sleep(self.rate_limit_window)
                # Retry once
                try:
                    with urllib.request.urlopen(req, timeout=self.REQUEST_TIMEOUT,
                                                context=ctx) as resp:
                        return json.loads(resp.read())
                except Exception:
                    pass
            self._stats["api_errors"] += 1
            self._log(f"HTTP error {e.code} for {url}")
            return None

        except (urllib.error.URLError, OSError, ssl.SSLError) as e:
            self._stats["api_errors"] += 1
            self._stats["api_available"] = False
            self._log(f"API unreachable: {e}")
            return None

        except (json.JSONDecodeError, ValueError) as e:
            self._stats["api_errors"] += 1
            self._log(f"Invalid JSON response: {e}")
            return None

    # ── Rate Limiting ────────────────────────────────────────────────────

    def _rate_limit_wait(self):
        """Token bucket rate limiter — sleeps if at capacity."""
        now = time.monotonic()

        # Remove timestamps outside the window
        self._request_timestamps = [
            ts for ts in self._request_timestamps
            if now - ts < self.rate_limit_window
        ]

        if len(self._request_timestamps) >= self.rate_limit_max:
            oldest = self._request_timestamps[0]
            sleep_time = self.rate_limit_window - (now - oldest) + 0.1
            if sleep_time > 0:
                self._log(f"Rate limit: sleeping {sleep_time:.1f}s")
                time.sleep(sleep_time)

        self._request_timestamps.append(time.monotonic())

    # ── Cache ────────────────────────────────────────────────────────────

    def _cache_get(self, key: str) -> Optional[dict]:
        """Read cached response if valid."""
        if not self.cache_enabled:
            return None

        cache_file = self.cache_dir / f"{key}.json"
        try:
            if not cache_file.exists():
                return None

            raw = cache_file.read_text(encoding="utf-8")
            entry = json.loads(raw)
            timestamp = entry.get("timestamp", 0)

            if time.time() - timestamp > self.CACHE_TTL_SECONDS:
                return None

            return entry.get("data")

        except (OSError, json.JSONDecodeError, KeyError):
            return None

    def _cache_put(self, key: str, data: dict):
        """Write response to cache."""
        if not self.cache_enabled:
            return

        cache_file = self.cache_dir / f"{key}.json"
        try:
            entry = {"timestamp": time.time(), "data": data}
            cache_file.write_text(json.dumps(entry), encoding="utf-8")
        except OSError:
            pass

    def _cache_key(self, identifier: str) -> str:
        """Generate cache key from identifier."""
        return hashlib.sha256(identifier.encode("utf-8")).hexdigest()[:16]

    # ── Helpers ───────────────────────────────────────────────────────────

    def _cpe_key(self, cpe: str) -> str:
        """Extract vendor:product:version from CPE 2.3 string."""
        # cpe:2.3:a:vendor:product:version:...
        parts = cpe.split(":")
        if len(parts) >= 6:
            return f"{parts[3]}:{parts[4]}:{parts[5]}"
        return cpe

    def _cvss_to_severity(self, score: float) -> Severity:
        """Map CVSS v3 score to Severity enum."""
        if score >= 9.0:
            return Severity.CRITICAL
        elif score >= 7.0:
            return Severity.HIGH
        elif score >= 4.0:
            return Severity.MEDIUM
        elif score >= 0.1:
            return Severity.LOW
        return Severity.INFO

    def _add_source(self, source: str):
        """Add data source if not already present."""
        if source not in self._stats["data_sources"]:
            self._stats["data_sources"].append(source)
