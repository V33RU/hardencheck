"""CycloneDX VEX 1.5 (Vulnerability Exploitability eXchange) report.

Emits CVE findings as a BOM of type "vex" with per-CVE analysis state
derived from reachability results. Not-reachable findings are marked
`not_affected` with justification `code_not_reachable`; reachable
findings stay `in_triage` (scanner cannot independently verify the fix).
"""
import json
import uuid
from datetime import datetime, timezone
from pathlib import Path

from hardencheck.constants.core import VERSION
from hardencheck.models import ScanResult, Severity


_SEV_TO_CDX = {
    Severity.CRITICAL: "critical",
    Severity.HIGH: "high",
    Severity.MEDIUM: "medium",
    Severity.LOW: "low",
    Severity.INFO: "info",
}


def _analysis(reachable: str, reason: str) -> dict:
    if reachable == "not_reachable":
        return {
            "state": "not_affected",
            "justification": "code_not_reachable",
            "detail": reason or "Component not referenced by any binary",
        }
    if reachable == "reachable":
        return {
            "state": "in_triage",
            "detail": reason or "Component is loaded by firmware binaries",
        }
    return {"state": "in_triage", "detail": "Reachability not evaluated"}


def generate_vex_report(result: ScanResult, output_path: Path) -> None:
    cve_findings = [
        f for f in result.security_tests
        if f.test_type in ("live_cve", "cve") and f.cve_id
    ]

    vulnerabilities = []
    seen = set()
    for f in cve_findings:
        key = (f.cve_id, f.component, f.version)
        if key in seen:
            continue
        seen.add(key)

        ratings = []
        # parse CVSS from details "CVSS: 9.8 (CRITICAL) | Vector: ..."
        details = f.details or ""
        score = None
        if "CVSS:" in details:
            try:
                head = details.split("CVSS:", 1)[1].strip().split()[0]
                score = float(head)
            except (ValueError, IndexError):
                score = None
        if score is not None:
            ratings.append({
                "source": {"name": "NVD"},
                "score": score,
                "severity": _SEV_TO_CDX.get(f.severity, "medium"),
                "method": "CVSSv31",
            })

        vulnerabilities.append({
            "id": f.cve_id,
            "source": {"name": "NVD", "url": f"https://nvd.nist.gov/vuln/detail/{f.cve_id}"},
            "ratings": ratings,
            "description": f.issue,
            "recommendation": f.recommendation,
            "affects": [{
                "ref": f.component,
                "versions": [{"version": f.version or "unknown", "status": "affected"}],
            }],
            "analysis": _analysis(f.reachable, f.reachability_reason),
        })

    bom = {
        "$schema": "http://cyclonedx.org/schema/bom-1.5.schema.json",
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "serialNumber": f"urn:uuid:{uuid.uuid4()}",
        "version": 1,
        "metadata": {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "tools": [{
                "vendor": "HardenCheck",
                "name": "hardencheck",
                "version": VERSION,
            }],
            "component": {
                "type": "firmware",
                "name": Path(result.target).name or "firmware",
                "version": result.profile.fw_type,
            },
        },
        "vulnerabilities": vulnerabilities,
    }

    output_path.write_text(json.dumps(bom, indent=2))
