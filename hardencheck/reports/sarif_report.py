"""SARIF 2.1.0 report for GitHub code-scanning integration."""
import json
from pathlib import Path

from hardencheck.constants.core import VERSION
from hardencheck.models import ScanResult, Severity


_SEVERITY_TO_LEVEL = {
    Severity.CRITICAL: "error",
    Severity.HIGH: "error",
    Severity.MEDIUM: "warning",
    Severity.LOW: "note",
    Severity.INFO: "none",
}


def _loc(uri: str, line: int = 1):
    return {
        "physicalLocation": {
            "artifactLocation": {"uri": uri},
            "region": {"startLine": max(1, int(line or 1))},
        }
    }


def _result(rule_id: str, message: str, uri: str, line: int, severity: Severity):
    return {
        "ruleId": rule_id,
        "level": _SEVERITY_TO_LEVEL.get(severity, "warning"),
        "message": {"text": message},
        "locations": [_loc(uri, line)],
    }


def generate_sarif_report(result: ScanResult, output_path: Path) -> None:
    rules = {}
    results = []

    def add_rule(rule_id: str, name: str, desc: str):
        if rule_id not in rules:
            rules[rule_id] = {
                "id": rule_id,
                "name": name,
                "shortDescription": {"text": name},
                "fullDescription": {"text": desc},
            }

    for hit in result.banned_functions:
        rid = f"banned-function/{hit.function}"
        add_rule(rid, f"Use of dangerous function {hit.function}",
                 f"Dangerous function '{hit.function}'. Prefer: {hit.alternative}")
        results.append(_result(rid, f"{hit.function}: {hit.snippet}", hit.file, hit.line, hit.severity))

    for c in result.credentials:
        rid = f"credential/{c.pattern}"
        add_rule(rid, "Hardcoded credential", f"Hardcoded credential matching '{c.pattern}'")
        results.append(_result(rid, c.snippet, c.file, c.line, c.severity))

    for cf in result.certificates:
        rid = "certificate-issue"
        add_rule(rid, "Certificate or key issue", "Certificate or private key issue detected.")
        results.append(_result(rid, f"{cf.file_type}: {cf.issue}", cf.file, 1, cf.severity))

    for ci in result.config_issues:
        rid = "insecure-config"
        add_rule(rid, "Insecure configuration", "Insecure configuration setting.")
        results.append(_result(rid, ci.issue, ci.file, ci.line, ci.severity))

    for b in result.binaries:
        missing = []
        if b.nx is False: missing.append("NX")
        if b.canary is False: missing.append("Canary")
        if b.pie is False: missing.append("PIE")
        if b.relro in ("none", "no"): missing.append("RELRO")
        if b.fortify is False: missing.append("FORTIFY_SOURCE")
        if missing:
            rid = "binary-hardening"
            add_rule(rid, "Missing binary hardening",
                     "Binary lacks one or more standard hardening features.")
            results.append(_result(
                rid, f"{b.filename}: missing {', '.join(missing)}",
                b.path, 1, Severity.MEDIUM,
            ))

    for s in result.security_tests:
        rid = f"security-test/{s.test_type or 'generic'}"
        add_rule(rid, s.test_type or "Security test finding", s.issue or "Security test finding")
        uri = s.affected_path or s.component or "firmware"
        results.append(_result(rid, f"{s.component}: {s.issue}", uri, 1, s.severity))

    sarif = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "HardenCheck",
                    "version": VERSION,
                    "informationUri": "https://github.com/v33ru/hardencheck",
                    "rules": list(rules.values()),
                }
            },
            "results": results,
        }],
    }

    output_path.write_text(json.dumps(sarif, indent=2))
