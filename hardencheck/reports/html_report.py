import html as html_module
from pathlib import Path
from typing import Dict, List, Tuple

from hardencheck.models import ASLRRating, ScanResult, Severity
from hardencheck.constants.core import VERSION
from hardencheck.reports.grading import classify_binary, calculate_grade


def esc(value) -> str:
    """HTML-escape a value to prevent XSS."""
    if value is None:
        return ""
    return html_module.escape(str(value))


GRADE_DESCRIPTIONS = {
    "A": "Excellent &mdash; strong security posture",
    "B": "Good &mdash; minor issues to address",
    "C": "Fair &mdash; moderate security gaps",
    "D": "Poor &mdash; significant weaknesses found",
    "F": "Critical &mdash; severe deficiencies, immediate action required.",
    "N/A": "No binaries analyzed",
}


def _aggregate_severities(result: ScanResult) -> Tuple[Dict[str, int], List[Tuple[str, str]]]:
    """Aggregate all findings into severity counts and top findings list.

    Returns:
        (counter_dict, top_findings) where counter_dict has keys
        'critical','high','medium','low' and top_findings is a sorted
        list of (severity_name, description) tuples.
    """
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    findings: List[Tuple[int, str, str]] = []  # (severity_value, severity_name, description)

    def add(sev: Severity, desc: str):
        key = sev.name.lower()
        if key in counts:
            counts[key] += 1
        findings.append((sev.value, sev.name, desc))

    # Banned functions
    for h in result.banned_functions:
        add(h.severity, f"Banned function: {h.function}() in {h.file}")

    # Credentials
    for c in result.credentials:
        add(c.severity, f"Hardcoded credential: {c.pattern} in {c.file}")

    # Certificates
    for c in result.certificates:
        add(c.severity, f"Certificate issue: {c.issue} ({c.file})")

    # Config issues
    for c in result.config_issues:
        add(c.severity, f"Config: {c.issue} in {c.file}")

    # Security tests
    for t in result.security_tests:
        add(t.severity, f"{t.test_type.replace('_', ' ').title()}: {t.issue}")

    # Insecure binaries → HIGH
    insecure_count = sum(1 for b in result.binaries if classify_binary(b) == "INSECURE")
    if insecure_count > 0:
        counts["high"] += 1
        findings.append((Severity.HIGH.value, "HIGH",
                         f"{insecure_count} binaries have no hardening protections"))

    # Kernel hardening
    if result.kernel_hardening:
        if not result.kernel_hardening.config_available:
            counts["critical"] += 1
            findings.append((Severity.CRITICAL.value, "CRITICAL",
                             "Kernel: Kernel config not found - cannot verify hardening"))
        else:
            for issue in result.kernel_hardening.issues:
                counts["high"] += 1
                findings.append((Severity.HIGH.value, "HIGH", f"Kernel: {issue}"))

    # Firmware signing
    if result.firmware_signing and not result.firmware_signing.is_signed:
        counts["high"] += 1
        findings.append((Severity.HIGH.value, "HIGH",
                         "Firmware is not signed - no integrity verification"))
    if result.firmware_signing:
        for issue in result.firmware_signing.issues:
            counts["high"] += 1
            findings.append((Severity.HIGH.value, "HIGH", f"Firmware signing: {issue}"))

    # Update mechanism
    if result.update_mechanism:
        risk_map = {"HIGH": Severity.HIGH, "MEDIUM": Severity.MEDIUM, "LOW": Severity.LOW}
        sev = risk_map.get(result.update_mechanism.risk_level, Severity.MEDIUM)
        for issue in result.update_mechanism.issues:
            key = sev.name.lower()
            if key in counts:
                counts[key] += 1
            findings.append((sev.value, sev.name, f"Update mechanism: {issue}"))

    # Crypto binaries
    risk_map = {"CRITICAL": Severity.CRITICAL, "HIGH": Severity.HIGH, "MEDIUM": Severity.MEDIUM, "LOW": Severity.LOW}
    for cb in result.crypto_binaries:
        sev = risk_map.get(cb.risk_level, Severity.MEDIUM)
        for issue in cb.issues:
            key = sev.name.lower()
            if key in counts:
                counts[key] += 1
            findings.append((sev.value, sev.name, f"Crypto binary {cb.name}: {issue}"))

    # Service privileges
    for sp in result.service_privileges:
        sev = risk_map.get(sp.risk_level, Severity.MEDIUM)
        for issue in sp.issues:
            key = sev.name.lower()
            if key in counts:
                counts[key] += 1
            findings.append((sev.value, sev.name, f"Service {sp.service_name}: {issue}"))

    # PQC readiness
    if result.pqc_readiness:
        for f in result.pqc_readiness.get("findings", []):
            sev = risk_map.get(f.get("risk_level", "MEDIUM"), Severity.MEDIUM)
            key = sev.name.lower()
            if key in counts:
                counts[key] += 1
            findings.append((sev.value, sev.name, f"PQC: {f['binary']} uses {', '.join(f.get('vulnerable_algorithms', [])[:3])} (quantum-vulnerable)"))

    # Sort by severity desc, take top 5
    findings.sort(key=lambda x: -x[0])
    # Deduplicate similar findings for top display
    seen = set()
    top = []
    for val, name, desc in findings:
        short = desc[:80]
        if short not in seen:
            seen.add(short)
            top.append((name, desc))
        if len(top) >= 5:
            break

    return counts, top


def generate_html_report(result: ScanResult, output_path: Path, slim: bool = False, extended: bool = False):
    """Generate HTML report with sidebar, executive summary, and collapsible sections."""
    total_binaries = len(result.binaries) or 1

    nx_count = sum(1 for b in result.binaries if b.nx is True)
    canary_count = sum(1 for b in result.binaries if b.canary is True)
    pie_count = sum(1 for b in result.binaries if b.pie is True)
    relro_count = sum(1 for b in result.binaries if b.relro == "full")
    fortify_count = sum(1 for b in result.binaries if b.fortify is True)
    stripped_count = sum(1 for b in result.binaries if b.stripped is True)
    stack_clash_count = sum(1 for b in result.binaries if b.stack_clash == "yes")
    cfi_count = sum(1 for b in result.binaries if b.cfi == "yes")

    secured = [b for b in result.binaries if classify_binary(b) == "SECURED"]
    partial = [b for b in result.binaries if classify_binary(b) == "PARTIAL"]
    insecure = [b for b in result.binaries if classify_binary(b) == "INSECURE"]

    grade, score = calculate_grade(result.binaries)
    display_score = round(score * 100 / 110) if score > 0 else 0
    grade_desc = GRADE_DESCRIPTIONS.get(grade, "")
    profile = result.profile
    aslr_summary = result.aslr_summary

    sev_counts, top_findings = _aggregate_severities(result)

    # --- Build table rows ---
    binary_rows = ""
    for binary in sorted(result.binaries, key=lambda x: x.filename):
        classification = classify_binary(binary)
        row_class = "rb" if classification == "INSECURE" else "rw" if classification == "PARTIAL" else ""

        def cell(value):
            if value is True: return '<td class="ok">Y</td>'
            elif value is False: return '<td class="bad">N</td>'
            elif value == "yes": return '<td class="ok">Y</td>'
            elif value == "no": return '<td class="bad">N</td>'
            elif value == "unknown": return '<td class="wrn">?</td>'
            elif value == "skipped": return ''
            elif value == "full": return '<td class="ok">full</td>'
            elif value == "partial": return '<td class="wrn">partial</td>'
            elif value == "none": return '<td class="bad">none</td>'
            else: return f"<td>{esc(value)}</td>"

        binary_rows += f'<tr class="{row_class}"><td class="fn">{esc(binary.filename)}</td>'
        binary_rows += cell(binary.nx) + cell(binary.canary) + cell(binary.pie) + cell(binary.relro)
        binary_rows += cell(binary.fortify) + cell(binary.stripped)
        if extended:
            binary_rows += cell(binary.stack_clash) + cell(binary.cfi)
        binary_rows += f'<td class="{"bad" if binary.textrel else "ok"}">{"-" if not binary.textrel else "!"}</td>'
        binary_rows += f'<td class="{"bad" if binary.rpath else "ok"}">{esc(binary.rpath[:12]) if binary.rpath else "-"}</td>'
        binary_rows += f"<td>{binary.confidence}%</td></tr>"

    aslr_rows = ""
    binaries_with_aslr = [b for b in result.binaries if b.aslr_analysis]
    for binary in sorted(binaries_with_aslr, key=lambda x: x.aslr_analysis.effective_entropy if x.aslr_analysis else 0):
        aslr = binary.aslr_analysis
        if not aslr:
            continue
        rating_class = {"Excellent": "ok", "Good": "ok", "Moderate": "wrn", "Weak": "bad", "Ineffective": "bad"}.get(aslr.rating.value, "")
        row_class = "rb" if aslr.rating in (ASLRRating.WEAK, ASLRRating.INEFFECTIVE) else ""
        issues_str = "; ".join(aslr.issues[:2]) if aslr.issues else "-"
        if len(aslr.issues) > 2:
            issues_str += f" (+{len(aslr.issues)-2})"
        aslr_rows += f'<tr class="{row_class}"><td class="fn">{esc(aslr.filename)}</td>'
        aslr_rows += f'<td>{esc(aslr.arch)}</td><td>{aslr.bits}-bit</td>'
        aslr_rows += f'<td class="{"ok" if aslr.is_pie else "bad"}">{"Yes" if aslr.is_pie else "No"}</td>'
        aslr_rows += f'<td>{aslr.theoretical_entropy}</td><td class="{rating_class}">{aslr.effective_entropy}</td>'
        aslr_rows += f'<td class="{rating_class}">{esc(aslr.rating.value)}</td>'
        aslr_rows += f'<td class="{"bad" if aslr.has_textrel else "ok"}">{"Yes" if aslr.has_textrel else "No"}</td>'
        aslr_rows += f'<td class="loc">{esc(issues_str)}</td></tr>'

    daemon_rows = ""
    for daemon in result.daemons:
        risk_class = "bad" if daemon.risk == "CRITICAL" else "wrn" if daemon.risk in ("HIGH", "UNKNOWN") else ""
        status_class = "ok" if daemon.status == "SECURED" else "bad" if daemon.status == "INSECURE" else "wrn"
        daemon_rows += f'<tr><td class="{risk_class}">{esc(daemon.risk)}</td><td>{esc(daemon.name)}</td>'
        daemon_rows += f'<td>{esc(daemon.binary)}</td><td>{esc(daemon.version)}</td>'
        daemon_rows += f'<td class="loc">{esc(daemon.path)}</td><td class="{status_class}">{esc(daemon.status)}</td>'
        daemon_rows += f'<td class="loc">{esc(daemon.reason)}</td></tr>'

    banned_rows = ""
    for hit in sorted(result.banned_functions, key=lambda x: (-x.severity.value, x.function)):
        sev_class = "bad" if hit.severity.value >= 3 else "wrn"
        clean_path = hit.file
        for pattern in ["_extract/", ".zip_extract/", ".tar_extract/"]:
            if pattern in clean_path:
                clean_path = clean_path.split(pattern)[-1]
                break
        location = f"{clean_path}:{hit.line}" if hit.line else clean_path
        banned_rows += f'<tr><td class="bad">{esc(hit.function)}()</td><td class="loc">{esc(location)}</td>'
        banned_rows += f'<td class="ok">{esc(hit.alternative)}</td><td class="{sev_class}">{esc(hit.severity.name)}</td>'
        banned_rows += f'<td class="loc">{esc(hit.compliance)}</td></tr>'

    dep_rows = "".join(f'<tr><td class="bad">{esc(r.library)}</td><td>{esc(r.issue)}</td><td>{esc(", ".join(r.used_by[:5]))}</td></tr>' for r in result.dependency_risks)
    cred_rows = "".join(f'<tr><td class="loc">{esc(c.file)}:{c.line}</td><td class="{"bad" if c.severity.value >= 3 else "wrn"}">{esc(c.pattern)}</td><td class="loc">{esc(c.snippet[:50])}</td></tr>' for c in result.credentials)
    cert_rows = "".join(f'<tr><td class="loc">{esc(c.file)}</td><td>{esc(c.file_type)}</td><td class="{"bad" if c.severity.value >= 3 else "wrn" if c.severity.value >= 2 else ""}">{esc(c.issue)}</td></tr>' for c in result.certificates)
    config_rows = "".join(f'<tr><td class="loc">{esc(i.file)}:{i.line}</td><td class="{"bad" if i.severity.value >= 3 else "wrn"}">{esc(i.issue)}</td><td class="loc">{esc(i.snippet[:50])}</td></tr>' for i in result.config_issues)

    # Security tests (Vuln Versions)
    vuln_rows = ""
    for t in sorted(result.security_tests, key=lambda x: -x.severity.value):
        sev_class = "bad" if t.severity.value >= 3 else "wrn" if t.severity.value >= 2 else ""
        vuln_rows += f'<tr><td class="{sev_class}">{esc(t.severity.name)}</td><td>{esc(t.test_type)}</td>'
        vuln_rows += f'<td>{esc(t.component)}</td><td>{esc(t.version)}</td>'
        vuln_rows += f'<td>{esc(t.issue)}</td><td class="loc">{esc(t.cve_id)}</td></tr>'

    # PQC readiness section
    pqc_html = ""
    if result.pqc_readiness and result.pqc_readiness.get("findings"):
        pqc = result.pqc_readiness
        pqc_overall = pqc["overall_readiness"]
        pqc_color = {"READY": "ok", "HYBRID": "wrn", "NOT_READY": "bad", "CRITICAL": "bad"}.get(pqc_overall, "dm")
        pqc_summ = pqc.get("summary", {})

        pqc_html += f'''<div class="profile">
<div class="profile-row"><span class="profile-label">Overall Readiness</span><span class="{pqc_color}" style="font-weight:700">{esc(pqc_overall)}</span></div>
<div class="profile-row"><span class="profile-label">Crypto Binaries</span><span>{pqc_summ.get("total_crypto_binaries", 0)}</span></div>
<div class="profile-row"><span class="profile-label">PQC Ready</span><span class="ok">{pqc_summ.get("pqc_ready", 0)}</span></div>
<div class="profile-row"><span class="profile-label">Hybrid (Classical+PQC)</span><span class="wrn">{pqc_summ.get("hybrid", 0)}</span></div>
<div class="profile-row"><span class="profile-label">Vulnerable Only</span><span class="bad">{pqc_summ.get("vulnerable_only", 0)}</span></div>
<div class="profile-row"><span class="profile-label">Deprecated Crypto</span><span class="bad">{pqc_summ.get("deprecated", 0)}</span></div>
</div>'''

        pqc_rows = ""
        for f in pqc["findings"]:
            r_class = {"READY": "ok", "HYBRID": "wrn", "NOT_READY": "bad", "CRITICAL": "bad"}.get(f["readiness"], "dm")
            risk_class = "bad" if f["risk_level"] in ("CRITICAL", "HIGH") else "wrn" if f["risk_level"] == "MEDIUM" else ""
            vuln_str = ", ".join(f.get("vulnerable_algorithms", [])[:4]) or "None"
            pqc_str = ", ".join(f.get("pqc_algorithms", [])[:3]) or "None"
            pqc_rows += f'<tr><td class="loc">{esc(f["binary"])}</td><td>{esc(f.get("crypto_library", ""))}</td>'
            pqc_rows += f'<td>{esc(f.get("crypto_version", ""))}</td>'
            pqc_rows += f'<td class="bad">{esc(vuln_str)}</td>'
            pqc_rows += f'<td class="ok">{esc(pqc_str)}</td>'
            pqc_rows += f'<td>{"Yes" if f.get("has_network") else "No"}</td>'
            pqc_rows += f'<td class="{r_class}">{esc(f["readiness"])}</td>'
            pqc_rows += f'<td class="{risk_class}">{esc(f["risk_level"])}</td></tr>'

        pqc_html += f'''<div class="tbl-wrap tbl-scroll" style="margin-top:10px">
<table id="pqcTable"><thead><tr><th>Binary</th><th>Crypto Lib</th><th>Version</th><th>Vulnerable Algos</th><th>PQC Algos</th><th>Network</th><th>Readiness</th><th>Risk</th></tr></thead>
<tbody>{pqc_rows}</tbody></table></div>'''

        recs = pqc.get("recommendations", [])
        if recs:
            pqc_html += '<div style="margin-top:12px"><strong>Recommendations:</strong><ul style="margin:5px 0;padding-left:20px">'
            for r in recs:
                pqc_html += f'<li style="margin:3px 0;font-size:11px">{esc(r)}</li>'
            pqc_html += '</ul></div>'
    else:
        pqc_html = '<div class="dm">No quantum-vulnerable cryptographic algorithm usage detected</div>'

    # Crypto binaries section
    crypto_bin_rows = ""
    if result.crypto_binaries:
        for cb in result.crypto_binaries:
            risk_class = "bad" if cb.risk_level in ("CRITICAL", "HIGH") else "wrn" if cb.risk_level == "MEDIUM" else ""
            sf = cb.security_flags
            def sflag(key):
                val = sf.get(key)
                if val is True: return '<td class="ok">Y</td>'
                elif val is False: return '<td class="bad">N</td>'
                elif val == "full": return '<td class="ok">full</td>'
                elif val == "partial": return '<td class="wrn">partial</td>'
                elif val == "none": return '<td class="bad">none</td>'
                return '<td class="dm">?</td>'
            issues_str = "; ".join(cb.issues[:2]) if cb.issues else "-"
            if len(cb.issues) > 2:
                issues_str += f" (+{len(cb.issues)-2})"
            crypto_bin_rows += f'<tr><td class="fn">{esc(cb.name)}</td><td>{esc(cb.purpose)}</td>'
            crypto_bin_rows += f'<td>{esc(cb.version)}</td>'
            crypto_bin_rows += f'<td>{"Yes" if cb.has_network else "No"}</td>'
            crypto_bin_rows += sflag("nx") + sflag("pie") + sflag("canary") + sflag("relro")
            crypto_bin_rows += f'<td class="{risk_class}">{esc(cb.risk_level)}</td>'
            crypto_bin_rows += f'<td class="loc">{esc(issues_str)}</td></tr>'

    # Service privileges section
    svc_priv_rows = ""
    if result.service_privileges:
        for sp in result.service_privileges:
            risk_class = "bad" if sp.risk_level in ("CRITICAL", "HIGH") else "wrn" if sp.risk_level == "MEDIUM" else ""
            root_class = "bad" if sp.runs_as_root else "ok"
            cap_str = ", ".join(sp.capabilities[:3]) if sp.capabilities else "-"
            if len(sp.capabilities) > 3:
                cap_str += f" (+{len(sp.capabilities)-3})"
            svc_priv_rows += f'<tr><td class="fn">{esc(sp.service_name)}</td>'
            svc_priv_rows += f'<td class="loc">{esc(sp.binary_path)}</td>'
            svc_priv_rows += f'<td>{esc(sp.user)}:{esc(sp.group)}</td>'
            svc_priv_rows += f'<td class="{root_class}">{"Yes" if sp.runs_as_root else "No"}</td>'
            svc_priv_rows += f'<td class="loc">{esc(cap_str)}</td>'
            svc_priv_rows += f'<td class="{"ok" if sp.chroot_jail else "dm"}">{"Yes" if sp.chroot_jail else "No"}</td>'
            svc_priv_rows += f'<td class="{"ok" if sp.namespace_isolation else "dm"}">{"Yes" if sp.namespace_isolation else "No"}</td>'
            svc_priv_rows += f'<td class="{"ok" if sp.cgroup_restrictions else "dm"}">{"Yes" if sp.cgroup_restrictions else "No"}</td>'
            svc_priv_rows += f'<td class="{risk_class}">{esc(sp.risk_level)}</td></tr>'

    # Update mechanism section
    update_html = ""
    if result.update_mechanism:
        um = result.update_mechanism
        risk_class = "bad" if um.risk_level in ("CRITICAL", "HIGH") else "wrn" if um.risk_level == "MEDIUM" else "ok"
        update_html = f'''<div class="profile">
<div class="profile-row"><span class="profile-label">Update System</span><span>{esc(um.update_system)}</span></div>
<div class="profile-row"><span class="profile-label">Update Binary</span><span>{esc(um.update_binary) if um.update_binary else '<span class="dm">Not found</span>'}</span></div>
<div class="profile-row"><span class="profile-label">Config File</span><span class="loc">{esc(um.update_config) if um.update_config else '<span class="dm">Not found</span>'}</span></div>
<div class="profile-row"><span class="profile-label">HTTPS</span><span class="{"ok" if um.uses_https else "bad"}">{"Yes" if um.uses_https else "No"}</span></div>
<div class="profile-row"><span class="profile-label">Signature Verification</span><span class="{"ok" if um.uses_signing else "bad"}">{"Yes" if um.uses_signing else "No"}</span></div>
<div class="profile-row"><span class="profile-label">Rollback Protection</span><span class="{"ok" if um.has_rollback_protection else "bad"}">{"Yes" if um.has_rollback_protection else "No"}</span></div>
<div class="profile-row"><span class="profile-label">Update Server</span><span class="loc">{esc(um.update_server) if um.update_server else '<span class="dm">Not configured</span>'}</span></div>
<div class="profile-row"><span class="profile-label">Risk Level</span><span class="{risk_class}">{esc(um.risk_level)}</span></div>
</div>'''
        if um.issues:
            update_html += '<div style="margin-top:10px">'
            for issue in um.issues:
                update_html += f'<div class="top-finding"><span class="sev-badge high">ISSUE</span><span>{esc(issue)}</span></div>'
            update_html += '</div>'
        if um.recommendation:
            update_html += f'<div style="margin-top:8px;font-size:11px;color:var(--dm)"><b>Recommendation:</b> {esc(um.recommendation)}</div>'
    else:
        update_html = '<div class="dm">No update mechanism data available</div>'

    # Missing tools warning
    missing_tools_html = ""
    if result.missing_tools:
        tools_list = ", ".join(result.missing_tools)
        missing_tools_html = f'''<div style="background:rgba(210,153,34,0.1);border:1px solid var(--wrn);padding:10px;margin-bottom:15px;border-radius:4px;font-size:11px">
<span class="wrn" style="font-weight:600">Missing Tools:</span> {esc(tools_list)}
<div class="dm" style="margin-top:4px">Some analysis capabilities are reduced. Install missing tools for complete results.</div>
</div>'''

    # SBOM table rows
    sbom_rows = ""
    sbom_summary_html = ""
    sbom_dep_rows = ""
    if result.sbom and result.sbom.components:
        sbom = result.sbom
        for comp in sbom.components:
            type_class = "ok" if comp.component_type == "library" else "wrn" if comp.component_type == "application" else ""
            ver_class = "ok" if comp.version and comp.version != "Unknown" else "bad"
            cpe_short = comp.cpe.split(":")[4] + ":" + comp.cpe.split(":")[5] if comp.cpe and len(comp.cpe.split(":")) > 5 else "-"
            sec_str = ""
            if comp.security_flags:
                flags = []
                for flag, val in comp.security_flags.items():
                    if isinstance(val, bool):
                        flags.append(f'<span class="{"ok" if val else "bad"}">{flag.upper()}</span>')
                    else:
                        flags.append(f'<span class="{"ok" if val == "full" else "wrn" if val == "partial" else "bad"}">{flag}={val}</span>')
                sec_str = " ".join(flags)
            sbom_rows += f'<tr><td class="fn">{esc(comp.name)}</td><td class="{ver_class}">{esc(comp.version)}</td>'
            sbom_rows += f'<td class="{type_class}">{esc(comp.component_type)}</td>'
            sbom_rows += f'<td>{esc(comp.supplier) if comp.supplier else "<span class=dm>-</span>"}</td>'
            sbom_rows += f'<td class="loc">{esc(cpe_short)}</td><td class="loc">{esc(comp.license_id) if comp.license_id else "-"}</td>'
            sbom_rows += f'<td class="loc">{esc(comp.source)}</td><td>{sec_str if sec_str else "-"}</td></tr>'

        for binary_path, needed_libs in sorted(sbom.dependency_tree.items()):
            binary_name = Path(binary_path).name
            for lib in needed_libs:
                lib_ver = ""
                for comp in sbom.components:
                    lib_base = lib.lower().split(".so")[0] if ".so" in lib.lower() else lib.lower()
                    if comp.name.lower() == lib_base or lib.lower().startswith(comp.name.lower()):
                        lib_ver = comp.version
                        break
                ver_class = "ok" if lib_ver and lib_ver != "Unknown" else "dm"
                sbom_dep_rows += f'<tr><td class="fn">{esc(binary_name)}</td><td>{esc(lib)}</td>'
                sbom_dep_rows += f'<td class="{ver_class}">{esc(lib_ver) if lib_ver else "?"}</td></tr>'

        sbom_summary_html = f'''<div class="aslr-stats">
<div class="aslr-stat"><div class="aslr-stat-value">{sbom.total_components}</div><div class="aslr-stat-label">Components</div></div>
<div class="aslr-stat"><div class="aslr-stat-value">{sbom.total_applications}</div><div class="aslr-stat-label">Applications</div></div>
<div class="aslr-stat"><div class="aslr-stat-value">{sbom.total_libraries}</div><div class="aslr-stat-label">Libraries</div></div>
<div class="aslr-stat"><div class="aslr-stat-value">{sbom.components_with_cpe}</div><div class="aslr-stat-label">With CPE</div></div>
</div>
<div class="aslr-ratings">
<div class="ar-item ar-good">Versioned: {sbom.components_with_version}/{sbom.total_components}</div>
<div class="ar-item ar-excellent">CPE Mapped: {sbom.components_with_cpe}/{sbom.total_components}</div>
<div class="ar-item ar-moderate">Dep Links: {len(sbom.dependency_tree)}</div>
{f'<div class="ar-item ar-weak">Pkg Source: {sbom.package_manager_source}</div>' if sbom.package_manager_source else ''}
</div>'''

    def build_class_section(title, items, css_class):
        if not items: return ""
        content = ""
        for b in items:
            missing = []
            if b.nx is not True: missing.append("NX")
            if b.canary is not True: missing.append("Canary")
            if b.pie is not True: missing.append("PIE")
            if b.relro != "full": missing.append("RELRO")
            if b.fortify is not True: missing.append("Fortify")
            content += f'<div class="ci"><b>{esc(b.filename)}</b><span class="cp">{esc(b.path)}</span><span class="cm">{", ".join(missing) if missing else "All OK"}</span></div>'
        scroll = ' style="max-height:400px;overflow-y:auto"' if len(items) > 20 else ''
        return f'<div class="cs {css_class}"><div class="ct">{esc(title)} ({len(items)})</div><div{scroll}>{content}</div></div>'

    def progress_bar(label, count, total):
        pct = count / total * 100 if total > 0 else 0
        bar_class = "lo" if pct < 50 else "me" if pct < 80 else ""
        return f'<div class="pi"><span class="pl">{esc(label)}</span><div class="pb"><div class="pf {bar_class}" style="width:{pct:.0f}%"></div></div><span class="pv">{count}/{total}</span></div>'

    aslr_summary_html = ""
    if aslr_summary.get("analyzed", 0) > 0:
        aslr_summary_html = f'''<div class="aslr-stats">
<div class="aslr-stat"><div class="aslr-stat-value">{aslr_summary.get("avg_effective_entropy", 0):.1f}</div><div class="aslr-stat-label">Avg Entropy (bits)</div></div>
<div class="aslr-stat"><div class="aslr-stat-value">{aslr_summary.get("min_effective_entropy", 0)}</div><div class="aslr-stat-label">Min Entropy</div></div>
<div class="aslr-stat"><div class="aslr-stat-value">{aslr_summary.get("max_effective_entropy", 0)}</div><div class="aslr-stat-label">Max Entropy</div></div>
<div class="aslr-stat"><div class="aslr-stat-value">{aslr_summary.get("total_pie_binaries", 0)}</div><div class="aslr-stat-label">PIE Binaries</div></div>
</div>
<div class="aslr-ratings">
<div class="ar-item ar-excellent">Excellent: {aslr_summary.get("by_rating", {}).get("excellent", 0)}</div>
<div class="ar-item ar-good">Good: {aslr_summary.get("by_rating", {}).get("good", 0)}</div>
<div class="ar-item ar-moderate">Moderate: {aslr_summary.get("by_rating", {}).get("moderate", 0)}</div>
<div class="ar-item ar-weak">Weak: {aslr_summary.get("by_rating", {}).get("weak", 0)}</div>
<div class="ar-item ar-ineff">Ineffective: {aslr_summary.get("by_rating", {}).get("ineffective", 0)}</div>
</div>
{f'<div class="aslr-issues"><b>Common Issues:</b><ul>{"".join(f"<li>{k}: {v} binaries</li>" for k, v in list(aslr_summary.get("common_issues", {}).items())[:5])}</ul></div>' if aslr_summary.get("common_issues") else ""}'''

    # Top findings HTML
    top_findings_html = ""
    for sev_name, desc in top_findings:
        badge_class = sev_name.lower()
        top_findings_html += f'<div class="top-finding"><span class="sev-badge {badge_class}">{esc(sev_name)}</span><span>{esc(desc)}</span></div>'

    # --- CSS ---
    slim_css = """body{font-family:monospace;font-size:12px;padding:10px;background:#111;color:#ccc}
table{border-collapse:collapse;width:100%}th,td{border:1px solid #333;padding:4px}
.ok{color:#3fb950}.bad{color:#f85149}.wrn{color:#d29922}
h1{font-size:16px}h2{font-size:14px}.card{background:#161b22;padding:10px;margin:10px 0;border:1px solid #333}
.card-body.collapsed{display:none}.toggle-btn{cursor:pointer;float:right}"""

    full_css = """*{margin:0;padding:0;box-sizing:border-box}
:root{--bg:#0d1117;--cd:#161b22;--bd:#30363d;--tx:#c9d1d9;--dm:#8b949e;--ok:#3fb950;--bad:#f85149;--wrn:#d29922}
body{font-family:'Fira Code',monospace;background:var(--bg);color:var(--tx);font-size:12px;padding:0;line-height:1.5}
.sidebar{position:fixed;left:0;top:0;width:200px;height:100vh;background:var(--cd);border-right:1px solid var(--bd);padding:0;overflow-y:auto;z-index:100}
.sidebar-header{padding:15px;border-bottom:1px solid var(--bd)}
.sidebar-header h2{font-size:14px;font-weight:600;margin:0}
.sidebar-header .sidebar-ver{font-size:10px;color:var(--dm)}
.sidebar a{display:block;padding:8px 15px;color:var(--dm);text-decoration:none;font-size:11px;border-left:3px solid transparent;transition:all 0.15s}
.sidebar a:hover,.sidebar a.active{color:var(--tx);background:var(--bg);border-left-color:var(--ok)}
.main-content{margin-left:200px;padding:20px;max-width:1600px}
h1{font-size:18px;font-weight:600;margin-bottom:5px}
.meta{color:var(--dm);font-size:11px;margin-bottom:20px;display:flex;align-items:center;justify-content:space-between}
.print-btn{background:var(--bd);border:1px solid var(--bd);color:var(--tx);padding:6px 14px;font-size:11px;font-family:inherit;cursor:pointer;border-radius:4px;display:flex;align-items:center;gap:6px}
.print-btn:hover{background:#444}
@media print{
.sidebar{display:none!important}
.main-content{margin-left:0!important;padding:10px!important}
.print-btn{display:none!important}
.toggle-btn{display:none!important}
.card-body,.card-body.collapsed{display:block!important;overflow:visible!important}
.tbl-scroll{max-height:none!important;overflow:visible!important}
.tbl-wrap{overflow:visible!important}
table{page-break-inside:auto}
tr{page-break-inside:avoid;page-break-after:auto}
thead{display:table-header-group}
section{page-break-before:auto;page-break-inside:avoid}
.card{page-break-inside:avoid;border:1px solid #555!important;margin-bottom:10px}
.card-title{background:#eee!important;color:#111!important;border-bottom:1px solid #999!important}
body{background:#fff!important;color:#111!important;font-size:10px!important}
.ok{color:#1a7f37!important}.bad{color:#cf222e!important}.wrn{color:#9a6700!important}.dm{color:#666!important}
.sev-box{border:1px solid #ccc!important}
.sev-badge{border:1px solid #999!important}
td,th{border-bottom:1px solid #ccc!important}
}
.card{background:var(--cd);border:1px solid var(--bd);margin-bottom:15px;border-radius:4px}
.card-title{font-size:13px;font-weight:600;padding:12px 15px;border-bottom:1px solid var(--bd);cursor:pointer;display:flex;align-items:center;justify-content:space-between;user-select:none}
.card-title:hover{background:rgba(255,255,255,0.02)}
.card-body{padding:15px}
.card-body.collapsed{display:none}
.toggle-btn{font-size:10px;color:var(--dm);transition:transform 0.2s;display:inline-block}
.toggle-btn.expanded{transform:rotate(90deg)}
.grade-row{display:flex;align-items:center;gap:20px;margin-bottom:15px}
.grade{font-size:48px;font-weight:600;line-height:1}
.ga{color:var(--ok)}.gb{color:#58a6ff}.gc{color:var(--wrn)}.gd{color:#f0883e}.gf{color:var(--bad)}
.grade-info .grade-score{font-size:14px;color:var(--dm)}
.grade-info .grade-desc{font-size:12px;margin-top:4px}
.sev-counters{display:grid;grid-template-columns:repeat(4,1fr);gap:10px;margin-bottom:15px}
.sev-box{padding:12px;text-align:center;border-radius:4px;background:var(--bd)}
.sev-box .sev-num{font-size:28px;font-weight:600}
.sev-box .sev-label{font-size:9px;text-transform:uppercase;color:var(--dm);margin-top:2px}
.sev-critical .sev-num{color:var(--bad)}
.sev-high .sev-num{color:#f0883e}
.sev-medium .sev-num{color:var(--wrn)}
.sev-low .sev-num{color:var(--dm)}
.top-findings{border-top:1px solid var(--bd);padding-top:10px}
.top-finding{padding:8px 0;border-bottom:1px solid var(--bd);display:flex;align-items:center;gap:10px;font-size:11px}
.top-finding:last-child{border-bottom:none}
.sev-badge{padding:2px 8px;font-size:9px;font-weight:600;border-radius:3px;min-width:65px;text-align:center;text-transform:uppercase;flex-shrink:0}
.sev-badge.critical{background:rgba(248,81,73,0.2);color:var(--bad)}
.sev-badge.high{background:rgba(240,136,62,0.2);color:#f0883e}
.sev-badge.medium{background:rgba(210,153,34,0.2);color:var(--wrn)}
.sev-badge.low{background:rgba(139,148,158,0.15);color:var(--dm)}
.summary{display:grid;grid-template-columns:repeat(3,1fr);gap:10px;margin-bottom:15px}
.sum-card{background:var(--cd);border:1px solid var(--bd);padding:12px;text-align:center}
.sum-card.se{border-color:var(--ok)}.sum-card.pa{border-color:var(--wrn)}.sum-card.in{border-color:var(--bad)}
.sum-num{font-size:28px;font-weight:600}
.sum-num.se{color:var(--ok)}.sum-num.pa{color:var(--wrn)}.sum-num.in{color:var(--bad)}
.sum-label{font-size:10px;color:var(--dm);text-transform:uppercase}
.profile{display:grid;grid-template-columns:1fr 1fr;gap:8px}
.profile-row{display:flex;justify-content:space-between;padding:4px 0;border-bottom:1px solid var(--bd)}
.profile-label{color:var(--dm)}
.pi{display:flex;align-items:center;margin-bottom:8px}
.pl{width:100px;font-size:11px}
.pb{flex:1;height:6px;background:var(--bd);margin:0 10px}
.pf{height:100%;background:var(--ok);transition:width 0.3s}
.pf.lo{background:var(--bad)}.pf.me{background:var(--wrn)}
.pv{width:50px;font-size:10px;text-align:right;color:var(--dm)}
table{width:100%;border-collapse:collapse;font-size:11px}
th{text-align:left;padding:6px;border-bottom:1px solid var(--bd);color:var(--dm);font-weight:500}
td{padding:6px;border-bottom:1px solid var(--bd)}
.fn{font-weight:500}.ok{color:var(--ok)}.bad{color:var(--bad)}.wrn{color:var(--wrn)}.dm{color:var(--dm)}
.rb{background:rgba(255,51,51,0.08)}.rw{background:rgba(255,170,0,0.05)}
.loc{color:var(--dm);font-size:10px}
.cs{margin-bottom:10px;border:1px solid var(--bd)}
.cs .ct{padding:8px 12px;font-weight:500;border-bottom:1px solid var(--bd)}
.cs.se .ct{border-left:3px solid var(--ok)}.cs.pa .ct{border-left:3px solid var(--wrn)}.cs.in .ct{border-left:3px solid var(--bad)}
.ci{padding:6px 12px;border-bottom:1px solid var(--bd)}.ci:last-child{border-bottom:none}
.ci b{display:block}.cp{font-size:10px;color:var(--dm);display:block}.cm{font-size:10px;color:var(--bad)}
.tools{display:flex;flex-wrap:wrap;gap:8px}.tool{background:var(--bd);padding:4px 10px;font-size:10px}
.tbl-wrap{overflow-x:auto;display:block}.tbl-scroll{max-height:500px;overflow-y:auto;display:block}
.search-box{margin-bottom:10px;display:flex;gap:8px;align-items:center}
.search-box input{background:var(--bd);border:1px solid var(--bd);color:var(--tx);padding:6px 10px;font-size:11px;font-family:inherit;width:200px}
.search-box button{background:var(--bd);border:1px solid var(--bd);color:var(--tx);padding:6px 12px;font-size:10px;cursor:pointer}
.search-box button:hover{background:#444}
.aslr-stats{display:grid;grid-template-columns:repeat(4,1fr);gap:10px;margin-bottom:15px}
.aslr-stat{background:var(--bd);padding:12px;text-align:center;border-radius:4px}
.aslr-stat-value{font-size:24px;font-weight:600;color:var(--ok)}
.aslr-stat-label{font-size:10px;color:var(--dm);text-transform:uppercase;margin-top:4px}
.aslr-ratings{display:flex;flex-wrap:wrap;gap:8px;margin-bottom:15px}
.ar-item{padding:6px 12px;font-size:11px;border-radius:3px;background:var(--bd)}
.ar-excellent{border-left:3px solid var(--ok)}.ar-good{border-left:3px solid #58a6ff}
.ar-moderate{border-left:3px solid var(--wrn)}.ar-weak{border-left:3px solid #f0883e}.ar-ineff{border-left:3px solid var(--bad)}
.aslr-issues ul{margin-left:20px;margin-top:5px}.aslr-issues li{color:var(--dm);margin-bottom:3px}"""

    css = slim_css if slim else full_css
    font_link = "" if slim else '<link href="https://fonts.googleapis.com/css2?family=Fira+Code:wght@400;600&display=swap" rel="stylesheet">'

    # --- Sidebar ---
    sidebar_html = f'''<nav class="sidebar">
<div class="sidebar-header"><h2>HardenCheck</h2><div class="sidebar-ver">v{VERSION} Security Report</div></div>
<a href="#sec-overview" class="active">Overview</a>
<a href="#sec-profile">Firmware Profile</a>
<a href="#sec-hardening">Binary Hardening</a>
<a href="#sec-aslr">ASLR Entropy</a>
<a href="#sec-services">Network Services</a>
<a href="#sec-kernel">Kernel Hardening</a>
<a href="#sec-signing">Firmware Signing</a>
<a href="#sec-crypto-bins">Crypto Binaries</a>
<a href="#sec-svc-privs">Service Privileges</a>
<a href="#sec-update">Update Mechanism</a>
<a href="#sec-deps">Dep Risks</a>
<a href="#sec-banned">Banned Functions</a>
<a href="#sec-vulns">Vuln Versions</a>
<a href="#sec-pqc">PQC Readiness</a>
<a href="#sec-sbom">SBOM</a>
<a href="#sec-classification">Classification</a>
</nav>''' if not slim else ''

    # --- Kernel hardening section ---
    kernel_html = ""
    if result.kernel_hardening and result.kernel_hardening.config_available:
        kh = result.kernel_hardening
        def kflag(val):
            return f'<span class="ok">Enabled</span>' if val else f'<span class="bad">Disabled</span>'
        kernel_html = f'''<div class="profile">
<div class="profile-row"><span class="profile-label">Config Source</span><span>{esc(kh.config_source)}</span></div>
<div class="profile-row"><span class="profile-label">Hardening Score</span><span>{kh.hardening_score}/100</span></div>
<div class="profile-row"><span class="profile-label">KASLR</span>{kflag(kh.kaslr_enabled)}</div>
<div class="profile-row"><span class="profile-label">SMEP</span>{kflag(kh.smep_enabled)}</div>
<div class="profile-row"><span class="profile-label">SMAP</span>{kflag(kh.smap_enabled)}</div>
<div class="profile-row"><span class="profile-label">PXN (ARM)</span>{kflag(kh.pxn_enabled)}</div>
<div class="profile-row"><span class="profile-label">Stack Protector</span>{kflag(kh.stack_protector)}</div>
<div class="profile-row"><span class="profile-label">FORTIFY_SOURCE</span>{kflag(kh.fortify_source)}</div>
<div class="profile-row"><span class="profile-label">Usercopy Protection</span>{kflag(kh.usercopy_protection)}</div>
<div class="profile-row"><span class="profile-label">RODATA Enforced</span>{kflag(kh.rodata_enforced)}</div>
<div class="profile-row"><span class="profile-label">dmesg Restricted</span>{kflag(kh.dmesg_restricted)}</div>
</div>'''
        if kh.issues:
            kernel_html += '<div style="margin-top:10px">'
            for issue in kh.issues:
                kernel_html += f'<div class="top-finding"><span class="sev-badge high">ISSUE</span><span>{esc(issue)}</span></div>'
            kernel_html += '</div>'
        if kh.recommendations:
            kernel_html += '<div style="margin-top:10px"><strong>Recommendations:</strong><ul style="margin:5px 0;padding-left:20px">'
            for rec in kh.recommendations:
                kernel_html += f'<li style="margin:3px 0;font-size:11px">{esc(rec)}</li>'
            kernel_html += '</ul></div>'
    elif result.kernel_hardening:
        kernel_html = '<div class="bad">Kernel config not found - cannot verify hardening</div>'
    else:
        kernel_html = '<div class="dm">No kernel hardening data available</div>'

    # --- Firmware signing section ---
    signing_html = ""
    if result.firmware_signing:
        fs = result.firmware_signing
        signing_html = f'''<div class="profile">
<div class="profile-row"><span class="profile-label">Signed</span><span class="{"ok" if fs.is_signed else "bad"}">{"Yes" if fs.is_signed else "No"}</span></div>
<div class="profile-row"><span class="profile-label">Signing Method</span><span>{esc(fs.signing_method)}</span></div>
<div class="profile-row"><span class="profile-label">Secure Boot</span><span class="{"ok" if fs.secure_boot_enabled else "bad"}">{"Enabled" if fs.secure_boot_enabled else "Disabled"}</span></div>
<div class="profile-row"><span class="profile-label">Signature Files</span><span>{len(fs.signature_files)}</span></div>
</div>'''
        if fs.issues:
            signing_html += '<div style="margin-top:10px">'
            for issue in fs.issues:
                signing_html += f'<div class="top-finding"><span class="sev-badge high">ISSUE</span><span>{esc(issue)}</span></div>'
            signing_html += '</div>'
    else:
        signing_html = '<div class="dm">No firmware signing data available</div>'

    # --- Build HTML ---
    html = f'''<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>HardenCheck Report - {esc(result.target)}</title>
{font_link}
<style>
{css}
</style>
</head>
<body>
{sidebar_html}
<div class="main-content">

<h1>Firmware Security Report</h1>
<div class="meta">
<span>{esc(result.target)} &middot; {result.scan_time} &middot; {result.duration:.1f}s</span>
<button class="print-btn" onclick="window.print()">&#128438; Print Report</button>
</div>

<!-- OVERVIEW / EXECUTIVE SUMMARY -->
<section id="sec-overview">
<div class="card">
<div class="card-title" onclick="toggleSection('overview')">
<span>Executive Summary</span>
<span class="toggle-btn expanded" id="overview-btn">&#9654;</span>
</div>
<div class="card-body" id="overview">

{missing_tools_html}
<div class="grade-row">
<span class="grade g{grade.lower()}">{grade}</span>
<div class="grade-info">
<div class="grade-score">{display_score} / 100</div>
<div class="grade-desc">{grade_desc}</div>
</div>
</div>

<div class="sev-counters">
<div class="sev-box sev-critical"><div class="sev-num">{sev_counts['critical']}</div><div class="sev-label">Critical</div></div>
<div class="sev-box sev-high"><div class="sev-num">{sev_counts['high']}</div><div class="sev-label">High</div></div>
<div class="sev-box sev-medium"><div class="sev-num">{sev_counts['medium']}</div><div class="sev-label">Medium</div></div>
<div class="sev-box sev-low"><div class="sev-num">{sev_counts['low']}</div><div class="sev-label">Low</div></div>
</div>

{f'<div class="top-findings">{top_findings_html}</div>' if top_findings_html else ''}

<div class="summary" style="margin-top:15px">
<div class="sum-card se"><div class="sum-num se">{len(secured)}</div><div class="sum-label">Secured</div></div>
<div class="sum-card pa"><div class="sum-num pa">{len(partial)}</div><div class="sum-label">Partial</div></div>
<div class="sum-card in"><div class="sum-num in">{len(insecure)}</div><div class="sum-label">Insecure</div></div>
</div>

<div style="margin-top:10px">
{progress_bar("NX", nx_count, total_binaries)}
{progress_bar("Canary", canary_count, total_binaries)}
{progress_bar("PIE", pie_count, total_binaries)}
{progress_bar("Full RELRO", relro_count, total_binaries)}
{progress_bar("Fortify", fortify_count, total_binaries)}
{progress_bar("Stripped", stripped_count, total_binaries)}
{progress_bar("Stack Clash", stack_clash_count, total_binaries) if extended else ''}
{progress_bar("CFI", cfi_count, total_binaries) if extended else ''}
</div>

</div></div>
</section>

<!-- FIRMWARE PROFILE -->
<section id="sec-profile">
<div class="card">
<div class="card-title" onclick="toggleSection('profile')">
<span>Firmware Profile</span>
<span class="toggle-btn" id="profile-btn">&#9654;</span>
</div>
<div class="card-body collapsed" id="profile">
<div class="profile">
<div class="profile-row"><span class="profile-label">Type</span><span>{profile.fw_type}</span></div>
<div class="profile-row"><span class="profile-label">Architecture</span><span>{profile.arch}{f" {profile.bits}-bit" if profile.bits != "Unknown" else ""}</span></div>
<div class="profile-row"><span class="profile-label">Endianness</span><span>{profile.endian}</span></div>
<div class="profile-row"><span class="profile-label">Libc</span><span>{profile.libc}</span></div>
<div class="profile-row"><span class="profile-label">Kernel</span><span>{profile.kernel}</span></div>
<div class="profile-row"><span class="profile-label">Filesystem</span><span>{profile.filesystem}</span></div>
<div class="profile-row"><span class="profile-label">Compression</span><span>{profile.compression}</span></div>
<div class="profile-row"><span class="profile-label">Bootloader</span><span>{profile.bootloader}</span></div>
<div class="profile-row"><span class="profile-label">Init System</span><span>{profile.init_system}</span></div>
<div class="profile-row"><span class="profile-label">Package Manager</span><span>{profile.package_manager}</span></div>
<div class="profile-row"><span class="profile-label">SSL/TLS Library</span><span>{profile.ssl_library}</span></div>
<div class="profile-row"><span class="profile-label">Crypto Library</span><span>{profile.crypto_library}</span></div>
<div class="profile-row"><span class="profile-label">Web Server</span><span>{profile.web_server}</span></div>
<div class="profile-row"><span class="profile-label">SSH Server</span><span>{profile.ssh_server}</span></div>
<div class="profile-row"><span class="profile-label">DNS Server</span><span>{profile.dns_server}</span></div>
<div class="profile-row"><span class="profile-label">Total Size</span><span>{profile.total_size_mb} MB</span></div>
<div class="profile-row"><span class="profile-label">Total Files</span><span>{profile.total_files}</span></div>
<div class="profile-row"><span class="profile-label">Symlinks</span><span>{profile.symlinks}</span></div>
<div class="profile-row"><span class="profile-label">ELF Binaries</span><span>{profile.elf_binaries}</span></div>
<div class="profile-row"><span class="profile-label">Shared Libraries</span><span>{profile.shared_libs}</span></div>
<div class="profile-row"><span class="profile-label">Shell Scripts</span><span>{profile.shell_scripts}</span></div>
<div class="profile-row"><span class="profile-label">BusyBox Applets</span><span>{profile.busybox_applets}</span></div>
<div class="profile-row"><span class="profile-label">Kernel Modules</span><span>{profile.kernel_modules}</span></div>
<div class="profile-row"><span class="profile-label">Setuid Files</span><span class="{"bad" if profile.setuid_files else ""}">{len(profile.setuid_files)}</span></div>
<div class="profile-row"><span class="profile-label">Setgid Files</span><span>{len(profile.setgid_files)}</span></div>
<div class="profile-row"><span class="profile-label">World Writable</span><span class="{"bad" if profile.world_writable else ""}">{len(profile.world_writable)}</span></div>
</div>
</div></div>
</section>

<!-- BINARY HARDENING -->
<section id="sec-hardening">
<div class="card">
<div class="card-title" onclick="toggleSection('hardening')">
<span>Binary Hardening ({len(result.binaries)})</span>
<span class="toggle-btn" id="hardening-btn">&#9654;</span>
</div>
<div class="card-body collapsed" id="hardening">
<div class="search-box"><input type="text" id="binSearch" placeholder="Search binaries..." onkeyup="filterTable('binSearch', 'binTable')">
<button onclick="filterByClass('binTable', 'rb')">Insecure</button>
<button onclick="filterByClass('binTable', 'rw')">Partial</button>
<button onclick="filterByClass('binTable', '')">All</button></div>
<div class="tbl-wrap tbl-scroll"><table id="binTable"><thead><tr><th>Binary</th><th>NX</th><th>Canary</th><th>PIE</th><th>RELRO</th><th>Fortify</th><th>Strip</th>{"<th>SClash</th><th>CFI</th>" if extended else ""}<th>TXREL</th><th>RPATH</th><th>Conf</th></tr></thead>
<tbody>{binary_rows}</tbody></table></div>
</div></div>
</section>

<!-- ASLR ENTROPY -->
<section id="sec-aslr">
<div class="card">
<div class="card-title" onclick="toggleSection('aslr')">
<span>ASLR Entropy{f" ({len(binaries_with_aslr)} PIE binaries)" if binaries_with_aslr else ""}</span>
<span class="toggle-btn" id="aslr-btn">&#9654;</span>
</div>
<div class="card-body collapsed" id="aslr">
{aslr_summary_html}
{f'<div class="search-box"><input type="text" id="aslrSearch" placeholder="Search binaries..." onkeyup="filterTable(\'aslrSearch\', \'aslrTable\')"><button onclick="filterByRating(\'aslrTable\', \'Weak\')">Weak</button><button onclick="filterByRating(\'aslrTable\', \'Ineffective\')">Ineffective</button><button onclick="filterByRating(\'aslrTable\', \'\')">All</button></div><div class="tbl-wrap tbl-scroll"><table id="aslrTable"><thead><tr><th>Binary</th><th>Arch</th><th>Bits</th><th>PIE</th><th>Max</th><th>Effective</th><th>Rating</th><th>TEXTREL</th><th>Issues</th></tr></thead><tbody>{aslr_rows}</tbody></table></div>' if binaries_with_aslr else '<div class="dm">No PIE binaries with ASLR analysis</div>'}
</div></div>
</section>

<!-- NETWORK SERVICES -->
<section id="sec-services">
<div class="card">
<div class="card-title" onclick="toggleSection('services')">
<span>Network Services ({len(result.daemons)})</span>
<span class="toggle-btn" id="services-btn">&#9654;</span>
</div>
<div class="card-body collapsed" id="services">
{f'<div class="search-box"><input type="text" id="daemonSearch" placeholder="Search daemons..." onkeyup="filterTable(\'daemonSearch\', \'daemonTable\')"><button onclick="filterByRisk(\'daemonTable\', \'CRITICAL\')">Critical</button><button onclick="filterByRisk(\'daemonTable\', \'HIGH\')">High</button><button onclick="filterByRisk(\'daemonTable\', \'\')">All</button></div><div class="tbl-wrap tbl-scroll"><table id="daemonTable"><thead><tr><th>Risk</th><th>Service</th><th>Binary</th><th>Version</th><th>Path</th><th>Status</th><th>Detection</th></tr></thead><tbody>{daemon_rows}</tbody></table></div>' if result.daemons else '<div class="dm">No daemons detected</div>'}
</div></div>
</section>

<!-- KERNEL HARDENING -->
<section id="sec-kernel">
<div class="card">
<div class="card-title" onclick="toggleSection('kernel')">
<span>Kernel Hardening</span>
<span class="toggle-btn" id="kernel-btn">&#9654;</span>
</div>
<div class="card-body collapsed" id="kernel">
{kernel_html}
</div></div>
</section>

<!-- FIRMWARE SIGNING -->
<section id="sec-signing">
<div class="card">
<div class="card-title" onclick="toggleSection('signing')">
<span>Firmware Signing</span>
<span class="toggle-btn" id="signing-btn">&#9654;</span>
</div>
<div class="card-body collapsed" id="signing">
{signing_html}
</div></div>
</section>

<!-- CRYPTO BINARIES -->
<section id="sec-crypto-bins">
<div class="card">
<div class="card-title" onclick="toggleSection('crypto-bins')">
<span>Crypto Binaries ({len(result.crypto_binaries)})</span>
<span class="toggle-btn" id="crypto-bins-btn">&#9654;</span>
</div>
<div class="card-body collapsed" id="crypto-bins">
{f'<div class="tbl-wrap tbl-scroll"><table id="cryptoBinTable"><thead><tr><th>Name</th><th>Purpose</th><th>Version</th><th>Network</th><th>NX</th><th>PIE</th><th>Canary</th><th>RELRO</th><th>Risk</th><th>Issues</th></tr></thead><tbody>{crypto_bin_rows}</tbody></table></div>' if result.crypto_binaries else '<div class="dm">No cryptographic binaries detected</div>'}
</div></div>
</section>

<!-- SERVICE PRIVILEGES -->
<section id="sec-svc-privs">
<div class="card">
<div class="card-title" onclick="toggleSection('svc-privs')">
<span>Service Privileges ({len(result.service_privileges)})</span>
<span class="toggle-btn" id="svc-privs-btn">&#9654;</span>
</div>
<div class="card-body collapsed" id="svc-privs">
{f'<div class="tbl-wrap tbl-scroll"><table id="svcPrivTable"><thead><tr><th>Service</th><th>Binary</th><th>User:Group</th><th>Root</th><th>Capabilities</th><th>Chroot</th><th>Namespaces</th><th>Cgroups</th><th>Risk</th></tr></thead><tbody>{svc_priv_rows}</tbody></table></div>' if result.service_privileges else '<div class="dm">No service privilege data available</div>'}
</div></div>
</section>

<!-- UPDATE MECHANISM -->
<section id="sec-update">
<div class="card">
<div class="card-title" onclick="toggleSection('update')">
<span>Update Mechanism</span>
<span class="toggle-btn" id="update-btn">&#9654;</span>
</div>
<div class="card-body collapsed" id="update">
{update_html}
</div></div>
</section>

<!-- DEP RISKS -->
<section id="sec-deps">
<div class="card">
<div class="card-title" onclick="toggleSection('deps')">
<span>Dependency Risks ({len(result.dependency_risks)})</span>
<span class="toggle-btn" id="deps-btn">&#9654;</span>
</div>
<div class="card-body collapsed" id="deps">
{f'<div class="search-box"><input type="text" id="depSearch" placeholder="Search dependencies..." onkeyup="filterTable(\'depSearch\', \'depTable\')"></div><div class="tbl-wrap tbl-scroll"><table id="depTable"><thead><tr><th>Library</th><th>Issue</th><th>Used By</th></tr></thead><tbody>{dep_rows}</tbody></table></div>' if result.dependency_risks else '<div class="dm">No insecure dependencies</div>'}
</div></div>
</section>

<!-- BANNED FUNCTIONS -->
<section id="sec-banned">
<div class="card">
<div class="card-title" onclick="toggleSection('banned')">
<span>Banned Functions ({len(result.banned_functions)})</span>
<span class="toggle-btn" id="banned-btn">&#9654;</span>
</div>
<div class="card-body collapsed" id="banned">
{f'<div class="search-box"><input type="text" id="bannedSearch" placeholder="Search functions..." onkeyup="filterTable(\'bannedSearch\', \'bannedTable\')"><button onclick="filterBySeverity(\'bannedTable\', \'CRITICAL\')">Critical</button><button onclick="filterBySeverity(\'bannedTable\', \'HIGH\')">High</button><button onclick="filterBySeverity(\'bannedTable\', \'\')">All</button></div><div class="tbl-wrap tbl-scroll"><table id="bannedTable"><thead><tr><th>Function</th><th>Location</th><th>Alternative</th><th>Severity</th><th>Compliance</th></tr></thead><tbody>{banned_rows}</tbody></table></div>' if result.banned_functions else '<div class="dm">No banned function usage detected</div>'}
{f'<div style="margin-top:15px"><div class="card-title" style="border-bottom:none;padding:8px 0">Hardcoded Credentials ({len(result.credentials)})</div><div class="tbl-wrap tbl-scroll"><table><thead><tr><th>Location</th><th>Pattern</th><th>Context</th></tr></thead><tbody>{cred_rows}</tbody></table></div></div>' if result.credentials else ''}
{f'<div style="margin-top:15px"><div class="card-title" style="border-bottom:none;padding:8px 0">Certificates &amp; Keys ({len(result.certificates)})</div><div class="tbl-wrap tbl-scroll"><table><thead><tr><th>File</th><th>Type</th><th>Issue</th></tr></thead><tbody>{cert_rows}</tbody></table></div></div>' if result.certificates else ''}
{f'<div style="margin-top:15px"><div class="card-title" style="border-bottom:none;padding:8px 0">Configuration Issues ({len(result.config_issues)})</div><div class="tbl-wrap tbl-scroll"><table><thead><tr><th>Location</th><th>Issue</th><th>Context</th></tr></thead><tbody>{config_rows}</tbody></table></div></div>' if result.config_issues else ''}
</div></div>
</section>

<!-- VULN VERSIONS -->
<section id="sec-vulns">
<div class="card">
<div class="card-title" onclick="toggleSection('vulns')">
<span>Vuln Versions ({len(result.security_tests)})</span>
<span class="toggle-btn" id="vulns-btn">&#9654;</span>
</div>
<div class="card-body collapsed" id="vulns">
{f'<div class="tbl-wrap tbl-scroll"><table id="vulnTable"><thead><tr><th>Severity</th><th>Type</th><th>Component</th><th>Version</th><th>Issue</th><th>CVE</th></tr></thead><tbody>{vuln_rows}</tbody></table></div>' if result.security_tests else '<div class="dm">No vulnerable versions detected</div>'}
</div></div>
</section>

<!-- PQC READINESS -->
<section id="sec-pqc">
<div class="card">
<div class="card-title" onclick="toggleSection('pqc')">
<span>Post-Quantum Crypto Readiness{f" ({result.pqc_readiness['summary']['total_crypto_binaries']})" if result.pqc_readiness and result.pqc_readiness.get('summary') else ""}</span>
<span class="toggle-btn" id="pqc-btn">&#9654;</span>
</div>
<div class="card-body collapsed" id="pqc">
{pqc_html}
</div></div>
</section>

<!-- SBOM -->
<section id="sec-sbom">
<div class="card">
<div class="card-title" onclick="toggleSection('sbom')">
<span>Software Bill of Materials (SBOM){f" ({result.sbom.total_components})" if result.sbom else ""}</span>
<span class="toggle-btn" id="sbom-btn">&#9654;</span>
</div>
<div class="card-body collapsed" id="sbom">
{sbom_summary_html}
{f'<div class="search-box"><input type="text" id="sbomSearch" placeholder="Search components..." onkeyup="filterTable(\'sbomSearch\', \'sbomTable\')"><button onclick="filterSbomType(\'sbomTable\', \'library\')">Libraries</button><button onclick="filterSbomType(\'sbomTable\', \'application\')">Apps</button><button onclick="filterSbomType(\'sbomTable\', \'\')">All</button></div><div class="tbl-wrap tbl-scroll"><table id="sbomTable"><thead><tr><th>Component</th><th>Version</th><th>Type</th><th>Supplier</th><th>CPE</th><th>License</th><th>Source</th><th>Security</th></tr></thead><tbody>{sbom_rows}</tbody></table></div>' if sbom_rows else '<div class="dm">No SBOM data</div>'}
{f'<div style="margin-top:15px"><div class="card-title" style="border-bottom:none;padding:8px 0">Dependency Tree ({len(result.sbom.dependency_tree)} binaries)</div><div class="search-box"><input type="text" id="depTreeSearch" placeholder="Search..." onkeyup="filterTable(\'depTreeSearch\', \'depTreeTable\')"></div><div class="tbl-wrap tbl-scroll"><table id="depTreeTable"><thead><tr><th>Binary</th><th>NEEDED Library</th><th>Version</th></tr></thead><tbody>{sbom_dep_rows}</tbody></table></div></div>' if sbom_dep_rows else ''}
</div></div>
</section>

<!-- CLASSIFICATION -->
<section id="sec-classification">
<div class="card">
<div class="card-title" onclick="toggleSection('classification')">
<span>Classification</span>
<span class="toggle-btn" id="classification-btn">&#9654;</span>
</div>
<div class="card-body collapsed" id="classification">
<div class="search-box"><input type="text" id="classSearch" placeholder="Search binaries..." onkeyup="filterClassification('classSearch')"></div>
<div id="classificationContent">
{build_class_section("SECURED", secured, "se")}
{build_class_section("PARTIAL", partial, "pa")}
{build_class_section("INSECURE", insecure, "in")}
</div>
</div></div>
</section>

<div class="card" style="border:none;background:transparent;text-align:center;padding:20px">
<div class="tools" style="justify-content:center">{" ".join(f'<span class="tool">{esc(n)}: {esc(c)}</span>' for n, c in result.tools.items())}</div>
</div>

</div><!-- /main-content -->

<script>
function toggleSection(id) {{
  var body = document.getElementById(id);
  var btn = document.getElementById(id + '-btn');
  if (body.classList.contains('collapsed')) {{
    body.classList.remove('collapsed');
    if (btn) {{ btn.classList.add('expanded'); }}
  }} else {{
    body.classList.add('collapsed');
    if (btn) {{ btn.classList.remove('expanded'); }}
  }}
}}
function filterTable(inputId, tableId) {{
  var input = document.getElementById(inputId);
  var filter = input.value.toLowerCase();
  var table = document.getElementById(tableId);
  var rows = table.getElementsByTagName("tr");
  for (var i = 1; i < rows.length; i++) {{
    var cells = rows[i].getElementsByTagName("td");
    var match = false;
    for (var j = 0; j < cells.length; j++) {{
      if (cells[j].textContent.toLowerCase().indexOf(filter) > -1) {{
        match = true; break;
      }}
    }}
    rows[i].style.display = match ? "" : "none";
  }}
}}
function filterByClass(tableId, className) {{
  var table = document.getElementById(tableId);
  var rows = table.getElementsByTagName("tr");
  for (var i = 1; i < rows.length; i++) {{
    if (className === "") {{ rows[i].style.display = ""; }}
    else {{ rows[i].style.display = rows[i].classList.contains(className) ? "" : "none"; }}
  }}
}}
function filterByRisk(tableId, risk) {{
  var table = document.getElementById(tableId);
  var rows = table.getElementsByTagName("tr");
  for (var i = 1; i < rows.length; i++) {{
    var cell = rows[i].getElementsByTagName("td")[0];
    if (risk === "" || (cell && cell.textContent.indexOf(risk) > -1)) {{ rows[i].style.display = ""; }}
    else {{ rows[i].style.display = "none"; }}
  }}
}}
function filterBySeverity(tableId, sev) {{
  var table = document.getElementById(tableId);
  var rows = table.getElementsByTagName("tr");
  for (var i = 1; i < rows.length; i++) {{
    var cell = rows[i].getElementsByTagName("td")[3];
    if (sev === "" || (cell && cell.textContent.indexOf(sev) > -1)) {{ rows[i].style.display = ""; }}
    else {{ rows[i].style.display = "none"; }}
  }}
}}
function filterByRating(tableId, rating) {{
  var table = document.getElementById(tableId);
  var rows = table.getElementsByTagName("tr");
  for (var i = 1; i < rows.length; i++) {{
    var cell = rows[i].getElementsByTagName("td")[6];
    if (rating === "" || (cell && cell.textContent.indexOf(rating) > -1)) {{ rows[i].style.display = ""; }}
    else {{ rows[i].style.display = "none"; }}
  }}
}}
function filterClassification(inputId) {{
  var input = document.getElementById(inputId);
  var filter = input.value.toLowerCase();
  var items = document.querySelectorAll("#classificationContent .ci");
  for (var i = 0; i < items.length; i++) {{
    var text = items[i].textContent.toLowerCase();
    items[i].style.display = text.indexOf(filter) > -1 ? "" : "none";
  }}
}}
function filterSbomType(tableId, compType) {{
  var table = document.getElementById(tableId);
  var rows = table.getElementsByTagName("tr");
  for (var i = 1; i < rows.length; i++) {{
    var cell = rows[i].getElementsByTagName("td")[2];
    if (compType === "" || (cell && cell.textContent.trim() === compType)) {{ rows[i].style.display = ""; }}
    else {{ rows[i].style.display = "none"; }}
  }}
}}
// Sidebar active link tracking
var observer = new IntersectionObserver(function(entries) {{
  entries.forEach(function(entry) {{
    if (entry.isIntersecting) {{
      document.querySelectorAll('.sidebar a').forEach(function(a) {{ a.classList.remove('active'); }});
      var link = document.querySelector('.sidebar a[href="#' + entry.target.id + '"]');
      if (link) link.classList.add('active');
    }}
  }});
}}, {{threshold: 0.1, rootMargin: '-80px 0px -80% 0px'}});
document.querySelectorAll('section[id]').forEach(function(s) {{ observer.observe(s); }});
</script>
</body></html>'''

    output_path.write_text(html, encoding="utf-8")
