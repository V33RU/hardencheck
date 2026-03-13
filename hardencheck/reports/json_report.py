import json
from pathlib import Path

from hardencheck.models import ScanResult
from hardencheck.constants.core import VERSION
from hardencheck.reports.grading import classify_binary, calculate_grade


def generate_json_report(result: ScanResult, output_path: Path):
    """Generate JSON report with ASLR analysis."""
    grade, score = calculate_grade(result.binaries)
    profile = result.profile

    data = {
        "version": VERSION,
        "target": result.target,
        "scan_time": result.scan_time,
        "duration": result.duration,
        "tools": result.tools,
        "grade": grade,
        "score": score,
        "profile": {
            "arch": profile.arch,
            "bits": profile.bits,
            "endian": profile.endian,
            "type": profile.fw_type,
            "libc": profile.libc,
            "kernel": profile.kernel,
            "filesystem": profile.filesystem,
            "compression": profile.compression,
            "bootloader": profile.bootloader,
            "init_system": profile.init_system,
            "package_manager": profile.package_manager,
            "ssl_library": profile.ssl_library,
            "crypto_library": profile.crypto_library,
            "web_server": profile.web_server,
            "ssh_server": profile.ssh_server,
            "dns_server": profile.dns_server,
            "busybox_applets": profile.busybox_applets,
            "kernel_modules": profile.kernel_modules,
            "total_size_mb": profile.total_size_mb,
            "total_files": profile.total_files,
            "symlinks": profile.symlinks,
            "elf_binaries": profile.elf_binaries,
            "shared_libs": profile.shared_libs,
            "shell_scripts": profile.shell_scripts,
            "config_files": profile.config_files,
            "setuid_files": profile.setuid_files,
            "setgid_files": profile.setgid_files,
            "world_writable": profile.world_writable,
            "interesting_files": profile.interesting_files
        },
        "summary": {
            "total_binaries": len(result.binaries),
            "secured": sum(1 for b in result.binaries if classify_binary(b) == "SECURED"),
            "partial": sum(1 for b in result.binaries if classify_binary(b) == "PARTIAL"),
            "insecure": sum(1 for b in result.binaries if classify_binary(b) == "INSECURE")
        },
        "missing_tools": result.missing_tools,
        "aslr_summary": result.aslr_summary,
        "daemons": [
            {"name": d.name, "binary": d.binary, "version": d.version, "path": d.path,
             "risk": d.risk, "reason": d.reason, "has_network": d.has_network, "status": d.status}
            for d in result.daemons
        ],
        "binaries": [
            {
                "path": b.path, "filename": b.filename, "type": b.binary_type.value,
                "nx": b.nx, "canary": b.canary, "pie": b.pie, "relro": b.relro,
                "fortify": b.fortify, "stripped": b.stripped, "stack_clash": b.stack_clash,
                "cfi": b.cfi, "textrel": b.textrel, "rpath": b.rpath,
                "confidence": b.confidence, "classification": classify_binary(b),
                "aslr_analysis": {
                    "arch": b.aslr_analysis.arch,
                    "bits": b.aslr_analysis.bits,
                    "is_pie": b.aslr_analysis.is_pie,
                    "entry_point": b.aslr_analysis.entry_point,
                    "text_vaddr": b.aslr_analysis.text_vaddr,
                    "data_vaddr": b.aslr_analysis.data_vaddr,
                    "load_base": b.aslr_analysis.load_base,
                    "theoretical_entropy": b.aslr_analysis.theoretical_entropy,
                    "effective_entropy": b.aslr_analysis.effective_entropy,
                    "available_entropy": b.aslr_analysis.available_entropy,
                    "page_offset_bits": b.aslr_analysis.page_offset_bits,
                    "num_load_segments": b.aslr_analysis.num_load_segments,
                    "has_fixed_segments": b.aslr_analysis.has_fixed_segments,
                    "fixed_segment_addrs": b.aslr_analysis.fixed_segment_addrs,
                    "rating": b.aslr_analysis.rating.value,
                    "has_textrel": b.aslr_analysis.has_textrel,
                    "has_rpath": b.aslr_analysis.has_rpath,
                    "stack_executable": b.aslr_analysis.stack_executable,
                    "issues": b.aslr_analysis.issues,
                    "recommendations": b.aslr_analysis.recommendations
                } if b.aslr_analysis else None
            }
            for b in result.binaries
        ],
        "banned_functions": [
            {"function": h.function, "file": h.file, "line": h.line,
             "alternative": h.alternative, "severity": h.severity.name, "compliance": h.compliance}
            for h in result.banned_functions
        ],
        "dependency_risks": [
            {"library": r.library, "issue": r.issue, "used_by": r.used_by}
            for r in result.dependency_risks
        ],
        "credentials": [
            {"file": c.file, "line": c.line, "pattern": c.pattern, "severity": c.severity.name}
            for c in result.credentials
        ],
        "certificates": [
            {"file": c.file, "type": c.file_type, "issue": c.issue, "severity": c.severity.name}
            for c in result.certificates
        ],
        "config_issues": [
            {"file": c.file, "line": c.line, "issue": c.issue, "severity": c.severity.name}
            for c in result.config_issues
        ],
        "security_tests": [
            {
                "test_type": t.test_type,
                "component": t.component,
                "version": t.version,
                "issue": t.issue,
                "severity": t.severity.name,
                "details": t.details,
                "recommendation": t.recommendation,
                "cve_id": t.cve_id,
                "affected_path": t.affected_path
            }
            for t in result.security_tests
        ],
        "crypto_binaries": [
            {
                "name": cb.name,
                "path": cb.path,
                "type": cb.binary_type.value,
                "version": cb.version,
                "purpose": cb.purpose,
                "has_network": cb.has_network,
                "risk_level": cb.risk_level,
                "security_flags": cb.security_flags,
                "issues": cb.issues,
                "recommendation": cb.recommendation
            }
            for cb in result.crypto_binaries
        ],
        "firmware_signing": {
            "is_signed": result.firmware_signing.is_signed if result.firmware_signing else False,
            "signing_method": result.firmware_signing.signing_method if result.firmware_signing else "Unknown",
            "secure_boot_enabled": result.firmware_signing.secure_boot_enabled if result.firmware_signing else False,
            "signature_files": result.firmware_signing.signature_files if result.firmware_signing else [],
            "bootloader_config": result.firmware_signing.bootloader_config if result.firmware_signing else {},
            "issues": result.firmware_signing.issues if result.firmware_signing else [],
            "recommendation": result.firmware_signing.recommendation if result.firmware_signing else ""
        } if result.firmware_signing else {},
        "service_privileges": [
            {
                "service_name": sp.service_name,
                "binary_path": sp.binary_path,
                "runs_as_root": sp.runs_as_root,
                "user": sp.user,
                "group": sp.group,
                "has_capabilities": sp.has_capabilities,
                "capabilities": sp.capabilities,
                "chroot_jail": sp.chroot_jail,
                "namespace_isolation": sp.namespace_isolation,
                "cgroup_restrictions": sp.cgroup_restrictions,
                "risk_level": sp.risk_level,
                "issues": sp.issues,
                "recommendation": sp.recommendation
            }
            for sp in result.service_privileges
        ],
        "kernel_hardening": {
            "config_available": result.kernel_hardening.config_available if result.kernel_hardening else False,
            "config_source": result.kernel_hardening.config_source if result.kernel_hardening else "",
            "kaslr_enabled": result.kernel_hardening.kaslr_enabled if result.kernel_hardening else False,
            "smep_enabled": result.kernel_hardening.smep_enabled if result.kernel_hardening else False,
            "smap_enabled": result.kernel_hardening.smap_enabled if result.kernel_hardening else False,
            "pxn_enabled": result.kernel_hardening.pxn_enabled if result.kernel_hardening else False,
            "stack_protector": result.kernel_hardening.stack_protector if result.kernel_hardening else False,
            "fortify_source": result.kernel_hardening.fortify_source if result.kernel_hardening else False,
            "usercopy_protection": result.kernel_hardening.usercopy_protection if result.kernel_hardening else False,
            "rodata_enforced": result.kernel_hardening.rodata_enforced if result.kernel_hardening else False,
            "dmesg_restricted": result.kernel_hardening.dmesg_restricted if result.kernel_hardening else False,
            "hardening_score": result.kernel_hardening.hardening_score if result.kernel_hardening else 0,
            "issues": result.kernel_hardening.issues if result.kernel_hardening else [],
            "recommendations": result.kernel_hardening.recommendations if result.kernel_hardening else []
        } if result.kernel_hardening else {},
        "update_mechanism": {
            "update_system": result.update_mechanism.update_system if result.update_mechanism else "Unknown",
            "update_binary": result.update_mechanism.update_binary if result.update_mechanism else None,
            "update_config": result.update_mechanism.update_config if result.update_mechanism else None,
            "uses_https": result.update_mechanism.uses_https if result.update_mechanism else False,
            "uses_signing": result.update_mechanism.uses_signing if result.update_mechanism else False,
            "has_rollback_protection": result.update_mechanism.has_rollback_protection if result.update_mechanism else False,
            "update_server": result.update_mechanism.update_server if result.update_mechanism else None,
            "issues": result.update_mechanism.issues if result.update_mechanism else [],
            "risk_level": result.update_mechanism.risk_level if result.update_mechanism else "Unknown",
            "recommendation": result.update_mechanism.recommendation if result.update_mechanism else ""
        } if result.update_mechanism else {},
        "pqc_readiness": result.pqc_readiness if result.pqc_readiness else {},
        "sbom": {
            "total_components": result.sbom.total_components,
            "total_libraries": result.sbom.total_libraries,
            "total_applications": result.sbom.total_applications,
            "components_with_version": result.sbom.components_with_version,
            "components_with_cpe": result.sbom.components_with_cpe,
            "package_manager_source": result.sbom.package_manager_source,
            "components": [
                {
                    "name": c.name, "version": c.version, "type": c.component_type,
                    "supplier": c.supplier, "cpe": c.cpe, "purl": c.purl,
                    "license": c.license_id, "path": c.path, "sha256": c.sha256,
                    "source": c.source, "dependencies": c.dependencies,
                    "security_flags": c.security_flags,
                }
                for c in result.sbom.components
            ],
            "dependency_tree": result.sbom.dependency_tree,
        } if result.sbom else {}
    }

    output_path.write_text(json.dumps(data, indent=2), encoding="utf-8")
