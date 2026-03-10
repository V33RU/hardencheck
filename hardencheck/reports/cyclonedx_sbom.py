import json
from pathlib import Path

from hardencheck.models import SBOMResult
from hardencheck.constants.core import VERSION


def generate_cyclonedx_sbom(sbom: SBOMResult, output_path: Path):
    """Generate CycloneDX 1.5 JSON SBOM.

    CycloneDX is the preferred SBOM format for firmware/IoT security analysis.
    Spec: https://cyclonedx.org/specification/overview/
    """
    components = []

    for comp in sbom.components:
        cdx_comp = {
            "type": comp.component_type,
            "name": comp.name,
            "version": comp.version if comp.version != "Unknown" else "",
        }

        if comp.supplier:
            cdx_comp["supplier"] = {"name": comp.supplier}

        if comp.description:
            cdx_comp["description"] = comp.description

        if comp.license_id:
            cdx_comp["licenses"] = [{"license": {"id": comp.license_id}}]

        if comp.cpe:
            cdx_comp["cpe"] = comp.cpe

        if comp.purl:
            cdx_comp["purl"] = comp.purl
            cdx_comp["bom-ref"] = comp.purl
        else:
            cdx_comp["bom-ref"] = f"ref:{comp.name}:{comp.version}"

        if comp.sha256:
            cdx_comp["hashes"] = [{"alg": "SHA-256", "content": comp.sha256}]

        props = []
        if comp.path:
            props.append({"name": "hardencheck:path", "value": comp.path})
        if comp.source:
            props.append({"name": "hardencheck:detection_source", "value": comp.source})
        if comp.arch:
            props.append({"name": "hardencheck:arch", "value": comp.arch})
        if comp.security_flags:
            for flag, value in comp.security_flags.items():
                props.append({"name": f"hardencheck:security:{flag}", "value": str(value)})

        if props:
            cdx_comp["properties"] = props

        components.append(cdx_comp)

    # Build dependency graph
    dependencies = []
    for binary_path, needed_libs in sbom.dependency_tree.items():
        binary_name = Path(binary_path).name.lower()
        dep_ref = None
        for comp in sbom.components:
            if comp.path == binary_path or comp.name.lower() == binary_name:
                dep_ref = comp.purl or f"ref:{comp.name}:{comp.version}"
                break

        if not dep_ref:
            dep_ref = f"ref:{binary_name}:unknown"

        lib_refs = []
        for lib in needed_libs:
            lib_lower = lib.lower()
            lib_base = lib_lower.split(".so")[0] if ".so" in lib_lower else lib_lower

            for comp in sbom.components:
                if comp.name.lower() == lib_base or lib_lower.startswith(comp.name.lower()):
                    lib_refs.append(comp.purl or f"ref:{comp.name}:{comp.version}")
                    break
            else:
                lib_refs.append(f"ref:{lib}:unknown")

        dependencies.append({
            "ref": dep_ref,
            "dependsOn": lib_refs
        })

    cdx_bom = {
        "$schema": "http://cyclonedx.org/schema/bom-1.5.schema.json",
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "serialNumber": sbom.serial_number,
        "version": 1,
        "metadata": {
            "timestamp": sbom.timestamp,
            "tools": {
                "components": [{
                    "type": "application",
                    "name": "HardenCheck",
                    "version": VERSION,
                    "supplier": {"name": "IOTSRG", "url": ["https://github.com/v33ru"]},
                    "description": "Firmware Binary Security Analyzer with SBOM generation"
                }]
            },
            "component": {
                "type": "firmware",
                "name": sbom.firmware_name,
                "version": sbom.firmware_version,
                "bom-ref": f"ref:firmware:{sbom.firmware_name}"
            }
        },
        "components": components,
        "dependencies": dependencies
    }

    output_path.write_text(json.dumps(cdx_bom, indent=2), encoding="utf-8")
