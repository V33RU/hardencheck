import json
import uuid
from pathlib import Path

from hardencheck.models import SBOMResult
from hardencheck.constants.core import VERSION


def generate_spdx_sbom(sbom: SBOMResult, output_path: Path):
    """Generate SPDX 2.3 JSON SBOM.

    SPDX is the ISO/IEC 5962:2021 standard for SBOMs.
    Spec: https://spdx.github.io/spdx-spec/v2.3/
    """
    doc_namespace = f"https://spdx.org/spdxdocs/hardencheck-{sbom.firmware_name}-{uuid.uuid4()}"

    packages = []
    relationships = []

    # Root document package
    root_spdx_id = "SPDXRef-firmware"
    packages.append({
        "SPDXID": root_spdx_id,
        "name": sbom.firmware_name,
        "versionInfo": sbom.firmware_version or "NOASSERTION",
        "downloadLocation": "NOASSERTION",
        "filesAnalyzed": False,
        "primaryPackagePurpose": "FIRMWARE",
        "supplier": "NOASSERTION",
    })

    relationships.append({
        "spdxElementId": "SPDXRef-DOCUMENT",
        "relationshipType": "DESCRIBES",
        "relatedSpdxElement": root_spdx_id
    })

    for idx, comp in enumerate(sbom.components):
        spdx_id = f"SPDXRef-Package-{idx}"

        purpose_map = {
            "library": "LIBRARY",
            "application": "APPLICATION",
            "firmware": "FIRMWARE",
            "framework": "FRAMEWORK",
            "os": "OPERATING_SYSTEM",
        }

        pkg = {
            "SPDXID": spdx_id,
            "name": comp.name,
            "versionInfo": comp.version if comp.version and comp.version != "Unknown" else "NOASSERTION",
            "downloadLocation": "NOASSERTION",
            "filesAnalyzed": False,
            "primaryPackagePurpose": purpose_map.get(comp.component_type, "LIBRARY"),
        }

        if comp.supplier:
            pkg["supplier"] = f"Organization: {comp.supplier}"
        else:
            pkg["supplier"] = "NOASSERTION"

        if comp.license_id:
            pkg["licenseConcluded"] = comp.license_id
            pkg["licenseDeclared"] = comp.license_id
        else:
            pkg["licenseConcluded"] = "NOASSERTION"
            pkg["licenseDeclared"] = "NOASSERTION"

        if comp.sha256:
            pkg["checksums"] = [{"algorithm": "SHA256", "checksumValue": comp.sha256}]

        if comp.cpe:
            pkg["externalRefs"] = [{
                "referenceCategory": "SECURITY",
                "referenceType": "cpe23Type",
                "referenceLocator": comp.cpe
            }]
            if comp.purl:
                pkg["externalRefs"].append({
                    "referenceCategory": "PACKAGE_MANAGER",
                    "referenceType": "purl",
                    "referenceLocator": comp.purl
                })
        elif comp.purl:
            pkg["externalRefs"] = [{
                "referenceCategory": "PACKAGE_MANAGER",
                "referenceType": "purl",
                "referenceLocator": comp.purl
            }]

        if comp.description:
            pkg["description"] = comp.description

        packages.append(pkg)

        relationships.append({
            "spdxElementId": root_spdx_id,
            "relationshipType": "CONTAINS",
            "relatedSpdxElement": spdx_id
        })

    # Add DEPENDS_ON relationships from dependency tree
    comp_spdx_map = {}
    for idx, comp in enumerate(sbom.components):
        comp_spdx_map[comp.name.lower()] = f"SPDXRef-Package-{idx}"
        if comp.path:
            comp_spdx_map[Path(comp.path).name.lower()] = f"SPDXRef-Package-{idx}"

    for binary_path, needed_libs in sbom.dependency_tree.items():
        binary_name = Path(binary_path).name.lower()
        src_id = comp_spdx_map.get(binary_name)
        if not src_id:
            continue

        for lib in needed_libs:
            lib_base = lib.lower().split(".so")[0] if ".so" in lib.lower() else lib.lower()
            dst_id = comp_spdx_map.get(lib_base) or comp_spdx_map.get(lib.lower())
            if dst_id:
                relationships.append({
                    "spdxElementId": src_id,
                    "relationshipType": "DEPENDS_ON",
                    "relatedSpdxElement": dst_id
                })

    spdx_doc = {
        "spdxVersion": "SPDX-2.3",
        "dataLicense": "CC0-1.0",
        "SPDXID": "SPDXRef-DOCUMENT",
        "name": f"hardencheck-sbom-{sbom.firmware_name}",
        "documentNamespace": doc_namespace,
        "creationInfo": {
            "created": sbom.timestamp,
            "creators": [
                f"Tool: HardenCheck-{VERSION}",
                "Organization: IOTSRG"
            ],
            "licenseListVersion": "3.22"
        },
        "packages": packages,
        "relationships": relationships
    }

    output_path.write_text(json.dumps(spdx_doc, indent=2), encoding="utf-8")
