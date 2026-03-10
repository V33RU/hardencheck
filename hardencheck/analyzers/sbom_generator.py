import re
import uuid
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Tuple

from hardencheck.models import BinaryType, BinaryAnalysis, FirmwareProfile, SBOMComponent, SBOMResult
from hardencheck.constants.sbom import CPE_COMPONENT_MAP, LICENSE_HINTS
from hardencheck.core.base import BaseAnalyzer
from hardencheck.core.utils import safe_read_file


class SBOMGenerator(BaseAnalyzer):
    """Generate Software Bill of Materials from firmware analysis."""

    def _lookup_cpe(self, name: str) -> Tuple[str, str, str, str]:
        """Lookup CPE mapping for a component name."""
        name_lower = name.lower()

        for key, value in CPE_COMPONENT_MAP.items():
            if key.lower() == name_lower or name_lower.startswith(key.lower()):
                return value

        base_name = name_lower.split(".so")[0] if ".so" in name_lower else name_lower
        base_name = re.sub(r'-[\d.]+$', '', base_name)

        for key, value in CPE_COMPONENT_MAP.items():
            if key.lower() == base_name or base_name.startswith(key.lower()):
                return value

        return ("", "", "", "")

    def _build_cpe23(self, vendor: str, product: str, version: str, part: str = "a") -> str:
        """Build CPE 2.3 formatted string."""
        ver = version if version and version != "Unknown" else "*"
        ver = re.sub(r'[^a-zA-Z0-9._\-]', '', ver)
        return f"cpe:2.3:{part}:{vendor}:{product}:{ver}:*:*:*:*:*:*:*"

    def _build_purl(self, pkg_type: str, namespace: str, name: str, version: str) -> str:
        """Build Package URL (PURL) string."""
        ver = version if version and version != "Unknown" else ""
        purl = f"pkg:{pkg_type}/{namespace}/{name}"
        if ver:
            purl += f"@{ver}"
        return purl

    def _get_needed_libs(self, filepath: Path) -> List[str]:
        """Extract NEEDED shared library dependencies from ELF binary."""
        if "readelf" not in self.tools:
            return []

        ret, out, _ = self._run_command(
            [self.tools["readelf"], "-W", "-d", str(filepath)], timeout=10
        )

        if ret != 0:
            return []

        needed = []
        for line in out.split("\n"):
            match = re.search(r'\(NEEDED\)\s+Shared library:\s+\[([^\]]+)\]', line)
            if match:
                needed.append(match.group(1))

        return needed

    def _enumerate_packages_opkg(self) -> List[Dict]:
        """Enumerate installed packages via opkg status file."""
        packages = []

        status_paths = [
            self.target / "usr" / "lib" / "opkg" / "status",
            self.target / "var" / "lib" / "opkg" / "status",
            self.target / "usr" / "lib" / "opkg" / "info",
            self.target / "opt" / "lib" / "opkg" / "status",
        ]

        for status_path in status_paths:
            if status_path.is_file():
                content = safe_read_file(status_path, max_size=2 * 1024 * 1024)
                if not content:
                    continue

                current = {}
                for line in content.split("\n"):
                    if line.startswith("Package:"):
                        if current.get("name"):
                            packages.append(current)
                        current = {"name": line.split(":", 1)[1].strip()}
                    elif line.startswith("Version:") and current:
                        current["version"] = line.split(":", 1)[1].strip()
                    elif line.startswith("Architecture:") and current:
                        current["arch"] = line.split(":", 1)[1].strip()
                    elif line.startswith("Depends:") and current:
                        deps = [d.strip().split(" ")[0] for d in line.split(":", 1)[1].split(",")]
                        current["depends"] = deps
                    elif line.startswith("Description:") and current:
                        current["description"] = line.split(":", 1)[1].strip()[:120]
                    elif line.startswith("Section:") and current:
                        current["section"] = line.split(":", 1)[1].strip()

                if current.get("name"):
                    packages.append(current)

                if packages:
                    break

            elif status_path.is_dir():
                try:
                    for control_file in status_path.iterdir():
                        if control_file.suffix == ".control":
                            content = safe_read_file(control_file, max_size=8192)
                            if not content:
                                continue
                            pkg = {}
                            for line in content.split("\n"):
                                if line.startswith("Package:"):
                                    pkg["name"] = line.split(":", 1)[1].strip()
                                elif line.startswith("Version:"):
                                    pkg["version"] = line.split(":", 1)[1].strip()
                                elif line.startswith("Architecture:"):
                                    pkg["arch"] = line.split(":", 1)[1].strip()
                                elif line.startswith("Depends:"):
                                    deps = [d.strip().split(" ")[0] for d in line.split(":", 1)[1].split(",")]
                                    pkg["depends"] = deps
                                elif line.startswith("Description:"):
                                    pkg["description"] = line.split(":", 1)[1].strip()[:120]
                            if pkg.get("name"):
                                packages.append(pkg)
                except (OSError, PermissionError):
                    pass

        return packages

    def _enumerate_packages_dpkg(self) -> List[Dict]:
        """Enumerate installed packages via dpkg status file."""
        packages = []

        status_path = self.target / "var" / "lib" / "dpkg" / "status"
        if not status_path.exists():
            return packages

        content = safe_read_file(status_path, max_size=5 * 1024 * 1024)
        if not content:
            return packages

        current = {}
        for line in content.split("\n"):
            if line.startswith("Package:"):
                if current.get("name"):
                    packages.append(current)
                current = {"name": line.split(":", 1)[1].strip()}
            elif line.startswith("Version:") and current:
                current["version"] = line.split(":", 1)[1].strip()
            elif line.startswith("Architecture:") and current:
                current["arch"] = line.split(":", 1)[1].strip()
            elif line.startswith("Depends:") and current:
                deps = [d.strip().split(" ")[0] for d in line.split(":", 1)[1].split(",")]
                current["depends"] = deps
            elif line.startswith("Description:") and current:
                current["description"] = line.split(":", 1)[1].strip()[:120]
            elif line.startswith("Status:") and current:
                current["status"] = line.split(":", 1)[1].strip()
            elif line.startswith("Source:") and current:
                current["source_pkg"] = line.split(":", 1)[1].strip().split(" ")[0]

        if current.get("name"):
            packages.append(current)

        packages = [p for p in packages if "installed" in p.get("status", "installed")]

        return packages

    def _extract_so_version(self, filename: str) -> str:
        """Extract version from shared library filename."""
        match = re.search(r'\.so\.(.+)$', filename)
        if match:
            return match.group(1)
        return ""

    def generate_sbom(self, binaries: List[BinaryAnalysis], profile: FirmwareProfile) -> SBOMResult:
        """Generate Software Bill of Materials from firmware analysis."""
        components = []
        dependency_tree = {}
        seen_components = set()
        pkg_manager_source = ""

        # Layer 1: Package manager enumeration
        pkg_components = {}

        pkgs = self._enumerate_packages_opkg()
        if pkgs:
            pkg_manager_source = "opkg"
        else:
            pkgs = self._enumerate_packages_dpkg()
            if pkgs:
                pkg_manager_source = "dpkg"

        if pkgs:
            self._log(f"SBOM: Found {len(pkgs)} packages from {pkg_manager_source}")

            for pkg in pkgs:
                name = pkg.get("name", "")
                version = pkg.get("version", "Unknown")

                if not name:
                    continue

                key = (name.lower(), version)
                if key in seen_components:
                    continue
                seen_components.add(key)

                vendor, product, cpe_part, purl_type = self._lookup_cpe(name)

                cpe = self._build_cpe23(vendor, product, version, cpe_part) if vendor else ""
                purl = self._build_purl(
                    "opkg" if pkg_manager_source == "opkg" else "deb",
                    vendor or "firmware", name, version
                ) if name else ""

                license_id = LICENSE_HINTS.get(product, "")

                comp = SBOMComponent(
                    name=name,
                    version=version,
                    component_type="library" if name.startswith("lib") else "application",
                    path="",
                    sha256="",
                    license_id=license_id,
                    supplier=vendor,
                    cpe=cpe,
                    purl=purl,
                    description=pkg.get("description", ""),
                    dependencies=pkg.get("depends", []),
                    source=f"package_manager:{pkg_manager_source}",
                    arch=pkg.get("arch", profile.arch),
                    is_third_party=True,
                )

                components.append(comp)
                pkg_components[name.lower()] = comp

        # Layer 2: ELF binary analysis
        for binary in binaries:
            filepath = self.target / binary.path
            filename = binary.filename
            filename_lower = filename.lower()

            if filename_lower in pkg_components:
                needed = self._get_needed_libs(filepath)
                if needed:
                    dependency_tree[binary.path] = needed
                continue

            version = ""

            if ".so" in filename:
                version = self._extract_so_version(filename)

            if not version and binary.binary_type in (BinaryType.EXECUTABLE, BinaryType.SHARED_LIB):
                version = self._extract_version(filepath)
                if version == "Unknown":
                    version = ""

            key = (filename_lower.split(".so")[0] if ".so" in filename_lower else filename_lower, version)
            if key in seen_components:
                continue
            seen_components.add(key)

            needed = self._get_needed_libs(filepath)
            if needed:
                dependency_tree[binary.path] = needed

            vendor, product, cpe_part, purl_type = self._lookup_cpe(filename)

            cpe = self._build_cpe23(vendor, product, version, cpe_part) if vendor and version else ""
            purl = self._build_purl(
                "generic", vendor or "firmware",
                product or filename_lower.split(".so")[0], version
            ) if version else ""

            license_id = LICENSE_HINTS.get(product, "")

            if binary.binary_type == BinaryType.SHARED_LIB:
                comp_type = "library"
            elif binary.binary_type == BinaryType.KERNEL_MODULE:
                comp_type = "firmware"
            else:
                comp_type = "application"

            sec_flags = {}
            if binary.nx is not None:
                sec_flags["nx"] = binary.nx
            if binary.canary is not None:
                sec_flags["canary"] = binary.canary
            if binary.pie is not None:
                sec_flags["pie"] = binary.pie
            if binary.relro != "none":
                sec_flags["relro"] = binary.relro
            if binary.fortify is not None:
                sec_flags["fortify"] = binary.fortify

            comp = SBOMComponent(
                name=product or (filename_lower.split(".so")[0] if ".so" in filename_lower else filename_lower),
                version=version if version else "Unknown",
                component_type=comp_type,
                path=binary.path,
                sha256=binary.sha256,
                license_id=license_id,
                supplier=vendor,
                cpe=cpe,
                purl=purl,
                description="",
                dependencies=needed,
                source="elf_analysis",
                arch=profile.arch,
                is_third_party=bool(vendor),
                security_flags=sec_flags,
            )

            components.append(comp)

        # Layer 3: Kernel and firmware-level components
        if profile.kernel and profile.kernel != "Unknown":
            key = ("linux_kernel", profile.kernel)
            if key not in seen_components:
                seen_components.add(key)
                components.append(SBOMComponent(
                    name="linux-kernel",
                    version=profile.kernel,
                    component_type="firmware",
                    path="",
                    cpe=self._build_cpe23("linux", "linux_kernel", profile.kernel, "o"),
                    purl=self._build_purl("generic", "linux", "linux-kernel", profile.kernel),
                    license_id="GPL-2.0-only",
                    supplier="linux",
                    source="firmware_profile",
                    arch=profile.arch,
                    is_third_party=True,
                ))

        if profile.busybox_applets > 0:
            bb_version = ""
            for binary in binaries:
                if binary.filename.lower() == "busybox":
                    bb_version = self._extract_version(self.target / binary.path)
                    break

            key = ("busybox", bb_version)
            if key not in seen_components:
                seen_components.add(key)
                components.append(SBOMComponent(
                    name="busybox",
                    version=bb_version if bb_version != "Unknown" else "",
                    component_type="application",
                    path="",
                    cpe=self._build_cpe23("busybox", "busybox", bb_version, "a") if bb_version and bb_version != "Unknown" else "",
                    purl=self._build_purl("generic", "busybox", "busybox", bb_version) if bb_version and bb_version != "Unknown" else "",
                    license_id="GPL-2.0-only",
                    supplier="busybox",
                    description=f"BusyBox with {profile.busybox_applets} applets",
                    source="firmware_profile",
                    arch=profile.arch,
                    is_third_party=True,
                ))

        type_order = {"application": 0, "firmware": 1, "library": 2, "framework": 3, "os": 4}
        components.sort(key=lambda c: (type_order.get(c.component_type, 5), c.name.lower()))

        total = len(components)
        total_libs = sum(1 for c in components if c.component_type == "library")
        total_apps = sum(1 for c in components if c.component_type == "application")
        with_version = sum(1 for c in components if c.version and c.version != "Unknown")
        with_cpe = sum(1 for c in components if c.cpe)

        return SBOMResult(
            serial_number=f"urn:uuid:{uuid.uuid4()}",
            timestamp=datetime.now(tz=None).strftime("%Y-%m-%dT%H:%M:%SZ"),
            firmware_name=Path(self.target).name,
            firmware_version="",
            components=components,
            dependency_tree=dependency_tree,
            total_components=total,
            total_libraries=total_libs,
            total_applications=total_apps,
            components_with_version=with_version,
            components_with_cpe=with_cpe,
            package_manager_source=pkg_manager_source,
        )
