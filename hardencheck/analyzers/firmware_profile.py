import os
import re
import stat
from pathlib import Path
from typing import List, Tuple, Dict

from hardencheck.models import BinaryType, FirmwareProfile
from hardencheck.constants.firmware import FIRMWARE_MARKERS
from hardencheck.core.base import BaseAnalyzer
from hardencheck.core.utils import safe_read_file


class FirmwareProfiler(BaseAnalyzer):
    """Detect firmware type, architecture, and metadata."""

    def detect_firmware_profile(self, binaries: List[Tuple[Path, BinaryType]]) -> FirmwareProfile:
        """Detect firmware type, architecture, and metadata."""
        profile = FirmwareProfile()

        executables = [b for b in binaries if b[1] == BinaryType.EXECUTABLE]

        if executables and "file" in self.tools:
            ret, out, _ = self._run_command([self.tools["file"], str(executables[0][0])])
            if ret == 0:
                out_lower = out.lower()

                arch_patterns = [
                    (["x86-64", "x86_64", "amd64"], "x86_64", "64"),
                    (["x86", "i386", "i486", "i586", "i686", "80386"], "x86", "32"),
                    (["aarch64", "arm64"], "ARM64", "64"),
                    (["arm"], "ARM", "32"),
                    (["mips64"], "MIPS64", "64"),
                    (["mips"], "MIPS", "32"),
                    (["powerpc64", "ppc64"], "PowerPC64", "64"),
                    (["powerpc", "ppc"], "PowerPC", "32"),
                    (["riscv64"], "RISC-V", "64"),
                    (["riscv"], "RISC-V", "32"),
                ]

                for patterns, arch, bits in arch_patterns:
                    if any(p in out_lower for p in patterns):
                        profile.arch = arch
                        profile.bits = bits
                        break

                if "lsb" in out_lower or "little endian" in out_lower:
                    profile.endian = "Little Endian"
                elif "msb" in out_lower or "big endian" in out_lower:
                    profile.endian = "Big Endian"

                # Capture ABI detail (e.g. EABI5) from file output
                abi_match = re.search(r'\b(EABI\d?)\b', out, re.IGNORECASE)
                if abi_match:
                    profile.abi = abi_match.group(1).upper()

        if profile.arch == "Unknown" and executables:
            try:
                with open(executables[0][0], "rb") as f:
                    header = f.read(20)
                    if len(header) >= 20 and header[:4] == b'\x7fELF':
                        elf_class = header[4]
                        profile.bits = "64" if elf_class == 2 else "32"

                        elf_endian = header[5]
                        profile.endian = "Little Endian" if elf_endian == 1 else "Big Endian"

                        if elf_endian == 1:
                            machine = header[18] | (header[19] << 8)
                        else:
                            machine = (header[18] << 8) | header[19]

                        machine_map = {
                            3: "x86", 6: "x86", 62: "x86_64",
                            40: "ARM", 183: "ARM64",
                            8: "MIPS", 20: "PowerPC", 21: "PowerPC64",
                            243: "RISC-V"
                        }
                        profile.arch = machine_map.get(machine, f"Unknown({machine})")
            except (OSError, IOError):
                pass

        for fw_type, markers in FIRMWARE_MARKERS.items():
            for marker in markers:
                marker_path = self.target / marker.lstrip("/")
                if marker_path.exists():
                    if fw_type == "Yocto":
                        content = safe_read_file(marker_path)
                        if content and "poky" in content.lower():
                            profile.fw_type = "Yocto/Poky"
                            break
                    else:
                        profile.fw_type = fw_type
                        content = safe_read_file(marker_path)
                        if content:
                            first_line = content.strip().split("\n")[0][:40]
                            if first_line and not first_line.startswith("#"):
                                profile.fw_type = f"{fw_type} ({first_line})"
                        break
            if profile.fw_type != "Unknown":
                break

        if profile.fw_type == "Unknown":
            for root, dirs, files in os.walk(self.target):
                if "busybox" in files:
                    profile.fw_type = "BusyBox-based"
                    break
                dirs[:] = dirs[:20]

        for root, dirs, files in os.walk(self.target):
            for filename in files:
                name_lower = filename.lower()
                if "musl" in name_lower and ".so" in name_lower:
                    profile.libc = "musl libc"
                    break
                elif name_lower.startswith("libc-") and name_lower.endswith(".so"):
                    version_match = re.search(r"libc-(\d+\.\d+)", filename)
                    if version_match:
                        profile.libc = f"glibc {version_match.group(1)}"
                    else:
                        profile.libc = "glibc"
                    break
                elif "uclibc" in name_lower or "libuClibc" in filename:
                    profile.libc = "uClibc"
                    break
            if profile.libc != "Unknown":
                break
            dirs[:] = dirs[:10]

        for root, dirs, files in os.walk(self.target):
            if "modules" in root:
                for dirname in dirs:
                    if re.match(r"^\d+\.\d+\.\d+", dirname):
                        profile.kernel = dirname
                        break
            if profile.kernel != "Unknown":
                break
            dirs[:] = dirs[:20]

        profile.filesystem = self._detect_filesystem()
        profile.compression = self._detect_compression()
        profile.bootloader = self._detect_bootloader()
        profile.init_system = self._detect_init_system()
        profile.package_manager = self._detect_package_manager()
        profile.ssl_library = self._detect_ssl_library()
        profile.crypto_library = self._detect_crypto_library()
        profile.web_server = self._detect_web_server(binaries)
        profile.ssh_server = self._detect_ssh_server(binaries)
        profile.dns_server = self._detect_dns_server(binaries)
        profile.platform = self._detect_platform(executables)
        profile.shells = self._detect_shells()
        profile.runtime = self._detect_runtime(binaries)
        profile.busybox_applets = self._count_busybox_applets()
        profile.kernel_modules = self._count_kernel_modules()
        profile.total_size_mb = self._calculate_total_size()
        profile.interesting_files = self._find_interesting_files()

        profile.elf_binaries = len([b for b in binaries if b[1] == BinaryType.EXECUTABLE])
        profile.shared_libs = len([b for b in binaries if b[1] == BinaryType.SHARED_LIB])

        for root, dirs, files in os.walk(self.target):
            dirs[:] = [d for d in dirs if not d.startswith(".")]
            profile.total_files += len(files)

            for filename in files:
                filepath = Path(root) / filename

                if filepath.is_symlink():
                    profile.symlinks += 1
                    continue

                if filename.endswith(".sh"):
                    profile.shell_scripts += 1
                else:
                    try:
                        with open(filepath, "rb") as f:
                            header = f.read(2)
                        if header == b"#!":
                            profile.shell_scripts += 1
                    except (OSError, PermissionError):
                        pass

                if filepath.suffix.lower() in {".conf", ".cfg", ".ini", ".config"}:
                    profile.config_files += 1

                try:
                    file_stat = filepath.stat()
                    mode = file_stat.st_mode
                    if mode & stat.S_ISUID:
                        rel_path = str(filepath.relative_to(self.target))
                        profile.setuid_files.append(rel_path)
                    if mode & stat.S_ISGID and stat.S_ISREG(mode):
                        rel_path = str(filepath.relative_to(self.target))
                        profile.setgid_files.append(rel_path)
                    if mode & stat.S_IWOTH and stat.S_ISREG(mode):
                        rel_path = str(filepath.relative_to(self.target))
                        profile.world_writable.append(rel_path)
                except (OSError, PermissionError):
                    pass

        return profile

    def _detect_filesystem(self) -> str:
        """Detect filesystem type from firmware structure."""
        fs_indicators = {
            "SquashFS": [
                ("hsqs", b"hsqs"),
                ("sqsh", b"sqsh"),
                ("sqlz", b"sqlz"),
            ],
            "JFFS2": [
                (".jffs2", None),
                ("jffs2", None),
            ],
            "UBIFS": [
                ("ubifs", None),
                (".ubi", None),
            ],
            "CramFS": [
                ("cramfs", None),
            ],
            "YAFFS": [
                ("yaffs", None),
            ],
            "Ext4": [
                ("lost+found", None),
            ],
            "ROMFS": [
                ("-rom1fs-", b"-rom1fs-"),
            ],
        }

        detected = []

        for root, dirs, files in os.walk(self.target):
            # Only check the immediate directory name (basename), not the full path,
            # to avoid false positives from parent directories with matching substrings.
            dir_basename = os.path.basename(root).lower()
            file_names_lower = [f.lower() for f in files]
            for fs_type, indicators in fs_indicators.items():
                for indicator, magic in indicators:
                    if dir_basename == indicator or indicator in file_names_lower:
                        if fs_type not in detected:
                            detected.append(fs_type)
            dirs[:] = dirs[:30]
            if len(detected) >= 3:
                break

        fstab_path = self.target / "etc" / "fstab"
        if fstab_path.exists():
            content = safe_read_file(fstab_path)
            if content:
                fs_types = ["squashfs", "jffs2", "ubifs", "cramfs", "yaffs", "ext4", "ext3", "ext2", "vfat", "tmpfs", "nfs"]
                for fs in fs_types:
                    if fs in content.lower() and fs.upper() not in [d.upper() for d in detected]:
                        detected.append(fs.upper() if fs not in ["ext4", "ext3", "ext2", "vfat", "tmpfs", "nfs"] else fs)

        if (self.target / "lost+found").exists():
            if "Ext4" not in detected and "ext4" not in detected:
                detected.append("Ext4")

        return ", ".join(detected[:3]) if detected else "Unknown"

    def _detect_compression(self) -> str:
        """Detect compression algorithms used in firmware."""
        compression_markers = {
            "LZMA": [".lzma", "lzma"],
            "XZ": [".xz", "xz-utils"],
            "GZIP": [".gz", "gzip"],
            "BZIP2": [".bz2", "bzip2"],
            "LZ4": [".lz4", "lz4"],
            "ZSTD": [".zst", ".zstd", "zstd"],
            "LZO": [".lzo", "lzop"],
        }

        detected = []

        for root, dirs, files in os.walk(self.target):
            for filename in files:
                name_lower = filename.lower()
                for comp_type, markers in compression_markers.items():
                    if any(marker in name_lower for marker in markers):
                        if comp_type not in detected:
                            detected.append(comp_type)
            dirs[:] = dirs[:20]
            if len(detected) >= 4:
                break

        for comp_tool in ["gzip", "bzip2", "xz", "lzma", "lz4", "zstd", "lzop"]:
            tool_path = self.target / "usr" / "bin" / comp_tool
            tool_path2 = self.target / "bin" / comp_tool
            if tool_path.exists() or tool_path2.exists():
                comp_name = comp_tool.upper()
                if comp_name == "LZOP":
                    comp_name = "LZO"
                if comp_name not in detected:
                    detected.append(comp_name)

        return ", ".join(detected[:4]) if detected else "Unknown"

    def _detect_bootloader(self) -> str:
        """Detect bootloader type."""
        bootloader_indicators = {
            "U-Boot": ["u-boot", "uboot", "fw_printenv", "fw_setenv", "u-boot.bin", "uboot.bin"],
            "GRUB": ["grub", "grub.cfg", "grub.conf"],
            "GRUB2": ["grub2", "grub2.cfg"],
            "Barebox": ["barebox"],
            "RedBoot": ["redboot"],
            "CFE": ["cfe", "cferam", "cfe.bin"],
            "PMON": ["pmon"],
            "Breed": ["breed"],
            "OpenWrt Bootloader": ["pb-boot"],
            "LK": ["lk.bin", "lk.img"],
            "UEFI": ["efi", "uefi"],
        }

        detected = []

        uboot_env = self.target / "etc" / "fw_env.config"
        if uboot_env.exists():
            detected.append("U-Boot")

        uboot_scripts = ["boot.scr", "boot.cmd", "uEnv.txt", "extlinux.conf"]
        for script in uboot_scripts:
            for search_dir in ["", "boot", "boot/extlinux"]:
                script_path = self.target / search_dir / script if search_dir else self.target / script
                if script_path.exists():
                    if "U-Boot" not in detected:
                        detected.append("U-Boot")
                    break

        for root, dirs, files in os.walk(self.target):
            all_names = [f.lower() for f in files] + [d.lower() for d in dirs]
            for bl_type, indicators in bootloader_indicators.items():
                if bl_type in detected:
                    continue
                for indicator in indicators:
                    if any(indicator in name for name in all_names):
                        detected.append(bl_type)
                        break
            dirs[:] = dirs[:30]
            if len(detected) >= 2:
                break

        proc_cmdline = self.target / "proc" / "cmdline"
        if proc_cmdline.exists():
            content = safe_read_file(proc_cmdline)
            if content:
                if "uboot" in content.lower() and "U-Boot" not in detected:
                    detected.append("U-Boot")

        if not detected:
            for root, dirs, files in os.walk(self.target):
                for f in files:
                    f_lower = f.lower()
                    if "kernel" in f_lower or "zimage" in f_lower or "uimage" in f_lower:
                        if "U-Boot" not in detected:
                            detected.append("U-Boot (likely)")
                        break
                dirs[:] = dirs[:10]
                if detected:
                    break

        return ", ".join(detected) if detected else "Unknown"

    def _detect_init_system(self) -> str:
        """Detect init system type."""
        if (self.target / "lib" / "systemd").exists() or (self.target / "etc" / "systemd").exists():
            return "systemd"

        if (self.target / "sbin" / "procd").exists():
            return "procd (OpenWrt)"

        if (self.target / "etc" / "init.d").exists():
            rcS = self.target / "etc" / "init.d" / "rcS"
            if rcS.exists():
                content = safe_read_file(rcS)
                if content and "procd" in content:
                    return "procd (OpenWrt)"

        if (self.target / "sbin" / "openrc-run").exists() or (self.target / "etc" / "runlevels").exists():
            return "OpenRC"

        if (self.target / "etc" / "runit").exists() or (self.target / "sbin" / "runit").exists():
            return "runit"

        if (self.target / "etc" / "s6").exists() or (self.target / "sbin" / "s6-svscan").exists():
            return "s6"

        inittab_path = self.target / "etc" / "inittab"
        if inittab_path.exists():
            content = safe_read_file(inittab_path)
            if content:
                if "sysinit" in content or "::respawn:" in content or "::ctrlaltdel:" in content:
                    return "BusyBox init"
                if "initdefault" in content:
                    return "SysVinit"
                return "init (inittab)"

        if (self.target / "sbin" / "init").exists():
            init_path = self.target / "sbin" / "init"
            if init_path.is_symlink():
                try:
                    link_target = os.readlink(init_path)
                    if "busybox" in link_target.lower():
                        return "BusyBox init"
                except (OSError, PermissionError):
                    pass
            return "init (generic)"

        if (self.target / "etc" / "init.d").exists():
            init_d = self.target / "etc" / "init.d"
            try:
                scripts = list(init_d.iterdir())
                if scripts:
                    return "SysVinit (init.d)"
            except (OSError, PermissionError):
                pass

        if (self.target / "etc" / "rcS.d").exists() or (self.target / "etc" / "rc.d").exists():
            return "SysVinit (rc.d)"

        return "Unknown"

    def _detect_package_manager(self) -> str:
        """Detect package management system."""
        package_managers = {
            "opkg": ["opkg", "opkg.conf", "/var/opkg-lists", "/etc/opkg.conf", "/etc/opkg"],
            "dpkg/apt": ["dpkg", "apt", "apt-get", "/var/lib/dpkg", "/var/cache/apt"],
            "rpm/yum": ["rpm", "yum", "dnf", "/var/lib/rpm"],
            "ipkg": ["ipkg", "ipkg.conf", "/etc/ipkg.conf"],
            "apk": ["apk", "/lib/apk", "/etc/apk"],
            "pacman": ["pacman", "/var/lib/pacman"],
            "Entware": ["/opt/etc/opkg.conf", "/opt/bin/opkg"],
            "swupdate": ["swupdate", "/etc/swupdate.cfg"],
            "RAUC": ["rauc", "/etc/rauc"],
            "Mender": ["mender", "/etc/mender"],
            "SWUpdate": ["swupdate"],
        }

        for pm_name, indicators in package_managers.items():
            for indicator in indicators:
                if indicator.startswith("/"):
                    check_path = self.target / indicator.lstrip("/")
                    if check_path.exists():
                        return pm_name
                else:
                    bin_paths = [
                        self.target / "usr" / "bin" / indicator,
                        self.target / "bin" / indicator,
                        self.target / "sbin" / indicator,
                        self.target / "usr" / "sbin" / indicator,
                    ]
                    for bin_path in bin_paths:
                        if bin_path.exists():
                            return pm_name

                    etc_path = self.target / "etc" / indicator
                    if etc_path.exists():
                        return pm_name

        for root, dirs, files in os.walk(self.target):
            for f in files:
                f_lower = f.lower()
                if f_lower.endswith(".ipk"):
                    return "opkg/ipkg (IPK packages found)"
                elif f_lower.endswith(".deb"):
                    return "dpkg (DEB packages found)"
                elif f_lower.endswith(".rpm"):
                    return "rpm (RPM packages found)"
                elif f_lower.endswith(".apk") and "apk" in root.lower():
                    return "apk (APK packages found)"
            dirs[:] = dirs[:20]

        return "None (static firmware)"

    def _calculate_total_size(self) -> float:
        """Calculate total size of firmware in MB."""
        total_bytes = 0
        try:
            for root, dirs, files in os.walk(self.target):
                for filename in files:
                    filepath = Path(root) / filename
                    try:
                        if not filepath.is_symlink():
                            total_bytes += filepath.stat().st_size
                    except (OSError, PermissionError):
                        pass
                dirs[:] = [d for d in dirs if not d.startswith(".")]
        except Exception:
            pass
        return round(total_bytes / (1024 * 1024), 2)

    def _detect_ssl_library(self) -> str:
        """Detect SSL/TLS library and version using strings output for accuracy."""
        ssl_libs = {
            "OpenSSL": ["libssl.so", "libcrypto.so", "openssl"],
            "wolfSSL": ["libwolfssl.so", "wolfssl"],
            "mbedTLS": ["libmbedtls.so", "libmbedcrypto.so", "mbedtls"],
            "GnuTLS": ["libgnutls.so", "gnutls"],
            "LibreSSL": ["libressl"],
            "BoringSSL": ["boringssl"],
            "BearSSL": ["libbearssl.so", "bearssl"],
            "MatrixSSL": ["libmatrixssl.so"],
            "axTLS": ["libaxtls.so", "axtls"],
        }

        # Version string patterns to search inside the binary with `strings`
        ssl_version_patterns = {
            "OpenSSL": re.compile(r'OpenSSL\s+([\d.]+\w*(?:-fips)?)', re.IGNORECASE),
            "wolfSSL": re.compile(r'wolfSSL\s+([\d.]+)', re.IGNORECASE),
            "mbedTLS": re.compile(r'mbed\s*TLS\s+([\d.]+)', re.IGNORECASE),
            "GnuTLS": re.compile(r'GnuTLS\s+([\d.]+)', re.IGNORECASE),
            "LibreSSL": re.compile(r'LibreSSL\s+([\d.]+)', re.IGNORECASE),
        }

        detected = []
        detected_paths = {}

        for root, dirs, files in os.walk(self.target):
            for f in files:
                f_lower = f.lower()
                for ssl_name, indicators in ssl_libs.items():
                    if ssl_name in [d.split()[0] for d in detected]:
                        continue
                    for indicator in indicators:
                        if indicator in f_lower:
                            detected_paths[ssl_name] = Path(root) / f
                            detected.append(ssl_name)
                            break
            dirs[:] = dirs[:20]
            if len(detected) >= 2:
                break

        # Now enrich with version from strings output
        result = []
        for ssl_name in detected:
            version = ""
            lib_path = detected_paths.get(ssl_name)
            if lib_path and "strings" in self.tools:
                ret, out, _ = self._run_command(
                    [self.tools["strings"], "-n", "6", str(lib_path)], timeout=10
                )
                if ret == 0 and out:
                    pat = ssl_version_patterns.get(ssl_name)
                    if pat:
                        m = pat.search(out)
                        if m:
                            version = f" {m.group(1)}"
            if not version and lib_path:
                # Fall back to .so.X.Y.Z in filename
                ver_match = re.search(r'\.so\.(\d+\.\d+\.?\d*)', lib_path.name)
                if ver_match:
                    version = f" {ver_match.group(1)}"
            result.append(f"{ssl_name}{version}")

        return ", ".join(result) if result else "Unknown"

    def _detect_crypto_library(self) -> str:
        """Detect cryptographic libraries."""
        crypto_libs = {
            "libsodium": ["libsodium.so"],
            "libgcrypt": ["libgcrypt.so"],
            "Nettle": ["libnettle.so", "libhogweed.so"],
            "libtomcrypt": ["libtomcrypt.so"],
            "Crypto++": ["libcryptopp.so", "libcrypto++.so"],
            "NSS": ["libnss3.so", "libnssutil3.so"],
        }

        detected = []
        for root, dirs, files in os.walk(self.target):
            for f in files:
                f_lower = f.lower()
                for lib_name, indicators in crypto_libs.items():
                    if lib_name in detected:
                        continue
                    for indicator in indicators:
                        if indicator in f_lower:
                            detected.append(lib_name)
                            break
            dirs[:] = dirs[:15]
            if len(detected) >= 3:
                break

        return ", ".join(detected) if detected else "None"

    def _detect_web_server(self, binaries: List[Tuple[Path, BinaryType]]) -> str:
        """Detect web server from binaries."""
        web_servers = {
            "nginx": "nginx",
            "lighttpd": "lighttpd",
            "httpd": "httpd",
            "uhttpd": "uhttpd",
            "apache": "Apache",
            "apache2": "Apache",
            "mini_httpd": "mini_httpd",
            "thttpd": "thttpd",
            "boa": "Boa",
            "goahead": "GoAhead",
            "mongoose": "Mongoose",
            "cherokee": "Cherokee",
            "hiawatha": "Hiawatha",
        }

        for binary_path, _ in binaries:
            name = binary_path.name.lower()
            for bin_name, display_name in web_servers.items():
                if bin_name == name or name.startswith(bin_name):
                    version = self._extract_version(binary_path)
                    label = f"{display_name} {version}" if version != "Unknown" else display_name

                    # Check if statically compiled (no NEEDED entries) and count modules
                    extra = []
                    if "readelf" in self.tools:
                        ret, dyn_out, _ = self._run_command(
                            [self.tools["readelf"], "-W", "-d", str(binary_path)], timeout=10
                        )
                        if ret == 0 and "NEEDED" not in dyn_out:
                            extra.append("statically compiled")

                    if "strings" in self.tools:
                        ret, str_out, _ = self._run_command(
                            [self.tools["strings"], "-n", "4", str(binary_path)], timeout=10
                        )
                        if ret == 0:
                            mod_count = len(re.findall(r'mod_\w+', str_out))
                            if mod_count > 0:
                                extra.append(f"{mod_count} modules")

                    if extra:
                        label = f"{label} ({', '.join(extra)})"
                    return label

        return "None"

    def _detect_ssh_server(self, binaries: List[Tuple[Path, BinaryType]]) -> str:
        """Detect SSH server from binaries."""
        ssh_servers = {
            "dropbear": "Dropbear",
            "sshd": "OpenSSH",
            "openssh": "OpenSSH",
            "tinyssh": "TinySSH",
        }

        for binary_path, _ in binaries:
            name = binary_path.name.lower()
            for bin_name, display_name in ssh_servers.items():
                if bin_name in name:
                    version = self._extract_version(binary_path)
                    if version != "Unknown":
                        return f"{display_name} {version}"
                    return display_name

        return "None"

    def _detect_dns_server(self, binaries: List[Tuple[Path, BinaryType]]) -> str:
        """Detect DNS server from binaries."""
        dns_servers = {
            "dnsmasq": "dnsmasq",
            "named": "BIND",
            "unbound": "Unbound",
            "pdns": "PowerDNS",
            "knot": "Knot DNS",
            "nsd": "NSD",
            "coredns": "CoreDNS",
        }

        for binary_path, _ in binaries:
            name = binary_path.name.lower()
            for bin_name, display_name in dns_servers.items():
                if bin_name in name:
                    version = self._extract_version(binary_path)
                    if version != "Unknown":
                        return f"{display_name} {version}"
                    return display_name

        return "None"

    def _count_busybox_applets(self) -> int:
        """Count BusyBox applets (symlinks to busybox)."""
        count = 0
        busybox_paths = [
            self.target / "bin" / "busybox",
            self.target / "sbin" / "busybox",
            self.target / "usr" / "bin" / "busybox",
            self.target / "usr" / "sbin" / "busybox",
        ]

        busybox_exists = any(p.exists() for p in busybox_paths)
        if not busybox_exists:
            return 0

        for search_dir in ["bin", "sbin", "usr/bin", "usr/sbin"]:
            dir_path = self.target / search_dir
            if not dir_path.exists():
                continue
            try:
                for item in dir_path.iterdir():
                    if item.is_symlink():
                        try:
                            link_target = os.readlink(item)
                            if "busybox" in link_target.lower():
                                count += 1
                        except (OSError, PermissionError):
                            pass
            except (OSError, PermissionError):
                pass

        return count

    def _count_kernel_modules(self) -> int:
        """Count kernel modules (.ko files)."""
        count = 0
        for root, dirs, files in os.walk(self.target):
            for f in files:
                if f.endswith(".ko") or f.endswith(".ko.gz") or f.endswith(".ko.xz"):
                    count += 1
            dirs[:] = dirs[:50]
        return count

    def _find_interesting_files(self) -> list:
        """Find potentially interesting files for security analysis."""
        interesting = []

        interesting_names = {
            "shadow", "passwd", "group", "gshadow",
            "id_rsa", "id_dsa", "id_ecdsa", "id_ed25519",
            "authorized_keys", "known_hosts",
            ".htpasswd", ".htaccess",
            "wp-config.php", "config.php", "settings.php",
            "database.yml", "secrets.yml",
            ".env", ".env.local", ".env.production",
            "credentials", "secrets", "passwords",
        }

        for root, dirs, files in os.walk(self.target):
            for f in files:
                f_lower = f.lower()

                if f_lower in interesting_names:
                    try:
                        rel_path = str((Path(root) / f).relative_to(self.target))
                        if rel_path not in interesting:
                            interesting.append(rel_path)
                    except ValueError:
                        pass

                for pattern in ["shadow", "passwd", "secret", "credential", "token", "backup"]:
                    if pattern in f_lower and "example" not in f_lower and "sample" not in f_lower:
                        try:
                            rel_path = str((Path(root) / f).relative_to(self.target))
                            if rel_path not in interesting:
                                interesting.append(rel_path)
                        except ValueError:
                            pass
                        break

            dirs[:] = [d for d in dirs if not d.startswith(".")][:30]
            if len(interesting) >= 50:
                break

        return interesting[:30]

    def _detect_platform(self, executables) -> str:
        """Detect SoC/board platform from cpuinfo, device-tree, U-Boot env, or kernel strings."""
        # 1. /proc/cpuinfo in extracted FS
        cpuinfo_path = self.target / "proc" / "cpuinfo"
        if cpuinfo_path.exists():
            content = safe_read_file(cpuinfo_path)
            if content:
                hw_match = re.search(r'Hardware\s*:\s*(.+)', content)
                model_match = re.search(r'Model\s*:\s*(.+)', content)
                cpu_match = re.search(r'CPU part\s*:\s*(0x[0-9a-f]+)', content, re.IGNORECASE)
                if hw_match or model_match:
                    platform = (model_match or hw_match).group(1).strip()
                    return platform

        # 2. Device-tree compatible string
        dt_compatible = self.target / "sys" / "firmware" / "devicetree" / "base" / "compatible"
        if not dt_compatible.exists():
            dt_compatible = self.target / "proc" / "device-tree" / "compatible"
        if dt_compatible.exists():
            try:
                with open(dt_compatible, "rb") as f:
                    compat = f.read(256).decode("utf-8", errors="replace").strip("\x00").split("\x00")
                if compat:
                    return compat[0].strip()
            except (OSError, UnicodeDecodeError):
                pass

        # 3. U-Boot environment / fw_env.config
        for env_file in ["etc/fw_env.config", "boot/uEnv.txt", "uEnv.txt"]:
            env_path = self.target / env_file
            if env_path.exists():
                content = safe_read_file(env_path)
                if content:
                    board_match = re.search(r'(?:board|machine|platform)\s*[=:]\s*(\S+)', content, re.IGNORECASE)
                    if board_match:
                        return board_match.group(1).strip()

        # 4. Known SoC markers from binary strings
        soc_markers = [
            (r'i\.MX8M?\s*(?:Mini|Nano|Plus|Quad)?', "NXP i.MX8M"),
            (r'i\.MX6\w*', "NXP i.MX6"),
            (r'Allwinner\s+[AH]\d+', "Allwinner"),
            (r'Rockchip\s+RK\d+', "Rockchip"),
            (r'Qualcomm\s+(?:SDM|MSM|APQ)\d+', "Qualcomm"),
            (r'Broadcom\s+BCM\d+', "Broadcom"),
            (r'MediaTek\s+MT\d+', "MediaTek"),
            (r'Raspberry\s+Pi\s+\d+', "Raspberry Pi"),
            (r'BeagleBone', "BeagleBone"),
            (r'OMAP\d+', "TI OMAP"),
            (r'AM\d{4}x?', "TI AM"),
            (r'STM32\w+', "STMicro STM32"),
            (r'ESP\d+', "Espressif ESP"),
            (r'nRF\d+', "Nordic nRF"),
        ]

        # Search in small kernel/boot binaries first
        for search_dir in ["boot", "lib/firmware"]:
            search_path = self.target / search_dir
            if not search_path.exists():
                continue
            for f in sorted(search_path.iterdir())[:5]:
                if not f.is_file() or f.stat().st_size > 8 * 1024 * 1024:
                    continue
                if "strings" not in self.tools:
                    continue
                ret, out, _ = self._run_command(
                    [self.tools["strings"], "-n", "6", str(f)], timeout=10
                )
                if ret == 0:
                    for pattern, label in soc_markers:
                        m = re.search(pattern, out, re.IGNORECASE)
                        if m:
                            return f"{label} ({m.group(0).strip()})"

        return "Unknown"

    def _detect_shells(self) -> str:
        """Detect available shells (bash, dash, zsh, ash, etc.)."""
        shell_names = ["bash", "dash", "zsh", "ksh", "ash", "sh", "fish", "tcsh", "csh"]
        bin_dirs = ["bin", "sbin", "usr/bin", "usr/sbin", "usr/local/bin"]

        found = []
        for shell in shell_names:
            for d in bin_dirs:
                shell_path = self.target / d / shell
                if shell_path.exists():
                    if shell not in found:
                        found.append(shell)
                    break

        # BusyBox provides a shell — label it clearly if present
        has_busybox = any(
            (self.target / d / "busybox").exists() for d in bin_dirs
        )
        if has_busybox and "busybox" not in found:
            found.append("busybox")

        # ash/sh via busybox symlink — avoid double-counting plain "sh"
        if has_busybox and "sh" in found and "ash" not in found:
            found.remove("sh")

        return " + ".join(found) if found else "Unknown"

    def _detect_runtime(self, binaries) -> str:
        """Detect language runtimes (Mono/.NET, Python, Java, Node.js, Ruby, Lua)."""
        runtimes = []

        runtime_bins = {
            "Mono/.NET": ["mono", "mono-runtime", "dotnet", "mcs"],
            "Java": ["java", "dalvikvm", "art"],
            "Python": ["python", "python2", "python3"],
            "Node.js": ["node", "nodejs"],
            "Ruby": ["ruby"],
            "Lua": ["lua", "lua5.1", "lua5.2", "lua5.3", "lua5.4"],
            "Perl": ["perl"],
            "PHP": ["php", "php-cgi", "php-fpm"],
        }

        bin_dirs = ["bin", "sbin", "usr/bin", "usr/sbin", "usr/local/bin"]

        for runtime_name, bin_names in runtime_bins.items():
            for bin_name in bin_names:
                for d in bin_dirs:
                    rt_path = self.target / d / bin_name
                    if rt_path.exists():
                        # Try to get version
                        version = ""
                        if "strings" in self.tools:
                            ret, out, _ = self._run_command(
                                [self.tools["strings"], "-n", "4", str(rt_path)], timeout=8
                            )
                            if ret == 0 and out:
                                # Generic version pattern
                                ver_m = re.search(
                                    r'(?:version|v)\s*([\d]+\.[\d]+\.?[\d]*)',
                                    out, re.IGNORECASE
                                )
                                if not ver_m:
                                    ver_m = re.search(r'\b([\d]+\.[\d]+\.[\d]+)\b', out)
                                if ver_m:
                                    version = f" {ver_m.group(1)}"
                        label = f"{runtime_name}{version}"
                        if label not in runtimes:
                            runtimes.append(label)
                        break
                else:
                    continue
                break

        # Also check for Mono assemblies (.dll, .exe with ECMA CLI header)
        if "Mono/.NET" not in [r.split()[0] for r in runtimes]:
            for root, dirs, files in os.walk(self.target):
                for f in files:
                    if f.lower().endswith((".exe", ".dll")):
                        filepath = Path(root) / f
                        try:
                            with open(filepath, "rb") as fh:
                                header = fh.read(4)
                            if header[:2] == b"MZ":  # PE header — .NET/Mono binary
                                runtimes.insert(0, "Mono/.NET")
                                break
                        except (OSError, PermissionError):
                            pass
                else:
                    dirs[:] = dirs[:20]
                    continue
                break

        return ", ".join(runtimes) if runtimes else "None"
