import os
import re
import subprocess
import hashlib
from pathlib import Path
from typing import Dict, List, Tuple, Optional

from hardencheck.models import BinaryType
from hardencheck.constants.core import SECURE_ENV
from hardencheck.constants.services import NETWORK_SYMBOLS
from hardencheck.core.utils import safe_read_file


class BaseAnalyzer:
    """Base class providing shared infrastructure for all analyzers."""

    def __init__(self, ctx):
        self.ctx = ctx
        self.target = ctx.target
        self.tools = ctx.tools
        self.verbose = ctx.verbose

    def _set_resource_limits(self):
        """Set resource limits for child process to prevent DoS."""
        try:
            import resource
            resource.setrlimit(resource.RLIMIT_CPU, (60, 60))
            resource.setrlimit(resource.RLIMIT_AS, (512 * 1024 * 1024, 512 * 1024 * 1024))
            resource.setrlimit(resource.RLIMIT_FSIZE, (10 * 1024 * 1024, 10 * 1024 * 1024))
        except (ImportError, ValueError, OSError):
            pass

    def _run_command(self, cmd: List[str], timeout: int = 30) -> Tuple[int, str, str]:
        """Execute command securely with restricted environment and resource limits."""
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout,
                stdin=subprocess.DEVNULL,
                env=SECURE_ENV,
                close_fds=True,
                preexec_fn=self._set_resource_limits
            )
            return result.returncode, result.stdout, result.stderr
        except subprocess.TimeoutExpired:
            return -1, "", "Command timed out"
        except FileNotFoundError:
            return -1, "", "Command not found"
        except Exception as e:
            return -1, "", str(e)

    def _log(self, message: str):
        """Print verbose message."""
        if self.verbose:
            print(f"    [*] {message}")

    def _compute_sha256(self, filepath: Path) -> str:
        """Compute SHA256 hash of file."""
        sha256 = hashlib.sha256()
        try:
            with open(filepath, "rb") as f:
                for chunk in iter(lambda: f.read(65536), b""):
                    sha256.update(chunk)
            return sha256.hexdigest()
        except (OSError, PermissionError):
            return ""

    def _is_elf_file(self, filepath: Path) -> bool:
        """Check if file is ELF format."""
        try:
            with open(filepath, "rb") as f:
                magic = f.read(4)
            return magic == b"\x7fELF"
        except (OSError, PermissionError):
            return False

    def _get_elf_type(self, filepath: Path) -> BinaryType:
        """Determine ELF binary type from header."""
        try:
            with open(filepath, "rb") as f:
                f.seek(16)
                e_type_bytes = f.read(2)
                if len(e_type_bytes) < 2:
                    return BinaryType.UNKNOWN
                e_type = int.from_bytes(e_type_bytes, "little")

            filename = filepath.name.lower()

            if e_type == 1:
                if filename.endswith(".ko"):
                    return BinaryType.KERNEL_MODULE
                return BinaryType.RELOCATABLE
            elif e_type == 2:
                return BinaryType.EXECUTABLE
            elif e_type == 3:
                if ".so" in filename:
                    return BinaryType.SHARED_LIB
                return BinaryType.EXECUTABLE

            return BinaryType.UNKNOWN
        except (OSError, PermissionError):
            return BinaryType.UNKNOWN

    def _has_network_symbols(self, filepath: Path) -> bool:
        """Check if binary imports network-related symbols."""
        if "readelf" not in self.tools:
            return False

        ret, out, _ = self._run_command(
            [self.tools["readelf"], "-W", "--dyn-syms", str(filepath)], timeout=10
        )

        if ret != 0:
            return False

        out_lower = out.lower()
        matches = sum(1 for sym in NETWORK_SYMBOLS if sym in out_lower)
        return matches >= 2

    def _is_referenced_in_init(self, binary_name: str) -> bool:
        """Check if binary is referenced in init scripts."""
        init_paths = ["etc/init.d", "etc/rc.d", "etc/systemd/system", "etc/inittab"]

        for init_path in init_paths:
            full_path = self.target / init_path

            if full_path.is_file():
                content = safe_read_file(full_path)
                if content and binary_name in content:
                    return True
            elif full_path.is_dir():
                try:
                    for script in full_path.iterdir():
                        if script.is_file():
                            content = safe_read_file(script)
                            if content and binary_name in content:
                                return True
                except (OSError, PermissionError):
                    pass

        return False

    def _extract_version(self, filepath: Path) -> str:
        """Extract version string from binary using strings."""
        if "strings" not in self.tools:
            return "Unknown"

        ret, out, _ = self._run_command(
            [self.tools["strings"], "-n", "4", str(filepath)], timeout=15
        )

        if ret != 0 or not out:
            return "Unknown"

        version_patterns = [
            r"OpenSSH[_\s](\d+\.\d+\w*)",
            r"dropbear.*?v?(\d{4}\.\d+)",
            r"BusyBox\s+v?(\d+\.\d+\.\d+)",
            r"nginx/(\d+\.\d+\.\d+)",
            r"lighttpd/(\d+\.\d+\.\d+)",
            r"Apache/(\d+\.\d+\.\d+)",
            r"dnsmasq[_-](\d+\.\d+)",
            r"OpenSSL\s+(\d+\.\d+\.\d+\w*)",
            r"(?:^|[^.\d])(\d+\.\d+\.\d+)(?:[^.\d]|$)",
        ]

        for pattern in version_patterns:
            match = re.search(pattern, out, re.IGNORECASE | re.MULTILINE)
            if match:
                version = match.group(1)
                if 3 <= len(version) <= 20:
                    return version

        filename_match = re.search(r"[_-](\d+\.\d+(?:\.\d+)?)", filepath.name)
        if filename_match:
            return filename_match.group(1)

        return "Unknown"
