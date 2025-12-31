#!/usr/bin/env python3
"""
HardenCheck - Firmware Binary Security Analyzer
Author: v33ru (Mr-IoT) | github.com/v33ru | IOTSRG
"""

import os
import sys
import json
import hashlib
import argparse
import shutil
import subprocess
import re
import stat
from pathlib import Path
from dataclasses import dataclass, field
from typing import List, Dict, Tuple, Optional
from enum import Enum
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime

VERSION = "1.0.0"

BANNER = r"""
    ╔═╤═╤═╤═╤═╤═╤═╤═╤═╤═╤═╤═╤═╤═╤═╤═╤═╤═╤═╤═╤═╤═╤═╤═╤═╤═╗
    ║●│ │ │ │ │●│ │ │ │ │●│ │ │ │ │●│ │ │ │ │●│ │ │ │●│●║
    ╟─┴─┴─┴─┴─┴─┴─┴─┴─┴─┴─┴─┴─┴─┴─┴─┴─┴─┴─┴─┴─┴─┴─┴─┴─┴─╢
    ║      ██   H A R D E N C H E C K   ██              ║
    ║      ██   Firmware Security Tool  ██              ║
    ║      ██   v1.0 | @v33ru | IOTSRG  ██              ║
    ╟─┬─┬─┬─┬─┬─┬─┬─┬─┬─┬─┬─┬─┬─┬─┬─┬─┬─┬─┬─┬─┬─┬─┬─┬─┬─╢
    ║●│ │ │ │ │●│ │ │ │ │●│ │ │ │ │●│ │ │ │ │●│ │ │ │●│●║
    ╚═╧═╧═╧═╧═╧═╧═╧═╧═╧═╧═╧═╧═╧═╧═╧═╧═╧═╧═╧═╧═╧═╧═╧═╧═╧═╝
"""


# =============================================================================
# DATA STRUCTURES
# =============================================================================

class Severity(Enum):
    """Risk severity levels."""
    CRITICAL = 4
    HIGH = 3
    MEDIUM = 2
    LOW = 1
    INFO = 0


class BinaryType(Enum):
    """ELF binary types."""
    EXECUTABLE = "Executable"
    SHARED_LIB = "Shared Library"
    RELOCATABLE = "Relocatable"
    KERNEL_MODULE = "Kernel Module"
    UNKNOWN = "Unknown"


@dataclass
class FirmwareProfile:
    """Firmware metadata."""
    arch: str = "Unknown"
    bits: str = "Unknown"
    endian: str = "Unknown"
    fw_type: str = "Unknown"
    libc: str = "Unknown"
    kernel: str = "Unknown"
    total_files: int = 0
    elf_binaries: int = 0
    shared_libs: int = 0
    shell_scripts: int = 0
    config_files: int = 0
    setuid_files: List[str] = field(default_factory=list)
    world_writable: List[str] = field(default_factory=list)


@dataclass
class Daemon:
    """Network service/daemon information."""
    name: str
    binary: str
    path: str
    version: str
    risk: str
    reason: str
    has_network: bool
    status: str = "Unknown"


@dataclass
class BinaryAnalysis:
    """Binary security analysis result."""
    path: str
    filename: str
    size: int
    sha256: str
    binary_type: BinaryType
    nx: Optional[bool] = None
    canary: Optional[bool] = None
    pie: Optional[bool] = None
    relro: str = "none"
    fortify: Optional[bool] = None
    stripped: Optional[bool] = None
    stack_clash: str = "unknown"
    cfi: str = "unknown"
    textrel: bool = False
    rpath: str = ""
    confidence: int = 100
    tools_used: List[str] = field(default_factory=list)


@dataclass
class BannedFunctionHit:
    """Dangerous function usage."""
    function: str
    file: str
    line: int
    snippet: str
    severity: Severity
    alternative: str
    compliance: str


@dataclass
class DependencyRisk:
    """Insecure library dependency."""
    library: str
    issue: str
    used_by: List[str] = field(default_factory=list)


@dataclass
class CredentialFinding:
    """Hardcoded credential finding."""
    file: str
    line: int
    pattern: str
    snippet: str
    severity: Severity


@dataclass
class CertificateFinding:
    """Certificate/key file finding."""
    file: str
    file_type: str
    issue: str
    severity: Severity


@dataclass
class ConfigFinding:
    """Dangerous configuration finding."""
    file: str
    line: int
    issue: str
    snippet: str
    severity: Severity


@dataclass
class ScanResult:
    """Complete scan result."""
    target: str
    scan_time: str
    duration: float
    tools: Dict[str, str]
    profile: FirmwareProfile
    daemons: List[Daemon]
    binaries: List[BinaryAnalysis]
    banned_functions: List[BannedFunctionHit]
    dependency_risks: List[DependencyRisk]
    credentials: List[CredentialFinding]
    certificates: List[CertificateFinding]
    config_issues: List[ConfigFinding]


# =============================================================================
# CONSTANTS
# =============================================================================

# Banned functions with alternatives and compliance mapping
BANNED_FUNCTIONS = {
    # Buffer overflow - CRITICAL
    "gets":     ("fgets(buf, size, stdin)", Severity.CRITICAL, "CWE-120, OWASP-I4"),
    
    # Buffer overflow - HIGH  
    "strcpy":   ("strlcpy() or strncpy()+null", Severity.HIGH, "CWE-120, OWASP-I4"),
    "strcat":   ("strlcat() or strncat()+null", Severity.HIGH, "CWE-120, OWASP-I4"),
    "sprintf":  ("snprintf(buf, size, ...)", Severity.HIGH, "CWE-120, OWASP-I4"),
    "vsprintf": ("vsnprintf(buf, size, ...)", Severity.HIGH, "CWE-120, OWASP-I4"),
    
    # Format string / Input validation
    "scanf":    ("fgets() + sscanf() or strtol()", Severity.HIGH, "CWE-134, OWASP-I4"),
    "fscanf":   ("fgets() + sscanf()", Severity.MEDIUM, "CWE-134, OWASP-I4"),
    "sscanf":   ("strtol/strtod with validation", Severity.LOW, "CWE-134"),
    
    # Command injection - HIGH (avoid external commands if possible)
    "system":   ("execve() with hardcoded path + validated args, or use library APIs", Severity.HIGH, "CWE-78, OWASP-I4"),
    "popen":    ("pipe()+fork()+execve() with validated args, or library APIs", Severity.HIGH, "CWE-78, OWASP-I4"),
    
    # Temporary file race condition
    "mktemp":   ("mkstemp() or mkdtemp()", Severity.HIGH, "CWE-377, NIST SI-16"),
    "tmpnam":   ("mkstemp() or tmpfile()", Severity.HIGH, "CWE-377, NIST SI-16"),
    "tempnam":  ("mkstemp()", Severity.HIGH, "CWE-377, NIST SI-16"),
    
    # Weak randomness - MEDIUM
    "rand":     ("getrandom() or /dev/urandom", Severity.MEDIUM, "CWE-338, NIST SC-13"),
    "srand":    ("getrandom() or /dev/urandom", Severity.MEDIUM, "CWE-338, NIST SC-13"),
    "random":   ("getrandom() or arc4random()", Severity.MEDIUM, "CWE-338, NIST SC-13"),
    
    # Thread safety
    "strtok":   ("strtok_r()", Severity.MEDIUM, "CWE-362"),
    "asctime":  ("strftime()", Severity.LOW, "CWE-362"),
    "ctime":    ("ctime_r() or strftime()", Severity.LOW, "CWE-362"),
    "gmtime":   ("gmtime_r()", Severity.LOW, "CWE-362"),
    "localtime":("localtime_r()", Severity.LOW, "CWE-362"),
}

# Known network services with risk levels
KNOWN_SERVICES = {
    # CRITICAL - Plaintext protocols
    "telnetd":     "CRITICAL",
    "utelnetd":    "CRITICAL",
    "rlogind":     "CRITICAL",
    "rshd":        "CRITICAL",
    # HIGH - Large attack surface
    "ftpd":        "HIGH",
    "vsftpd":      "HIGH",
    "proftpd":     "HIGH",
    "httpd":       "HIGH",
    "uhttpd":      "HIGH",
    "lighttpd":    "HIGH",
    "nginx":       "HIGH",
    "goahead":     "HIGH",
    "boa":         "HIGH",
    "thttpd":      "HIGH",
    "mini_httpd":  "HIGH",
    "miniupnpd":   "HIGH",
    "upnpd":       "HIGH",
    "snmpd":       "HIGH",
    "cwmpd":       "HIGH",
    "tr069":       "HIGH",
    "smbd":        "HIGH",
    "nmbd":        "HIGH",
    # MEDIUM - Encrypted but exposed
    "sshd":        "MEDIUM",
    "dropbear":    "MEDIUM",
    "dnsmasq":     "MEDIUM",
    "named":       "MEDIUM",
    "mosquitto":   "MEDIUM",
    "mqttd":       "MEDIUM",
    "hostapd":     "MEDIUM",
    "wpa_supplicant": "MEDIUM",
    # LOW - Minimal attack surface
    "ntpd":        "LOW",
    "chronyd":     "LOW",
    "crond":       "LOW",
    "syslogd":     "LOW",
    "klogd":       "LOW",
}

# Network-related symbols that indicate a daemon
NETWORK_SYMBOLS = {
    "socket", "bind", "listen", "accept", "accept4",
    "connect", "recv", "recvfrom", "recvmsg",
    "send", "sendto", "sendmsg", "select", "poll",
    "epoll_create", "epoll_wait", "getaddrinfo",
}

# Patterns for hardcoded credentials
CREDENTIAL_PATTERNS = [
    # Password assignments - require actual value (not empty, not variable)
    (r'(?i)(?:^|[^a-z_])password\s*[=:]\s*["\']([^"\'$%{}<>\s]{4,})["\']', "hardcoded password"),
    (r'(?i)(?:^|[^a-z_])passwd\s*[=:]\s*["\']([^"\'$%{}<>\s]{4,})["\']', "hardcoded passwd"),
    (r'(?i)(?:^|[^a-z_])pwd\s*[=:]\s*["\']([^"\'$%{}<>\s]{4,})["\']', "hardcoded pwd"),
    (r'(?i)(?:^|[^a-z_])secret\s*[=:]\s*["\']([^"\'$%{}<>\s]{8,})["\']', "hardcoded secret"),
    # API keys - require longer values that look like real keys
    (r'(?i)api[_-]?key\s*[=:]\s*["\']([a-zA-Z0-9_\-]{16,})["\']', "API key"),
    (r'(?i)apikey\s*[=:]\s*["\']([a-zA-Z0-9_\-]{16,})["\']', "API key"),
    # Auth tokens - require minimum length and alphanumeric
    (r'(?i)auth[_-]?token\s*[=:]\s*["\']([a-zA-Z0-9_\-]{16,})["\']', "auth token"),
    (r'(?i)access[_-]?token\s*[=:]\s*["\']([a-zA-Z0-9_\-]{16,})["\']', "access token"),
    (r'(?i)bearer\s*[=:]\s*["\']([a-zA-Z0-9_\-\.]{20,})["\']', "bearer token"),
    # AWS/Cloud specific patterns
    (r'(?i)aws[_-]?secret[_-]?access[_-]?key\s*[=:]\s*["\']([A-Za-z0-9/+=]{40})["\']', "AWS secret key"),
    (r'AKIA[0-9A-Z]{16}', "AWS access key ID"),
    # Private keys embedded
    (r'-----BEGIN\s+(?:RSA\s+)?PRIVATE\s+KEY-----', "embedded private key"),
    # Default credentials - exact patterns
    (r'["\']admin["\']\s*[,:]\s*["\']admin["\']', "default admin:admin"),
    (r'["\']root["\']\s*[,:]\s*["\']root["\']', "default root:root"),
    (r'["\']root["\']\s*[,:]\s*["\']toor["\']', "default root:toor"),
]

# Extended false positive indicators
FALSE_POSITIVE_INDICATORS = {
    # Variable references
    "get_", "set_", "fetch_", "read_", "load_", "parse_",
    "env.", "os.environ", "getenv", "process.env",
    "config.", "settings.", "options.",
    # Function/method contexts
    "def ", "function ", "func ", "->", "return ",
    # Documentation/examples
    "example", "sample", "demo", "test", "mock", "fake", "dummy",
    "todo", "fixme", "xxx", "placeholder", "your_",
    # Type hints and declarations
    ": str", ": string", ": String", "String ", "str ",
}

# Common weak/default passwords to flag
WEAK_PASSWORDS = {
    "admin", "password", "123456", "12345678", "root", "toor",
    "default", "guest", "user", "test", "pass", "1234",
    "qwerty", "letmein", "welcome", "monkey", "dragon",
}

# Dangerous configuration patterns
CONFIG_PATTERNS = [
    # SSH issues
    (r'^\s*PermitRootLogin\s+yes', "sshd_config", "SSH root login enabled", Severity.HIGH),
    (r'^\s*PermitEmptyPasswords\s+yes', "sshd_config", "SSH empty passwords allowed", Severity.CRITICAL),
    (r'^\s*PasswordAuthentication\s+yes', "sshd_config", "SSH password auth enabled", Severity.LOW),
    # Telnet enabled
    (r'^\s*telnet\s+stream', "inetd.conf", "Telnet service enabled", Severity.CRITICAL),
    (r'::respawn:/usr/sbin/telnetd', "inittab", "Telnet auto-start enabled", Severity.CRITICAL),
    # Debug/development settings
    (r'(?i)^\s*debug\s*[=:]\s*(true|1|yes|on)', "*", "Debug mode enabled", Severity.MEDIUM),
    (r'(?i)^\s*DEBUG\s*[=:]\s*(true|1|yes|on)', "*", "Debug mode enabled", Severity.MEDIUM),
    # Empty root password in shadow
    (r'^root::[\d]*:', "shadow", "Root has empty password", Severity.CRITICAL),
    (r'^root:\*:', "shadow", "Root has no password", Severity.MEDIUM),
]

# Certificate and key file extensions
CERT_EXTENSIONS = {".pem", ".crt", ".cer", ".der", ".key", ".p12", ".pfx", ".jks"}

# Firmware type markers
FIRMWARE_MARKERS = {
    "OpenWrt": ["/etc/openwrt_release", "/etc/openwrt_version"],
    "DD-WRT": ["/etc/dd-wrt_version"],
    "Buildroot": ["/etc/buildroot_version", "/etc/br-version"],
    "Yocto": ["/etc/os-release"],
    "Android": ["/system/build.prop", "/default.prop"],
}


# =============================================================================
# HELPER FUNCTIONS
# =============================================================================

def safe_read_file(filepath: Path, max_size: int = 1024 * 1024) -> Optional[str]:
    """Safely read file content with size limit."""
    try:
        if not filepath.is_file():
            return None
        if filepath.stat().st_size > max_size:
            return None
        return filepath.read_text(encoding="utf-8", errors="replace")
    except (OSError, PermissionError):
        return None


def safe_read_binary(filepath: Path, max_size: int = 10 * 1024 * 1024) -> Optional[bytes]:
    """Safely read binary file with size limit."""
    try:
        if not filepath.is_file():
            return None
        if filepath.stat().st_size > max_size:
            return None
        return filepath.read_bytes()
    except (OSError, PermissionError):
        return None


# =============================================================================
# MAIN SCANNER CLASS
# =============================================================================

class HardenCheck:
    """Firmware security analyzer."""

    def __init__(self, target: Path, threads: int = 4, verbose: bool = False):
        """Initialize scanner."""
        self.target = Path(target).resolve()
        self.threads = min(max(threads, 1), 16)
        self.verbose = verbose
        self.tools = self._detect_tools()

    def _detect_tools(self) -> Dict[str, str]:
        """Detect available analysis tools."""
        tools = {}

        # rabin2 - prefer snap version, then system
        for cmd in ["radare2.rabin2", "rabin2"]:
            path = shutil.which(cmd)
            if path:
                tools["rabin2"] = cmd
                break

        # Other tools
        tool_commands = [
            ("hardening-check", "hardening-check"),
            ("scanelf", "scanelf"),
            ("file", "file"),
            ("strings", "strings"),
            ("openssl", "openssl"),
        ]
        for name, cmd in tool_commands:
            path = shutil.which(cmd)
            if path:
                tools[name] = cmd

        # Prefer eu-readelf over readelf
        if shutil.which("eu-readelf"):
            tools["readelf"] = "eu-readelf"
        elif shutil.which("readelf"):
            tools["readelf"] = "readelf"

        return tools

    def _run_command(self, cmd: List[str], timeout: int = 30) -> Tuple[int, str, str]:
        """Execute command safely with timeout."""
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout,
                stdin=subprocess.DEVNULL
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

            if e_type == 1:  # ET_REL
                if filename.endswith(".ko"):
                    return BinaryType.KERNEL_MODULE
                return BinaryType.RELOCATABLE
            elif e_type == 2:  # ET_EXEC
                return BinaryType.EXECUTABLE
            elif e_type == 3:  # ET_DYN
                if ".so" in filename:
                    return BinaryType.SHARED_LIB
                return BinaryType.EXECUTABLE

            return BinaryType.UNKNOWN
        except (OSError, PermissionError):
            return BinaryType.UNKNOWN

    # =========================================================================
    # FILE DISCOVERY
    # =========================================================================

    def find_files(self) -> Tuple[List[Tuple[Path, BinaryType]], List[Path], List[Path]]:
        """
        Discover files in target directory.
        Returns: (elf_binaries, source_files, config_files)
        """
        binaries = []
        sources = []
        configs = []

        source_extensions = {".c", ".cpp", ".cc", ".cxx", ".h", ".hpp", ".hxx"}
        config_extensions = {".conf", ".cfg", ".ini", ".config", ".xml", ".json", ".yaml", ".yml"}
        config_names = {"passwd", "shadow", "hosts", "resolv.conf", "fstab", "inittab", "profile"}

        skip_dirs = {".git", ".svn", "__pycache__", "node_modules", ".cache"}

        for root, dirs, files in os.walk(self.target):
            # Skip hidden and irrelevant directories
            dirs[:] = [d for d in dirs if d not in skip_dirs and not d.startswith(".")]

            for filename in files:
                filepath = Path(root) / filename

                # Skip symlinks
                if filepath.is_symlink():
                    continue

                # Check for ELF binary
                if self._is_elf_file(filepath):
                    binary_type = self._get_elf_type(filepath)
                    binaries.append((filepath, binary_type))
                    continue

                # Check for source file
                suffix = filepath.suffix.lower()
                if suffix in source_extensions:
                    sources.append(filepath)
                    continue

                # Check for config file
                if suffix in config_extensions or filename in config_names:
                    configs.append(filepath)

        return binaries, sources, configs

    # =========================================================================
    # FIRMWARE PROFILE DETECTION
    # =========================================================================

    def detect_firmware_profile(self, binaries: List[Tuple[Path, BinaryType]]) -> FirmwareProfile:
        """Detect firmware type, architecture, and metadata."""
        profile = FirmwareProfile()

        # Detect architecture from first executable
        executables = [b for b in binaries if b[1] == BinaryType.EXECUTABLE]
        if executables and "file" in self.tools:
            ret, out, _ = self._run_command([self.tools["file"], str(executables[0][0])])
            if ret == 0:
                out_lower = out.lower()

                # Architecture detection
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

                # Endianness detection
                if "lsb" in out_lower or "little endian" in out_lower:
                    profile.endian = "Little Endian"
                elif "msb" in out_lower or "big endian" in out_lower:
                    profile.endian = "Big Endian"

        # Detect firmware type from marker files
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

        # Search for busybox if type still unknown
        if profile.fw_type == "Unknown":
            for root, dirs, files in os.walk(self.target):
                if "busybox" in files:
                    profile.fw_type = "BusyBox-based"
                    break
                dirs[:] = dirs[:20]  # Limit depth

        # Detect libc version
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

        # Detect kernel version from modules directory
        for root, dirs, files in os.walk(self.target):
            if "modules" in root:
                for dirname in dirs:
                    if re.match(r"^\d+\.\d+\.\d+", dirname):
                        profile.kernel = dirname
                        break
            if profile.kernel != "Unknown":
                break
            dirs[:] = dirs[:20]

        # Count file statistics
        profile.elf_binaries = len([b for b in binaries if b[1] == BinaryType.EXECUTABLE])
        profile.shared_libs = len([b for b in binaries if b[1] == BinaryType.SHARED_LIB])

        for root, dirs, files in os.walk(self.target):
            dirs[:] = [d for d in dirs if not d.startswith(".")]
            profile.total_files += len(files)

            for filename in files:
                filepath = Path(root) / filename

                # Count shell scripts
                if filename.endswith(".sh"):
                    profile.shell_scripts += 1
                elif not filepath.is_symlink():
                    try:
                        with open(filepath, "rb") as f:
                            header = f.read(2)
                        if header == b"#!":
                            profile.shell_scripts += 1
                    except (OSError, PermissionError):
                        pass

                # Count config files
                if filepath.suffix.lower() in {".conf", ".cfg", ".ini", ".config"}:
                    profile.config_files += 1

                # Check for setuid/world-writable
                try:
                    file_stat = filepath.stat()
                    mode = file_stat.st_mode
                    if mode & stat.S_ISUID:
                        rel_path = str(filepath.relative_to(self.target))
                        profile.setuid_files.append(rel_path)
                    if mode & stat.S_IWOTH and stat.S_ISREG(mode):
                        rel_path = str(filepath.relative_to(self.target))
                        profile.world_writable.append(rel_path)
                except (OSError, PermissionError):
                    pass

        return profile

    # =========================================================================
    # DAEMON DETECTION
    # =========================================================================

    def _has_network_symbols(self, filepath: Path) -> bool:
        """Check if binary imports network-related symbols."""
        if "readelf" not in self.tools:
            return False

        ret, out, _ = self._run_command(
            [self.tools["readelf"], "-W", "--dyn-syms", str(filepath)],
            timeout=10
        )

        if ret != 0:
            return False

        out_lower = out.lower()
        matches = sum(1 for sym in NETWORK_SYMBOLS if sym in out_lower)
        return matches >= 2  # Require at least 2 network symbols

    def _is_referenced_in_init(self, binary_name: str) -> bool:
        """Check if binary is referenced in init scripts."""
        init_paths = [
            "etc/init.d",
            "etc/rc.d",
            "etc/systemd/system",
            "etc/inittab",
        ]

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
            [self.tools["strings"], "-n", "4", str(filepath)],
            timeout=15
        )

        if ret != 0 or not out:
            return "Unknown"

        # Version patterns ordered by specificity
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

        # Try filename pattern
        filename_match = re.search(r"[_-](\d+\.\d+(?:\.\d+)?)", filepath.name)
        if filename_match:
            return filename_match.group(1)

        return "Unknown"

    def detect_daemons(self, binaries: List[BinaryAnalysis]) -> List[Daemon]:
        """Detect network services and daemons."""
        daemons = []
        seen_binaries = set()

        # Filter to executables only
        executables = [b for b in binaries if b.binary_type == BinaryType.EXECUTABLE]

        for binary in executables:
            filename = binary.filename
            filename_lower = filename.lower()

            # Skip if already processed
            if filename_lower in seen_binaries:
                continue

            is_daemon = False
            reason_parts = []
            risk = "UNKNOWN"

            # Check 1: Known service name
            if filename_lower in KNOWN_SERVICES:
                is_daemon = True
                risk = KNOWN_SERVICES[filename_lower]
                reason_parts.append("known service")

            # Check 2: Name ends with 'd' and length > 3 (avoid 'cd', 'id', etc.)
            elif (filename_lower.endswith("d") and
                  len(filename_lower) > 3 and
                  not filename_lower.endswith(".so.d")):
                # Verify it's not a common non-daemon
                non_daemons = {"systemd", "udevd", "lvmetad", "kmod"}  # System utilities
                if filename_lower not in non_daemons:
                    is_daemon = True
                    reason_parts.append("name pattern (*d)")
                    risk = "UNKNOWN"

            # Check 3: Has network symbols
            if is_daemon or filename_lower.endswith("d"):
                filepath = self.target / binary.path
                if self._has_network_symbols(filepath):
                    if not is_daemon:
                        is_daemon = True
                    reason_parts.append("network symbols")
                    if risk == "UNKNOWN":
                        risk = "MEDIUM"

            # Check 4: Referenced in init scripts
            if is_daemon and self._is_referenced_in_init(filename):
                reason_parts.append("init script")

            if is_daemon:
                seen_binaries.add(filename_lower)
                filepath = self.target / binary.path
                version = self._extract_version(filepath)
                status = classify_binary(binary)

                # Determine service name
                service_name = filename_lower
                for known_name in KNOWN_SERVICES:
                    if filename_lower.startswith(known_name):
                        service_name = known_name
                        break

                daemons.append(Daemon(
                    name=service_name,
                    binary=filename,
                    path=binary.path,
                    version=version,
                    risk=risk,
                    reason=", ".join(reason_parts),
                    has_network="network symbols" in reason_parts,
                    status=status
                ))

        # Sort by risk level
        risk_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "UNKNOWN": 4}
        daemons.sort(key=lambda d: (risk_order.get(d.risk, 5), d.name))

        return daemons

    # =========================================================================
    # BINARY ANALYSIS
    # =========================================================================

    def _analyze_with_rabin2(self, filepath: Path) -> Optional[Dict]:
        """Analyze binary with rabin2."""
        if "rabin2" not in self.tools:
            return None

        ret, out, _ = self._run_command(
            [self.tools["rabin2"], "-Ij", str(filepath)],
            timeout=15
        )

        if ret != 0:
            return None

        try:
            data = json.loads(out)
            return data.get("info", {})
        except (json.JSONDecodeError, KeyError):
            return None

    def _analyze_with_readelf(self, filepath: Path) -> Dict:
        """Analyze binary with readelf."""
        result = {
            "nx": None,
            "canary": None,
            "pie": None,
            "relro": "none",
            "stripped": None,
            "rpath": ""
        }

        if "readelf" not in self.tools:
            return result

        readelf = self.tools["readelf"]

        # Program headers for NX, RELRO, PIE
        ret, out, _ = self._run_command([readelf, "-W", "-l", str(filepath)], timeout=10)
        if ret == 0:
            if "GNU_STACK" in out:
                for line in out.split("\n"):
                    if "GNU_STACK" in line:
                        result["nx"] = "E" not in line
                        break

            if "GNU_RELRO" in out:
                result["relro"] = "partial"

            if "DYN" in out:
                result["pie"] = True

        # Dynamic section for BIND_NOW, RPATH
        ret, out, _ = self._run_command([readelf, "-W", "-d", str(filepath)], timeout=10)
        if ret == 0:
            if "BIND_NOW" in out:
                result["relro"] = "full"

            rpath_match = re.search(r"RPATH.*?\[(.*?)\]", out)
            if rpath_match:
                result["rpath"] = rpath_match.group(1)

        # Dynamic symbols for stack canary
        ret, out, _ = self._run_command([readelf, "-W", "--dyn-syms", str(filepath)], timeout=10)
        if ret == 0:
            result["canary"] = "__stack_chk_fail" in out

        # Section headers for stripped check
        ret, out, _ = self._run_command([readelf, "-W", "-S", str(filepath)], timeout=10)
        if ret == 0:
            result["stripped"] = ".symtab" not in out

        return result

    def _analyze_with_hardening_check(self, filepath: Path) -> Dict:
        """Analyze binary with hardening-check."""
        result = {
            "fortify": None,
            "stack_clash": "unknown",
            "cfi": "unknown"
        }

        if "hardening-check" not in self.tools:
            return result

        ret, out, _ = self._run_command(
            [self.tools["hardening-check"], str(filepath)],
            timeout=15
        )

        if ret not in (0, 1):
            return result

        out_lower = out.lower()

        if "fortify source functions: yes" in out_lower:
            result["fortify"] = True
        elif "fortify source functions: no" in out_lower:
            result["fortify"] = False

        if "stack clash protection: yes" in out_lower:
            result["stack_clash"] = "yes"
        elif "stack clash protection: no" in out_lower:
            result["stack_clash"] = "no"

        if "control flow integrity: yes" in out_lower:
            result["cfi"] = "yes"
        elif "control flow integrity: no" in out_lower:
            result["cfi"] = "no"

        return result

    def _analyze_with_scanelf(self, filepath: Path) -> Dict:
        """Analyze binary with scanelf."""
        result = {"textrel": False}

        if "scanelf" not in self.tools:
            return result

        ret, out, _ = self._run_command(
            [self.tools["scanelf"], "-T", str(filepath)],
            timeout=10
        )

        if ret == 0 and "TEXTREL" in out:
            result["textrel"] = True

        return result

    def analyze_binary(self, filepath: Path, binary_type: BinaryType) -> BinaryAnalysis:
        """Perform complete binary analysis."""
        try:
            rel_path = str(filepath.relative_to(self.target))
        except ValueError:
            rel_path = str(filepath)

        analysis = BinaryAnalysis(
            path=rel_path,
            filename=filepath.name,
            size=filepath.stat().st_size,
            sha256=self._compute_sha256(filepath),
            binary_type=binary_type
        )

        # Gather data from all tools
        rabin2_data = self._analyze_with_rabin2(filepath)
        readelf_data = self._analyze_with_readelf(filepath)
        hardening_data = self._analyze_with_hardening_check(filepath)
        scanelf_data = self._analyze_with_scanelf(filepath)

        # Merge results with cross-validation
        confidence = 100
        tools_used = []

        # NX (No Execute)
        if rabin2_data and "nx" in rabin2_data:
            analysis.nx = rabin2_data.get("nx", False)
            tools_used.append("rabin2")
            if readelf_data["nx"] is not None and rabin2_data.get("nx") != readelf_data["nx"]:
                confidence -= 15
        elif readelf_data["nx"] is not None:
            analysis.nx = readelf_data["nx"]
            tools_used.append("readelf")

        # Stack Canary
        if rabin2_data and "canary" in rabin2_data:
            analysis.canary = rabin2_data.get("canary", False)
            if readelf_data["canary"] is not None and rabin2_data.get("canary") != readelf_data["canary"]:
                confidence -= 15
        elif readelf_data["canary"] is not None:
            analysis.canary = readelf_data["canary"]

        # PIE (Position Independent Executable)
        if rabin2_data and "pic" in rabin2_data:
            analysis.pie = rabin2_data.get("pic", False)
        elif readelf_data["pie"] is not None:
            analysis.pie = readelf_data["pie"]

        # RELRO
        if rabin2_data and rabin2_data.get("relro"):
            analysis.relro = rabin2_data.get("relro", "none")
        else:
            analysis.relro = readelf_data["relro"]

        # Stripped
        if rabin2_data and "stripped" in rabin2_data:
            analysis.stripped = rabin2_data.get("stripped", False)
        elif readelf_data["stripped"] is not None:
            analysis.stripped = readelf_data["stripped"]

        # RPATH
        if rabin2_data:
            rpath = rabin2_data.get("rpath", "NONE")
            analysis.rpath = "" if rpath == "NONE" else rpath
        else:
            analysis.rpath = readelf_data["rpath"]

        # Fortify, Stack Clash, CFI from hardening-check
        analysis.fortify = hardening_data["fortify"]
        analysis.stack_clash = hardening_data["stack_clash"]
        analysis.cfi = hardening_data["cfi"]

        # TEXTREL from scanelf
        analysis.textrel = scanelf_data["textrel"]

        analysis.confidence = max(confidence, 50)
        analysis.tools_used = tools_used

        return analysis

    # =========================================================================
    # DEPENDENCY ANALYSIS
    # =========================================================================

    def analyze_dependencies(self, binaries: List[BinaryAnalysis]) -> List[DependencyRisk]:
        """Analyze dependency chain for insecure libraries."""
        risks = []

        if "readelf" not in self.tools:
            return risks

        # Find insecure shared libraries
        insecure_libs = {}
        for binary in binaries:
            if binary.binary_type == BinaryType.SHARED_LIB:
                classification = classify_binary(binary)
                if classification == "INSECURE":
                    issues = []
                    if binary.nx is False:
                        issues.append("No NX")
                    if binary.canary is False:
                        issues.append("No Canary")
                    if issues:
                        insecure_libs[binary.filename] = ", ".join(issues)

        if not insecure_libs:
            return risks

        # Find executables that use insecure libraries
        lib_users = {lib: [] for lib in insecure_libs}

        for binary in binaries:
            if binary.binary_type != BinaryType.EXECUTABLE:
                continue

            filepath = self.target / binary.path
            ret, out, _ = self._run_command(
                [self.tools["readelf"], "-W", "-d", str(filepath)],
                timeout=10
            )

            if ret != 0:
                continue

            for lib in insecure_libs:
                lib_base = lib.split(".so")[0] if ".so" in lib else lib
                if lib in out or lib_base in out:
                    lib_users[lib].append(binary.filename)

        # Create risk entries
        for lib, issue in insecure_libs.items():
            if lib_users[lib]:
                risks.append(DependencyRisk(
                    library=lib,
                    issue=issue,
                    used_by=lib_users[lib][:10]  # Limit to 10
                ))

        return risks

    # =========================================================================
    # BANNED FUNCTION SCANNING
    # =========================================================================

    def scan_banned_functions_binary(self, binaries: List[BinaryAnalysis]) -> List[BannedFunctionHit]:
        """Scan binaries for banned function imports."""
        hits = []

        if "readelf" not in self.tools:
            return hits

        # Precompile patterns
        patterns = {}
        for func in BANNED_FUNCTIONS:
            patterns[func] = re.compile(rf"\s{re.escape(func)}(?:@|$|\s)", re.MULTILINE)

        for binary in binaries:
            filepath = self.target / binary.path
            ret, out, _ = self._run_command(
                [self.tools["readelf"], "-W", "--dyn-syms", str(filepath)],
                timeout=10
            )

            if ret != 0:
                continue

            for func, (alternative, severity, compliance) in BANNED_FUNCTIONS.items():
                if patterns[func].search(out):
                    hits.append(BannedFunctionHit(
                        function=func,
                        file=binary.path,
                        line=0,
                        snippet="(imported symbol)",
                        severity=severity,
                        alternative=alternative,
                        compliance=compliance
                    ))

        return hits

    def scan_banned_functions_source(self, sources: List[Path]) -> List[BannedFunctionHit]:
        """Scan source files for banned function calls."""
        hits = []

        # Precompile patterns
        patterns = {}
        for func in BANNED_FUNCTIONS:
            patterns[func] = re.compile(rf"(?<![_a-zA-Z0-9]){re.escape(func)}\s*\(")

        for source_path in sources:
            content = safe_read_file(source_path)
            if not content:
                continue

            # Remove comments to avoid false positives
            content_clean = re.sub(r"//[^\n]*", "", content)
            content_clean = re.sub(r"/\*.*?\*/", "", content_clean, flags=re.DOTALL)

            try:
                rel_path = str(source_path.relative_to(self.target))
            except ValueError:
                rel_path = str(source_path)

            lines = content.split("\n")
            lines_clean = content_clean.split("\n")

            for line_num, (original, cleaned) in enumerate(zip(lines, lines_clean), start=1):
                for func, (alternative, severity, compliance) in BANNED_FUNCTIONS.items():
                    if patterns[func].search(cleaned):
                        hits.append(BannedFunctionHit(
                            function=func,
                            file=rel_path,
                            line=line_num,
                            snippet=original.strip()[:60],
                            severity=severity,
                            alternative=alternative,
                            compliance=compliance
                        ))

        return hits

    # =========================================================================
    # CREDENTIAL SCANNING
    # =========================================================================

    def scan_credentials(self, config_files: List[Path], sources: List[Path]) -> List[CredentialFinding]:
        """Scan for hardcoded credentials."""
        findings = []
        scanned_files = set()
        
        # Paths to skip (translations, UI configs, documentation)
        skip_patterns = {
            "/locales/", "/locale/", "/i18n/", "/translations/",
            "/doc/", "/docs/", "/documentation/", "/examples/",
            "/share/doc/", "/usr/share/doc/",
            "translation.json", "translations.json",
            "UserInterfaceConfig.json", "device-payload",
        }

        all_files = list(config_files) + list(sources)

        # Also scan shell scripts and common config locations
        for root, dirs, files in os.walk(self.target):
            dirs[:] = [d for d in dirs if not d.startswith(".")][:20]
            for filename in files:
                filepath = Path(root) / filename
                if filepath.suffix in {".sh", ".py", ".pl", ".rb", ".php"}:
                    all_files.append(filepath)
                elif filename in {"config", "settings", "credentials", ".env", "secrets"}:
                    all_files.append(filepath)

        for filepath in all_files:
            if filepath in scanned_files:
                continue
            
            # Skip files in excluded paths
            filepath_str = str(filepath)
            if any(skip in filepath_str for skip in skip_patterns):
                continue
            scanned_files.add(filepath)

            content = safe_read_file(filepath, max_size=512 * 1024)
            if not content:
                continue

            try:
                rel_path = str(filepath.relative_to(self.target))
            except ValueError:
                rel_path = str(filepath)

            lines = content.split("\n")

            for line_num, line in enumerate(lines, start=1):
                line_stripped = line.strip()

                # Skip comments
                if line_stripped.startswith("#") or line_stripped.startswith("//"):
                    continue

                # Check credential patterns
                for pattern, description in CREDENTIAL_PATTERNS:
                    match = re.search(pattern, line)
                    if match:
                        # Get the captured value if any
                        value = match.group(1) if match.lastindex and match.lastindex >= 1 else match.group(0)
                        
                        # Skip if it's a placeholder or false positive
                        if self._is_placeholder(value, line):
                            continue
                        
                        # Skip if line looks like documentation or example
                        if any(x in line_stripped.lower() for x in ["example", "sample", "usage:", "e.g.", "// ", "# "]):
                            continue
                            
                        findings.append(CredentialFinding(
                            file=rel_path,
                            line=line_num,
                            pattern=description,
                            snippet=line_stripped[:80],
                            severity=Severity.HIGH
                        ))
                        break

                # Check for weak passwords - only in actual assignment context
                for weak_pass in WEAK_PASSWORDS:
                    # Pattern: variable = "weak_password" (actual credential assignment)
                    weak_pattern = rf'(?i)(?:password|passwd|pwd|secret|key_passwd)\s*[=:]\s*["\']({re.escape(weak_pass)})["\']'
                    if re.search(weak_pattern, line):
                        # Skip if it's a JSON key with non-credential value
                        if re.search(r'"Password"\s*:\s*"[^"]*"', line):
                            # Check if value is NOT a weak password itself
                            json_match = re.search(r'"Password"\s*:\s*"([^"]*)"', line)
                            if json_match:
                                json_value = json_match.group(1).lower()
                                # Skip translations, descriptions, empty values
                                if json_value not in WEAK_PASSWORDS or len(json_value) > 20:
                                    continue
                                if json_value in {"", "false", "true", "set", "get not supported"}:
                                    continue
                        
                        findings.append(CredentialFinding(
                            file=rel_path,
                            line=line_num,
                            pattern=f"weak password: {weak_pass}",
                            snippet=line_stripped[:80],
                            severity=Severity.CRITICAL
                        ))
                        break

        return findings[:100]  # Limit results

    def _is_placeholder(self, value: str, line: str = "") -> bool:
        """Check if value is a placeholder, not a real credential."""
        value_lower = value.lower().strip()
        line_lower = line.lower()

        # Check line context for false positive indicators
        for indicator in FALSE_POSITIVE_INDICATORS:
            if indicator in line_lower:
                return True

        # Known placeholder values
        placeholders = {
            "xxx", "yyy", "zzz", "changeme", "placeholder", "example",
            "your_password", "your_secret", "insert_here", "todo",
            "fixme", "none", "null", "undefined", "empty", "test",
            "password", "secret", "token", "key", "value", "string",
            "change_me", "replace_me", "enter_password", "your_key",
        }
        if value_lower in placeholders:
            return True

        # Check for variable/template patterns
        if re.match(r"^[\$%]\{?\w+\}?$", value):  # $VAR, ${VAR}, %VAR%
            return True
        if re.match(r"^\$\(\w+\)$", value):  # $(VAR)
            return True
        if re.match(r"^<[a-zA-Z_]+>$", value):  # <PLACEHOLDER>
            return True
        if re.match(r"^\{\{?\w+\}?\}$", value):  # {{VAR}} or {VAR}
            return True
        if re.match(r"^%[a-zA-Z_]+%$", value):  # %VAR%
            return True

        # Check for all same characters (xxxx, ****)
        if len(set(value)) <= 2 and len(value) >= 3:
            return True

        # Check if value looks like a variable name (all lowercase with underscores)
        if re.match(r"^[a-z_]+$", value) and len(value) < 20:
            return True

        # Check if value is just repeated pattern
        if len(value) >= 4:
            half = len(value) // 2
            if value[:half] == value[half:2*half]:
                return True

        return False

    # =========================================================================
    # CERTIFICATE SCANNING
    # =========================================================================

    def scan_certificates(self) -> List[CertificateFinding]:
        """Scan for certificate and key files."""
        findings = []

        for root, dirs, files in os.walk(self.target):
            dirs[:] = [d for d in dirs if not d.startswith(".")]

            for filename in files:
                filepath = Path(root) / filename
                suffix = filepath.suffix.lower()

                if suffix not in CERT_EXTENSIONS:
                    continue

                try:
                    rel_path = str(filepath.relative_to(self.target))
                except ValueError:
                    rel_path = str(filepath)

                # Check file type and issues
                if suffix == ".key" or "private" in filename.lower():
                    findings.append(CertificateFinding(
                        file=rel_path,
                        file_type="Private Key",
                        issue="Private key file found in firmware",
                        severity=Severity.HIGH
                    ))

                elif suffix in {".pem", ".crt", ".cer"}:
                    # Try to analyze certificate with openssl
                    issue = self._analyze_certificate(filepath)
                    if issue:
                        findings.append(CertificateFinding(
                            file=rel_path,
                            file_type="Certificate",
                            issue=issue,
                            severity=Severity.MEDIUM
                        ))
                    else:
                        findings.append(CertificateFinding(
                            file=rel_path,
                            file_type="Certificate",
                            issue="Certificate embedded in firmware",
                            severity=Severity.LOW
                        ))

                elif suffix in {".p12", ".pfx"}:
                    findings.append(CertificateFinding(
                        file=rel_path,
                        file_type="PKCS12 Bundle",
                        issue="PKCS12 bundle with private key",
                        severity=Severity.HIGH
                    ))

        return findings[:50]

    def _analyze_certificate(self, filepath: Path) -> Optional[str]:
        """Analyze certificate for issues."""
        if "openssl" not in self.tools:
            return None

        ret, out, _ = self._run_command(
            [self.tools["openssl"], "x509", "-in", str(filepath), "-noout", "-text"],
            timeout=10
        )

        if ret != 0:
            return None

        issues = []

        # Check for self-signed
        if "Issuer:" in out and "Subject:" in out:
            issuer_match = re.search(r"Issuer:\s*(.+)", out)
            subject_match = re.search(r"Subject:\s*(.+)", out)
            if issuer_match and subject_match:
                if issuer_match.group(1).strip() == subject_match.group(1).strip():
                    issues.append("self-signed")

        # Check key size
        if "RSA Public-Key:" in out:
            key_match = re.search(r"RSA Public-Key:\s*\((\d+) bit\)", out)
            if key_match:
                key_size = int(key_match.group(1))
                if key_size < 2048:
                    issues.append(f"weak key ({key_size}-bit)")

        # Check expiry
        if "Not After :" in out:
            expiry_match = re.search(r"Not After :\s*(.+)", out)
            if expiry_match:
                try:
                    expiry_str = expiry_match.group(1).strip()
                    # Simple year check
                    year_match = re.search(r"\b(20\d{2})\b", expiry_str)
                    if year_match:
                        expiry_year = int(year_match.group(1))
                        if expiry_year < datetime.now().year:
                            issues.append("expired")
                except (ValueError, AttributeError):
                    pass

        return ", ".join(issues) if issues else None

    # =========================================================================
    # CONFIGURATION SCANNING
    # =========================================================================

    def scan_configurations(self, config_files: List[Path]) -> List[ConfigFinding]:
        """Scan configuration files for dangerous patterns."""
        findings = []

        # Add common config locations
        common_configs = [
            "etc/ssh/sshd_config",
            "etc/sshd_config",
            "etc/inetd.conf",
            "etc/xinetd.conf",
            "etc/inittab",
            "etc/shadow",
            "etc/passwd",
        ]

        all_configs = list(config_files)
        for config_path in common_configs:
            full_path = self.target / config_path
            if full_path.exists() and full_path not in all_configs:
                all_configs.append(full_path)

        for filepath in all_configs:
            content = safe_read_file(filepath, max_size=256 * 1024)
            if not content:
                continue

            try:
                rel_path = str(filepath.relative_to(self.target))
            except ValueError:
                rel_path = str(filepath)

            filename = filepath.name.lower()
            lines = content.split("\n")

            for line_num, line in enumerate(lines, start=1):
                line_stripped = line.strip()

                for pattern, file_pattern, issue, severity in CONFIG_PATTERNS:
                    # Check if pattern applies to this file
                    if file_pattern != "*" and file_pattern not in filename:
                        continue

                    if re.search(pattern, line_stripped, re.IGNORECASE):
                        findings.append(ConfigFinding(
                            file=rel_path,
                            line=line_num,
                            issue=issue,
                            snippet=line_stripped[:80],
                            severity=severity
                        ))

        return findings[:50]

    # =========================================================================
    # MAIN SCAN
    # =========================================================================

    def scan(self) -> ScanResult:
        """Execute complete security scan."""
        start_time = datetime.now()

        print(BANNER)
        print(f"  Target:  {self.target}")
        print(f"  Started: {start_time.strftime('%Y-%m-%d %H:%M:%S')}")
        print("=" * 55)
        print()

        # Display detected tools
        print("[*] Tools detected:")
        for name, cmd in self.tools.items():
            print(f"    + {name}: {cmd}")
        missing = {"rabin2", "hardening-check", "scanelf", "readelf", "file", "strings"} - set(self.tools.keys())
        if missing:
            print(f"    - Missing: {', '.join(missing)}")
        print()

        # Step 1: Discover files
        print("[1/8] Discovering files...")
        binaries_raw, sources, configs = self.find_files()
        print(f"      ELF binaries: {len(binaries_raw)}")
        print(f"      Source files: {len(sources)}")
        print(f"      Config files: {len(configs)}")
        print()

        # Step 2: Detect firmware profile
        print("[2/8] Analyzing firmware profile...")
        profile = self.detect_firmware_profile(binaries_raw)
        print(f"      Type: {profile.fw_type}")
        print(f"      Arch: {profile.arch} {profile.bits}-bit {profile.endian}")
        print(f"      Libc: {profile.libc}")
        if profile.kernel != "Unknown":
            print(f"      Kernel: {profile.kernel}")
        if profile.setuid_files:
            print(f"      Setuid: {len(profile.setuid_files)} files")
        print()

        # Step 3: Analyze binaries
        print("[3/8] Analyzing binary hardening...")
        analyzed_binaries = []
        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = {
                executor.submit(self.analyze_binary, path, btype): path
                for path, btype in binaries_raw
            }
            for future in as_completed(futures):
                try:
                    result = future.result()
                    analyzed_binaries.append(result)
                except Exception as e:
                    self._log(f"Analysis error: {e}")

        secured = sum(1 for b in analyzed_binaries if classify_binary(b) == "SECURED")
        partial = sum(1 for b in analyzed_binaries if classify_binary(b) == "PARTIAL")
        insecure = sum(1 for b in analyzed_binaries if classify_binary(b) == "INSECURE")
        print(f"      Analyzed: {len(analyzed_binaries)}")
        print(f"      Secured: {secured}, Partial: {partial}, Insecure: {insecure}")
        print()

        # Step 4: Detect daemons
        print("[4/8] Detecting network services/daemons...")
        daemons = self.detect_daemons(analyzed_binaries)
        if daemons:
            for daemon in daemons[:5]:
                ver_str = f" v{daemon.version}" if daemon.version != "Unknown" else ""
                print(f"      [{daemon.risk}] {daemon.name} ({daemon.binary}{ver_str})")
            if len(daemons) > 5:
                print(f"      ... and {len(daemons) - 5} more")
        else:
            print("      No daemons detected")
        print()

        # Step 5: Analyze dependencies
        print("[5/8] Analyzing dependency chain...")
        dep_risks = self.analyze_dependencies(analyzed_binaries)
        if dep_risks:
            for risk in dep_risks[:3]:
                print(f"      {risk.library}: {risk.issue}")
            if len(dep_risks) > 3:
                print(f"      ... and {len(dep_risks) - 3} more")
        else:
            print("      No insecure dependencies")
        print()

        # Step 6: Scan for banned functions
        print("[6/8] Scanning for banned functions...")
        banned_binary = self.scan_banned_functions_binary(analyzed_binaries)
        banned_source = self.scan_banned_functions_source(sources)
        banned_all = banned_binary + banned_source
        print(f"      Found: {len(banned_all)} ({len(banned_binary)} binary, {len(banned_source)} source)")
        print()

        # Step 7: Scan for credentials and certificates
        print("[7/8] Scanning for credentials and certificates...")
        credentials = self.scan_credentials(configs, sources)
        certificates = self.scan_certificates()
        print(f"      Credentials: {len(credentials)} findings")
        print(f"      Certificates: {len(certificates)} files")
        print()

        # Step 8: Scan configurations
        print("[8/8] Scanning configuration files...")
        config_issues = self.scan_configurations(configs)
        print(f"      Config issues: {len(config_issues)}")
        print()

        duration = (datetime.now() - start_time).total_seconds()

        # Summary
        grade, score = calculate_grade(analyzed_binaries)
        print(f"""{'=' * 65}
  SCAN COMPLETE
{'=' * 65}
  Grade: {grade} (Score: {score}/110)
  
  Binaries:     {len(analyzed_binaries)} ({secured} secured, {partial} partial, {insecure} insecure)
  Daemons:      {len(daemons)} detected
  Dependencies: {len(dep_risks)} risks
  Banned Funcs: {len(banned_all)} hits
  Credentials:  {len(credentials)} findings
  Certificates: {len(certificates)} files
  Config Issues:{len(config_issues)} findings
  
  Duration: {duration:.1f}s
{'=' * 65}
""")

        return ScanResult(
            target=str(self.target),
            scan_time=start_time.isoformat(),
            duration=duration,
            tools=self.tools,
            profile=profile,
            daemons=daemons,
            binaries=analyzed_binaries,
            banned_functions=banned_all,
            dependency_risks=dep_risks,
            credentials=credentials,
            certificates=certificates,
            config_issues=config_issues
        )


# =============================================================================
# CLASSIFICATION AND GRADING
# =============================================================================

def classify_binary(binary: BinaryAnalysis) -> str:
    """Classify binary security level."""
    # INSECURE: Missing critical protections
    if binary.nx is False or binary.canary is False:
        return "INSECURE"

    # SECURED: All protections verified
    all_protected = (
        binary.nx is True and
        binary.canary is True and
        binary.pie is True and
        binary.relro == "full" and
        binary.fortify is True and
        binary.stripped is True and
        binary.stack_clash == "yes" and
        binary.cfi == "yes" and
        not binary.textrel and
        not binary.rpath
    )

    if all_protected:
        return "SECURED"

    return "PARTIAL"


def calculate_grade(binaries: List[BinaryAnalysis]) -> Tuple[str, int]:
    """Calculate overall security grade."""
    if not binaries:
        return "N/A", 0

    total_score = 0

    for binary in binaries:
        score = 0
        if binary.nx is True:
            score += 15
        if binary.canary is True:
            score += 15
        if binary.pie is True:
            score += 15
        if binary.relro == "full":
            score += 15
        elif binary.relro == "partial":
            score += 7
        if binary.fortify is True:
            score += 10
        if binary.stripped is True:
            score += 5
        if binary.stack_clash == "yes":
            score += 10
        if binary.cfi == "yes":
            score += 10
        if not binary.textrel:
            score += 5
        if not binary.rpath:
            score += 5
        total_score += score

    average = total_score / len(binaries)

    if average >= 90:
        return "A", int(average)
    elif average >= 80:
        return "B", int(average)
    elif average >= 70:
        return "C", int(average)
    elif average >= 60:
        return "D", int(average)
    else:
        return "F", int(average)


# =============================================================================
# HTML REPORT GENERATION
# =============================================================================

def generate_html_report(result: ScanResult, output_path: Path):
    """Generate HTML report."""
    total_binaries = len(result.binaries) or 1

    # Calculate statistics
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
    profile = result.profile

    # Build binary rows
    binary_rows = ""
    for binary in sorted(result.binaries, key=lambda x: x.filename):
        classification = classify_binary(binary)
        row_class = "rb" if classification == "INSECURE" else "rw" if classification == "PARTIAL" else ""

        def cell(value):
            if value is True:
                return '<td class="ok">Y</td>'
            elif value is False:
                return '<td class="bad">N</td>'
            elif value == "yes":
                return '<td class="ok">Y</td>'
            elif value == "no":
                return '<td class="bad">N</td>'
            elif value == "unknown":
                return '<td class="wrn">?</td>'
            elif value == "full":
                return '<td class="ok">full</td>'
            elif value == "partial":
                return '<td class="wrn">partial</td>'
            elif value == "none":
                return '<td class="bad">none</td>'
            else:
                return f"<td>{value}</td>"

        binary_rows += f'<tr class="{row_class}"><td class="fn">{binary.filename}</td>'
        binary_rows += cell(binary.nx)
        binary_rows += cell(binary.canary)
        binary_rows += cell(binary.pie)
        binary_rows += cell(binary.relro)
        binary_rows += cell(binary.fortify)
        binary_rows += cell(binary.stripped)
        binary_rows += cell(binary.stack_clash)
        binary_rows += cell(binary.cfi)
        binary_rows += f'<td class="{"bad" if binary.textrel else "ok"}">{"-" if not binary.textrel else "!"}</td>'
        binary_rows += f'<td class="{"bad" if binary.rpath else "ok"}">{binary.rpath[:12] if binary.rpath else "-"}</td>'
        binary_rows += f"<td>{binary.confidence}%</td></tr>"

    # Build daemon rows
    daemon_rows = ""
    for daemon in result.daemons:
        risk_class = "bad" if daemon.risk == "CRITICAL" else "wrn" if daemon.risk in ("HIGH", "UNKNOWN") else ""
        status_class = "ok" if daemon.status == "SECURED" else "bad" if daemon.status == "INSECURE" else "wrn"
        daemon_rows += f'<tr><td class="{risk_class}">{daemon.risk}</td>'
        daemon_rows += f"<td>{daemon.name}</td>"
        daemon_rows += f"<td>{daemon.binary}</td>"
        daemon_rows += f'<td>{daemon.version}</td>'
        daemon_rows += f'<td class="loc">{daemon.path}</td>'
        daemon_rows += f'<td class="{status_class}">{daemon.status}</td>'
        daemon_rows += f'<td class="loc">{daemon.reason}</td></tr>'

    # Build banned function rows
    banned_rows = ""
    for hit in sorted(result.banned_functions, key=lambda x: (-x.severity.value, x.function)):
        sev_class = "bad" if hit.severity.value >= 3 else "wrn"
        
        # Clean up path to show firmware-relative path
        clean_path = hit.file
        # Remove common extraction path patterns to show clean firmware path
        for pattern in ["_extract/", ".zip_extract/", ".tar_extract/", ".gz_extract/"]:
            if pattern in clean_path:
                parts = clean_path.split(pattern)
                clean_path = parts[-1]  # Take the last part after extraction
                break
        
        # If path contains rootfs or filesystem marker, show from there
        for marker in [".rootfs.", "/rootfs/", "/squashfs-root/", "/jffs2-root/", "/cramfs-root/"]:
            if marker in clean_path:
                idx = clean_path.find(marker)
                clean_path = clean_path[idx:].lstrip(".")
                if not clean_path.startswith("/"):
                    clean_path = "/" + clean_path
                break
        
        # Show line number if available
        location = f"{clean_path}:{hit.line}" if hit.line else clean_path
        
        # Use title attribute for full path on hover
        banned_rows += f'<tr><td class="bad">{hit.function}()</td>'
        banned_rows += f'<td class="loc" title="{hit.file}">{location}</td>'
        banned_rows += f'<td class="ok">{hit.alternative}</td>'
        banned_rows += f'<td class="{sev_class}">{hit.severity.name}</td>'
        banned_rows += f'<td class="loc">{hit.compliance}</td></tr>'

    # Build dependency risk rows
    dep_rows = ""
    for risk in result.dependency_risks:
        dep_rows += f'<tr><td class="bad">{risk.library}</td>'
        dep_rows += f"<td>{risk.issue}</td>"
        dep_rows += f'<td>{", ".join(risk.used_by[:5])}</td></tr>'

    # Build credential rows
    cred_rows = ""
    for cred in result.credentials:
        sev_class = "bad" if cred.severity.value >= 3 else "wrn"
        cred_rows += f'<tr><td class="loc">{cred.file}:{cred.line}</td>'
        cred_rows += f'<td class="{sev_class}">{cred.pattern}</td>'
        cred_rows += f'<td class="loc">{cred.snippet[:50]}</td></tr>'

    # Build certificate rows
    cert_rows = ""
    for cert in result.certificates:
        sev_class = "bad" if cert.severity.value >= 3 else "wrn" if cert.severity.value >= 2 else ""
        cert_rows += f'<tr><td class="loc">{cert.file}</td>'
        cert_rows += f"<td>{cert.file_type}</td>"
        cert_rows += f'<td class="{sev_class}">{cert.issue}</td></tr>'

    # Build config issue rows
    config_rows = ""
    for issue in result.config_issues:
        sev_class = "bad" if issue.severity.value >= 3 else "wrn"
        config_rows += f'<tr><td class="loc">{issue.file}:{issue.line}</td>'
        config_rows += f'<td class="{sev_class}">{issue.issue}</td>'
        config_rows += f'<td class="loc">{issue.snippet[:50]}</td></tr>'

    # Build classification sections
    def build_class_section(title, items, css_class):
        if not items:
            return ""
        content = ""
        for binary in items:
            missing = []
            if binary.nx is not True:
                missing.append("NX")
            if binary.canary is not True:
                missing.append("Canary")
            if binary.pie is not True:
                missing.append("PIE")
            if binary.relro != "full":
                missing.append("RELRO")
            if binary.fortify is not True:
                missing.append("Fortify")
            if binary.stack_clash != "yes":
                missing.append("StackClash")
            if binary.cfi != "yes":
                missing.append("CFI")
            content += f'<div class="ci"><b>{binary.filename}</b>'
            content += f'<span class="cp">{binary.path}</span>'
            content += f'<span class="cm">{", ".join(missing) if missing else "All OK"}</span></div>'
        # Add scrollable container if many items
        scroll_style = ' style="max-height:400px;overflow-y:auto"' if len(items) > 20 else ''
        return f'<div class="cs {css_class}"><div class="ct">{title} ({len(items)})</div><div{scroll_style}>{content}</div></div>'

    # Generate progress bar helper
    def progress_bar(label, count, total):
        pct = count / total * 100 if total > 0 else 0
        # Determine bar class based on percentage ranges
        bar_class = ""
        if pct < 50:
            bar_class = "lo"  # Low (red) - below 50%
        elif pct >= 50 and pct < 80:
            bar_class = "me"  # Medium (yellow) - 50% to 79%
        # else: bar_class remains "" for 80%+ (green/good)
        return f'''<div class="pi"><span class="pl">{label}</span>
<div class="pb"><div class="pf {bar_class}" style="width:{pct:.0f}%"></div></div>
<span class="pv">{count}/{total}</span></div>'''

    html = f'''<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>HardenCheck Report - {result.target}</title>
<link href="https://fonts.googleapis.com/css2?family=Fira+Code:wght@400;600&display=swap" rel="stylesheet">
<style>
*{{margin:0;padding:0;box-sizing:border-box}}
:root{{--bg:#0a0a0a;--cd:#111;--bd:#222;--tx:#e0e0e0;--dm:#666;--ok:#0c6;--bad:#f33;--wrn:#fa0}}
body{{font-family:'Fira Code',monospace;background:var(--bg);color:var(--tx);font-size:12px;padding:20px;line-height:1.5}}
.container{{max-width:1600px;margin:0 auto}}
h1{{font-size:18px;font-weight:600;margin-bottom:5px}}
.meta{{color:var(--dm);font-size:11px;margin-bottom:20px}}
.card{{background:var(--cd);border:1px solid var(--bd);padding:15px;margin-bottom:15px}}
.card-title{{font-size:13px;font-weight:600;margin-bottom:12px;padding-bottom:8px;border-bottom:1px solid var(--bd)}}
.grade{{font-size:48px;font-weight:600;display:inline-block;margin-right:20px}}
.ga{{color:var(--ok)}}.gb{{color:#6c6}}.gc{{color:var(--wrn)}}.gd{{color:#f60}}.gf{{color:var(--bad)}}
.summary{{display:grid;grid-template-columns:repeat(3,1fr);gap:10px;margin-bottom:15px}}
.sum-card{{background:var(--cd);border:1px solid var(--bd);padding:12px;text-align:center}}
.sum-card.se{{border-color:var(--ok)}}.sum-card.pa{{border-color:var(--wrn)}}.sum-card.in{{border-color:var(--bad)}}
.sum-num{{font-size:28px;font-weight:600}}
.sum-num.se{{color:var(--ok)}}.sum-num.pa{{color:var(--wrn)}}.sum-num.in{{color:var(--bad)}}
.sum-label{{font-size:10px;color:var(--dm);text-transform:uppercase}}
.profile{{display:grid;grid-template-columns:1fr 1fr;gap:8px}}
.profile-row{{display:flex;justify-content:space-between;padding:4px 0;border-bottom:1px solid var(--bd)}}
.profile-label{{color:var(--dm)}}
.pi{{display:flex;align-items:center;margin-bottom:8px}}
.pl{{width:100px;font-size:11px}}
.pb{{flex:1;height:6px;background:var(--bd);margin:0 10px}}
.pf{{height:100%;background:var(--ok);transition:width 0.3s}}
.pf.lo{{background:var(--bad)}}.pf.me{{background:var(--wrn)}}
.pv{{width:50px;font-size:10px;text-align:right;color:var(--dm)}}
table{{width:100%;border-collapse:collapse;font-size:11px}}
th{{text-align:left;padding:6px;border-bottom:1px solid var(--bd);color:var(--dm);font-weight:500}}
td{{padding:6px;border-bottom:1px solid var(--bd)}}
.fn{{font-weight:500}}
.ok{{color:var(--ok)}}.bad{{color:var(--bad)}}.wrn{{color:var(--wrn)}}
.rb{{background:rgba(255,51,51,0.08)}}.rw{{background:rgba(255,170,0,0.05)}}
.loc{{color:var(--dm);font-size:10px}}
.cs{{margin-bottom:10px;border:1px solid var(--bd)}}
.cs .ct{{padding:8px 12px;font-weight:500;border-bottom:1px solid var(--bd)}}
.cs.se .ct{{border-left:3px solid var(--ok)}}
.cs.pa .ct{{border-left:3px solid var(--wrn)}}
.cs.in .ct{{border-left:3px solid var(--bad)}}
.ci{{padding:6px 12px;border-bottom:1px solid var(--bd)}}
.ci:last-child{{border-bottom:none}}
.ci b{{display:block}}
.cp{{font-size:10px;color:var(--dm);display:block}}
.cm{{font-size:10px;color:var(--bad)}}
.tools{{display:flex;flex-wrap:wrap;gap:8px}}
.tool{{background:var(--bd);padding:4px 10px;font-size:10px}}
.warn-box{{background:rgba(255,170,0,0.1);border:1px solid var(--wrn);padding:10px;margin-bottom:15px;font-size:11px}}
.warn-box.crit{{background:rgba(255,51,51,0.1);border-color:var(--bad)}}
.tbl-wrap{{overflow-x:auto}}
.tbl-scroll{{max-height:700px;overflow-y:auto}}
.search-box{{display:flex;gap:10px;margin-bottom:15px;flex-wrap:wrap;align-items:center}}
.search-input{{background:var(--cd);border:1px solid var(--bd);color:var(--tx);padding:8px 12px;font-family:inherit;font-size:12px;width:250px}}
.search-input:focus{{outline:none;border-color:var(--ok)}}
.filter-btn{{background:var(--bd);border:1px solid var(--bd);color:var(--tx);padding:6px 12px;cursor:pointer;font-family:inherit;font-size:11px}}
.filter-btn:hover{{border-color:var(--dm)}}
.filter-btn.active{{background:var(--ok);color:#000;border-color:var(--ok)}}
.filter-btn.active-bad{{background:var(--bad);color:#fff;border-color:var(--bad)}}
.filter-btn.active-wrn{{background:var(--wrn);color:#000;border-color:var(--wrn)}}
.search-count{{color:var(--dm);font-size:11px;margin-left:10px}}
.hidden{{display:none!important}}
</style>
<script>
function initSearch(){{
    // Universal table search function
    function setupTableSearch(searchId,tableId,countId){{
        const input=document.getElementById(searchId);
        const table=document.getElementById(tableId);
        const count=document.getElementById(countId);
        if(!input||!table)return;
        const rows=table.querySelectorAll('tbody tr');
        input.addEventListener('input',()=>{{
            const term=input.value.toLowerCase();
            let visible=0;
            rows.forEach(row=>{{
                const match=!term||row.textContent.toLowerCase().includes(term);
                row.classList.toggle('hidden',!match);
                if(match)visible++;
            }});
            if(count)count.textContent=visible+'/'+rows.length;
        }});
    }}
    
    // Binary table with filters
    const binarySearch=document.getElementById('binarySearch');
    const binaryTable=document.getElementById('binaryTable');
    const binaryCount=document.getElementById('binaryCount');
    const filterBtns=document.querySelectorAll('.filter-btn[data-filter]');
    let activeFilter='all';
    
    if(binarySearch&&binaryTable){{
        const rows=binaryTable.querySelectorAll('tbody tr');
        function filterBinaries(){{
            const term=binarySearch.value.toLowerCase();
            let visible=0;
            rows.forEach(row=>{{
                const text=row.textContent.toLowerCase();
                const matchesSearch=!term||text.includes(term);
                const cls=row.className;
                let matchesFilter=activeFilter==='all'||(activeFilter==='insecure'&&cls.includes('rb'))||(activeFilter==='partial'&&cls.includes('rw'))||(activeFilter==='secured'&&!cls.includes('rb')&&!cls.includes('rw'));
                row.classList.toggle('hidden',!(matchesSearch&&matchesFilter));
                if(matchesSearch&&matchesFilter)visible++;
            }});
            if(binaryCount)binaryCount.textContent=visible+'/'+rows.length;
        }}
        binarySearch.addEventListener('input',filterBinaries);
        filterBtns.forEach(btn=>{{
            btn.addEventListener('click',()=>{{
                filterBtns.forEach(b=>b.classList.remove('active','active-bad','active-wrn'));
                activeFilter=btn.dataset.filter;
                btn.classList.add(activeFilter==='insecure'?'active-bad':activeFilter==='partial'?'active-wrn':'active');
                filterBinaries();
            }});
        }});
        filterBinaries();
    }}
    
    // Setup search for other tables
    setupTableSearch('daemonSearch','daemonTable','daemonCount');
    setupTableSearch('bannedSearch','bannedTable','bannedCount');
    setupTableSearch('credSearch','credTable','credCount');
    setupTableSearch('certSearch','certTable','certCount');
    setupTableSearch('configSearch','configTable','configCount');
    setupTableSearch('depSearch','depTable','depCount');
    
    // Classification search
    const classSearch=document.getElementById('classSearch');
    const classItems=document.querySelectorAll('.ci');
    const classCount=document.getElementById('classCount');
    if(classSearch){{
        classSearch.addEventListener('input',()=>{{
            const term=classSearch.value.toLowerCase();
            let visible=0;
            classItems.forEach(item=>{{
                const match=!term||item.textContent.toLowerCase().includes(term);
                item.classList.toggle('hidden',!match);
                if(match)visible++;
            }});
            if(classCount)classCount.textContent=visible+'/'+classItems.length;
        }});
    }}
}}
document.addEventListener('DOMContentLoaded',initSearch);
</script>
</head>
<body>
<div class="container">

<h1>HardenCheck Security Report</h1>
<div class="meta">{result.target} | {result.scan_time} | {result.duration:.1f}s | v{VERSION}</div>

<div class="card">
<div class="card-title">Security Grade</div>
<span class="grade g{grade.lower()}">{grade}</span>
<span style="color:var(--dm)">Score: {score}/110</span>
</div>

<div class="card">
<div class="card-title">Firmware Profile</div>
<div class="profile">
<div class="profile-row"><span class="profile-label">Type</span><span>{profile.fw_type}</span></div>
<div class="profile-row"><span class="profile-label">Architecture</span><span>{profile.arch} {profile.bits}-bit</span></div>
<div class="profile-row"><span class="profile-label">Endianness</span><span>{profile.endian}</span></div>
<div class="profile-row"><span class="profile-label">Libc</span><span>{profile.libc}</span></div>
<div class="profile-row"><span class="profile-label">Kernel</span><span>{profile.kernel}</span></div>
<div class="profile-row"><span class="profile-label">Total Files</span><span>{profile.total_files}</span></div>
<div class="profile-row"><span class="profile-label">ELF Binaries</span><span>{profile.elf_binaries}</span></div>
<div class="profile-row"><span class="profile-label">Shared Libraries</span><span>{profile.shared_libs}</span></div>
<div class="profile-row"><span class="profile-label">Shell Scripts</span><span>{profile.shell_scripts}</span></div>
<div class="profile-row"><span class="profile-label">Setuid Files</span><span class="{"bad" if profile.setuid_files else ""}">{len(profile.setuid_files)}</span></div>
</div>
</div>

{f'<div class="warn-box crit"><b>⚠ Setuid Files Found:</b> {", ".join(profile.setuid_files[:5])}</div>' if profile.setuid_files else ''}

<div class="summary">
<div class="sum-card se"><div class="sum-num se">{len(secured)}</div><div class="sum-label">Secured</div></div>
<div class="sum-card pa"><div class="sum-num pa">{len(partial)}</div><div class="sum-label">Partial</div></div>
<div class="sum-card in"><div class="sum-num in">{len(insecure)}</div><div class="sum-label">Insecure</div></div>
</div>

<div class="card">
<div class="card-title">Protection Coverage</div>
{progress_bar("NX", nx_count, total_binaries)}
{progress_bar("Canary", canary_count, total_binaries)}
{progress_bar("PIE", pie_count, total_binaries)}
{progress_bar("Full RELRO", relro_count, total_binaries)}
{progress_bar("Fortify", fortify_count, total_binaries)}
{progress_bar("Stripped", stripped_count, total_binaries)}
{progress_bar("Stack Clash", stack_clash_count, total_binaries)}
{progress_bar("CFI", cfi_count, total_binaries)}
</div>

{f'''<div class="card">
<div class="card-title">Network Services / Daemons ({len(result.daemons)})</div>
{f'<div class="search-box"><input type="text" id="daemonSearch" class="search-input" placeholder="Search services..."><span id="daemonCount" class="search-count"></span></div>' if len(result.daemons) > 20 else ''}
<div class="tbl-wrap{' tbl-scroll' if len(result.daemons) > 20 else ''}"><table id="daemonTable">
<thead><tr><th>Risk</th><th>Service</th><th>Binary</th><th>Version</th><th>Path</th><th>Status</th><th>Detection</th></tr></thead>
<tbody>{daemon_rows}</tbody>
</table></div>
</div>''' if result.daemons else ''}

{f'''<div class="card">
<div class="card-title">Dependency Risks ({len(result.dependency_risks)})</div>
{f'<div class="search-box"><input type="text" id="depSearch" class="search-input" placeholder="Search dependencies..."><span id="depCount" class="search-count"></span></div>' if len(result.dependency_risks) > 20 else ''}
<div class="tbl-wrap{' tbl-scroll' if len(result.dependency_risks) > 20 else ''}"><table id="depTable">
<thead><tr><th>Library</th><th>Issue</th><th>Used By</th></tr></thead>
<tbody>{dep_rows}</tbody>
</table></div>
</div>''' if result.dependency_risks else ''}

<div class="card">
<div class="card-title">Binary Analysis ({len(result.binaries)})</div>
{f'''<div class="search-box">
<input type="text" id="binarySearch" class="search-input" placeholder="Search binaries...">
<button class="filter-btn active" data-filter="all">All</button>
<button class="filter-btn" data-filter="insecure">Insecure</button>
<button class="filter-btn" data-filter="partial">Partial</button>
<button class="filter-btn" data-filter="secured">Secured</button>
<span id="binaryCount" class="search-count"></span>
</div>''' if len(result.binaries) > 20 else ''}
<div class="tbl-wrap{' tbl-scroll' if len(result.binaries) > 20 else ''}"><table id="binaryTable">
<thead><tr><th>Binary</th><th>NX</th><th>Canary</th><th>PIE</th><th>RELRO</th><th>Fortify</th><th>Strip</th><th>SClash</th><th>CFI</th><th>TXREL</th><th>RPATH</th><th>Conf</th></tr></thead>
<tbody>{binary_rows}</tbody>
</table></div>
</div>

<div class="card">
<div class="card-title">Banned Functions ({len(result.banned_functions)})</div>
{f'''<div class="search-box">
<input type="text" id="bannedSearch" class="search-input" placeholder="Search functions...">
<span id="bannedCount" class="search-count"></span>
</div>''' if len(result.banned_functions) > 20 else ''}
{f'''<div class="tbl-wrap{' tbl-scroll' if len(result.banned_functions) > 20 else ''}"><table id="bannedTable">
<thead><tr><th>Function</th><th>Location</th><th>Alternative</th><th>Severity</th><th>Compliance</th></tr></thead>
<tbody>{banned_rows}</tbody>
</table></div>''' if result.banned_functions else '<div style="color:var(--dm)">No banned functions detected</div>'}
</div>

{f'''<div class="card">
<div class="card-title">Hardcoded Credentials ({len(result.credentials)})</div>
{f'<div class="search-box"><input type="text" id="credSearch" class="search-input" placeholder="Search credentials..."><span id="credCount" class="search-count"></span></div>' if len(result.credentials) > 20 else ''}
<div class="tbl-wrap{' tbl-scroll' if len(result.credentials) > 20 else ''}"><table id="credTable">
<thead><tr><th>Location</th><th>Pattern</th><th>Context</th></tr></thead>
<tbody>{cred_rows}</tbody>
</table></div>
</div>''' if result.credentials else ''}

{f'''<div class="card">
<div class="card-title">Certificates & Keys ({len(result.certificates)})</div>
{f'<div class="search-box"><input type="text" id="certSearch" class="search-input" placeholder="Search certificates..."><span id="certCount" class="search-count"></span></div>' if len(result.certificates) > 20 else ''}
<div class="tbl-wrap{' tbl-scroll' if len(result.certificates) > 20 else ''}"><table id="certTable">
<thead><tr><th>File</th><th>Type</th><th>Issue</th></tr></thead>
<tbody>{cert_rows}</tbody>
</table></div>
</div>''' if result.certificates else ''}

{f'''<div class="card">
<div class="card-title">Configuration Issues ({len(result.config_issues)})</div>
{f'<div class="search-box"><input type="text" id="configSearch" class="search-input" placeholder="Search config issues..."><span id="configCount" class="search-count"></span></div>' if len(result.config_issues) > 20 else ''}
<div class="tbl-wrap{' tbl-scroll' if len(result.config_issues) > 20 else ''}"><table id="configTable">
<thead><tr><th>Location</th><th>Issue</th><th>Context</th></tr></thead>
<tbody>{config_rows}</tbody>
</table></div>
</div>''' if result.config_issues else ''}

<div class="card">
<div class="card-title">Classification</div>
{f'''<div class="search-box">
<input type="text" id="classSearch" class="search-input" placeholder="Search by filename or path...">
<span id="classCount" class="search-count"></span>
</div>''' if len(result.binaries) > 20 else ''}
{build_class_section("SECURED", secured, "se")}
{build_class_section("PARTIAL", partial, "pa")}
{build_class_section("INSECURE", insecure, "in")}
</div>

<div class="card">
<div class="card-title">Tools Used</div>
<div class="tools">
{" ".join(f'<span class="tool">{name}: {cmd}</span>' for name, cmd in result.tools.items())}
</div>
</div>

</div>
</body>
</html>'''

    output_path.write_text(html, encoding="utf-8")


# =============================================================================
# JSON REPORT GENERATION
# =============================================================================

def generate_json_report(result: ScanResult, output_path: Path):
    """Generate JSON report."""
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
            "total_files": profile.total_files,
            "elf_binaries": profile.elf_binaries,
            "shared_libs": profile.shared_libs,
            "shell_scripts": profile.shell_scripts,
            "setuid_files": profile.setuid_files,
            "world_writable": profile.world_writable
        },
        "summary": {
            "total_binaries": len(result.binaries),
            "secured": sum(1 for b in result.binaries if classify_binary(b) == "SECURED"),
            "partial": sum(1 for b in result.binaries if classify_binary(b) == "PARTIAL"),
            "insecure": sum(1 for b in result.binaries if classify_binary(b) == "INSECURE")
        },
        "daemons": [
            {
                "name": d.name,
                "binary": d.binary,
                "version": d.version,
                "path": d.path,
                "risk": d.risk,
                "reason": d.reason,
                "has_network": d.has_network,
                "status": d.status
            }
            for d in result.daemons
        ],
        "binaries": [
            {
                "path": b.path,
                "filename": b.filename,
                "type": b.binary_type.value,
                "nx": b.nx,
                "canary": b.canary,
                "pie": b.pie,
                "relro": b.relro,
                "fortify": b.fortify,
                "stripped": b.stripped,
                "stack_clash": b.stack_clash,
                "cfi": b.cfi,
                "textrel": b.textrel,
                "rpath": b.rpath,
                "confidence": b.confidence,
                "classification": classify_binary(b)
            }
            for b in result.binaries
        ],
        "banned_functions": [
            {
                "function": h.function,
                "file": h.file,
                "line": h.line,
                "alternative": h.alternative,
                "severity": h.severity.name,
                "compliance": h.compliance
            }
            for h in result.banned_functions
        ],
        "dependency_risks": [
            {
                "library": r.library,
                "issue": r.issue,
                "used_by": r.used_by
            }
            for r in result.dependency_risks
        ],
        "credentials": [
            {
                "file": c.file,
                "line": c.line,
                "pattern": c.pattern,
                "severity": c.severity.name
            }
            for c in result.credentials
        ],
        "certificates": [
            {
                "file": c.file,
                "type": c.file_type,
                "issue": c.issue,
                "severity": c.severity.name
            }
            for c in result.certificates
        ],
        "config_issues": [
            {
                "file": c.file,
                "line": c.line,
                "issue": c.issue,
                "severity": c.severity.name
            }
            for c in result.config_issues
        ]
    }

    output_path.write_text(json.dumps(data, indent=2), encoding="utf-8")


# =============================================================================
# MAIN ENTRY POINT
# =============================================================================

def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description="HardenCheck v1.0 - Firmware Binary Security Analyzer",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s /path/to/firmware
  %(prog)s /path/to/firmware -o report.html --json
  %(prog)s /path/to/firmware -t 8 -v

Required Tools:
  apt install radare2 devscripts pax-utils elfutils binutils
        """
    )

    parser.add_argument("target", help="Firmware directory to scan")
    parser.add_argument("-o", "--output", default="hardencheck_report.html",
                        help="Output HTML report path (default: hardencheck_report.html)")
    parser.add_argument("-t", "--threads", type=int, default=4,
                        help="Number of analysis threads (default: 4)")
    parser.add_argument("-v", "--verbose", action="store_true",
                        help="Enable verbose output")
    parser.add_argument("--json", action="store_true",
                        help="Also generate JSON report")
    parser.add_argument("--version", action="version",
                        version=f"HardenCheck v{VERSION}")

    args = parser.parse_args()

    # Validate target
    target = Path(args.target)
    if not target.exists():
        print(f"Error: Target directory not found: {target}")
        sys.exit(1)
    if not target.is_dir():
        print(f"Error: Target must be a directory: {target}")
        sys.exit(1)

    # Run scan
    try:
        scanner = HardenCheck(target, threads=args.threads, verbose=args.verbose)
        result = scanner.scan()

        # Generate HTML report
        output_path = Path(args.output)
        generate_html_report(result, output_path)
        print(f"[+] HTML Report: {output_path}")

        # Generate JSON report if requested
        if args.json:
            json_path = output_path.with_suffix(".json")
            generate_json_report(result, json_path)
            print(f"[+] JSON Report: {json_path}")

    except KeyboardInterrupt:
        print("\n[!] Scan interrupted by user")
        sys.exit(130)
    except Exception as e:
        print(f"\n[!] Error: {e}")
        if args.verbose:
            import traceback
            traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()
