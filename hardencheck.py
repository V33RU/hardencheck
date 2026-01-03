#!/usr/bin/env python3
"""
HardenCheck - Firmware Binary Security Analyzer
Author: v33ru (Mr-IoT) | github.com/v33ru | IOTSRG
Version: 1.0.0 - Security fixes + improved detection accuracy
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
import struct
import math
import html as html_module
from pathlib import Path
from dataclasses import dataclass, field
from typing import List, Dict, Tuple, Optional, Set
from enum import Enum
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime

VERSION = "1.0.0"

# Secure subprocess environment - restrict PATH to standard locations
SECURE_ENV = {
    "PATH": "/usr/bin:/bin:/usr/sbin:/sbin",
    "LC_ALL": "C",
    "LANG": "C",
}

# Maximum recursion depth for directory walking
MAX_RECURSION_DEPTH = 20

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


class ASLRRating(Enum):
    """ASLR effectiveness rating."""
    EXCELLENT = "Excellent"      # >= 28 bits effective entropy
    GOOD = "Good"                # 20-27 bits
    MODERATE = "Moderate"        # 15-19 bits
    WEAK = "Weak"                # 8-14 bits
    INEFFECTIVE = "Ineffective"  # < 8 bits or non-PIE
    NOT_APPLICABLE = "N/A"       # Static binary or analysis failed


@dataclass
class ASLRAnalysis:
    """ASLR entropy analysis result for a binary."""
    path: str
    filename: str
    is_pie: bool
    arch: str
    bits: int
    
    # Address space layout
    text_vaddr: int = 0
    data_vaddr: int = 0
    bss_vaddr: int = 0
    entry_point: int = 0
    load_base: int = 0
    
    # Entropy metrics
    theoretical_entropy: int = 0
    page_offset_bits: int = 12
    available_entropy: int = 0
    effective_entropy: int = 0
    
    # Segment analysis
    num_load_segments: int = 0
    has_fixed_segments: bool = False
    fixed_segment_addrs: List[int] = field(default_factory=list)
    
    # Additional checks
    has_textrel: bool = False
    has_rpath: bool = False
    stack_executable: bool = False
    
    # Rating
    rating: ASLRRating = ASLRRating.NOT_APPLICABLE
    issues: List[str] = field(default_factory=list)
    recommendations: List[str] = field(default_factory=list)


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
    """Binary security analysis result.
    
    Confidence scoring model:
    - Base confidence: 100
    - Unknown values (None): -10 per field (detection failed)
    - Tool disagreement: -15 per disagreement
    - Minimum confidence: 50
    """
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
    # NEW: Separate tracking for confidence factors
    unknown_fields: List[str] = field(default_factory=list)  # Fields we couldn't detect
    tool_disagreements: List[str] = field(default_factory=list)  # Fields where tools disagreed
    tools_used: List[str] = field(default_factory=list)
    aslr_analysis: Optional[ASLRAnalysis] = None


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
    aslr_summary: Dict = field(default_factory=dict)
    missing_tools: List[str] = field(default_factory=list)  # Track missing tools


# =============================================================================
# CONSTANTS
# =============================================================================

# Architecture-specific ASLR entropy limits
# Reference: Linux kernel mm/mmap.c and arch/*/include/asm/elf.h
ARCH_ASLR_ENTROPY = {
    "x86_64": (47, 28, 22),
    "x86": (32, 8, 8),
    "ARM64": (48, 24, 18),
    "ARM": (32, 8, 8),
    "MIPS64": (40, 18, 14),
    "MIPS": (32, 8, 8),
    "PowerPC64": (46, 28, 22),
    "PowerPC": (32, 8, 8),
    "RISC-V": (39, 18, 14),
}

# Banned functions with alternatives and compliance mapping
# Only HIGH/CRITICAL severity functions that are truly dangerous
BANNED_FUNCTIONS = {
    "gets":     ("fgets(buf, size, stdin)", Severity.CRITICAL, "CWE-120, OWASP-I4"),
    "strcpy":   ("strlcpy() or strncpy()+null", Severity.HIGH, "CWE-120, OWASP-I4"),
    "strcat":   ("strlcat() or strncat()+null", Severity.HIGH, "CWE-120, OWASP-I4"),
    "sprintf":  ("snprintf(buf, size, ...)", Severity.HIGH, "CWE-120, OWASP-I4"),
    "vsprintf": ("vsnprintf(buf, size, ...)", Severity.HIGH, "CWE-120, OWASP-I4"),
    "scanf":    ("fgets() + sscanf() or strtol()", Severity.MEDIUM, "CWE-134, OWASP-I4"),
    "system":   ("execve() with hardcoded path + validated args", Severity.HIGH, "CWE-78, OWASP-I4"),
    "popen":    ("pipe()+fork()+execve() with validated args", Severity.HIGH, "CWE-78, OWASP-I4"),
    "mktemp":   ("mkstemp() or mkdtemp()", Severity.HIGH, "CWE-377, NIST SI-16"),
    "tmpnam":   ("mkstemp() or tmpfile()", Severity.HIGH, "CWE-377, NIST SI-16"),
    "tempnam":  ("mkstemp()", Severity.HIGH, "CWE-377, NIST SI-16"),
}

# Lower severity functions - only flagged in source code analysis, not binary imports
# These are commonly used and not always dangerous
LOW_RISK_FUNCTIONS = {
    "fscanf":   ("fgets() + sscanf()", Severity.LOW, "CWE-134"),
    "sscanf":   ("strtol/strtod with validation", Severity.INFO, "CWE-134"),
    "rand":     ("getrandom() for crypto use", Severity.INFO, "CWE-338"),
    "srand":    ("getrandom() for crypto use", Severity.INFO, "CWE-338"),
    "random":   ("getrandom() for crypto use", Severity.INFO, "CWE-338"),
    "strtok":   ("strtok_r() for thread safety", Severity.INFO, "CWE-362"),
    "asctime":  ("strftime()", Severity.INFO, "CWE-362"),
    "ctime":    ("ctime_r() or strftime()", Severity.INFO, "CWE-362"),
    "gmtime":   ("gmtime_r()", Severity.INFO, "CWE-362"),
    "localtime":("localtime_r()", Severity.INFO, "CWE-362"),
}

# Known network services with risk levels
KNOWN_SERVICES = {
    # Critical - unauthenticated/weak auth remote access
    "telnetd":     "CRITICAL",
    "utelnetd":    "CRITICAL", 
    "rlogind":     "CRITICAL",
    "rshd":        "CRITICAL",
    "rexecd":      "CRITICAL",
    "tftpd":       "CRITICAL",
    "atftpd":      "CRITICAL",
    
    # High - common attack targets
    "ftpd":        "HIGH",
    "vsftpd":      "HIGH",
    "proftpd":     "HIGH",
    "pure-ftpd":   "HIGH",
    "bftpd":       "HIGH",
    "httpd":       "HIGH",
    "uhttpd":      "HIGH",
    "lighttpd":    "HIGH",
    "nginx":       "HIGH",
    "apache":      "HIGH",
    "apache2":     "HIGH",
    "goahead":     "HIGH",
    "boa":         "HIGH",
    "thttpd":      "HIGH",
    "mini_httpd":  "HIGH",
    "minihttpd":   "HIGH",
    "alphapd":     "HIGH",
    "httpd_gargoyle": "HIGH",
    "miniupnpd":   "HIGH",
    "upnpd":       "HIGH",
    "igmpproxy":   "HIGH",
    "snmpd":       "HIGH",
    "net-snmpd":   "HIGH",
    "cwmpd":       "HIGH",
    "tr069":       "HIGH",
    "tr064":       "HIGH",
    "smbd":        "HIGH",
    "nmbd":        "HIGH",
    "afpd":        "HIGH",
    "netatalk":    "HIGH",
    "lpd":         "HIGH",
    "cupsd":       "HIGH",
    "xinetd":      "HIGH",
    "inetd":       "HIGH",
    
    # Medium - usually authenticated or limited exposure
    "sshd":        "MEDIUM",
    "dropbear":    "MEDIUM",
    "dnsmasq":     "MEDIUM",
    "named":       "MEDIUM",
    "bind":        "MEDIUM",
    "unbound":     "MEDIUM",
    "mosquitto":   "MEDIUM",
    "mqttd":       "MEDIUM",
    "emqx":        "MEDIUM",
    "hostapd":     "MEDIUM",
    "wpa_supplicant": "MEDIUM",
    "pppd":        "MEDIUM",
    "pppoe":       "MEDIUM",
    "xl2tpd":      "MEDIUM",
    "openl2tpd":   "MEDIUM",
    "openvpn":     "MEDIUM",
    "ipsec":       "MEDIUM",
    "racoon":      "MEDIUM",
    "zebra":       "MEDIUM",
    "ripd":        "MEDIUM",
    "ospfd":       "MEDIUM",
    "bgpd":        "MEDIUM",
    "dhcpd":       "MEDIUM",
    "dhclient":    "MEDIUM",
    "udhcpd":      "MEDIUM",
    "udhcpc":      "MEDIUM",
    "radvd":       "MEDIUM",
    "avahi-daemon": "MEDIUM",
    "mdnsd":       "MEDIUM",
    "wsdd":        "MEDIUM",
    "lldpd":       "MEDIUM",
    "portmap":     "MEDIUM",
    "rpcbind":     "MEDIUM",
    "nfsd":        "MEDIUM",
    "mountd":      "MEDIUM",
    "statd":       "MEDIUM",
    "ypbind":      "MEDIUM",
    "ypserv":      "MEDIUM",
    
    # Low - monitoring/logging/time
    "ntpd":        "LOW",
    "chronyd":     "LOW",
    "crond":       "LOW",
    "cron":        "LOW",
    "atd":         "LOW",
    "syslogd":     "LOW",
    "klogd":       "LOW",
    "rsyslogd":    "LOW",
    "syslog-ng":   "LOW",
    "logd":        "LOW",
    "watchdog":    "LOW",
    "monit":       "LOW",
    "collectd":    "LOW",
    "snortd":      "LOW",
    "zabbix_agentd": "LOW",
}

NETWORK_SYMBOLS = {
    "socket", "bind", "listen", "accept", "accept4",
    "connect", "recv", "recvfrom", "recvmsg",
    "send", "sendto", "sendmsg", "select", "poll",
    "epoll_create", "epoll_wait", "getaddrinfo",
}

CREDENTIAL_PATTERNS = [
    (r'(?i)(?:^|[^a-z_])password\s*[=:]\s*["\']([^"\'$%{}<>\s]{4,})["\']', "hardcoded password"),
    (r'(?i)(?:^|[^a-z_])passwd\s*[=:]\s*["\']([^"\'$%{}<>\s]{4,})["\']', "hardcoded passwd"),
    (r'(?i)(?:^|[^a-z_])pwd\s*[=:]\s*["\']([^"\'$%{}<>\s]{4,})["\']', "hardcoded pwd"),
    (r'(?i)(?:^|[^a-z_])secret\s*[=:]\s*["\']([^"\'$%{}<>\s]{8,})["\']', "hardcoded secret"),
    (r'(?i)api[_-]?key\s*[=:]\s*["\']([a-zA-Z0-9_\-]{16,})["\']', "API key"),
    (r'(?i)apikey\s*[=:]\s*["\']([a-zA-Z0-9_\-]{16,})["\']', "API key"),
    (r'(?i)auth[_-]?token\s*[=:]\s*["\']([a-zA-Z0-9_\-]{16,})["\']', "auth token"),
    (r'(?i)access[_-]?token\s*[=:]\s*["\']([a-zA-Z0-9_\-]{16,})["\']', "access token"),
    (r'(?i)bearer\s*[=:]\s*["\']([a-zA-Z0-9_\-\.]{20,})["\']', "bearer token"),
    (r'(?i)aws[_-]?secret[_-]?access[_-]?key\s*[=:]\s*["\']([A-Za-z0-9/+=]{40})["\']', "AWS secret key"),
    (r'AKIA[0-9A-Z]{16}', "AWS access key ID"),
    (r'-----BEGIN\s+(?:RSA\s+)?PRIVATE\s+KEY-----', "embedded private key"),
    (r'["\']admin["\']\s*[,:]\s*["\']admin["\']', "default admin:admin"),
    (r'["\']root["\']\s*[,:]\s*["\']root["\']', "default root:root"),
    (r'["\']root["\']\s*[,:]\s*["\']toor["\']', "default root:toor"),
]

FALSE_POSITIVE_INDICATORS = {
    # Function/method patterns
    "get_", "set_", "fetch_", "read_", "load_", "parse_", "validate_",
    "check_", "verify_", "update_", "create_", "delete_", "handle_",
    # Environment variable patterns
    "env.", "os.environ", "getenv", "process.env", "environ[",
    # Config object patterns
    "config.", "settings.", "options.", "params.", "args.",
    # Code definition patterns
    "def ", "function ", "func ", "->", "return ", "class ",
    "const ", "let ", "var ", "private ", "public ", "protected ",
    # Documentation/example patterns
    "example", "sample", "demo", "test", "mock", "fake", "dummy",
    "todo", "fixme", "xxx", "placeholder", "your_", "my_",
    # Type annotation patterns
    ": str", ": string", ": String", "String ", "str ", ": &str",
    "<string>", "std::string", "QString", "NSString",
    # Comment patterns (additional)
    "/*", "*/", "<!--", "-->", "'''", '"""',
    # UI/Form field patterns
    "label=", "placeholder=", "hint=", "title=", "name=",
    "inputType=", "type=\"password\"", "type='password'",
    # Schema/validation patterns
    "schema", "validate", "required", "optional", "field",
    # Template patterns
    "{{", "}}", "{%", "%}", "<%", "%>", "${", "#{",
}

WEAK_PASSWORDS = {
    "admin", "password", "123456", "12345678", "root", "toor",
    "default", "guest", "user", "test", "pass", "1234",
    "qwerty", "letmein", "welcome", "monkey", "dragon",
}

CONFIG_PATTERNS = [
    # SSH configuration - only flag in actual sshd_config files
    (r'^\s*PermitRootLogin\s+yes\s*$', "sshd_config", "SSH root login enabled", Severity.HIGH),
    (r'^\s*PermitEmptyPasswords\s+yes\s*$', "sshd_config", "SSH empty passwords allowed", Severity.CRITICAL),
    # Telnet service detection
    (r'^\s*telnet\s+stream\s+tcp', "inetd.conf", "Telnet service enabled", Severity.CRITICAL),
    (r'::respawn:.*/telnetd', "inittab", "Telnet auto-start enabled", Severity.CRITICAL),
    # Password files - empty root password
    (r'^root::0:', "shadow", "Root has empty password", Severity.CRITICAL),
]

# Patterns that are informational only (not security issues)
CONFIG_INFO_PATTERNS = [
    (r'^\s*PasswordAuthentication\s+yes', "sshd_config", "SSH password auth enabled (consider keys)", Severity.INFO),
    (r'^root:\*:', "shadow", "Root account locked", Severity.INFO),
]

CERT_EXTENSIONS = {".pem", ".crt", ".cer", ".der", ".key", ".p12", ".pfx", ".jks"}

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
# ASLR ENTROPY ANALYZER
# =============================================================================

class ASLREntropyAnalyzer:
    """Analyzes ASLR entropy effectiveness for PIE binaries."""
    
    ELF_MAGIC = b'\x7fELF'
    ET_DYN = 3
    PT_LOAD = 1
    PT_GNU_STACK = 0x6474e551
    
    def __init__(self, tools: Dict[str, str]):
        self.tools = tools
    
    def _set_resource_limits(self):
        """Set resource limits for child process to prevent DoS."""
        try:
            import resource
            # CPU time limit: 60 seconds
            resource.setrlimit(resource.RLIMIT_CPU, (60, 60))
            # Virtual memory limit: 512MB
            resource.setrlimit(resource.RLIMIT_AS, (512 * 1024 * 1024, 512 * 1024 * 1024))
            # File size limit: 10MB (for any output files)
            resource.setrlimit(resource.RLIMIT_FSIZE, (10 * 1024 * 1024, 10 * 1024 * 1024))
        except (ImportError, ValueError, OSError):
            pass  # Resource limits not available on this platform
    
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
    
    def _parse_elf_header(self, data: bytes) -> Optional[Dict]:
        """Parse ELF header to extract basic info."""
        if len(data) < 64 or data[:4] != self.ELF_MAGIC:
            return None
        
        info = {}
        info['class'] = data[4]
        info['bits'] = 64 if info['class'] == 2 else 32
        info['endian'] = '<' if data[5] == 1 else '>'
        info['machine'] = struct.unpack(info['endian'] + 'H', data[18:20])[0]
        
        machine_map = {
            3: "x86", 62: "x86_64", 40: "ARM", 183: "ARM64",
            8: "MIPS", 20: "PowerPC", 21: "PowerPC64", 243: "RISC-V",
        }
        info['arch'] = machine_map.get(info['machine'], f"Unknown({info['machine']})")
        
        if info['bits'] == 64:
            info['type'] = struct.unpack(info['endian'] + 'H', data[16:18])[0]
            info['entry'] = struct.unpack(info['endian'] + 'Q', data[24:32])[0]
            info['phoff'] = struct.unpack(info['endian'] + 'Q', data[32:40])[0]
            info['phentsize'] = struct.unpack(info['endian'] + 'H', data[54:56])[0]
            info['phnum'] = struct.unpack(info['endian'] + 'H', data[56:58])[0]
        else:
            info['type'] = struct.unpack(info['endian'] + 'H', data[16:18])[0]
            info['entry'] = struct.unpack(info['endian'] + 'I', data[24:28])[0]
            info['phoff'] = struct.unpack(info['endian'] + 'I', data[28:32])[0]
            info['phentsize'] = struct.unpack(info['endian'] + 'H', data[42:44])[0]
            info['phnum'] = struct.unpack(info['endian'] + 'H', data[44:46])[0]
        
        return info
    
    def _parse_program_headers(self, data: bytes, elf_info: Dict) -> List[Dict]:
        """Parse program headers from ELF."""
        headers = []
        endian = elf_info['endian']
        phoff = elf_info['phoff']
        phentsize = elf_info['phentsize']
        phnum = elf_info['phnum']
        is_64 = elf_info['bits'] == 64
        
        for i in range(phnum):
            offset = phoff + (i * phentsize)
            if offset + phentsize > len(data):
                break
            
            ph = {}
            if is_64:
                ph['type'] = struct.unpack(endian + 'I', data[offset:offset+4])[0]
                ph['flags'] = struct.unpack(endian + 'I', data[offset+4:offset+8])[0]
                ph['offset'] = struct.unpack(endian + 'Q', data[offset+8:offset+16])[0]
                ph['vaddr'] = struct.unpack(endian + 'Q', data[offset+16:offset+24])[0]
                ph['paddr'] = struct.unpack(endian + 'Q', data[offset+24:offset+32])[0]
                ph['filesz'] = struct.unpack(endian + 'Q', data[offset+32:offset+40])[0]
                ph['memsz'] = struct.unpack(endian + 'Q', data[offset+40:offset+48])[0]
                ph['align'] = struct.unpack(endian + 'Q', data[offset+48:offset+56])[0]
            else:
                ph['type'] = struct.unpack(endian + 'I', data[offset:offset+4])[0]
                ph['offset'] = struct.unpack(endian + 'I', data[offset+4:offset+8])[0]
                ph['vaddr'] = struct.unpack(endian + 'I', data[offset+8:offset+12])[0]
                ph['paddr'] = struct.unpack(endian + 'I', data[offset+12:offset+16])[0]
                ph['filesz'] = struct.unpack(endian + 'I', data[offset+16:offset+20])[0]
                ph['memsz'] = struct.unpack(endian + 'I', data[offset+20:offset+24])[0]
                ph['flags'] = struct.unpack(endian + 'I', data[offset+24:offset+28])[0]
                ph['align'] = struct.unpack(endian + 'I', data[offset+28:offset+32])[0]
            
            headers.append(ph)
        
        return headers
    
    def _check_dynamic_section(self, filepath: Path) -> Dict:
        """Check dynamic section for TEXTREL, RPATH using readelf."""
        result = {'has_textrel': False, 'has_rpath': False, 'rpath': ''}
        
        if 'readelf' not in self.tools:
            return result
        
        ret, out, _ = self._run_command(
            [self.tools['readelf'], '-W', '-d', str(filepath)], timeout=10
        )
        
        if ret != 0:
            return result
        
        if 'TEXTREL' in out:
            result['has_textrel'] = True
        
        rpath_match = re.search(r'(?:RPATH|RUNPATH).*?\[(.*?)\]', out)
        if rpath_match:
            result['has_rpath'] = True
            result['rpath'] = rpath_match.group(1)
        
        return result
    
    def _calculate_entropy_rating(self, effective_entropy: int, issues: List[str]) -> ASLRRating:
        """Calculate ASLR rating based on effective entropy and issues."""
        critical_issues = [i for i in issues if 'TEXTREL' in i or 'non-PIE' in i.lower()]
        
        if critical_issues or effective_entropy < 8:
            return ASLRRating.INEFFECTIVE
        elif effective_entropy < 15:
            return ASLRRating.WEAK
        elif effective_entropy < 20:
            return ASLRRating.MODERATE
        elif effective_entropy < 28:
            return ASLRRating.GOOD
        else:
            return ASLRRating.EXCELLENT
    
    def analyze(self, filepath: Path, binary_analysis: BinaryAnalysis) -> ASLRAnalysis:
        """Perform complete ASLR entropy analysis on a binary.
        
        NOTE: Entropy values are STATIC THEORETICAL ESTIMATES based on 
        architecture defaults. Actual runtime entropy depends on kernel 
        configuration (mmap_rnd_bits, mmap_rnd_compat_bits) which cannot 
        be determined from static analysis alone.
        """
        analysis = ASLRAnalysis(
            path=binary_analysis.path,
            filename=binary_analysis.filename,
            is_pie=binary_analysis.pie is True,
            arch="Unknown",
            bits=32
        )
        
        data = safe_read_binary(filepath, max_size=50 * 1024 * 1024)
        if not data:
            analysis.issues.append("Failed to read binary")
            return analysis
        
        elf_info = self._parse_elf_header(data)
        if not elf_info:
            analysis.issues.append("Invalid ELF format")
            return analysis
        
        analysis.arch = elf_info['arch']
        analysis.bits = elf_info['bits']
        analysis.entry_point = elf_info['entry']
        
        # Check if binary is actually PIE (ET_DYN)
        is_pie = elf_info['type'] == self.ET_DYN
        if not is_pie:
            analysis.is_pie = False
            analysis.rating = ASLRRating.NOT_APPLICABLE
            analysis.issues.append("Non-PIE executable (static addresses)")
            analysis.recommendations.append("Recompile with -fPIE -pie flags")
            return analysis
        
        analysis.is_pie = True
        
        # Parse program headers
        phdrs = self._parse_program_headers(data, elf_info)
        load_segments = [ph for ph in phdrs if ph['type'] == self.PT_LOAD]
        analysis.num_load_segments = len(load_segments)
        
        # Improved fixed-segment detection using delta consistency
        # Linker scripts often use repeated delta patterns (e.g., 0x200000 gaps)
        # PIE binaries typically have low base vaddrs and random-friendly layout
        if len(load_segments) >= 2:
            vaddrs = [ph['vaddr'] for ph in load_segments]
            
            # Calculate deltas between consecutive segments
            deltas = [vaddrs[i+1] - vaddrs[i] for i in range(len(vaddrs)-1)]
            
            # Heuristics for fixed layout detection:
            # 1. High absolute addresses (non-PIE typically starts at 0x400000+)
            has_high_base = vaddrs[0] >= 0x400000
            
            # 2. Consistent delta pattern (suggests linker script)
            # Check if deltas are suspiciously uniform (within 1MB of each other)
            if len(deltas) >= 2:
                delta_variance = max(deltas) - min(deltas)
                has_consistent_deltas = delta_variance < 0x100000  # 1MB tolerance
            else:
                has_consistent_deltas = False
            
            # 3. Very large gaps between segments (uncommon in PIE)
            has_large_gaps = any(d > 0x10000000 for d in deltas)  # 256MB gap
            
            # Only flag as fixed if strong indicators present
            if has_high_base and (has_consistent_deltas or has_large_gaps):
                analysis.has_fixed_segments = True
                analysis.fixed_segment_addrs = vaddrs
                analysis.issues.append("Fixed segment layout detected (linker script pattern)")
            elif has_high_base and analysis.bits == 64:
                # For 64-bit, high base alone isn't definitive, just note it
                analysis.issues.append(f"High base address: 0x{vaddrs[0]:x} (verify PIE)")
        
        if load_segments:
            analysis.load_base = load_segments[0]['vaddr']
            analysis.text_vaddr = load_segments[0]['vaddr']
            if len(load_segments) > 1:
                analysis.data_vaddr = load_segments[1]['vaddr']
        
        # Check for GNU_STACK (executable stack)
        for ph in phdrs:
            if ph['type'] == self.PT_GNU_STACK:
                if ph['flags'] & 0x1:
                    analysis.stack_executable = True
                    analysis.issues.append("Executable stack detected")
        
        # Check dynamic section
        dyn_info = self._check_dynamic_section(filepath)
        analysis.has_textrel = dyn_info['has_textrel'] or binary_analysis.textrel
        analysis.has_rpath = dyn_info['has_rpath']
        
        if analysis.has_textrel:
            analysis.issues.append("TEXTREL present - text relocations reduce ASLR effectiveness")
        
        if analysis.has_rpath:
            analysis.issues.append(f"RPATH/RUNPATH set: {dyn_info['rpath']}")
        
        # Calculate entropy based on architecture
        # NOTE: These are DEFAULT kernel values; actual may differ
        arch_key = analysis.arch
        if arch_key not in ARCH_ASLR_ENTROPY:
            arch_key = "x86_64" if analysis.bits == 64 else "x86"
        
        user_bits, mmap_rand, stack_rand = ARCH_ASLR_ENTROPY.get(
            arch_key, 
            (47 if analysis.bits == 64 else 32, 28 if analysis.bits == 64 else 8, 22 if analysis.bits == 64 else 8)
        )
        
        analysis.theoretical_entropy = mmap_rand
        analysis.page_offset_bits = 12
        analysis.available_entropy = mmap_rand
        
        # Add disclaimer about theoretical nature
        analysis.issues.append(f"Entropy is theoretical estimate (kernel default: {mmap_rand} bits)")
        
        # Calculate effective entropy considering constraints
        effective = analysis.available_entropy
        
        # Penalties for issues
        if analysis.has_textrel:
            effective -= 8
            analysis.recommendations.append("Remove TEXTREL by compiling with -fPIC")
        
        if analysis.has_fixed_segments:
            effective -= 4
            analysis.recommendations.append("Avoid fixed segment addresses in PIE")
        
        if analysis.stack_executable:
            effective -= 2
            analysis.recommendations.append("Disable executable stack with -z noexecstack")
        
        # Architecture-specific adjustments
        if analysis.bits == 32:
            effective = min(effective, 8)
            if effective < 12:
                analysis.issues.append("32-bit architecture has limited ASLR entropy")
                analysis.recommendations.append("Consider 64-bit build for better ASLR")
        
        analysis.effective_entropy = max(0, effective)
        
        # Calculate rating
        analysis.rating = self._calculate_entropy_rating(
            analysis.effective_entropy, 
            analysis.issues
        )
        
        # Add recommendations based on rating
        if analysis.rating in (ASLRRating.WEAK, ASLRRating.INEFFECTIVE):
            if analysis.bits == 32:
                analysis.recommendations.append("Migrate to 64-bit for stronger ASLR")
            if binary_analysis.canary is not True:
                analysis.recommendations.append("Enable stack canaries as compensating control")
            if binary_analysis.fortify is not True:
                analysis.recommendations.append("Enable FORTIFY_SOURCE as compensating control")
        
        return analysis


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
        self.aslr_analyzer = ASLREntropyAnalyzer(self.tools)

    def _detect_tools(self) -> Dict[str, str]:
        """Detect available analysis tools."""
        tools = {}

        for cmd in ["radare2.rabin2", "rabin2"]:
            path = shutil.which(cmd)
            if path:
                tools["rabin2"] = cmd
                break

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

        if shutil.which("eu-readelf"):
            tools["readelf"] = "eu-readelf"
        elif shutil.which("readelf"):
            tools["readelf"] = "readelf"

        return tools

    def _set_resource_limits(self):
        """Set resource limits for child process to prevent DoS."""
        try:
            import resource
            # CPU time limit: 60 seconds
            resource.setrlimit(resource.RLIMIT_CPU, (60, 60))
            # Virtual memory limit: 512MB  
            resource.setrlimit(resource.RLIMIT_AS, (512 * 1024 * 1024, 512 * 1024 * 1024))
            # File size limit: 10MB
            resource.setrlimit(resource.RLIMIT_FSIZE, (10 * 1024 * 1024, 10 * 1024 * 1024))
        except (ImportError, ValueError, OSError):
            pass  # Resource limits not available on this platform

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

    def find_files(self) -> Tuple[List[Tuple[Path, BinaryType]], List[Path], List[Path]]:
        """Discover files in target directory."""
        binaries = []
        sources = []
        configs = []
        seen_inodes = set()  # Track seen files to avoid duplicates

        source_extensions = {".c", ".cpp", ".cc", ".cxx", ".h", ".hpp", ".hxx"}
        config_extensions = {".conf", ".cfg", ".ini", ".config", ".xml", ".json", ".yaml", ".yml"}
        config_names = {"passwd", "shadow", "hosts", "resolv.conf", "fstab", "inittab", "profile"}
        skip_dirs = {".git", ".svn", "__pycache__", "node_modules", ".cache"}

        for root, dirs, files in os.walk(self.target):
            dirs[:] = [d for d in dirs if d not in skip_dirs and not d.startswith(".")]

            for filename in files:
                filepath = Path(root) / filename

                # Follow symlinks but track to avoid duplicates
                try:
                    if filepath.is_symlink():
                        real_path = filepath.resolve()
                        # Check if target exists and is within our scan directory
                        if not real_path.exists():
                            continue
                        # Get inode to detect duplicates (same file, different symlinks)
                        stat_info = real_path.stat()
                        inode = (stat_info.st_dev, stat_info.st_ino)
                        if inode in seen_inodes:
                            continue
                        seen_inodes.add(inode)
                except (OSError, PermissionError):
                    continue

                if self._is_elf_file(filepath):
                    binary_type = self._get_elf_type(filepath)
                    binaries.append((filepath, binary_type))
                    continue

                suffix = filepath.suffix.lower()
                if suffix in source_extensions:
                    sources.append(filepath)
                    continue

                if suffix in config_extensions or filename in config_names:
                    configs.append(filepath)

        return binaries, sources, configs

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

        profile.elf_binaries = len([b for b in binaries if b[1] == BinaryType.EXECUTABLE])
        profile.shared_libs = len([b for b in binaries if b[1] == BinaryType.SHARED_LIB])

        for root, dirs, files in os.walk(self.target):
            dirs[:] = [d for d in dirs if not d.startswith(".")]
            profile.total_files += len(files)

            for filename in files:
                filepath = Path(root) / filename

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

                if filepath.suffix.lower() in {".conf", ".cfg", ".ini", ".config"}:
                    profile.config_files += 1

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

    def detect_daemons(self, binaries: List[BinaryAnalysis]) -> List[Daemon]:
        """Detect network services and daemons.
        
        Detection methods (in order of confidence):
        1. Known service names (KNOWN_SERVICES dict) - HIGH confidence
        2. Ends with 'd' + has network symbols - MEDIUM confidence  
        3. Ends with 'd' + referenced in init scripts - MEDIUM confidence
        4. Has network symbols + referenced in init - MEDIUM confidence
        5. Ends with 'd' + common daemon patterns - LOW confidence
        """
        daemons = []
        seen_binaries = set()
        
        # Detect BusyBox multicall binary
        busybox_path = None
        for binary in binaries:
            if binary.filename.lower() == "busybox":
                busybox_path = binary.path
                break

        executables = [b for b in binaries if b.binary_type == BinaryType.EXECUTABLE]

        # Common non-daemon binaries ending in 'd' to exclude
        non_daemons = {
            "systemd", "udevd", "lvmetad", "kmod", "modload",
            "chmod", "chgrp", "chown", "find", "sed", "awk", "gawk",
            "head", "tail", "fold", "expand", "unexpand", "od",
            "bind", "send", "read", "unload", "reload", "load",
            "passwd", "chpasswd", "mkpasswd", "grpck", "pwck",
            "insmod", "rmmod", "lsmod", "depmod", "modprobe",
            "mknod", "makedevd", "start-stop-daemon",
            "ifupd", "ifdownd", "ip", "id", "md", "cd",
        }

        for binary in executables:
            filename = binary.filename
            filename_lower = filename.lower()

            if filename_lower in seen_binaries:
                continue
            
            # Skip excluded non-daemons
            if filename_lower in non_daemons:
                continue
            
            # Skip if this is a BusyBox symlink
            if busybox_path and binary.path != busybox_path:
                filepath = self.target / binary.path
                try:
                    if filepath.is_symlink():
                        link_target = os.readlink(filepath)
                        if "busybox" in link_target.lower():
                            continue
                except (OSError, PermissionError):
                    pass

            is_daemon = False
            reason_parts = []
            risk = "UNKNOWN"

            # Method 1: Known service names (HIGH confidence)
            if filename_lower in KNOWN_SERVICES:
                is_daemon = True
                risk = KNOWN_SERVICES[filename_lower]
                reason_parts.append("known service")
            
            # Check properties for other methods
            if not is_daemon:
                filepath = self.target / binary.path
                has_network = self._has_network_symbols(filepath)
                in_init = self._is_referenced_in_init(filename)
                ends_with_d = filename_lower.endswith("d") and len(filename_lower) > 3
                
                # Method 2: *d + network symbols (MEDIUM confidence)
                if ends_with_d and has_network:
                    is_daemon = True
                    reason_parts.append("daemon name (*d)")
                    reason_parts.append("network symbols")
                    risk = "MEDIUM"
                
                # Method 3: *d + init script (MEDIUM confidence)
                elif ends_with_d and in_init:
                    is_daemon = True
                    reason_parts.append("daemon name (*d)")
                    reason_parts.append("init script")
                    risk = "MEDIUM"
                
                # Method 4: network + init (MEDIUM confidence)
                elif has_network and in_init:
                    is_daemon = True
                    reason_parts.append("network symbols")
                    reason_parts.append("init script")
                    risk = "MEDIUM"
                
                # Method 5: Just *d pattern with daemon-like name (LOW confidence)
                elif ends_with_d and len(filename_lower) > 4:
                    # Look for daemon-like patterns in name
                    daemon_patterns = ["serv", "daemon", "agent", "proxy", "server", "listen", "mgr", "mgmt"]
                    if any(p in filename_lower for p in daemon_patterns):
                        is_daemon = True
                        reason_parts.append("daemon name pattern")
                        risk = "LOW"

            if is_daemon:
                seen_binaries.add(filename_lower)
                filepath = self.target / binary.path
                version = self._extract_version(filepath)
                status = classify_binary(binary)

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

        risk_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "UNKNOWN": 4}
        daemons.sort(key=lambda d: (risk_order.get(d.risk, 5), d.name))

        return daemons

    def _analyze_with_rabin2(self, filepath: Path) -> Optional[Dict]:
        """Analyze binary with rabin2."""
        if "rabin2" not in self.tools:
            return None

        ret, out, _ = self._run_command(
            [self.tools["rabin2"], "-Ij", str(filepath)], timeout=15
        )

        if ret != 0:
            return None

        try:
            data = json.loads(out)
            return data.get("info", {})
        except (json.JSONDecodeError, KeyError):
            return None

    def _analyze_with_readelf(self, filepath: Path) -> Dict:
        """Analyze binary with readelf - explicit field parsing for reliability.
        
        Uses explicit field parsing to avoid localization/format breakage.
        """
        result = {
            "nx": None, "canary": None, "pie": None,
            "relro": "none", "stripped": None, "rpath": "",
            "has_interp": False, "is_shared_lib": False
        }

        if "readelf" not in self.tools:
            return result

        readelf = self.tools["readelf"]

        # Parse ELF header explicitly for type detection
        ret, header_out, _ = self._run_command([readelf, "-W", "-h", str(filepath)], timeout=10)
        elf_type = None
        if ret == 0:
            # Parse "Type:" field explicitly - format: "Type:                              DYN (Shared object file)"
            type_match = re.search(r'Type:\s+(\w+)', header_out)
            if type_match:
                elf_type = type_match.group(1)  # "EXEC", "DYN", "REL", etc.

        # Get program headers for NX and PIE detection
        ret, out, _ = self._run_command([readelf, "-W", "-l", str(filepath)], timeout=10)
        if ret == 0:
            # NX Detection: Parse GNU_STACK segment flags explicitly
            # Format: "  GNU_STACK      0x000000 0x00000000 0x00000000 0x00000 0x00000 RW  0x10"
            # The flags field (RW, RWE, etc.) is what we need
            if "GNU_STACK" in out:
                for line in out.split("\n"):
                    if "GNU_STACK" in line:
                        # Split by whitespace and look for flags pattern (RW, RWE, R, etc.)
                        parts = line.split()
                        for part in parts:
                            if re.match(r'^R?W?E?$', part) and len(part) <= 3 and len(part) > 0:
                                result["nx"] = 'E' not in part
                                break
                        # Alternative: check for explicit "RWE" or just "RW"
                        if result["nx"] is None:
                            result["nx"] = "RWE" not in line
                        break
            # If no GNU_STACK, result["nx"] stays None (unknown)

            # Check for RELRO
            if "GNU_RELRO" in out:
                result["relro"] = "partial"

            # Check for INTERP segment (indicates executable, not shared lib)
            has_interp = "INTERP" in out
            result["has_interp"] = has_interp
            
            # PIE Detection: Must be ET_DYN AND have INTERP
            if elf_type == "DYN":
                if has_interp:
                    # ET_DYN + INTERP = PIE executable
                    result["pie"] = True
                else:
                    # ET_DYN without INTERP = shared library (not PIE)
                    result["pie"] = False
                    result["is_shared_lib"] = True
            elif elf_type == "EXEC":
                # Traditional non-PIE executable
                result["pie"] = False

        # Get dynamic section - parse explicitly
        ret, out, _ = self._run_command([readelf, "-W", "-d", str(filepath)], timeout=10)
        if ret == 0:
            # Look for BIND_NOW or FLAGS containing BIND_NOW
            if "BIND_NOW" in out or "(NOW)" in out:
                result["relro"] = "full"

            # Parse RPATH/RUNPATH explicitly
            # Format: " 0x000000000000001d (RUNPATH)            Library runpath: [/lib]"
            rpath_match = re.search(r'(?:RPATH|RUNPATH)[^\[]*\[([^\]]+)\]', out)
            if rpath_match:
                result["rpath"] = rpath_match.group(1)
                result["relro"] = "full"

        # Check for stack canary
        ret, out, _ = self._run_command([readelf, "-W", "--dyn-syms", str(filepath)], timeout=10)
        if ret == 0:
            result["canary"] = "__stack_chk_fail" in out

        # Check if stripped
        ret, out, _ = self._run_command([readelf, "-W", "-S", str(filepath)], timeout=10)
        if ret == 0:
            result["stripped"] = ".symtab" not in out

        return result

    def _analyze_with_hardening_check(self, filepath: Path) -> Dict:
        """Analyze binary with hardening-check."""
        result = {"fortify": None, "stack_clash": "unknown", "cfi": "unknown"}

        if "hardening-check" not in self.tools:
            return result

        ret, out, _ = self._run_command(
            [self.tools["hardening-check"], str(filepath)], timeout=15
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
            [self.tools["scanelf"], "-T", str(filepath)], timeout=10
        )

        if ret == 0 and "TEXTREL" in out:
            result["textrel"] = True

        return result

    def analyze_binary(self, filepath: Path, binary_type: BinaryType) -> BinaryAnalysis:
        """Perform complete binary analysis with improved confidence tracking."""
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

        rabin2_data = self._analyze_with_rabin2(filepath)
        readelf_data = self._analyze_with_readelf(filepath)
        hardening_data = self._analyze_with_hardening_check(filepath)
        scanelf_data = self._analyze_with_scanelf(filepath)

        confidence = 100
        tools_used = []
        unknown_fields = []
        tool_disagreements = []

        # NX detection with disagreement tracking
        if rabin2_data and "nx" in rabin2_data:
            analysis.nx = rabin2_data.get("nx", False)
            tools_used.append("rabin2")
            if readelf_data["nx"] is not None and rabin2_data.get("nx") != readelf_data["nx"]:
                confidence -= 15
                tool_disagreements.append("nx")
        elif readelf_data["nx"] is not None:
            analysis.nx = readelf_data["nx"]
            tools_used.append("readelf")
        else:
            unknown_fields.append("nx")
            confidence -= 10

        # Canary detection
        if rabin2_data and "canary" in rabin2_data:
            analysis.canary = rabin2_data.get("canary", False)
            if readelf_data["canary"] is not None and rabin2_data.get("canary") != readelf_data["canary"]:
                confidence -= 15
                tool_disagreements.append("canary")
        elif readelf_data["canary"] is not None:
            analysis.canary = readelf_data["canary"]
        else:
            unknown_fields.append("canary")
            confidence -= 10

        # PIE detection
        if rabin2_data and "pic" in rabin2_data:
            analysis.pie = rabin2_data.get("pic", False)
        elif readelf_data["pie"] is not None:
            analysis.pie = readelf_data["pie"]
        else:
            unknown_fields.append("pie")
            confidence -= 10

        # RELRO detection
        if rabin2_data and rabin2_data.get("relro"):
            analysis.relro = rabin2_data.get("relro", "none")
        else:
            analysis.relro = readelf_data["relro"]

        # Stripped detection
        if rabin2_data and "stripped" in rabin2_data:
            analysis.stripped = rabin2_data.get("stripped", False)
        elif readelf_data["stripped"] is not None:
            analysis.stripped = readelf_data["stripped"]
        else:
            unknown_fields.append("stripped")

        # RPATH
        if rabin2_data:
            rpath = rabin2_data.get("rpath", "NONE")
            analysis.rpath = "" if rpath == "NONE" else rpath
        else:
            analysis.rpath = readelf_data["rpath"]

        # Hardening checks
        analysis.fortify = hardening_data["fortify"]
        if hardening_data["fortify"] is None:
            unknown_fields.append("fortify")
        
        analysis.stack_clash = hardening_data["stack_clash"]
        analysis.cfi = hardening_data["cfi"]
        analysis.textrel = scanelf_data["textrel"]

        # Store tracking info
        analysis.confidence = max(confidence, 50)
        analysis.tools_used = tools_used
        analysis.unknown_fields = unknown_fields
        analysis.tool_disagreements = tool_disagreements

        # NEW: Perform ASLR entropy analysis for PIE binaries
        if analysis.pie is True and binary_type == BinaryType.EXECUTABLE:
            analysis.aslr_analysis = self.aslr_analyzer.analyze(filepath, analysis)

        return analysis

    def analyze_dependencies(self, binaries: List[BinaryAnalysis]) -> List[DependencyRisk]:
        """Analyze dependency chain for insecure libraries.
        
        Note: Missing canary in shared libs is less critical than missing NX,
        since libs typically don't have their own stack frames that need protection.
        Only flag libs with truly critical issues (no NX, or TEXTREL).
        """
        risks = []

        if "readelf" not in self.tools:
            return risks

        # Only flag shared libs with CRITICAL security issues
        # Missing canary alone is not critical for shared libs
        insecure_libs = {}
        for binary in binaries:
            if binary.binary_type == BinaryType.SHARED_LIB:
                issues = []
                # NX is critical for all binaries
                if binary.nx is False:
                    issues.append("No NX (executable stack)")
                # TEXTREL is a security issue for libs
                if binary.textrel:
                    issues.append("TEXTREL (reduced ASLR)")
                # Missing RELRO can be an issue
                if binary.relro == "none":
                    issues.append("No RELRO")
                # Note: We intentionally DON'T flag missing canary for shared libs
                # because it's often acceptable and causes too many false positives
                
                if issues:
                    insecure_libs[binary.filename] = ", ".join(issues)

        if not insecure_libs:
            return risks

        lib_users = {lib: [] for lib in insecure_libs}

        for binary in binaries:
            if binary.binary_type != BinaryType.EXECUTABLE:
                continue

            filepath = self.target / binary.path
            ret, out, _ = self._run_command(
                [self.tools["readelf"], "-W", "-d", str(filepath)], timeout=10
            )

            if ret != 0:
                continue

            for lib in insecure_libs:
                lib_base = lib.split(".so")[0] if ".so" in lib else lib
                if lib in out or lib_base in out:
                    lib_users[lib].append(binary.filename)

        for lib, issue in insecure_libs.items():
            if lib_users[lib]:
                risks.append(DependencyRisk(
                    library=lib,
                    issue=issue,
                    used_by=lib_users[lib][:10]
                ))

        return risks

    def scan_banned_functions_binary(self, binaries: List[BinaryAnalysis]) -> List[BannedFunctionHit]:
        """Scan binaries for dangerous function imports (high severity only)."""
        hits = []

        if "readelf" not in self.tools:
            return hits

        # Only scan for truly dangerous functions in binaries
        patterns = {}
        for func in BANNED_FUNCTIONS:
            patterns[func] = re.compile(rf"\s{re.escape(func)}(?:@|$|\s)", re.MULTILINE)

        for binary in binaries:
            filepath = self.target / binary.path
            ret, out, _ = self._run_command(
                [self.tools["readelf"], "-W", "--dyn-syms", str(filepath)], timeout=10
            )

            if ret != 0:
                continue

            for func, (alternative, severity, compliance) in BANNED_FUNCTIONS.items():
                # Only report HIGH/CRITICAL severity for binary imports
                if severity.value < Severity.MEDIUM.value:
                    continue
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

        # Combine both high and low risk functions for source analysis
        all_functions = {**BANNED_FUNCTIONS, **LOW_RISK_FUNCTIONS}
        
        patterns = {}
        for func in all_functions:
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
                # Skip comment lines
                stripped = original.strip()
                if stripped.startswith("//") or stripped.startswith("/*") or stripped.startswith("*"):
                    continue
                    
                for func, (alternative, severity, compliance) in all_functions.items():
                    # Skip INFO level unless explicitly requested
                    if severity == Severity.INFO:
                        continue
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

    def scan_credentials(self, config_files: List[Path], sources: List[Path]) -> List[CredentialFinding]:
        """Scan for hardcoded credentials."""
        findings = []
        scanned_files = set()
        
        skip_patterns = {
            # Localization/translation files
            "/locales/", "/locale/", "/i18n/", "/translations/", "/lang/",
            "translation.json", "translations.json", "messages.json",
            # Documentation
            "/doc/", "/docs/", "/documentation/", "/examples/", "/samples/",
            "/share/doc/", "/usr/share/doc/", "/man/", "/help/",
            "README", "CHANGELOG", "LICENSE", "COPYING",
            # Test files
            "/test/", "/tests/", "/spec/", "/specs/", "/__tests__/",
            "_test.py", "_test.go", "_test.js", ".test.js", ".spec.js",
            "test_", "mock_", "fake_", "stub_",
            # UI/Config templates
            "UserInterfaceConfig.json", "device-payload",
            "/templates/", "/views/", "/layouts/",
            # Package/dependency files
            "package.json", "package-lock.json", "yarn.lock",
            "Cargo.lock", "go.sum", "requirements.txt", "Gemfile.lock",
            # Build artifacts
            "/node_modules/", "/vendor/", "/dist/", "/build/",
            "/.git/", "/.svn/", "/.hg/",
            # Binary/compiled paths
            ".pyc", ".pyo", ".class", ".o", ".obj",
        }

        all_files = list(config_files) + list(sources)

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

                if line_stripped.startswith("#") or line_stripped.startswith("//"):
                    continue

                for pattern, description in CREDENTIAL_PATTERNS:
                    match = re.search(pattern, line)
                    if match:
                        value = match.group(1) if match.lastindex and match.lastindex >= 1 else match.group(0)
                        
                        if self._is_placeholder(value, line):
                            continue
                        
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

                for weak_pass in WEAK_PASSWORDS:
                    weak_pattern = rf'(?i)(?:password|passwd|pwd|secret|key_passwd)\s*[=:]\s*["\']({re.escape(weak_pass)})["\']'
                    if re.search(weak_pattern, line):
                        if re.search(r'"Password"\s*:\s*"[^"]*"', line):
                            json_match = re.search(r'"Password"\s*:\s*"([^"]*)"', line)
                            if json_match:
                                json_value = json_match.group(1).lower()
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

        return findings[:100]

    def _is_placeholder(self, value: str, line: str = "") -> bool:
        """Check if value is a placeholder, not a real credential."""
        value_lower = value.lower().strip()
        line_lower = line.lower()

        # Check false positive indicators in line context
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
            "default", "sample", "demo", "temp", "tmp", "foo", "bar",
            "baz", "qux", "asdf", "1234", "abcd", "testing", "development",
            "redacted", "hidden", "masked", "removed", "deleted",
            "notset", "not_set", "unset", "blank", "n/a", "na", "tbd",
        }
        if value_lower in placeholders:
            return True

        # Environment variable patterns: $VAR, ${VAR}, %VAR%
        if re.match(r"^[\$%]\{?\w+\}?$", value):
            return True
        if re.match(r"^\$\(\w+\)$", value):
            return True
        if re.match(r"^<[a-zA-Z_]+>$", value):
            return True
        if re.match(r"^\{\{?\w+\}?\}$", value):
            return True
        if re.match(r"^%[a-zA-Z_]+%$", value):
            return True
        # Ruby/ERB: <%= var %>
        if re.match(r"^<%[=]?\s*\w+\s*%>$", value):
            return True
        # Jinja2/Django: {{ var }}
        if re.match(r"^\{\{\s*\w+\s*\}\}$", value):
            return True

        # Repetitive characters (like "aaaa" or "1111")
        if len(set(value)) <= 2 and len(value) >= 3:
            return True

        # All lowercase with underscores only (likely variable name)
        if re.match(r"^[a-z_]+$", value) and len(value) < 20:
            return True

        # Repeated pattern (like "abcabc")
        if len(value) >= 4:
            half = len(value) // 2
            if value[:half] == value[half:2*half]:
                return True

        # Common filename/path patterns
        if re.match(r"^[./\\]", value) or value.endswith((".txt", ".json", ".xml", ".yaml", ".yml")):
            return True

        # URL-like patterns without actual credentials
        if re.match(r"^https?://", value_lower):
            return True

        # Numeric only (not a password)
        if value.isdigit():
            return True

        # Very short values (< 4 chars) are usually not real passwords
        if len(value) < 4:
            return True

        return False

    def scan_certificates(self) -> List[CertificateFinding]:
        """Scan for certificate and key files with content verification."""
        findings = []
        depth = 0

        for root, dirs, files in os.walk(self.target):
            # Limit recursion depth
            depth = root.count(os.sep) - str(self.target).count(os.sep)
            if depth > MAX_RECURSION_DEPTH:
                dirs[:] = []
                continue
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

                # For .key files, verify PEM header before flagging
                if suffix == ".key" or "private" in filename.lower():
                    # Read first 100 bytes to check for PEM header
                    try:
                        with open(filepath, 'rb') as f:
                            header = f.read(100)
                        # Check for actual private key PEM header
                        if b"-----BEGIN" in header and b"PRIVATE KEY-----" in header:
                            findings.append(CertificateFinding(
                                file=rel_path,
                                file_type="Private Key",
                                issue="Private key (PEM) found in firmware",
                                severity=Severity.HIGH
                            ))
                        elif b"-----BEGIN" in header and b"KEY-----" in header:
                            findings.append(CertificateFinding(
                                file=rel_path,
                                file_type="Private Key",
                                issue="Key file (PEM) found in firmware",
                                severity=Severity.MEDIUM
                            ))
                        # If no PEM header, it might just be named .key but not a key
                        # Don't flag it as high severity
                        elif suffix == ".key":
                            findings.append(CertificateFinding(
                                file=rel_path,
                                file_type="Unknown Key Format",
                                issue="File with .key extension (verify manually)",
                                severity=Severity.LOW
                            ))
                    except (OSError, PermissionError):
                        pass

                elif suffix in {".pem", ".crt", ".cer"}:
                    # Verify it's actually a certificate/key
                    try:
                        with open(filepath, 'rb') as f:
                            header = f.read(100)
                        if b"-----BEGIN" not in header:
                            continue  # Not a PEM file, skip
                        
                        if b"PRIVATE KEY-----" in header:
                            findings.append(CertificateFinding(
                                file=rel_path,
                                file_type="Private Key",
                                issue="Private key in PEM file",
                                severity=Severity.HIGH
                            ))
                        else:
                            issue = self._analyze_certificate(filepath)
                            if issue:
                                findings.append(CertificateFinding(
                                    file=rel_path,
                                    file_type="Certificate",
                                    issue=issue,
                                    severity=Severity.MEDIUM
                                ))
                            # Don't flag normal certificates as issues
                    except (OSError, PermissionError):
                        pass

                elif suffix in {".p12", ".pfx"}:
                    findings.append(CertificateFinding(
                        file=rel_path,
                        file_type="PKCS12 Bundle",
                        issue="PKCS12 bundle (may contain private key)",
                        severity=Severity.MEDIUM
                    ))
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

        if "Issuer:" in out and "Subject:" in out:
            issuer_match = re.search(r"Issuer:\s*(.+)", out)
            subject_match = re.search(r"Subject:\s*(.+)", out)
            if issuer_match and subject_match:
                if issuer_match.group(1).strip() == subject_match.group(1).strip():
                    issues.append("self-signed")

        if "RSA Public-Key:" in out:
            key_match = re.search(r"RSA Public-Key:\s*\((\d+) bit\)", out)
            if key_match:
                key_size = int(key_match.group(1))
                if key_size < 2048:
                    issues.append(f"weak key ({key_size}-bit)")

        if "Not After :" in out:
            expiry_match = re.search(r"Not After :\s*(.+)", out)
            if expiry_match:
                try:
                    expiry_str = expiry_match.group(1).strip()
                    year_match = re.search(r"\b(20\d{2})\b", expiry_str)
                    if year_match:
                        expiry_year = int(year_match.group(1))
                        if expiry_year < datetime.now().year:
                            issues.append("expired")
                except (ValueError, AttributeError):
                    pass

        return ", ".join(issues) if issues else None

    def scan_configurations(self, config_files: List[Path]) -> List[ConfigFinding]:
        """Scan configuration files for dangerous patterns."""
        findings = []

        common_configs = [
            "etc/ssh/sshd_config", "etc/sshd_config", "etc/inetd.conf",
            "etc/xinetd.conf", "etc/inittab", "etc/shadow", "etc/passwd",
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

    def generate_aslr_summary(self, binaries: List[BinaryAnalysis]) -> Dict:
        """Generate summary of ASLR analysis across all binaries."""
        summary = {
            "total_pie_binaries": 0,
            "analyzed": 0,
            "by_rating": {
                "excellent": 0, "good": 0, "moderate": 0,
                "weak": 0, "ineffective": 0, "not_applicable": 0
            },
            "common_issues": {},
            "arch_distribution": {},
            "avg_effective_entropy": 0,
            "min_effective_entropy": float('inf'),
            "max_effective_entropy": 0,
            "recommendations": set()
        }
        
        entropy_values = []
        
        for binary in binaries:
            if binary.aslr_analysis:
                analysis = binary.aslr_analysis
                summary["analyzed"] += 1
                
                if analysis.is_pie:
                    summary["total_pie_binaries"] += 1
                
                rating_key = analysis.rating.name.lower()
                if rating_key in summary["by_rating"]:
                    summary["by_rating"][rating_key] += 1
                
                arch = analysis.arch
                summary["arch_distribution"][arch] = summary["arch_distribution"].get(arch, 0) + 1
                
                for issue in analysis.issues:
                    issue_key = issue.split(" - ")[0] if " - " in issue else issue[:50]
                    summary["common_issues"][issue_key] = summary["common_issues"].get(issue_key, 0) + 1
                
                if analysis.effective_entropy > 0:
                    entropy_values.append(analysis.effective_entropy)
                    summary["min_effective_entropy"] = min(summary["min_effective_entropy"], analysis.effective_entropy)
                    summary["max_effective_entropy"] = max(summary["max_effective_entropy"], analysis.effective_entropy)
                
                for rec in analysis.recommendations:
                    summary["recommendations"].add(rec)
        
        if entropy_values:
            summary["avg_effective_entropy"] = sum(entropy_values) / len(entropy_values)
        else:
            summary["min_effective_entropy"] = 0
        
        summary["recommendations"] = list(summary["recommendations"])
        summary["common_issues"] = dict(sorted(summary["common_issues"].items(), key=lambda x: -x[1])[:10])
        
        return summary

    def scan(self) -> ScanResult:
        """Execute complete security scan."""
        start_time = datetime.now()

        print(BANNER)
        print(f"  Target:  {self.target}")
        print(f"  Started: {start_time.strftime('%Y-%m-%d %H:%M:%S')}")
        print("=" * 55)
        print()

        print("[*] Tools detected:")
        for name, cmd in self.tools.items():
            print(f"    + {name}: {cmd}")
        missing = {"rabin2", "hardening-check", "scanelf", "readelf", "file", "strings"} - set(self.tools.keys())
        if missing:
            print(f"    - Missing: {', '.join(missing)}")
        print()

        print("[1/9] Discovering files...")
        binaries_raw, sources, configs = self.find_files()
        print(f"      ELF binaries: {len(binaries_raw)}")
        print(f"      Source files: {len(sources)}")
        print(f"      Config files: {len(configs)}")
        print()

        print("[2/9] Analyzing firmware profile...")
        profile = self.detect_firmware_profile(binaries_raw)
        print(f"      Type: {profile.fw_type}")
        print(f"      Arch: {profile.arch} {profile.bits}-bit {profile.endian}")
        print(f"      Libc: {profile.libc}")
        if profile.kernel != "Unknown":
            print(f"      Kernel: {profile.kernel}")
        if profile.setuid_files:
            print(f"      Setuid: {len(profile.setuid_files)} files")
        print()

        print("[3/9] Analyzing binary hardening + ASLR entropy...")
        analyzed_binaries = []
        
        # Process in batches to prevent memory spikes
        BATCH_SIZE = 50
        total_binaries = len(binaries_raw)
        
        for batch_start in range(0, total_binaries, BATCH_SIZE):
            batch_end = min(batch_start + BATCH_SIZE, total_binaries)
            batch = binaries_raw[batch_start:batch_end]
            
            with ThreadPoolExecutor(max_workers=self.threads) as executor:
                futures = {
                    executor.submit(self.analyze_binary, path, btype): path
                    for path, btype in batch
                }
                for future in as_completed(futures):
                    try:
                        result = future.result()
                        analyzed_binaries.append(result)
                    except Exception as e:
                        self._log(f"Analysis error: {e}")
            
            # Progress indicator for large scans
            if total_binaries > 100:
                print(f"      Progress: {len(analyzed_binaries)}/{total_binaries}")

        secured = sum(1 for b in analyzed_binaries if classify_binary(b) == "SECURED")
        partial = sum(1 for b in analyzed_binaries if classify_binary(b) == "PARTIAL")
        insecure = sum(1 for b in analyzed_binaries if classify_binary(b) == "INSECURE")
        print(f"      Analyzed: {len(analyzed_binaries)}")
        print(f"      Secured: {secured}, Partial: {partial}, Insecure: {insecure}")
        
        aslr_count = sum(1 for b in analyzed_binaries if b.aslr_analysis and b.aslr_analysis.is_pie)
        print(f"      PIE binaries with ASLR analysis: {aslr_count}")
        print()

        print("[4/9] Detecting network services/daemons...")
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

        print("[5/9] Analyzing dependency chain...")
        dep_risks = self.analyze_dependencies(analyzed_binaries)
        if dep_risks:
            for risk in dep_risks[:3]:
                print(f"      {risk.library}: {risk.issue}")
            if len(dep_risks) > 3:
                print(f"      ... and {len(dep_risks) - 3} more")
        else:
            print("      No insecure dependencies")
        print()

        print("[6/9] Scanning for banned functions...")
        banned_binary = self.scan_banned_functions_binary(analyzed_binaries)
        banned_source = self.scan_banned_functions_source(sources)
        banned_all = banned_binary + banned_source
        print(f"      Found: {len(banned_all)} ({len(banned_binary)} binary, {len(banned_source)} source)")
        print()

        print("[7/9] Scanning for credentials and certificates...")
        credentials = self.scan_credentials(configs, sources)
        certificates = self.scan_certificates()
        print(f"      Credentials: {len(credentials)} findings")
        print(f"      Certificates: {len(certificates)} files")
        print()

        print("[8/9] Scanning configuration files...")
        config_issues = self.scan_configurations(configs)
        print(f"      Config issues: {len(config_issues)}")
        print()

        print("[9/9] Generating ASLR entropy summary...")
        aslr_summary = self.generate_aslr_summary(analyzed_binaries)
        if aslr_summary["analyzed"] > 0:
            print(f"      Average effective entropy: {aslr_summary['avg_effective_entropy']:.1f} bits")
            print(f"      Ratings: Excellent={aslr_summary['by_rating']['excellent']}, "
                  f"Good={aslr_summary['by_rating']['good']}, "
                  f"Weak={aslr_summary['by_rating']['weak']}, "
                  f"Ineffective={aslr_summary['by_rating']['ineffective']}")
        print()

        duration = (datetime.now() - start_time).total_seconds()
        
        # Track missing tools
        all_tools = {"rabin2", "hardening-check", "scanelf", "readelf", "file", "strings", "openssl"}
        missing_tools = list(all_tools - set(self.tools.keys()))

        grade, score = calculate_grade(analyzed_binaries)
        print(f"""{'=' * 65}
  SCAN COMPLETE
{'=' * 65}
  Grade: {grade} (Score: {score}/110)
  
  Binaries:     {len(analyzed_binaries)} ({secured} secured, {partial} partial, {insecure} insecure)
  ASLR Analysis:{aslr_summary['analyzed']} PIE binaries analyzed
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
            config_issues=config_issues,
            aslr_summary=aslr_summary,
            missing_tools=missing_tools
        )


# =============================================================================
# CLASSIFICATION AND GRADING
# =============================================================================

def classify_binary(binary: BinaryAnalysis) -> str:
    """Classify binary security level.
    
    Treats shared libraries differently from executables:
    - Shared libs don't need PIE (they're already position-independent)
    - Shared libs have different security requirements
    """
    is_shared_lib = binary.binary_type == BinaryType.SHARED_LIB
    
    # For shared libraries, only NX is critical (canary less important for libs)
    if is_shared_lib:
        if binary.nx is False:
            return "INSECURE"
        # Shared libs with NX and RELRO are reasonably secure
        if binary.nx is True and binary.relro in ("full", "partial"):
            if binary.canary is True and binary.relro == "full":
                return "SECURED"
            return "PARTIAL"
        return "PARTIAL"
    
    # For executables, both NX and canary are critical
    if binary.nx is False or binary.canary is False:
        return "INSECURE"

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
    """Calculate overall security grade.
    
    SCORING MODEL (documented for transparency):
    =============================================
    Per-binary score (max 110 points):
      - NX (No Execute):        15 pts  - Critical: prevents code execution on stack/heap
      - Stack Canary:           15 pts  - Critical: detects stack buffer overflows
      - PIE (Position Indep.):  15 pts  - High: enables full ASLR
      - Full RELRO:             15 pts  - High: protects GOT from overwrites
      - Partial RELRO:           7 pts  - Medium: partial GOT protection
      - Fortify Source:         10 pts  - Medium: compile-time buffer checks
      - Stack Clash Protection: 10 pts  - Medium: prevents stack-heap collision
      - CFI (Control Flow):     10 pts  - Medium: prevents ROP/JOP attacks
      - Stripped:                5 pts  - Low: removes debug info
      - No TEXTREL:              5 pts  - Low: allows better ASLR
      - No RPATH:                5 pts  - Low: prevents library hijacking
    
    Grade thresholds (average score):
      - A: >= 90  (Excellent - most protections enabled)
      - B: >= 80  (Good - strong protection)
      - C: >= 70  (Fair - basic protection)
      - D: >= 60  (Poor - minimal protection)
      - F: <  60  (Fail - inadequate protection)
    """
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

def esc(value) -> str:
    """HTML-escape a value to prevent XSS."""
    if value is None:
        return ""
    return html_module.escape(str(value))


def generate_html_report(result: ScanResult, output_path: Path, slim: bool = False):
    """Generate HTML report with ASLR entropy analysis section.
    
    All user-controlled content is HTML-escaped to prevent XSS attacks.
    
    Args:
        result: Scan result data
        output_path: Path to write HTML file
        slim: If True, generate minimal CSS for smaller file size
    """
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
    profile = result.profile
    aslr_summary = result.aslr_summary

    # Build binary rows - ALL values are HTML-escaped
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
            elif value == "full": return '<td class="ok">full</td>'
            elif value == "partial": return '<td class="wrn">partial</td>'
            elif value == "none": return '<td class="bad">none</td>'
            else: return f"<td>{esc(value)}</td>"

        binary_rows += f'<tr class="{row_class}"><td class="fn">{esc(binary.filename)}</td>'
        binary_rows += cell(binary.nx) + cell(binary.canary) + cell(binary.pie) + cell(binary.relro)
        binary_rows += cell(binary.fortify) + cell(binary.stripped) + cell(binary.stack_clash) + cell(binary.cfi)
        binary_rows += f'<td class="{"bad" if binary.textrel else "ok"}">{"-" if not binary.textrel else "!"}</td>'
        binary_rows += f'<td class="{"bad" if binary.rpath else "ok"}">{esc(binary.rpath[:12]) if binary.rpath else "-"}</td>'
        binary_rows += f"<td>{binary.confidence}%</td></tr>"

    # Build ASLR analysis rows - with HTML escaping
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

    # Build daemon rows - with HTML escaping
    daemon_rows = ""
    for daemon in result.daemons:
        risk_class = "bad" if daemon.risk == "CRITICAL" else "wrn" if daemon.risk in ("HIGH", "UNKNOWN") else ""
        status_class = "ok" if daemon.status == "SECURED" else "bad" if daemon.status == "INSECURE" else "wrn"
        daemon_rows += f'<tr><td class="{risk_class}">{esc(daemon.risk)}</td><td>{esc(daemon.name)}</td>'
        daemon_rows += f'<td>{esc(daemon.binary)}</td><td>{esc(daemon.version)}</td>'
        daemon_rows += f'<td class="loc">{esc(daemon.path)}</td><td class="{status_class}">{esc(daemon.status)}</td>'
        daemon_rows += f'<td class="loc">{esc(daemon.reason)}</td></tr>'

    # Build banned function rows - with HTML escaping
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

    # Build other rows - ALL with HTML escaping
    dep_rows = "".join(f'<tr><td class="bad">{esc(r.library)}</td><td>{esc(r.issue)}</td><td>{esc(", ".join(r.used_by[:5]))}</td></tr>' for r in result.dependency_risks)
    cred_rows = "".join(f'<tr><td class="loc">{esc(c.file)}:{c.line}</td><td class="{"bad" if c.severity.value >= 3 else "wrn"}">{esc(c.pattern)}</td><td class="loc">{esc(c.snippet[:50])}</td></tr>' for c in result.credentials)
    cert_rows = "".join(f'<tr><td class="loc">{esc(c.file)}</td><td>{esc(c.file_type)}</td><td class="{"bad" if c.severity.value >= 3 else "wrn" if c.severity.value >= 2 else ""}">{esc(c.issue)}</td></tr>' for c in result.certificates)
    config_rows = "".join(f'<tr><td class="loc">{esc(i.file)}:{i.line}</td><td class="{"bad" if i.severity.value >= 3 else "wrn"}">{esc(i.issue)}</td><td class="loc">{esc(i.snippet[:50])}</td></tr>' for i in result.config_issues)

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
        aslr_summary_html = f'''<div class="card">
<div class="card-title">ASLR Entropy Summary</div>
<div class="aslr-stats">
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
{f'<div class="aslr-issues"><b>Common Issues:</b><ul>{"".join(f"<li>{k}: {v} binaries</li>" for k, v in list(aslr_summary.get("common_issues", {}).items())[:5])}</ul></div>' if aslr_summary.get("common_issues") else ""}
</div>'''

    # Slim CSS for embedded/minimal reports
    slim_css = """body{font-family:monospace;font-size:12px;padding:10px}
table{border-collapse:collapse;width:100%}th,td{border:1px solid #ccc;padding:4px;text-align:left}
.ok{color:green}.bad{color:red}.wrn{color:orange}
h1{font-size:16px}h2{font-size:14px}"""
    
    # Full CSS for rich reports
    full_css = """*{margin:0;padding:0;box-sizing:border-box}
:root{--bg:#0a0a0a;--cd:#111;--bd:#222;--tx:#e0e0e0;--dm:#666;--ok:#0c6;--bad:#f33;--wrn:#fa0}
body{font-family:'Fira Code',monospace;background:var(--bg);color:var(--tx);font-size:12px;padding:20px;line-height:1.5}
.container{max-width:1600px;margin:0 auto}
h1{font-size:18px;font-weight:600;margin-bottom:5px}
.meta{color:var(--dm);font-size:11px;margin-bottom:20px}
.card{background:var(--cd);border:1px solid var(--bd);padding:15px;margin-bottom:15px}
.card-title{font-size:13px;font-weight:600;margin-bottom:12px;padding-bottom:8px;border-bottom:1px solid var(--bd)}
.grade{font-size:48px;font-weight:600;display:inline-block;margin-right:20px}
.ga{color:var(--ok)}.gb{color:#6c6}.gc{color:var(--wrn)}.gd{color:#f60}.gf{color:var(--bad)}
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
.fn{font-weight:500}.ok{color:var(--ok)}.bad{color:var(--bad)}.wrn{color:var(--wrn)}
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
.search-box button:hover{background:#333}
.aslr-stats{display:grid;grid-template-columns:repeat(4,1fr);gap:10px;margin-bottom:15px}
.aslr-stat{background:var(--bd);padding:12px;text-align:center;border-radius:4px}
.aslr-stat-value{font-size:24px;font-weight:600;color:var(--ok)}
.aslr-stat-label{font-size:10px;color:var(--dm);text-transform:uppercase;margin-top:4px}
.aslr-ratings{display:flex;flex-wrap:wrap;gap:8px;margin-bottom:15px}
.ar-item{padding:6px 12px;font-size:11px;border-radius:3px;background:var(--bd)}
.ar-excellent{border-left:3px solid var(--ok)}.ar-good{border-left:3px solid #6c6}
.ar-moderate{border-left:3px solid var(--wrn)}.ar-weak{border-left:3px solid #f60}.ar-ineff{border-left:3px solid var(--bad)}
.aslr-issues ul{margin-left:20px;margin-top:5px}.aslr-issues li{color:var(--dm);margin-bottom:3px}"""

    css = slim_css if slim else full_css
    font_link = "" if slim else '<link href="https://fonts.googleapis.com/css2?family=Fira+Code:wght@400;600&display=swap" rel="stylesheet">'

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
<div class="container">
<h1>HardenCheck Security Report</h1>
<div class="meta">{esc(result.target)} | {result.scan_time} | {result.duration:.1f}s | v{VERSION}</div>

<div class="card"><div class="card-title">Security Grade</div>
<span class="grade g{grade.lower()}">{grade}</span><span style="color:var(--dm)">Score: {score}/110</span></div>

<div class="card"><div class="card-title">Firmware Profile</div>
<div class="profile">
<div class="profile-row"><span class="profile-label">Type</span><span>{profile.fw_type}</span></div>
<div class="profile-row"><span class="profile-label">Architecture</span><span>{profile.arch} {profile.bits}-bit</span></div>
<div class="profile-row"><span class="profile-label">Endianness</span><span>{profile.endian}</span></div>
<div class="profile-row"><span class="profile-label">Libc</span><span>{profile.libc}</span></div>
<div class="profile-row"><span class="profile-label">Kernel</span><span>{profile.kernel}</span></div>
<div class="profile-row"><span class="profile-label">Total Files</span><span>{profile.total_files}</span></div>
<div class="profile-row"><span class="profile-label">ELF Binaries</span><span>{profile.elf_binaries}</span></div>
<div class="profile-row"><span class="profile-label">Shared Libraries</span><span>{profile.shared_libs}</span></div>
</div></div>

<div class="summary">
<div class="sum-card se"><div class="sum-num se">{len(secured)}</div><div class="sum-label">Secured</div></div>
<div class="sum-card pa"><div class="sum-num pa">{len(partial)}</div><div class="sum-label">Partial</div></div>
<div class="sum-card in"><div class="sum-num in">{len(insecure)}</div><div class="sum-label">Insecure</div></div>
</div>

<div class="card"><div class="card-title">Protection Coverage</div>
{progress_bar("NX", nx_count, total_binaries)}
{progress_bar("Canary", canary_count, total_binaries)}
{progress_bar("PIE", pie_count, total_binaries)}
{progress_bar("Full RELRO", relro_count, total_binaries)}
{progress_bar("Fortify", fortify_count, total_binaries)}
{progress_bar("Stripped", stripped_count, total_binaries)}
{progress_bar("Stack Clash", stack_clash_count, total_binaries)}
{progress_bar("CFI", cfi_count, total_binaries)}
</div>

{aslr_summary_html}

{f'<div class="card"><div class="card-title">ASLR Entropy Analysis ({len(binaries_with_aslr)} PIE binaries)</div><div class="tbl-wrap tbl-scroll"><table><thead><tr><th>Binary</th><th>Arch</th><th>Bits</th><th>PIE</th><th>Max</th><th>Effective</th><th>Rating</th><th>TEXTREL</th><th>Issues</th></tr></thead><tbody>{aslr_rows}</tbody></table></div></div>' if binaries_with_aslr else ''}

{f'<div class="card"><div class="card-title">Daemons &amp; Services ({len(result.daemons)})</div><div class="tbl-wrap tbl-scroll"><table><thead><tr><th>Risk</th><th>Service</th><th>Binary</th><th>Version</th><th>Path</th><th>Status</th><th>Detection</th></tr></thead><tbody>{daemon_rows}</tbody></table></div></div>' if result.daemons else ''}

{f'<div class="card"><div class="card-title">Dependency Risks ({len(result.dependency_risks)})</div><div class="tbl-wrap tbl-scroll"><table><thead><tr><th>Library</th><th>Issue</th><th>Used By</th></tr></thead><tbody>{dep_rows}</tbody></table></div></div>' if result.dependency_risks else ''}

<div class="card"><div class="card-title">Binary Analysis ({len(result.binaries)})</div>
<div class="search-box"><input type="text" id="binSearch" placeholder="Search binaries..." onkeyup="filterTable('binSearch', 'binTable')">
<button onclick="filterByClass('binTable', 'rb')">Insecure</button>
<button onclick="filterByClass('binTable', 'rw')">Partial</button>
<button onclick="filterByClass('binTable', '')">All</button></div>
<div class="tbl-wrap tbl-scroll"><table id="binTable"><thead><tr><th>Binary</th><th>NX</th><th>Canary</th><th>PIE</th><th>RELRO</th><th>Fortify</th><th>Strip</th><th>SClash</th><th>CFI</th><th>TXREL</th><th>RPATH</th><th>Conf</th></tr></thead>
<tbody>{binary_rows}</tbody></table></div></div>

{f'<div class="card"><div class="card-title">Banned Functions ({len(result.banned_functions)})</div><div class="tbl-wrap tbl-scroll"><table><thead><tr><th>Function</th><th>Location</th><th>Alternative</th><th>Severity</th><th>Compliance</th></tr></thead><tbody>{banned_rows}</tbody></table></div></div>' if result.banned_functions else ''}

{f'<div class="card"><div class="card-title">Hardcoded Credentials ({len(result.credentials)})</div><div class="tbl-wrap tbl-scroll"><table><thead><tr><th>Location</th><th>Pattern</th><th>Context</th></tr></thead><tbody>{cred_rows}</tbody></table></div></div>' if result.credentials else ''}

{f'<div class="card"><div class="card-title">Certificates &amp; Keys ({len(result.certificates)})</div><div class="tbl-wrap tbl-scroll"><table><thead><tr><th>File</th><th>Type</th><th>Issue</th></tr></thead><tbody>{cert_rows}</tbody></table></div></div>' if result.certificates else ''}

{f'<div class="card"><div class="card-title">Configuration Issues ({len(result.config_issues)})</div><div class="tbl-wrap tbl-scroll"><table><thead><tr><th>Location</th><th>Issue</th><th>Context</th></tr></thead><tbody>{config_rows}</tbody></table></div></div>' if result.config_issues else ''}

<div class="card"><div class="card-title">Classification</div>
{build_class_section("SECURED", secured, "se")}
{build_class_section("PARTIAL", partial, "pa")}
{build_class_section("INSECURE", insecure, "in")}
</div>

<div class="card"><div class="card-title">Tools Used</div>
<div class="tools">{" ".join(f'<span class="tool">{esc(n)}: {esc(c)}</span>' for n, c in result.tools.items())}</div>
</div>
</div>
<script>
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
        match = true;
        break;
      }}
    }}
    rows[i].style.display = match ? "" : "none";
  }}
}}
function filterByClass(tableId, className) {{
  var table = document.getElementById(tableId);
  var rows = table.getElementsByTagName("tr");
  for (var i = 1; i < rows.length; i++) {{
    if (className === "") {{
      rows[i].style.display = "";
    }} else {{
      rows[i].style.display = rows[i].classList.contains(className) ? "" : "none";
    }}
  }}
}}
</script>
</body></html>'''

    output_path.write_text(html, encoding="utf-8")


# =============================================================================
# JSON REPORT GENERATION
# =============================================================================

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
        ]
    }

    output_path.write_text(json.dumps(data, indent=2), encoding="utf-8")


# =============================================================================
# MAIN ENTRY POINT
# =============================================================================

def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description="HardenCheck v1.0.0 - Firmware Binary Security Analyzer with ASLR Entropy Analysis",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s /path/to/firmware
  %(prog)s /path/to/firmware -o report.html --json
  %(prog)s /path/to/firmware -t 8 -v --slim

Required Tools:
  apt install radare2 devscripts pax-utils elfutils binutils

Scoring Model:
  NX=15, Canary=15, PIE=15, RELRO=15, Fortify=10, 
  StackClash=10, CFI=10, Stripped=5, NoTEXTREL=5, NoRPATH=5
  Grade: A>=90, B>=80, C>=70, D>=60, F<60
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
    parser.add_argument("--slim", action="store_true",
                        help="Generate slim HTML report (no CSS, smaller size)")
    parser.add_argument("--version", action="version",
                        version=f"HardenCheck v{VERSION}")

    args = parser.parse_args()

    target = Path(args.target)
    if not target.exists():
        print(f"Error: Target directory not found: {target}")
        sys.exit(1)
    if not target.is_dir():
        print(f"Error: Target must be a directory: {target}")
        sys.exit(1)

    try:
        scanner = HardenCheck(target, threads=args.threads, verbose=args.verbose)
        result = scanner.scan()

        output_path = Path(args.output)
        generate_html_report(result, output_path, slim=args.slim)
        print(f"[+] HTML Report: {output_path}")

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
