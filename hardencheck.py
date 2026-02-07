#!/usr/bin/env python3
"""
HardenCheck - Firmware Binary Security Analyzer
Author: v33ru (Mr-IoT) | github.com/v33ru | IOTSRG
Version: 1.0 - Firmware Binary Security Analyzer
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
import uuid
import html as html_module
from pathlib import Path
from dataclasses import dataclass, field
from typing import List, Dict, Tuple, Optional, Set
from enum import Enum
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime

VERSION = "1.0"

SECURE_ENV = {
    "PATH": "/usr/bin:/bin:/usr/sbin:/sbin",
    "LC_ALL": "C",
    "LANG": "C",
}

MAX_RECURSION_DEPTH = 20

BANNER = r"""
    ╔═╤═╤═╤═╤═╤═╤═╤═╤═╤═╤═╤═╤═╤═╤═╤═╤═╤═╤═╤═╤═╤═╤═╤═╤═╤═╗
    ║●│ │ │ │ │●│ │ │ │ │●│ │ │ │ │●│ │ │ │ │●│ │ │ │●│●║
    ╟─┴─┴─┴─┴─┴─┴─┴─┴─┴─┴─┴─┴─┴─┴─┴─┴─┴─┴─┴─┴─┴─┴─┴─┴─┴─╢
    ║      ██  H A R D E N C H E C K  ██                ║
    ║      ██  Firmware Security Tool ██                ║
    ║      ██  v1.0 | @v33ru | IOTSRG ██                ║
    ╟─┬─┬─┬─┬─┬─┬─┬─┬─┬─┬─┬─┬─┬─┬─┬─┬─┬─┬─┬─┬─┬─┬─┬─┬─┬─╢
    ║●│ │ │ │ │●│ │ │ │ │●│ │ │ │ │●│ │ │ │ │●│ │ │ │●│●║
    ╚═╧═╧═╧═╧═╧═╧═╧═╧═╧═╧═╧═╧═╧═╧═╧═╧═╧═╧═╧═╧═╧═╧═╧═╧═╧═╝
"""



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
    EXCELLENT = "Excellent"
    GOOD = "Good"
    MODERATE = "Moderate"
    WEAK = "Weak"
    INEFFECTIVE = "Ineffective"
    NOT_APPLICABLE = "N/A"


@dataclass
class ASLRAnalysis:
    """ASLR entropy analysis result for a binary."""
    path: str
    filename: str
    is_pie: bool
    arch: str
    bits: int
    
    text_vaddr: int = 0
    data_vaddr: int = 0
    bss_vaddr: int = 0
    entry_point: int = 0
    load_base: int = 0
    
    theoretical_entropy: int = 0
    page_offset_bits: int = 12
    available_entropy: int = 0
    effective_entropy: int = 0
    
    num_load_segments: int = 0
    has_fixed_segments: bool = False
    fixed_segment_addrs: List[int] = field(default_factory=list)
    
    has_textrel: bool = False
    has_rpath: bool = False
    stack_executable: bool = False
    
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
    filesystem: str = "Unknown"
    compression: str = "Unknown"
    bootloader: str = "Unknown"
    init_system: str = "Unknown"
    package_manager: str = "Unknown"
    ssl_library: str = "Unknown"
    crypto_library: str = "Unknown"
    web_server: str = "Unknown"
    ssh_server: str = "Unknown"
    dns_server: str = "Unknown"
    busybox_applets: int = 0
    kernel_modules: int = 0
    total_files: int = 0
    total_size_mb: float = 0.0
    elf_binaries: int = 0
    shared_libs: int = 0
    shell_scripts: int = 0
    config_files: int = 0
    symlinks: int = 0
    setuid_files: List[str] = field(default_factory=list)
    setgid_files: List[str] = field(default_factory=list)
    world_writable: List[str] = field(default_factory=list)
    interesting_files: List[str] = field(default_factory=list)


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
    unknown_fields: List[str] = field(default_factory=list)
    tool_disagreements: List[str] = field(default_factory=list)
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
class SBOMComponent:
    """Software Bill of Materials component."""
    name: str
    version: str
    component_type: str  # library, application, firmware, framework, os
    path: str
    sha256: str = ""
    license_id: str = ""
    supplier: str = ""
    cpe: str = ""
    purl: str = ""
    description: str = ""
    dependencies: List[str] = field(default_factory=list)  # NEEDED libs
    source: str = ""  # detection method: elf, package_manager, strings, filename
    arch: str = ""
    is_third_party: bool = True
    security_flags: Dict = field(default_factory=dict)  # nx, pie, canary etc from BinaryAnalysis


@dataclass
class SBOMResult:
    """Complete SBOM output."""
    serial_number: str
    timestamp: str
    firmware_name: str
    firmware_version: str
    components: List[SBOMComponent]
    dependency_tree: Dict[str, List[str]]  # binary -> [needed_libs]
    total_components: int = 0
    total_libraries: int = 0
    total_applications: int = 0
    components_with_version: int = 0
    components_with_cpe: int = 0
    package_manager_source: str = ""


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
    missing_tools: List[str] = field(default_factory=list)
    sbom: Optional[SBOMResult] = None



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

KNOWN_SERVICES = {
    "telnetd":     "CRITICAL",
    "utelnetd":    "CRITICAL", 
    "rlogind":     "CRITICAL",
    "rshd":        "CRITICAL",
    "rexecd":      "CRITICAL",
    "tftpd":       "CRITICAL",
    "atftpd":      "CRITICAL",
    
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
    "get_", "set_", "fetch_", "read_", "load_", "parse_", "validate_",
    "check_", "verify_", "update_", "create_", "delete_", "handle_",
    "env.", "os.environ", "getenv", "process.env", "environ[",
    "config.", "settings.", "options.", "params.", "args.",
    "def ", "function ", "func ", "->", "return ", "class ",
    "const ", "let ", "var ", "private ", "public ", "protected ",
    "example", "sample", "demo", "test", "mock", "fake", "dummy",
    "todo", "fixme", "xxx", "placeholder", "your_", "my_",
    ": str", ": string", ": String", "String ", "str ", ": &str",
    "<string>", "std::string", "QString", "NSString",
    "/*", "*/", "<!--", "-->", "'''", '"""',
    "label=", "placeholder=", "hint=", "title=", "name=",
    "inputType=", "type=\"password\"", "type='password'",
    "schema", "validate", "required", "optional", "field",
    "{{", "}}", "{%", "%}", "<%", "%>", "${", "#{",
}

WEAK_PASSWORDS = {
    "admin", "password", "123456", "12345678", "root", "toor",
    "default", "guest", "user", "test", "pass", "1234",
    "qwerty", "letmein", "welcome", "monkey", "dragon",
}

CONFIG_PATTERNS = [
    (r'^\s*PermitRootLogin\s+yes\s*$', "sshd_config", "SSH root login enabled", Severity.HIGH),
    (r'^\s*PermitEmptyPasswords\s+yes\s*$', "sshd_config", "SSH empty passwords allowed", Severity.CRITICAL),
    (r'^\s*telnet\s+stream\s+tcp', "inetd.conf", "Telnet service enabled", Severity.CRITICAL),
    (r'::respawn:.*/telnetd', "inittab", "Telnet auto-start enabled", Severity.CRITICAL),
    (r'^root::0:', "shadow", "Root has empty password", Severity.CRITICAL),
]

CONFIG_INFO_PATTERNS = [
    (r'^\s*PasswordAuthentication\s+yes', "sshd_config", "SSH password auth enabled (consider keys)", Severity.INFO),
    (r'^root:\*:', "shadow", "Root account locked", Severity.INFO),
]

CERT_EXTENSIONS = {".pem", ".crt", ".cer", ".der", ".key", ".p12", ".pfx", ".jks"}

# ============================================================================
# SBOM: CPE/PURL mapping for known IoT firmware components
# Format: binary_name -> (vendor, product, cpe_prefix, purl_type)
# CPE 2.3: cpe:2.3:a:vendor:product:version:*:*:*:*:*:*:*
# ============================================================================
CPE_COMPONENT_MAP = {
    # Core system
    "busybox":       ("busybox", "busybox", "a", "generic"),
    "libc.so":       ("gnu", "glibc", "a", "generic"),
    "libc-":         ("gnu", "glibc", "a", "generic"),
    "ld-linux":      ("gnu", "glibc", "a", "generic"),
    "ld-musl":       ("musl-libc", "musl", "a", "generic"),
    "libuClibc":     ("uclibc", "uclibc", "a", "generic"),

    # SSL/TLS
    "libssl":        ("openssl", "openssl", "a", "generic"),
    "libcrypto":     ("openssl", "openssl", "a", "generic"),
    "openssl":       ("openssl", "openssl", "a", "generic"),
    "libwolfssl":    ("wolfssl", "wolfssl", "a", "generic"),
    "libmbedtls":    ("arm", "mbed_tls", "a", "generic"),
    "libmbedcrypto": ("arm", "mbed_tls", "a", "generic"),
    "libgnutls":     ("gnu", "gnutls", "a", "generic"),

    # Crypto
    "libsodium":     ("libsodium_project", "libsodium", "a", "generic"),
    "libgcrypt":     ("gnupg", "libgcrypt", "a", "generic"),
    "libnettle":     ("gnu", "nettle", "a", "generic"),

    # Web servers
    "nginx":         ("f5", "nginx", "a", "generic"),
    "lighttpd":      ("lighttpd", "lighttpd", "a", "generic"),
    "httpd":         ("apache", "http_server", "a", "generic"),
    "apache2":       ("apache", "http_server", "a", "generic"),
    "uhttpd":        ("openwrt", "uhttpd", "a", "generic"),
    "goahead":       ("embedthis", "goahead", "a", "generic"),
    "boa":           ("boa", "boa_web_server", "a", "generic"),
    "thttpd":        ("acme", "thttpd", "a", "generic"),
    "mini_httpd":    ("acme", "mini_httpd", "a", "generic"),
    "mongoose":      ("cesanta", "mongoose", "a", "generic"),

    # SSH
    "dropbear":      ("dropbear_ssh_project", "dropbear_ssh", "a", "generic"),
    "sshd":          ("openbsd", "openssh", "a", "generic"),

    # DNS
    "dnsmasq":       ("thekelleys", "dnsmasq", "a", "generic"),
    "named":         ("isc", "bind", "a", "generic"),
    "unbound":       ("nlnetlabs", "unbound", "a", "generic"),

    # Network services
    "hostapd":       ("w1.fi", "hostapd", "a", "generic"),
    "wpa_supplicant":("w1.fi", "wpa_supplicant", "a", "generic"),
    "openvpn":       ("openvpn", "openvpn", "a", "generic"),
    "pppd":          ("samba", "ppp", "a", "generic"),
    "mosquitto":     ("eclipse", "mosquitto", "a", "generic"),
    "avahi-daemon":  ("avahi", "avahi", "a", "generic"),

    # SMB/NFS
    "smbd":          ("samba", "samba", "a", "generic"),
    "nmbd":          ("samba", "samba", "a", "generic"),
    "nfsd":          ("linux", "nfs-utils", "a", "generic"),

    # FTP
    "vsftpd":        ("vsftpd_project", "vsftpd", "a", "generic"),
    "proftpd":       ("proftpd", "proftpd", "a", "generic"),

    # SNMP
    "snmpd":         ("net-snmp", "net-snmp", "a", "generic"),

    # Misc libraries
    "libz.so":       ("zlib", "zlib", "a", "generic"),
    "libcurl":       ("haxx", "curl", "a", "generic"),
    "curl":          ("haxx", "curl", "a", "generic"),
    "wget":          ("gnu", "wget", "a", "generic"),
    "libjson-c":     ("json-c_project", "json-c", "a", "generic"),
    "libxml2":       ("xmlsoft", "libxml2", "a", "generic"),
    "libsqlite":     ("sqlite", "sqlite", "a", "generic"),
    "sqlite3":       ("sqlite", "sqlite", "a", "generic"),
    "libpcre":       ("pcre", "pcre", "a", "generic"),
    "libexpat":      ("libexpat_project", "libexpat", "a", "generic"),
    "libpng":        ("libpng", "libpng", "a", "generic"),
    "libjpeg":       ("ijg", "libjpeg", "a", "generic"),
    "libdbus":       ("freedesktop", "dbus", "a", "generic"),
    "libubus":       ("openwrt", "ubus", "a", "generic"),
    "libubox":       ("openwrt", "libubox", "a", "generic"),
    "libuci":        ("openwrt", "uci", "a", "generic"),
    "libblkid":      ("kernel", "util-linux", "a", "generic"),
    "libuuid":       ("kernel", "util-linux", "a", "generic"),
    "libpthread":    ("gnu", "glibc", "a", "generic"),
    "librt":         ("gnu", "glibc", "a", "generic"),
    "libdl":         ("gnu", "glibc", "a", "generic"),
    "libm":          ("gnu", "glibc", "a", "generic"),
    "libstdc++":     ("gnu", "gcc", "a", "generic"),
    "libgcc_s":      ("gnu", "gcc", "a", "generic"),
    "libnl":         ("libnl_project", "libnl", "a", "generic"),
    "libiwinfo":     ("openwrt", "iwinfo", "a", "generic"),
    "libnfnetlink":  ("netfilter", "libnetfilter", "a", "generic"),
    "libiptc":       ("netfilter", "iptables", "a", "generic"),
    "iptables":      ("netfilter", "iptables", "a", "generic"),
    "ip6tables":     ("netfilter", "iptables", "a", "generic"),
    "nftables":      ("netfilter", "nftables", "a", "generic"),
    "libreadline":   ("gnu", "readline", "a", "generic"),
    "libncurses":    ("gnu", "ncurses", "a", "generic"),

    # IoT / MQTT / CoAP
    "libcoap":       ("libcoap", "libcoap", "a", "generic"),
    "libmosquitto":  ("eclipse", "mosquitto", "a", "generic"),
    "libpaho":       ("eclipse", "paho_mqtt", "a", "generic"),

    # Containers / runtime
    "containerd":    ("linuxfoundation", "containerd", "a", "generic"),
    "dockerd":       ("docker", "docker", "a", "generic"),
    "runc":          ("opencontainers", "runc", "a", "generic"),

    # Kernel
    "vmlinux":       ("linux", "linux_kernel", "o", "generic"),
    "vmlinuz":       ("linux", "linux_kernel", "o", "generic"),
    "zImage":        ("linux", "linux_kernel", "o", "generic"),
    "uImage":        ("linux", "linux_kernel", "o", "generic"),
    "bzImage":       ("linux", "linux_kernel", "o", "generic"),

    # UPnP / TR-069
    "miniupnpd":     ("miniupnp_project", "miniupnpd", "a", "generic"),
    "cwmpd":         ("cwmp", "cwmpd", "a", "generic"),
}

# License hints from binary/package names
LICENSE_HINTS = {
    "busybox": "GPL-2.0-only",
    "glibc": "LGPL-2.1-or-later",
    "musl": "MIT",
    "uclibc": "LGPL-2.1-or-later",
    "openssl": "Apache-2.0",
    "wolfssl": "GPL-2.0-or-later",
    "mbed_tls": "Apache-2.0",
    "gnutls": "LGPL-2.1-or-later",
    "nginx": "BSD-2-Clause",
    "lighttpd": "BSD-3-Clause",
    "dropbear_ssh": "MIT",
    "openssh": "BSD-2-Clause",
    "dnsmasq": "GPL-2.0-only",
    "curl": "curl",
    "zlib": "Zlib",
    "sqlite": "blessing",
    "libxml2": "MIT",
    "libpng": "Libpng",
    "samba": "GPL-3.0-or-later",
    "mosquitto": "EPL-2.0",
    "openvpn": "GPL-2.0-only",
    "hostapd": "BSD-3-Clause",
    "wpa_supplicant": "BSD-3-Clause",
    "iptables": "GPL-2.0-or-later",
    "linux_kernel": "GPL-2.0-only",
    "util-linux": "GPL-2.0-or-later",
    "gcc": "GPL-3.0-or-later",
    "readline": "GPL-3.0-or-later",
    "ncurses": "MIT",
    "net-snmp": "BSD-3-Clause",
    "dbus": "AFL-2.1 OR GPL-2.0-or-later",
    "json-c": "MIT",
}

FIRMWARE_MARKERS = {
    "OpenWrt": ["/etc/openwrt_release", "/etc/openwrt_version"],
    "DD-WRT": ["/etc/dd-wrt_version"],
    "Buildroot": ["/etc/buildroot_version", "/etc/br-version"],
    "Yocto": ["/etc/os-release"],
    "Android": ["/system/build.prop", "/default.prop"],
}



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
        
        is_pie = elf_info['type'] == self.ET_DYN
        if not is_pie:
            analysis.is_pie = False
            analysis.rating = ASLRRating.NOT_APPLICABLE
            analysis.issues.append("Non-PIE executable (static addresses)")
            analysis.recommendations.append("Recompile with -fPIE -pie flags")
            return analysis
        
        analysis.is_pie = True
        
        phdrs = self._parse_program_headers(data, elf_info)
        load_segments = [ph for ph in phdrs if ph['type'] == self.PT_LOAD]
        analysis.num_load_segments = len(load_segments)
        
        if len(load_segments) >= 2:
            vaddrs = [ph['vaddr'] for ph in load_segments]
            
            deltas = [vaddrs[i+1] - vaddrs[i] for i in range(len(vaddrs)-1)]
            
            has_high_base = vaddrs[0] >= 0x400000
            
            if len(deltas) >= 2:
                delta_variance = max(deltas) - min(deltas)
                has_consistent_deltas = delta_variance < 0x100000
            else:
                has_consistent_deltas = False
            
            has_large_gaps = any(d > 0x10000000 for d in deltas)
            
            if has_high_base and (has_consistent_deltas or has_large_gaps):
                analysis.has_fixed_segments = True
                analysis.fixed_segment_addrs = vaddrs
                analysis.issues.append("Fixed segment layout detected (linker script pattern)")
            elif has_high_base and analysis.bits == 64:
                analysis.issues.append(f"High base address: 0x{vaddrs[0]:x} (verify PIE)")
        
        if load_segments:
            analysis.load_base = load_segments[0]['vaddr']
            analysis.text_vaddr = load_segments[0]['vaddr']
            if len(load_segments) > 1:
                analysis.data_vaddr = load_segments[1]['vaddr']
        
        for ph in phdrs:
            if ph['type'] == self.PT_GNU_STACK:
                if ph['flags'] & 0x1:
                    analysis.stack_executable = True
                    analysis.issues.append("Executable stack detected")
        
        dyn_info = self._check_dynamic_section(filepath)
        analysis.has_textrel = dyn_info['has_textrel'] or binary_analysis.textrel
        analysis.has_rpath = dyn_info['has_rpath']
        
        if analysis.has_textrel:
            analysis.issues.append("TEXTREL present - text relocations reduce ASLR effectiveness")
        
        if analysis.has_rpath:
            analysis.issues.append(f"RPATH/RUNPATH set: {dyn_info['rpath']}")
        
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
        
        analysis.issues.append(f"Entropy is theoretical estimate (kernel default: {mmap_rand} bits)")
        
        effective = analysis.available_entropy
        
        if analysis.has_textrel:
            effective -= 8
            analysis.recommendations.append("Remove TEXTREL by compiling with -fPIC")
        
        if analysis.has_fixed_segments:
            effective -= 4
            analysis.recommendations.append("Avoid fixed segment addresses in PIE")
        
        if analysis.stack_executable:
            effective -= 2
            analysis.recommendations.append("Disable executable stack with -z noexecstack")
        
        if analysis.bits == 32:
            effective = min(effective, 8)
            if effective < 12:
                analysis.issues.append("32-bit architecture has limited ASLR entropy")
                analysis.recommendations.append("Consider 64-bit build for better ASLR")
        
        analysis.effective_entropy = max(0, effective)
        
        analysis.rating = self._calculate_entropy_rating(
            analysis.effective_entropy, 
            analysis.issues
        )
        
        if analysis.rating in (ASLRRating.WEAK, ASLRRating.INEFFECTIVE):
            if analysis.bits == 32:
                analysis.recommendations.append("Migrate to 64-bit for stronger ASLR")
            if binary_analysis.canary is not True:
                analysis.recommendations.append("Enable stack canaries as compensating control")
            if binary_analysis.fortify is not True:
                analysis.recommendations.append("Enable FORTIFY_SOURCE as compensating control")
        
        return analysis



class HardenCheck:
    """Firmware security analyzer."""

    def __init__(self, target: Path, threads: int = 4, verbose: bool = False, extended: bool = False):
        """Initialize scanner.
        
        Args:
            target: Path to firmware directory
            threads: Number of analysis threads
            verbose: Enable verbose output
            extended: Enable extended checks (Stack Clash, CFI)
        """
        self.target = Path(target).resolve()
        self.threads = min(max(threads, 1), 16)
        self.verbose = verbose
        self.extended = extended
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

    def find_files(self) -> Tuple[List[Tuple[Path, BinaryType]], List[Path], List[Path]]:
        """Discover files in target directory."""
        binaries = []
        sources = []
        configs = []
        seen_inodes = set()

        source_extensions = {".c", ".cpp", ".cc", ".cxx", ".h", ".hpp", ".hxx"}
        config_extensions = {".conf", ".cfg", ".ini", ".config", ".xml", ".json", ".yaml", ".yml"}
        config_names = {"passwd", "shadow", "hosts", "resolv.conf", "fstab", "inittab", "profile"}
        skip_dirs = {".git", ".svn", "__pycache__", "node_modules", ".cache"}

        for root, dirs, files in os.walk(self.target):
            dirs[:] = [d for d in dirs if d not in skip_dirs and not d.startswith(".")]

            for filename in files:
                filepath = Path(root) / filename

                try:
                    if filepath.is_symlink():
                        real_path = filepath.resolve()
                        if not real_path.exists():
                            continue
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
            root_lower = root.lower()
            for fs_type, indicators in fs_indicators.items():
                for indicator, magic in indicators:
                    if indicator in root_lower or indicator in [f.lower() for f in files]:
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
        
        strings_to_check = [
            (self.target / "dev" / "mtd0", ["U-Boot", "CFE", "RedBoot"]),
        ]
        
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
        """Detect SSL/TLS library used."""
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
        
        detected = []
        for root, dirs, files in os.walk(self.target):
            for f in files:
                f_lower = f.lower()
                for ssl_name, indicators in ssl_libs.items():
                    if ssl_name in detected:
                        continue
                    for indicator in indicators:
                        if indicator in f_lower:
                            version = ""
                            ver_match = re.search(r'\.so\.(\d+\.\d+\.?\d*)', f)
                            if ver_match:
                                version = f" {ver_match.group(1)}"
                            detected.append(f"{ssl_name}{version}")
                            break
            dirs[:] = dirs[:20]
            if len(detected) >= 2:
                break
        
        return ", ".join(detected) if detected else "Unknown"

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
                    if version != "Unknown":
                        return f"{display_name} {version}"
                    return display_name
        
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

    def _find_interesting_files(self) -> List[str]:
        """Find potentially interesting files for security analysis."""
        interesting = []
        
        interesting_patterns = [
            "*.db", "*.sqlite", "*.sqlite3",
            "*shadow*", "*passwd*",
            "*.pem", "*.key", "*.crt",
            "*secret*", "*credential*", "*token*",
            "*.conf", "*.cfg",
            "*backup*", "*.bak", "*.old",
            "core", "core.*",
        ]
        
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
        
        busybox_path = None
        for binary in binaries:
            if binary.filename.lower() == "busybox":
                busybox_path = binary.path
                break

        executables = [b for b in binaries if b.binary_type == BinaryType.EXECUTABLE]

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
            
            if filename_lower in non_daemons:
                continue
            
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

            if filename_lower in KNOWN_SERVICES:
                is_daemon = True
                risk = KNOWN_SERVICES[filename_lower]
                reason_parts.append("known service")
            
            if not is_daemon:
                filepath = self.target / binary.path
                has_network = self._has_network_symbols(filepath)
                in_init = self._is_referenced_in_init(filename)
                ends_with_d = filename_lower.endswith("d") and len(filename_lower) > 3
                
                if ends_with_d and has_network:
                    is_daemon = True
                    reason_parts.append("daemon name (*d)")
                    reason_parts.append("network symbols")
                    risk = "MEDIUM"
                
                elif ends_with_d and in_init:
                    is_daemon = True
                    reason_parts.append("daemon name (*d)")
                    reason_parts.append("init script")
                    risk = "MEDIUM"
                
                elif has_network and in_init:
                    is_daemon = True
                    reason_parts.append("network symbols")
                    reason_parts.append("init script")
                    risk = "MEDIUM"
                
                elif ends_with_d and len(filename_lower) > 4:
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

        ret, header_out, _ = self._run_command([readelf, "-W", "-h", str(filepath)], timeout=10)
        elf_type = None
        if ret == 0:
            type_match = re.search(r'Type:\s+(\w+)', header_out)
            if type_match:
                elf_type = type_match.group(1)

        ret, out, _ = self._run_command([readelf, "-W", "-l", str(filepath)], timeout=10)
        if ret == 0:
            if "GNU_STACK" in out:
                for line in out.split("\n"):
                    if "GNU_STACK" in line:
                        parts = line.split()
                        for part in parts:
                            if re.match(r'^R?W?E?$', part) and len(part) <= 3 and len(part) > 0:
                                result["nx"] = 'E' not in part
                                break
                        if result["nx"] is None:
                            result["nx"] = "RWE" not in line
                        break

            if "GNU_RELRO" in out:
                result["relro"] = "partial"

            has_interp = "INTERP" in out
            result["has_interp"] = has_interp
            
            if elf_type == "DYN":
                if has_interp:
                    result["pie"] = True
                else:
                    result["pie"] = False
                    result["is_shared_lib"] = True
            elif elf_type == "EXEC":
                result["pie"] = False

        ret, out, _ = self._run_command([readelf, "-W", "-d", str(filepath)], timeout=10)
        if ret == 0:
            if "BIND_NOW" in out or "(NOW)" in out:
                result["relro"] = "full"

            rpath_match = re.search(r'(?:RPATH|RUNPATH)[^\[]*\[([^\]]+)\]', out)
            if rpath_match:
                result["rpath"] = rpath_match.group(1)
                result["relro"] = "full"

        ret, out, _ = self._run_command([readelf, "-W", "--dyn-syms", str(filepath)], timeout=10)
        if ret == 0:
            result["canary"] = "__stack_chk_fail" in out

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

        if rabin2_data and "pic" in rabin2_data:
            analysis.pie = rabin2_data.get("pic", False)
        elif readelf_data["pie"] is not None:
            analysis.pie = readelf_data["pie"]
        else:
            unknown_fields.append("pie")
            confidence -= 10

        if rabin2_data and rabin2_data.get("relro"):
            analysis.relro = rabin2_data.get("relro", "none")
        else:
            analysis.relro = readelf_data["relro"]

        if rabin2_data and "stripped" in rabin2_data:
            analysis.stripped = rabin2_data.get("stripped", False)
        elif readelf_data["stripped"] is not None:
            analysis.stripped = readelf_data["stripped"]
        else:
            unknown_fields.append("stripped")

        if rabin2_data:
            rpath = rabin2_data.get("rpath", "NONE")
            analysis.rpath = "" if rpath == "NONE" else rpath
        else:
            analysis.rpath = readelf_data["rpath"]

        analysis.fortify = hardening_data["fortify"]
        if hardening_data["fortify"] is None:
            unknown_fields.append("fortify")
        
        if self.extended:
            analysis.stack_clash = hardening_data["stack_clash"]
            analysis.cfi = hardening_data["cfi"]
        else:
            analysis.stack_clash = "skipped"
            analysis.cfi = "skipped"
        
        analysis.textrel = scanelf_data["textrel"]

        analysis.confidence = max(confidence, 50)
        analysis.tools_used = tools_used
        analysis.unknown_fields = unknown_fields
        analysis.tool_disagreements = tool_disagreements

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

        insecure_libs = {}
        for binary in binaries:
            if binary.binary_type == BinaryType.SHARED_LIB:
                issues = []
                if binary.nx is False:
                    issues.append("No NX (executable stack)")
                if binary.textrel:
                    issues.append("TEXTREL (reduced ASLR)")
                if binary.relro == "none":
                    issues.append("No RELRO")
                
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

        all_functions = {**BANNED_FUNCTIONS, **LOW_RISK_FUNCTIONS}
        
        patterns = {}
        for func in all_functions:
            patterns[func] = re.compile(rf"(?<![_a-zA-Z0-9]){re.escape(func)}\s*\(")

        for source_path in sources:
            content = safe_read_file(source_path)
            if not content:
                continue

            content_clean = re.sub(r"//[^\n]*", "", content)
            content_clean = re.sub(r"/\*.*?\*/", "", content_clean, flags=re.DOTALL)

            try:
                rel_path = str(source_path.relative_to(self.target))
            except ValueError:
                rel_path = str(source_path)

            lines = content.split("\n")
            lines_clean = content_clean.split("\n")

            for line_num, (original, cleaned) in enumerate(zip(lines, lines_clean), start=1):
                stripped = original.strip()
                if stripped.startswith("//") or stripped.startswith("/*") or stripped.startswith("*"):
                    continue
                    
                for func, (alternative, severity, compliance) in all_functions.items():
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
            "/locales/", "/locale/", "/i18n/", "/translations/", "/lang/",
            "translation.json", "translations.json", "messages.json",
            "/doc/", "/docs/", "/documentation/", "/examples/", "/samples/",
            "/share/doc/", "/usr/share/doc/", "/man/", "/help/",
            "README", "CHANGELOG", "LICENSE", "COPYING",
            "/test/", "/tests/", "/spec/", "/specs/", "/__tests__/",
            "_test.py", "_test.go", "_test.js", ".test.js", ".spec.js",
            "test_", "mock_", "fake_", "stub_",
            "UserInterfaceConfig.json", "device-payload",
            "/templates/", "/views/", "/layouts/",
            "package.json", "package-lock.json", "yarn.lock",
            "Cargo.lock", "go.sum", "requirements.txt", "Gemfile.lock",
            "/node_modules/", "/vendor/", "/dist/", "/build/",
            "/.git/", "/.svn/", "/.hg/",
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

        for indicator in FALSE_POSITIVE_INDICATORS:
            if indicator in line_lower:
                return True

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
        if re.match(r"^<%[=]?\s*\w+\s*%>$", value):
            return True
        if re.match(r"^\{\{\s*\w+\s*\}\}$", value):
            return True

        if len(set(value)) <= 2 and len(value) >= 3:
            return True

        if re.match(r"^[a-z_]+$", value) and len(value) < 20:
            return True

        if len(value) >= 4:
            half = len(value) // 2
            if value[:half] == value[half:2*half]:
                return True

        if re.match(r"^[./\\]", value) or value.endswith((".txt", ".json", ".xml", ".yaml", ".yml")):
            return True

        if re.match(r"^https?://", value_lower):
            return True

        if value.isdigit():
            return True

        if len(value) < 4:
            return True

        return False

    def scan_certificates(self) -> List[CertificateFinding]:
        """Scan for certificate and key files with content verification."""
        findings = []
        depth = 0

        for root, dirs, files in os.walk(self.target):
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

                if suffix == ".key" or "private" in filename.lower():
                    try:
                        with open(filepath, 'rb') as f:
                            header = f.read(100)
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
                    try:
                        with open(filepath, 'rb') as f:
                            header = f.read(100)
                        if b"-----BEGIN" not in header:
                            continue
                        
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

    # ========================================================================
    # SBOM (Software Bill of Materials) Generation
    # ========================================================================

    def _lookup_cpe(self, name: str) -> Tuple[str, str, str, str]:
        """Lookup CPE mapping for a component name.
        
        Returns: (vendor, product, cpe_part, purl_type) or empty strings.
        """
        name_lower = name.lower()
        
        # Direct match
        for key, value in CPE_COMPONENT_MAP.items():
            if key.lower() == name_lower or name_lower.startswith(key.lower()):
                return value
        
        # Partial match on library soname
        base_name = name_lower.split(".so")[0] if ".so" in name_lower else name_lower
        base_name = re.sub(r'-[\d.]+$', '', base_name)  # strip version suffix
        
        for key, value in CPE_COMPONENT_MAP.items():
            if key.lower() == base_name or base_name.startswith(key.lower()):
                return value
        
        return ("", "", "", "")

    def _build_cpe23(self, vendor: str, product: str, version: str, part: str = "a") -> str:
        """Build CPE 2.3 formatted string."""
        ver = version if version and version != "Unknown" else "*"
        ver = re.sub(r'[^a-zA-Z0-9._\-]', '', ver)  # sanitize
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
        
        # Only include installed packages
        packages = [p for p in packages if "installed" in p.get("status", "installed")]
        
        return packages

    def _extract_so_version(self, filename: str) -> str:
        """Extract version from shared library filename (e.g., libssl.so.1.1.1k -> 1.1.1k)."""
        match = re.search(r'\.so\.(.+)$', filename)
        if match:
            return match.group(1)
        return ""

    def generate_sbom(self, binaries: List[BinaryAnalysis], profile: FirmwareProfile) -> SBOMResult:
        """Generate Software Bill of Materials from firmware analysis.
        
        Detection methods (layered, highest confidence first):
        1. Package manager metadata (opkg/dpkg status files)
        2. ELF binary analysis (readelf NEEDED + strings version)
        3. Shared library soname + version suffix
        4. Known component CPE mapping
        
        Args:
            binaries: Analyzed binary list from scan
            profile: Firmware profile metadata
            
        Returns:
            SBOMResult with all discovered components
        """
        components = []
        dependency_tree = {}
        seen_components = set()  # (name, version) dedup
        pkg_manager_source = ""
        
        # ---- Layer 1: Package manager enumeration ----
        pkg_components = {}  # name -> SBOMComponent (for dedup with Layer 2)
        
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
        
        # ---- Layer 2: ELF binary analysis ----
        for binary in binaries:
            filepath = self.target / binary.path
            filename = binary.filename
            filename_lower = filename.lower()
            
            # Skip if already covered by package manager with same name
            if filename_lower in pkg_components:
                # But still extract dependency tree
                needed = self._get_needed_libs(filepath)
                if needed:
                    dependency_tree[binary.path] = needed
                continue
            
            key = (filename_lower, "")
            
            # Get version from multiple sources
            version = ""
            
            # a) soname version suffix
            if ".so" in filename:
                version = self._extract_so_version(filename)
            
            # b) strings-based extraction (if no soname version)
            if not version and binary.binary_type in (BinaryType.EXECUTABLE, BinaryType.SHARED_LIB):
                version = self._extract_version(filepath)
                if version == "Unknown":
                    version = ""
            
            key = (filename_lower.split(".so")[0] if ".so" in filename_lower else filename_lower, version)
            if key in seen_components:
                continue
            seen_components.add(key)
            
            # Build dependency tree
            needed = self._get_needed_libs(filepath)
            if needed:
                dependency_tree[binary.path] = needed
            
            # CPE/PURL lookup
            vendor, product, cpe_part, purl_type = self._lookup_cpe(filename)
            
            cpe = self._build_cpe23(vendor, product, version, cpe_part) if vendor and version else ""
            purl = self._build_purl(
                "generic", vendor or "firmware",
                product or filename_lower.split(".so")[0], version
            ) if version else ""
            
            license_id = LICENSE_HINTS.get(product, "")
            
            # Determine component type
            if binary.binary_type == BinaryType.SHARED_LIB:
                comp_type = "library"
            elif binary.binary_type == BinaryType.KERNEL_MODULE:
                comp_type = "firmware"
            else:
                comp_type = "application"
            
            # Security flags from hardening analysis
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
        
        # ---- Layer 3: Kernel and firmware-level components ----
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
        
        # BusyBox as a top-level component
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
        
        # Sort: applications first, then libraries, then by name
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

        print("[1/10] Discovering files...")
        binaries_raw, sources, configs = self.find_files()
        print(f"      ELF binaries: {len(binaries_raw)}")
        print(f"      Source files: {len(sources)}")
        print(f"      Config files: {len(configs)}")
        print()

        print("[2/10] Analyzing firmware profile...")
        profile = self.detect_firmware_profile(binaries_raw)
        print(f"      Type: {profile.fw_type}")
        arch_str = profile.arch
        if profile.bits != "Unknown":
            arch_str += f" {profile.bits}-bit"
        if profile.endian != "Unknown":
            arch_str += f" {profile.endian}"
        print(f"      Arch: {arch_str}")
        print(f"      Libc: {profile.libc}")
        if profile.kernel != "Unknown":
            print(f"      Kernel: {profile.kernel}")
        if profile.filesystem != "Unknown":
            print(f"      Filesystem: {profile.filesystem}")
        if profile.compression != "Unknown":
            print(f"      Compression: {profile.compression}")
        if profile.bootloader != "Unknown":
            print(f"      Bootloader: {profile.bootloader}")
        if profile.init_system != "Unknown":
            print(f"      Init System: {profile.init_system}")
        if profile.package_manager not in ("Unknown", "None (static firmware)"):
            print(f"      Package Mgr: {profile.package_manager}")
        if profile.ssl_library != "Unknown":
            print(f"      SSL/TLS: {profile.ssl_library}")
        if profile.web_server != "None":
            print(f"      Web Server: {profile.web_server}")
        if profile.ssh_server != "None":
            print(f"      SSH Server: {profile.ssh_server}")
        print(f"      Total Size: {profile.total_size_mb} MB | Files: {profile.total_files} | Symlinks: {profile.symlinks}")
        if profile.busybox_applets > 0:
            print(f"      BusyBox: {profile.busybox_applets} applets")
        if profile.kernel_modules > 0:
            print(f"      Kernel Modules: {profile.kernel_modules}")
        if profile.setuid_files:
            print(f"      Setuid: {len(profile.setuid_files)} files")
        if profile.setgid_files:
            print(f"      Setgid: {len(profile.setgid_files)} files")
        print()

        print("[3/10] Analyzing binary hardening + ASLR entropy...")
        analyzed_binaries = []
        
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

        print("[4/10] Detecting network services/daemons...")
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

        print("[5/10] Analyzing dependency chain...")
        dep_risks = self.analyze_dependencies(analyzed_binaries)
        if dep_risks:
            for risk in dep_risks[:3]:
                print(f"      {risk.library}: {risk.issue}")
            if len(dep_risks) > 3:
                print(f"      ... and {len(dep_risks) - 3} more")
        else:
            print("      No insecure dependencies")
        print()

        print("[6/10] Scanning for banned functions...")
        banned_binary = self.scan_banned_functions_binary(analyzed_binaries)
        banned_source = self.scan_banned_functions_source(sources)
        banned_all = banned_binary + banned_source
        print(f"      Found: {len(banned_all)} ({len(banned_binary)} binary, {len(banned_source)} source)")
        print()

        print("[7/10] Scanning for credentials and certificates...")
        credentials = self.scan_credentials(configs, sources)
        certificates = self.scan_certificates()
        print(f"      Credentials: {len(credentials)} findings")
        print(f"      Certificates: {len(certificates)} files")
        print()

        print("[8/10] Scanning configuration files...")
        config_issues = self.scan_configurations(configs)
        print(f"      Config issues: {len(config_issues)}")
        print()

        print("[9/10] Generating ASLR entropy summary...")
        aslr_summary = self.generate_aslr_summary(analyzed_binaries)
        if aslr_summary["analyzed"] > 0:
            print(f"      Average effective entropy: {aslr_summary['avg_effective_entropy']:.1f} bits")
            print(f"      Ratings: Excellent={aslr_summary['by_rating']['excellent']}, "
                  f"Good={aslr_summary['by_rating']['good']}, "
                  f"Weak={aslr_summary['by_rating']['weak']}, "
                  f"Ineffective={aslr_summary['by_rating']['ineffective']}")
        print()

        print("[10/10] Generating SBOM (Software Bill of Materials)...")
        sbom = self.generate_sbom(analyzed_binaries, profile)
        print(f"      Components: {sbom.total_components} ({sbom.total_applications} apps, {sbom.total_libraries} libs)")
        print(f"      With version: {sbom.components_with_version}/{sbom.total_components}")
        print(f"      With CPE:     {sbom.components_with_cpe}/{sbom.total_components}")
        print(f"      Dependency links: {len(sbom.dependency_tree)}")
        if sbom.package_manager_source:
            print(f"      Package source: {sbom.package_manager_source}")
        print()

        duration = (datetime.now() - start_time).total_seconds()
        
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
  SBOM:         {sbom.total_components} components ({sbom.components_with_cpe} with CPE)
  
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
            missing_tools=missing_tools,
            sbom=sbom
        )



def classify_binary(binary: BinaryAnalysis) -> str:
    """Classify binary security level.
    
    Treats shared libraries differently from executables:
    - Shared libs don't need PIE (they're already position-independent)
    - Shared libs have different security requirements
    """
    is_shared_lib = binary.binary_type == BinaryType.SHARED_LIB
    
    if is_shared_lib:
        if binary.nx is False:
            return "INSECURE"
        if binary.nx is True and binary.relro in ("full", "partial"):
            if binary.canary is True and binary.relro == "full":
                return "SECURED"
            return "PARTIAL"
        return "PARTIAL"
    
    if binary.nx is False or binary.canary is False:
        return "INSECURE"

    extended_ok = True
    if binary.stack_clash not in ("yes", "skipped"):
        extended_ok = False
    if binary.cfi not in ("yes", "skipped"):
        extended_ok = False

    all_protected = (
        binary.nx is True and
        binary.canary is True and
        binary.pie is True and
        binary.relro == "full" and
        binary.fortify is True and
        binary.stripped is True and
        extended_ok and
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



def esc(value) -> str:
    """HTML-escape a value to prevent XSS."""
    if value is None:
        return ""
    return html_module.escape(str(value))


def generate_html_report(result: ScanResult, output_path: Path, slim: bool = False, extended: bool = False):
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
            
            sbom_rows += f'<tr>'
            sbom_rows += f'<td class="fn">{esc(comp.name)}</td>'
            sbom_rows += f'<td class="{ver_class}">{esc(comp.version)}</td>'
            sbom_rows += f'<td class="{type_class}">{esc(comp.component_type)}</td>'
            sbom_rows += f'<td>{esc(comp.supplier) if comp.supplier else "<span class=dm>-</span>"}</td>'
            sbom_rows += f'<td class="loc">{esc(cpe_short)}</td>'
            sbom_rows += f'<td class="loc">{esc(comp.license_id) if comp.license_id else "-"}</td>'
            sbom_rows += f'<td class="loc">{esc(comp.source)}</td>'
            sbom_rows += f'<td>{sec_str if sec_str else "-"}</td>'
            sbom_rows += f'</tr>'
        
        # SBOM dependency tree rows
        for binary_path, needed_libs in sorted(sbom.dependency_tree.items()):
            binary_name = Path(binary_path).name
            for lib in needed_libs:
                # Lookup version for the lib
                lib_ver = ""
                for comp in sbom.components:
                    lib_base = lib.lower().split(".so")[0] if ".so" in lib.lower() else lib.lower()
                    if comp.name.lower() == lib_base or lib.lower().startswith(comp.name.lower()):
                        lib_ver = comp.version
                        break
                ver_class = "ok" if lib_ver and lib_ver != "Unknown" else "dm"
                sbom_dep_rows += f'<tr><td class="fn">{esc(binary_name)}</td>'
                sbom_dep_rows += f'<td>{esc(lib)}</td>'
                sbom_dep_rows += f'<td class="{ver_class}">{esc(lib_ver) if lib_ver else "?"}</td></tr>'
        
        # SBOM summary stats
        sbom_summary_html = f'''<div class="card">
<div class="card-title">Software Bill of Materials (SBOM)</div>
<div class="aslr-stats">
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
</div>
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

    slim_css = """body{font-family:monospace;font-size:12px;padding:10px;background:#111;color:#ccc}
table{border-collapse:collapse;width:100%}th,td{border:1px solid #333;padding:4px}
.ok{color:#3fb950}.bad{color:#f85149}.wrn{color:#d29922}
h1{font-size:16px}h2{font-size:14px}.card{background:#161b22;padding:10px;margin:10px 0;border:1px solid #333}"""
    
    full_css = """*{margin:0;padding:0;box-sizing:border-box}
:root{--bg:#0d1117;--cd:#161b22;--bd:#30363d;--tx:#c9d1d9;--dm:#8b949e;--ok:#3fb950;--bad:#f85149;--wrn:#d29922}
body{font-family:'Fira Code',monospace;background:var(--bg);color:var(--tx);font-size:12px;padding:20px;line-height:1.5}
.container{max-width:1600px;margin:0 auto}
h1{font-size:18px;font-weight:600;margin-bottom:5px}
.meta{color:var(--dm);font-size:11px;margin-bottom:20px}
.card{background:var(--cd);border:1px solid var(--bd);padding:15px;margin-bottom:15px}
.card-title{font-size:13px;font-weight:600;margin-bottom:12px;padding-bottom:8px;border-bottom:1px solid var(--bd)}
.grade{font-size:48px;font-weight:600;display:inline-block;margin-right:20px}
.ga{color:var(--ok)}.gb{color:#58a6ff}.gc{color:var(--wrn)}.gd{color:#f0883e}.gf{color:var(--bad)}
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
{progress_bar("Stack Clash", stack_clash_count, total_binaries) if extended else ''}
{progress_bar("CFI", cfi_count, total_binaries) if extended else ''}
</div>

{aslr_summary_html}

{f'<div class="card"><div class="card-title">ASLR Entropy Analysis ({len(binaries_with_aslr)} PIE binaries)</div><div class="search-box"><input type="text" id="aslrSearch" placeholder="Search binaries..." onkeyup="filterTable(\'aslrSearch\', \'aslrTable\')"><button onclick="filterByRating(\'aslrTable\', \'Weak\')">Weak</button><button onclick="filterByRating(\'aslrTable\', \'Ineffective\')">Ineffective</button><button onclick="filterByRating(\'aslrTable\', \'\')">All</button></div><div class="tbl-wrap tbl-scroll"><table id="aslrTable"><thead><tr><th>Binary</th><th>Arch</th><th>Bits</th><th>PIE</th><th>Max</th><th>Effective</th><th>Rating</th><th>TEXTREL</th><th>Issues</th></tr></thead><tbody>{aslr_rows}</tbody></table></div></div>' if binaries_with_aslr else ''}

{f'<div class="card"><div class="card-title">Daemons &amp; Services ({len(result.daemons)})</div><div class="search-box"><input type="text" id="daemonSearch" placeholder="Search daemons..." onkeyup="filterTable(\'daemonSearch\', \'daemonTable\')"><button onclick="filterByRisk(\'daemonTable\', \'CRITICAL\')">Critical</button><button onclick="filterByRisk(\'daemonTable\', \'HIGH\')">High</button><button onclick="filterByRisk(\'daemonTable\', \'\')">All</button></div><div class="tbl-wrap tbl-scroll"><table id="daemonTable"><thead><tr><th>Risk</th><th>Service</th><th>Binary</th><th>Version</th><th>Path</th><th>Status</th><th>Detection</th></tr></thead><tbody>{daemon_rows}</tbody></table></div></div>' if result.daemons else ''}

{f'<div class="card"><div class="card-title">Dependency Risks ({len(result.dependency_risks)})</div><div class="search-box"><input type="text" id="depSearch" placeholder="Search dependencies..." onkeyup="filterTable(\'depSearch\', \'depTable\')"></div><div class="tbl-wrap tbl-scroll"><table id="depTable"><thead><tr><th>Library</th><th>Issue</th><th>Used By</th></tr></thead><tbody>{dep_rows}</tbody></table></div></div>' if result.dependency_risks else ''}

<div class="card"><div class="card-title">Binary Analysis ({len(result.binaries)})</div>
<div class="search-box"><input type="text" id="binSearch" placeholder="Search binaries..." onkeyup="filterTable('binSearch', 'binTable')">
<button onclick="filterByClass('binTable', 'rb')">Insecure</button>
<button onclick="filterByClass('binTable', 'rw')">Partial</button>
<button onclick="filterByClass('binTable', '')">All</button></div>
<div class="tbl-wrap tbl-scroll"><table id="binTable"><thead><tr><th>Binary</th><th>NX</th><th>Canary</th><th>PIE</th><th>RELRO</th><th>Fortify</th><th>Strip</th>{"<th>SClash</th><th>CFI</th>" if extended else ""}<th>TXREL</th><th>RPATH</th><th>Conf</th></tr></thead>
<tbody>{binary_rows}</tbody></table></div></div>

{f'<div class="card"><div class="card-title">Banned Functions ({len(result.banned_functions)})</div><div class="search-box"><input type="text" id="bannedSearch" placeholder="Search functions..." onkeyup="filterTable(\'bannedSearch\', \'bannedTable\')"><button onclick="filterBySeverity(\'bannedTable\', \'CRITICAL\')">Critical</button><button onclick="filterBySeverity(\'bannedTable\', \'HIGH\')">High</button><button onclick="filterBySeverity(\'bannedTable\', \'\')">All</button></div><div class="tbl-wrap tbl-scroll"><table id="bannedTable"><thead><tr><th>Function</th><th>Location</th><th>Alternative</th><th>Severity</th><th>Compliance</th></tr></thead><tbody>{banned_rows}</tbody></table></div></div>' if result.banned_functions else ''}

{f'<div class="card"><div class="card-title">Hardcoded Credentials ({len(result.credentials)})</div><div class="tbl-wrap tbl-scroll"><table><thead><tr><th>Location</th><th>Pattern</th><th>Context</th></tr></thead><tbody>{cred_rows}</tbody></table></div></div>' if result.credentials else ''}

{f'<div class="card"><div class="card-title">Certificates &amp; Keys ({len(result.certificates)})</div><div class="tbl-wrap tbl-scroll"><table><thead><tr><th>File</th><th>Type</th><th>Issue</th></tr></thead><tbody>{cert_rows}</tbody></table></div></div>' if result.certificates else ''}

{f'<div class="card"><div class="card-title">Configuration Issues ({len(result.config_issues)})</div><div class="tbl-wrap tbl-scroll"><table><thead><tr><th>Location</th><th>Issue</th><th>Context</th></tr></thead><tbody>{config_rows}</tbody></table></div></div>' if result.config_issues else ''}

{sbom_summary_html}

{f'<div class="card"><div class="card-title">SBOM Components ({result.sbom.total_components})</div><div class="search-box"><input type="text" id="sbomSearch" placeholder="Search components..." onkeyup="filterTable(\'sbomSearch\', \'sbomTable\')"><button onclick="filterSbomType(\'sbomTable\', \'library\')">Libraries</button><button onclick="filterSbomType(\'sbomTable\', \'application\')">Apps</button><button onclick="filterSbomType(\'sbomTable\', \'firmware\')">Firmware</button><button onclick="filterSbomType(\'sbomTable\', \'\')">All</button></div><div class="tbl-wrap tbl-scroll"><table id="sbomTable"><thead><tr><th>Component</th><th>Version</th><th>Type</th><th>Supplier</th><th>CPE</th><th>License</th><th>Source</th><th>Security</th></tr></thead><tbody>{sbom_rows}</tbody></table></div></div>' if sbom_rows else ''}

{f'<div class="card"><div class="card-title">Dependency Tree ({len(result.sbom.dependency_tree)} binaries)</div><div class="search-box"><input type="text" id="depTreeSearch" placeholder="Search dependencies..." onkeyup="filterTable(\'depTreeSearch\', \'depTreeTable\')"></div><div class="tbl-wrap tbl-scroll"><table id="depTreeTable"><thead><tr><th>Binary</th><th>NEEDED Library</th><th>Version</th></tr></thead><tbody>{sbom_dep_rows}</tbody></table></div></div>' if sbom_dep_rows else ''}

<div class="card"><div class="card-title">Classification</div>
<div class="search-box"><input type="text" id="classSearch" placeholder="Search binaries..." onkeyup="filterClassification('classSearch')"></div>
<div id="classificationContent">
{build_class_section("SECURED", secured, "se")}
{build_class_section("PARTIAL", partial, "pa")}
{build_class_section("INSECURE", insecure, "in")}
</div>
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
function filterByRisk(tableId, risk) {{
  var table = document.getElementById(tableId);
  var rows = table.getElementsByTagName("tr");
  for (var i = 1; i < rows.length; i++) {{
    var cell = rows[i].getElementsByTagName("td")[0];
    if (risk === "" || (cell && cell.textContent.indexOf(risk) > -1)) {{
      rows[i].style.display = "";
    }} else {{
      rows[i].style.display = "none";
    }}
  }}
}}
function filterBySeverity(tableId, sev) {{
  var table = document.getElementById(tableId);
  var rows = table.getElementsByTagName("tr");
  for (var i = 1; i < rows.length; i++) {{
    var cell = rows[i].getElementsByTagName("td")[3];
    if (sev === "" || (cell && cell.textContent.indexOf(sev) > -1)) {{
      rows[i].style.display = "";
    }} else {{
      rows[i].style.display = "none";
    }}
  }}
}}
function filterByRating(tableId, rating) {{
  var table = document.getElementById(tableId);
  var rows = table.getElementsByTagName("tr");
  for (var i = 1; i < rows.length; i++) {{
    var cell = rows[i].getElementsByTagName("td")[6];
    if (rating === "" || (cell && cell.textContent.indexOf(rating) > -1)) {{
      rows[i].style.display = "";
    }} else {{
      rows[i].style.display = "none";
    }}
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
    if (compType === "" || (cell && cell.textContent.trim() === compType)) {{
      rows[i].style.display = "";
    }} else {{
      rows[i].style.display = "none";
    }}
  }}
}}
</script>
</body></html>'''

    output_path.write_text(html, encoding="utf-8")



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
        
        # Hashes
        if comp.sha256:
            cdx_comp["hashes"] = [{"alg": "SHA-256", "content": comp.sha256}]
        
        # Properties (custom metadata)
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
        # Find the bom-ref for this binary
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
        
        # Map component_type to SPDX primaryPackagePurpose
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
        
        # Relationship: firmware CONTAINS component
        relationships.append({
            "spdxElementId": root_spdx_id,
            "relationshipType": "CONTAINS",
            "relatedSpdxElement": spdx_id
        })
    
    # Add DEPENDS_ON relationships from dependency tree
    comp_spdx_map = {}  # name -> spdx_id
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



def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description="HardenCheck v1.0 - Firmware Binary Security Analyzer with ASLR Entropy Analysis & SBOM",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s /path/to/firmware
  %(prog)s /path/to/firmware -o report.html --json
  %(prog)s /path/to/firmware -t 8 -v --slim
  %(prog)s /path/to/firmware --sbom cyclonedx       # CycloneDX 1.5 SBOM
  %(prog)s /path/to/firmware --sbom spdx             # SPDX 2.3 SBOM
  %(prog)s /path/to/firmware --sbom all --json       # Both SBOMs + JSON report

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
    parser.add_argument("--extended", action="store_true",
                        help="Enable extended checks (Stack Clash, CFI) - requires hardening-check tool")
    parser.add_argument("--sbom", choices=["cyclonedx", "spdx", "all"], default=None,
                        help="Generate SBOM: cyclonedx (CycloneDX 1.5), spdx (SPDX 2.3), or all")
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
        scanner = HardenCheck(target, threads=args.threads, verbose=args.verbose, extended=args.extended)
        result = scanner.scan()

        output_path = Path(args.output)
        generate_html_report(result, output_path, slim=args.slim, extended=args.extended)
        print(f"[+] HTML Report: {output_path}")

        if args.json:
            json_path = output_path.with_suffix(".json")
            generate_json_report(result, json_path)
            print(f"[+] JSON Report: {json_path}")

        # SBOM generation
        if args.sbom and result.sbom:
            sbom_base = output_path.with_suffix("")
            
            if args.sbom in ("cyclonedx", "all"):
                cdx_path = Path(f"{sbom_base}_sbom_cyclonedx.json")
                generate_cyclonedx_sbom(result.sbom, cdx_path)
                print(f"[+] CycloneDX 1.5 SBOM: {cdx_path}")
            
            if args.sbom in ("spdx", "all"):
                spdx_path = Path(f"{sbom_base}_sbom_spdx.json")
                generate_spdx_sbom(result.sbom, spdx_path)
                print(f"[+] SPDX 2.3 SBOM: {spdx_path}")

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
