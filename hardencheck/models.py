from dataclasses import dataclass, field
from typing import List, Dict, Optional
from enum import Enum


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
class SecurityTestFinding:
    """Security testing finding."""
    test_type: str  # "weak_crypto", "cve", "default_creds", "rop_gadgets"
    component: str  # Component/service name
    version: str = ""
    issue: str = ""
    severity: Severity = Severity.INFO
    details: str = ""
    recommendation: str = ""
    cve_id: str = ""  # For CVE findings
    affected_path: str = ""  # File/binary path


@dataclass
class CryptographicBinary:
    """Security-sensitive cryptographic utility binary."""
    name: str
    path: str
    binary_type: BinaryType
    version: str = "Unknown"
    purpose: str = ""  # "encrypt", "decrypt", "keygen", "hash", "sign", "verify", etc.
    has_network: bool = False
    security_flags: Dict = field(default_factory=dict)  # nx, pie, canary, etc.
    risk_level: str = "MEDIUM"  # Based on purpose and security flags
    issues: List[str] = field(default_factory=list)
    recommendation: str = ""


@dataclass
class FirmwareSigningInfo:
    """Firmware signing and secure boot information."""
    is_signed: bool = False
    signing_method: str = "Unknown"  # "uImage+FIT", "GRUB", "UEFI", "Custom", "None"
    secure_boot_enabled: bool = False
    signature_files: List[str] = field(default_factory=list)
    bootloader_config: Dict[str, str] = field(default_factory=dict)
    issues: List[str] = field(default_factory=list)
    recommendation: str = ""


@dataclass
class ServicePrivilegeInfo:
    """Service privilege and isolation information."""
    service_name: str
    binary_path: str
    runs_as_root: bool = False
    user: str = "root"
    group: str = "root"
    has_capabilities: bool = False
    capabilities: List[str] = field(default_factory=list)
    chroot_jail: Optional[str] = None
    namespace_isolation: bool = False
    cgroup_restrictions: bool = False
    risk_level: str = "MEDIUM"
    issues: List[str] = field(default_factory=list)
    recommendation: str = ""


@dataclass
class KernelHardeningInfo:
    """Kernel security hardening configuration."""
    config_available: bool = False
    config_source: str = ""  # "config.gz", "config", "embedded"
    kaslr_enabled: bool = False
    smep_enabled: bool = False
    smap_enabled: bool = False
    pxn_enabled: bool = False  # ARM Privileged Execute Never
    stack_protector: bool = False
    fortify_source: bool = False
    usercopy_protection: bool = False
    rodata_enforced: bool = False
    dmesg_restricted: bool = False
    hardening_score: int = 0
    issues: List[str] = field(default_factory=list)
    recommendations: List[str] = field(default_factory=list)


@dataclass
class UpdateMechanismInfo:
    """Firmware update mechanism analysis."""
    update_system: str = "Unknown"  # "OTA", "SWUpdate", "RAUC", "Custom", "None"
    update_binary: Optional[str] = None
    update_config: Optional[str] = None
    uses_https: bool = False
    uses_signing: bool = False
    has_rollback_protection: bool = False
    update_server: Optional[str] = None
    issues: List[str] = field(default_factory=list)
    risk_level: str = "MEDIUM"
    recommendation: str = ""


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
    security_tests: List[SecurityTestFinding] = field(default_factory=list)
    crypto_binaries: List[CryptographicBinary] = field(default_factory=list)
    firmware_signing: Optional[FirmwareSigningInfo] = None
    service_privileges: List[ServicePrivilegeInfo] = field(default_factory=list)
    kernel_hardening: Optional[KernelHardeningInfo] = None
    update_mechanism: Optional[UpdateMechanismInfo] = None
    aslr_summary: Dict = field(default_factory=dict)
    missing_tools: List[str] = field(default_factory=list)
    sbom: Optional[SBOMResult] = None
