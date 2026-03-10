# ============================================================================
# Firmware Signing & Secure Boot Patterns
# ============================================================================
SIGNATURE_FILE_PATTERNS = [
    r'\.sig$', r'\.sign$', r'\.asc$', r'\.gpg$',
    r'\.p7s$', r'\.p7m$', r'\.pem\.sig$',
    r'\.dtb\.sig$', r'\.fit\.sig$', r'\.img\.sig$',
]

SECURE_BOOT_MARKERS = {
    "u-boot": ["CONFIG_FIT_SIGNATURE", "CONFIG_FIT_SIGNATURE_MAX_SIZE", "CONFIG_OF_CONTROL"],
    "grub": ["GRUB_CMDLINE_LINUX.*lockdown", "GRUB_CMDLINE_LINUX.*secure"],
    "uefi": ["SecureBoot", "PK", "KEK", "db", "dbx"],
    "uboot_env": ["bootcmd.*verify", "bootcmd.*check_signature"],
}

UPDATE_SYSTEM_PATTERNS = {
    "swupdate": ["swupdate", "swupdate-client", "/etc/swupdate"],
    "rauc": ["rauc", "/etc/rauc"],
    "mender": ["mender", "mender-client", "/etc/mender"],
    "ostree": ["ostree", "/ostree"],
    "custom_ota": ["ota", "firmware-update", "fwupdate"],
}

FIRMWARE_MARKERS = {
    "OpenWrt": ["/etc/openwrt_release", "/etc/openwrt_version"],
    "DD-WRT": ["/etc/dd-wrt_version"],
    "Buildroot": ["/etc/buildroot_version", "/etc/br-version"],
    "Yocto": ["/etc/os-release"],
    "Android": ["/system/build.prop", "/default.prop"],
}
