import os
import re
from pathlib import Path
from typing import List

from hardencheck.models import FirmwareSigningInfo
from hardencheck.constants.firmware import SIGNATURE_FILE_PATTERNS, SECURE_BOOT_MARKERS
from hardencheck.core.base import BaseAnalyzer
from hardencheck.core.utils import safe_read_file


class FirmwareSigningAnalyzer(BaseAnalyzer):
    """Detect firmware signing and secure boot configuration."""

    def detect_firmware_signing(self) -> FirmwareSigningInfo:
        """Detect firmware signing and secure boot configuration."""
        signing_info = FirmwareSigningInfo()
        signature_files = []
        bootloader_config = {}

        for root, dirs, files in os.walk(self.target):
            for filename in files:
                filepath = Path(root) / filename
                rel_path = str(filepath.relative_to(self.target))

                for pattern in SIGNATURE_FILE_PATTERNS:
                    if re.search(pattern, filename, re.IGNORECASE):
                        signature_files.append(rel_path)
                        signing_info.is_signed = True
                        break

        bootloader_configs = [
            "boot/u-boot.env", "boot/grub.cfg", "boot/grub/grub.cfg",
            "etc/default/grub", "boot/efi/EFI/BOOT/grub.cfg",
            "boot/loader/entries", "etc/bootloader.d",
        ]

        for config_path in bootloader_configs:
            full_path = self.target / config_path
            if full_path.exists():
                content = safe_read_file(full_path)
                if content:
                    for bootloader, markers in SECURE_BOOT_MARKERS.items():
                        for marker in markers:
                            if re.search(marker, content, re.IGNORECASE):
                                signing_info.secure_boot_enabled = True
                                bootloader_config[bootloader] = marker
                                break

                    if "FIT" in content or "fit_image" in content.lower():
                        signing_info.signing_method = "uImage+FIT"
                        signing_info.is_signed = True
                    elif "grub" in config_path.lower():
                        signing_info.signing_method = "GRUB"
                        if "lockdown" in content.lower() or "secure" in content.lower():
                            signing_info.secure_boot_enabled = True
                    elif "efi" in config_path.lower():
                        signing_info.signing_method = "UEFI"

        uboot_env_paths = [
            "boot/u-boot.env", "boot/uEnv.txt", "etc/u-boot.env",
        ]
        for env_path in uboot_env_paths:
            full_path = self.target / env_path
            if full_path.exists():
                content = safe_read_file(full_path)
                if content and ("verify" in content.lower() or "signature" in content.lower()):
                    signing_info.is_signed = True
                    signing_info.signing_method = "uImage+FIT"
                    bootloader_config["u-boot"] = "signature_verification"

        signing_info.signature_files = signature_files
        signing_info.bootloader_config = bootloader_config

        if not signing_info.is_signed:
            signing_info.issues.append("Firmware images are not signed")
            signing_info.recommendation = "Implement firmware signing to prevent tampering"
        elif not signing_info.secure_boot_enabled:
            signing_info.issues.append("Secure boot is not enabled despite signing")
            signing_info.recommendation = "Enable secure boot to enforce signature verification at boot"
        else:
            signing_info.recommendation = "Firmware signing and secure boot are properly configured"

        return signing_info
