import gzip
from pathlib import Path

from hardencheck.models import KernelHardeningInfo
from hardencheck.core.base import BaseAnalyzer
from hardencheck.core.utils import safe_read_file


def _read_kernel_config(path: Path, max_size: int = 4 * 1024 * 1024):
    """Read a kernel config file, transparently decompressing .gz."""
    if path.suffix == ".gz" or path.name.endswith(".gz"):
        try:
            size = path.stat().st_size
            if size > max_size:
                return None
            with gzip.open(path, "rb") as f:
                data = f.read(max_size)
            return data.decode("utf-8", errors="replace")
        except (OSError, EOFError, gzip.BadGzipFile):
            return None
    return safe_read_file(path, max_size=max_size)


class KernelHardeningAnalyzer(BaseAnalyzer):
    """Detect kernel security hardening features."""

    def detect_kernel_hardening(self) -> KernelHardeningInfo:
        """Detect kernel security hardening features from config."""
        hardening_info = KernelHardeningInfo()

        config_paths = [
            "proc/config.gz",
            "boot/config", "boot/config-*",
            "usr/src/linux/.config", "lib/modules/*/config",
        ]

        config_content = None
        config_source = None

        for config_pattern in config_paths:
            if "*" in config_pattern:
                for path in self.target.glob(config_pattern):
                    if path.is_file():
                        config_content = _read_kernel_config(path)
                        if config_content:
                            config_source = str(path.relative_to(self.target))
                            break
            else:
                full_path = self.target / config_pattern
                if full_path.exists() and full_path.is_file():
                    config_content = _read_kernel_config(full_path)
                    if config_content:
                        config_source = config_pattern
                        break

        if not config_content:
            hardening_info.config_available = False
            hardening_info.issues.append("Kernel config not found - cannot assess hardening")
            hardening_info.recommendation = "Provide kernel config.gz for hardening analysis"
            return hardening_info

        hardening_info.config_available = True
        hardening_info.config_source = config_source

        config_dict = {}
        for line in config_content.split('\n'):
            line = line.strip()
            if line.startswith('#') or not line:
                continue
            if '=' in line:
                key, value = line.split('=', 1)
                config_dict[key.strip()] = value.strip()

        hardening_info.kaslr_enabled = (
            config_dict.get('CONFIG_RANDOMIZE_BASE') == 'y' or
            config_dict.get('CONFIG_RANDOMIZE_MEMORY') == 'y'
        )

        hardening_info.smep_enabled = config_dict.get('CONFIG_X86_SMEP') == 'y'
        hardening_info.smap_enabled = config_dict.get('CONFIG_X86_SMAP') == 'y'
        hardening_info.pxn_enabled = config_dict.get('CONFIG_ARM_KERNMEM_PERMS') == 'y'

        hardening_info.stack_protector = (
            config_dict.get('CONFIG_STACKPROTECTOR') == 'y' or
            config_dict.get('CONFIG_STACKPROTECTOR_STRONG') == 'y'
        )

        hardening_info.fortify_source = config_dict.get('CONFIG_FORTIFY_SOURCE') == 'y'

        hardening_info.usercopy_protection = (
            config_dict.get('CONFIG_HARDENED_USERCOPY') == 'y' or
            config_dict.get('CONFIG_HARDENED_USERCOPY_FALLBACK') == 'y'
        )

        hardening_info.rodata_enforced = config_dict.get('CONFIG_DEBUG_RODATA') == 'y'

        hardening_info.dmesg_restricted = config_dict.get('CONFIG_SECURITY_DMESG_RESTRICT') == 'y'

        score = 0
        if hardening_info.kaslr_enabled:
            score += 15
        if hardening_info.smep_enabled or hardening_info.pxn_enabled:
            score += 10
        if hardening_info.smap_enabled:
            score += 10
        if hardening_info.stack_protector:
            score += 10
        if hardening_info.fortify_source:
            score += 10
        if hardening_info.usercopy_protection:
            score += 10
        if hardening_info.rodata_enforced:
            score += 10
        if hardening_info.dmesg_restricted:
            score += 5

        hardening_info.hardening_score = score

        if not hardening_info.kaslr_enabled:
            hardening_info.issues.append("KASLR not enabled - memory layout predictable")
            hardening_info.recommendations.append("Enable CONFIG_RANDOMIZE_BASE")

        if not hardening_info.stack_protector:
            hardening_info.issues.append("Stack protector disabled")
            hardening_info.recommendations.append("Enable CONFIG_STACKPROTECTOR_STRONG")

        if not hardening_info.fortify_source:
            hardening_info.issues.append("FORTIFY_SOURCE not enabled")
            hardening_info.recommendations.append("Enable CONFIG_FORTIFY_SOURCE")

        if score < 50:
            hardening_info.recommendations.append("Overall kernel hardening is weak - enable more security features")

        return hardening_info
