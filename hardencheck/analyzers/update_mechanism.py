import re
from typing import List

from hardencheck.models import BinaryAnalysis, UpdateMechanismInfo
from hardencheck.constants.firmware import UPDATE_SYSTEM_PATTERNS
from hardencheck.core.base import BaseAnalyzer
from hardencheck.core.utils import safe_read_file


class UpdateMechanismAnalyzer(BaseAnalyzer):
    """Detect firmware update mechanism and assess security."""

    def detect_update_mechanism(self, binaries: List[BinaryAnalysis]) -> UpdateMechanismInfo:
        """Detect firmware update mechanism and assess security."""
        update_info = UpdateMechanismInfo()

        for binary in binaries:
            filename_lower = binary.filename.lower()
            for system, patterns in UPDATE_SYSTEM_PATTERNS.items():
                for pattern in patterns:
                    if pattern.lower() in filename_lower:
                        update_info.update_system = system
                        update_info.update_binary = str(binary.path)
                        break

        update_config_paths = [
            "etc/swupdate/swupdate.conf",
            "etc/rauc/system.conf",
            "etc/mender/mender.conf",
            "etc/firmware-update.conf",
            "etc/ota.conf",
        ]

        for config_path in update_config_paths:
            full_path = self.target / config_path
            if full_path.exists():
                update_info.update_config = config_path
                content = safe_read_file(full_path)
                if content:
                    if re.search(r'https://', content, re.IGNORECASE):
                        update_info.uses_https = True
                    elif re.search(r'http://', content, re.IGNORECASE):
                        update_info.issues.append("Update uses HTTP instead of HTTPS")

                    if re.search(r'sign|signature|cert', content, re.IGNORECASE):
                        update_info.uses_signing = True
                    else:
                        update_info.issues.append("Update mechanism does not use signing")

                    if re.search(r'rollback|version.*check|minimum.*version', content, re.IGNORECASE):
                        update_info.has_rollback_protection = True
                    else:
                        update_info.issues.append("No rollback protection detected")

                    server_match = re.search(r'url\s*[=:]\s*([^\s]+)', content, re.IGNORECASE)
                    if server_match:
                        update_info.update_server = server_match.group(1).strip()

        if not update_info.update_system or update_info.update_system == "Unknown":
            update_info.risk_level = "MEDIUM"
            update_info.issues.append("Update mechanism not clearly identified")
        elif not update_info.uses_https:
            update_info.risk_level = "HIGH"
            update_info.recommendation = "Use HTTPS for firmware updates"
        elif not update_info.uses_signing:
            update_info.risk_level = "HIGH"
            update_info.recommendation = "Implement firmware signing for updates"
        elif not update_info.has_rollback_protection:
            update_info.risk_level = "MEDIUM"
            update_info.recommendation = "Add rollback protection to prevent downgrade attacks"
        else:
            update_info.risk_level = "LOW"
            update_info.recommendation = "Update mechanism appears secure"

        return update_info
