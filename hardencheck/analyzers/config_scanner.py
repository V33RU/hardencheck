import re
from pathlib import Path
from typing import List

from hardencheck.models import ConfigFinding
from hardencheck.constants.config import CONFIG_PATTERNS
from hardencheck.core.base import BaseAnalyzer
from hardencheck.core.utils import safe_read_file


class ConfigScanner(BaseAnalyzer):
    """Scan configuration files for dangerous patterns."""

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

                if not line_stripped or line_stripped.startswith("#") or line_stripped.startswith(";"):
                    continue

                # Strip inline comments so patterns don't match commented-out values
                line_stripped = re.split(r'\s+#', line_stripped, maxsplit=1)[0].strip()
                if not line_stripped:
                    continue

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
