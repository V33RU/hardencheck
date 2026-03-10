import os
from pathlib import Path
from typing import List

from hardencheck.models import BinaryType, BinaryAnalysis, Daemon
from hardencheck.constants.services import KNOWN_SERVICES
from hardencheck.core.base import BaseAnalyzer


class DaemonDetector(BaseAnalyzer):
    """Detect network services and daemons."""

    def detect_daemons(self, binaries: List[BinaryAnalysis]) -> List[Daemon]:
        """Detect network services and daemons."""
        from hardencheck.reports.grading import classify_binary

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
