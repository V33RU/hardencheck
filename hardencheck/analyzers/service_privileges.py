import re
from pathlib import Path
from typing import List

from hardencheck.models import BinaryAnalysis, Daemon, ServicePrivilegeInfo
from hardencheck.core.base import BaseAnalyzer
from hardencheck.core.utils import safe_read_file


class ServicePrivilegeAnalyzer(BaseAnalyzer):
    """Analyze service privileges from init scripts and systemd units."""

    def detect_service_privileges(self, binaries: List[BinaryAnalysis],
                                   daemons: List[Daemon]) -> List[ServicePrivilegeInfo]:
        """Analyze service privileges from init scripts and systemd units."""
        privilege_info = []
        daemon_binaries = {d.binary.lower(): d for d in daemons}

        init_paths = [
            "etc/init.d", "etc/rc.d", "etc/rc.local",
            "usr/lib/systemd/system", "etc/systemd/system",
            "lib/systemd/system", "run/systemd/system",
        ]

        for init_dir in init_paths:
            full_dir = self.target / init_dir
            if not full_dir.exists():
                continue

            for filepath in full_dir.rglob("*"):
                if not filepath.is_file():
                    continue

                content = safe_read_file(filepath, max_size=64 * 1024)
                if not content:
                    continue

                service_name = filepath.stem
                if service_name.startswith("."):
                    continue

                binary_path = None
                binary_name = None

                exec_patterns = [
                    r'ExecStart\s*=\s*(.+?)(?:\s|$)',
                    r'^exec\s+(.+?)(?:\s|$)',
                    r'^(\S+)\s+',
                ]

                for pattern in exec_patterns:
                    match = re.search(pattern, content, re.MULTILINE | re.IGNORECASE)
                    if match:
                        cmd = match.group(1).strip().split()[0]
                        cmd = re.sub(r'["\']|^\$|^\$\{|\}', '', cmd)
                        binary_name = Path(cmd).name.lower()
                        binary_path = cmd
                        break

                if not binary_name:
                    continue

                daemon = daemon_binaries.get(binary_name)
                if not daemon:
                    daemon = daemon_binaries.get(service_name.lower())

                user = "root"
                group = "root"
                runs_as_root = True

                user_match = re.search(r'User\s*=\s*(\S+)', content, re.IGNORECASE)
                if user_match:
                    user = user_match.group(1).strip()
                    runs_as_root = (user.lower() == "root")
                else:
                    su_match = re.search(r'su\s+-?\s*(\S+)', content, re.IGNORECASE)
                    if su_match:
                        user = su_match.group(1).strip()
                        runs_as_root = (user.lower() == "root")

                group_match = re.search(r'Group\s*=\s*(\S+)', content, re.IGNORECASE)
                if group_match:
                    group = group_match.group(1).strip()

                capabilities = []
                cap_match = re.search(r'CapabilityBoundingSet\s*=\s*(.+)', content, re.IGNORECASE)
                if cap_match:
                    caps_str = cap_match.group(1).strip()
                    capabilities = [c.strip() for c in re.split(r'[\s,]+', caps_str) if c.strip()]
                else:
                    setcap_match = re.search(r'setcap\s+([^\s]+)', content, re.IGNORECASE)
                    if setcap_match:
                        capabilities = [setcap_match.group(1).strip()]

                chroot_jail = None
                chroot_match = re.search(r'chroot\s+(\S+)', content, re.IGNORECASE)
                if chroot_match:
                    chroot_jail = chroot_match.group(1).strip()

                namespace_isolation = bool(re.search(
                    r'PrivateTmp|PrivateDevices|ProtectSystem|ProtectHome|ReadWritePaths',
                    content, re.IGNORECASE
                ))

                cgroup_restrictions = bool(re.search(
                    r'MemoryLimit|CPUQuota|IOWeight|DevicePolicy',
                    content, re.IGNORECASE
                ))

                risk_level = "LOW"
                issues = []

                if runs_as_root:
                    risk_level = "HIGH"
                    issues.append("Service runs as root user")
                elif user == "root":
                    risk_level = "MEDIUM"

                if not capabilities and runs_as_root:
                    issues.append("No capability restrictions - full root privileges")

                if not chroot_jail and not namespace_isolation:
                    issues.append("No filesystem isolation")

                if not cgroup_restrictions:
                    issues.append("No resource limits configured")

                privilege_info.append(ServicePrivilegeInfo(
                    service_name=service_name,
                    binary_path=binary_path or binary_name,
                    runs_as_root=runs_as_root,
                    user=user,
                    group=group,
                    has_capabilities=len(capabilities) > 0,
                    capabilities=capabilities,
                    chroot_jail=chroot_jail,
                    namespace_isolation=namespace_isolation,
                    cgroup_restrictions=cgroup_restrictions,
                    risk_level=risk_level,
                    issues=issues,
                    recommendation="Run service as non-root user with minimal capabilities" if runs_as_root else "Consider adding namespace isolation"
                ))

        return privilege_info
