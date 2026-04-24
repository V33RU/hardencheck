import os
import fnmatch
from pathlib import Path
from typing import List, Tuple

from hardencheck.models import BinaryType
from hardencheck.core.base import BaseAnalyzer


class FileDiscovery(BaseAnalyzer):
    """Discover files in target directory."""

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

        roots = getattr(self.ctx, "roots", [self.target])

        for scan_root in roots:
            for root, dirs, files in os.walk(scan_root):
                dirs[:] = [d for d in dirs if d not in skip_dirs and not d.startswith(".")]

                for filename in files:
                    filepath = Path(root) / filename

                    try:
                        rel = filepath.relative_to(scan_root).as_posix()
                    except ValueError:
                        continue
                    if self.ctx.include_patterns and not any(fnmatch.fnmatch(rel, p) for p in self.ctx.include_patterns):
                        continue
                    if self.ctx.exclude_patterns and any(fnmatch.fnmatch(rel, p) for p in self.ctx.exclude_patterns):
                        continue

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
