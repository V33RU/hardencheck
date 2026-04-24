import shutil
from pathlib import Path
from typing import Dict, List, Optional


class ScanContext:
    """Shared state for all analyzers."""

    def __init__(self, target, threads=4, verbose=False, extended=False,
                 include_patterns=None, exclude_patterns=None, quiet=False,
                 extra_roots=None):
        self.target = Path(target).resolve()
        self.extra_roots = [Path(p).resolve() for p in (extra_roots or [])]
        # All roots, primary first. Used by multi-root aware analyzers.
        self.roots: List[Path] = [self.target] + self.extra_roots
        self.threads = min(max(threads, 1), 16)
        self.verbose = verbose
        self.extended = extended
        self.include_patterns = include_patterns or []
        self.exclude_patterns = exclude_patterns or []
        self.quiet = quiet
        self.tools = self._detect_tools()

    def root_for(self, path: Path) -> Path:
        """Return the root that contains `path` (longest prefix wins)."""
        p = Path(path).resolve()
        best = self.target
        best_len = -1
        for r in self.roots:
            try:
                p.relative_to(r)
                if len(str(r)) > best_len:
                    best = r
                    best_len = len(str(r))
            except ValueError:
                continue
        return best

    def _detect_tools(self) -> Dict[str, str]:
        """Detect available analysis tools."""
        tools = {}

        for cmd in ["radare2.rabin2", "rabin2"]:
            path = shutil.which(cmd)
            if path:
                # Store the absolute path so we don't depend on PATH later,
                # which is intentionally restricted in SECURE_ENV.
                tools["rabin2"] = path
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
                tools[name] = path

        readelf_path = shutil.which("eu-readelf") or shutil.which("readelf")
        if readelf_path:
            tools["readelf"] = readelf_path

        return tools
