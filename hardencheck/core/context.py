import shutil
from pathlib import Path
from typing import Dict, List, Optional


class ScanContext:
    """Shared state for all analyzers."""

    def __init__(self, target, threads=4, verbose=False, extended=False,
                 include_patterns=None, exclude_patterns=None, quiet=False):
        self.target = Path(target).resolve()
        self.threads = min(max(threads, 1), 16)
        self.verbose = verbose
        self.extended = extended
        self.include_patterns = include_patterns or []
        self.exclude_patterns = exclude_patterns or []
        self.quiet = quiet
        self.tools = self._detect_tools()

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
