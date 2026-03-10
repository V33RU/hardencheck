import re
from pathlib import Path
from typing import Optional


def safe_read_file(filepath: Path, max_size: int = 1024 * 1024) -> Optional[str]:
    """Safely read file content with size limit."""
    try:
        if not filepath.is_file():
            return None
        if filepath.stat().st_size > max_size:
            return None
        return filepath.read_text(encoding="utf-8", errors="replace")
    except (OSError, PermissionError):
        return None


def safe_read_binary(filepath: Path, max_size: int = 10 * 1024 * 1024) -> Optional[bytes]:
    """Safely read binary file with size limit."""
    try:
        if not filepath.is_file():
            return None
        if filepath.stat().st_size > max_size:
            return None
        return filepath.read_bytes()
    except (OSError, PermissionError):
        return None


def version_compare(v1: str, v2: str) -> int:
    """Simple version comparison. Returns -1 if v1 < v2, 0 if equal, 1 if v1 > v2."""
    try:
        # Remove non-numeric prefixes/suffixes and split by dots
        def normalize(v):
            v = re.sub(r'[^0-9.]', '', v.split('-')[0].split('+')[0])
            parts = [int(x) for x in v.split('.') if x.isdigit()]
            return parts if parts else [0]

        parts1 = normalize(v1)
        parts2 = normalize(v2)

        # Pad with zeros to same length
        max_len = max(len(parts1), len(parts2))
        parts1.extend([0] * (max_len - len(parts1)))
        parts2.extend([0] * (max_len - len(parts2)))

        for p1, p2 in zip(parts1, parts2):
            if p1 < p2:
                return -1
            elif p1 > p2:
                return 1
        return 0
    except (ValueError, AttributeError):
        return 0  # If comparison fails, assume equal
