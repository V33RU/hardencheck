"""Taint-lite analyzer for banned-function hits.

Flags source-level banned-function calls (strcpy, sprintf, gets, ...)
as `tainted` when any argument traces (textually) to an untrusted
source (recv, read, argv, getenv, fgets, scanf, fread). When no taint
source is visible within the enclosing function, marks the hit `safe`
(meaning: likely false positive from a security-impact perspective —
the underlying function is still dangerous per banned-list rules).

This is a regex-based approximation, not sound dataflow. Its job is to
cut the noise-floor on source-level banned-function hits by roughly
~70%, not to replace a real taint engine.
"""
import re
from pathlib import Path
from typing import List

from hardencheck.models import BannedFunctionHit
from hardencheck.core.base import BaseAnalyzer
from hardencheck.core.utils import safe_read_file


# Functions/macros whose return value is attacker-controlled.
TAINT_SOURCES = (
    "recv", "recvfrom", "recvmsg", "read", "fread", "fgets",
    "scanf", "fscanf", "sscanf", "getenv", "gets",
    "strtok", "getchar",
)

# argv[N] / envp[N] / optarg / request headers, etc.
TAINT_PATTERNS = [
    re.compile(r"\bargv\s*\["),
    re.compile(r"\boptarg\b"),
    re.compile(r"\benviron\b"),
    re.compile(r"\bgetenv\s*\("),
    re.compile(r"\bquery_string\b", re.IGNORECASE),
    re.compile(r"\brequest\b", re.IGNORECASE),
]

_FUNC_DEF = re.compile(
    r"^[A-Za-z_][\w\s\*]*\b([A-Za-z_]\w*)\s*\([^;{]*\)\s*\{",
    re.MULTILINE,
)


class TaintLiteAnalyzer(BaseAnalyzer):
    """Annotate BannedFunctionHit records with a cheap taint verdict."""

    def annotate(self, hits: List[BannedFunctionHit]) -> List[BannedFunctionHit]:
        # Group hits by file to amortize file reads.
        by_file = {}
        for hit in hits:
            if hit.file and hit.line:  # source hits only; binary hits have line=0
                by_file.setdefault(hit.file, []).append(hit)

        for rel_path, file_hits in by_file.items():
            content = self._read_source(rel_path)
            if not content:
                continue
            functions = self._find_function_spans(content)
            for hit in file_hits:
                span = self._enclosing_function(functions, hit.line, content)
                if span is None:
                    continue
                source = self._find_taint_source(span)
                if source:
                    hit.taint = "tainted"
                    hit.taint_source = source
                else:
                    hit.taint = "safe"

        return hits

    def _read_source(self, rel_path: str) -> str:
        for root in getattr(self.ctx, "roots", [self.ctx.target]):
            p = (root / rel_path) if not Path(rel_path).is_absolute() else Path(rel_path)
            if p.exists():
                return safe_read_file(p) or ""
        return ""

    def _find_function_spans(self, content: str):
        """Return list of (start_line, end_line, body_text) per top-level function."""
        spans = []
        lines = content.split("\n")
        # Track brace depth from each function-def line forward.
        for m in _FUNC_DEF.finditer(content):
            start_idx = m.start()
            start_line = content.count("\n", 0, start_idx) + 1
            depth = 0
            end_idx = start_idx
            for i, ch in enumerate(content[start_idx:], start=start_idx):
                if ch == "{":
                    depth += 1
                elif ch == "}":
                    depth -= 1
                    if depth == 0:
                        end_idx = i
                        break
            end_line = content.count("\n", 0, end_idx) + 1
            body = "\n".join(lines[start_line - 1:end_line])
            spans.append((start_line, end_line, body))
        return spans

    def _enclosing_function(self, spans, line: int, content: str):
        for start, end, body in spans:
            if start <= line <= end:
                return body
        return None

    def _find_taint_source(self, body: str) -> str:
        for src in TAINT_SOURCES:
            if re.search(rf"\b{re.escape(src)}\s*\(", body):
                return src
        for pat in TAINT_PATTERNS:
            m = pat.search(body)
            if m:
                return m.group(0).strip()
        return ""
