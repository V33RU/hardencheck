import re
from pathlib import Path
from typing import List

from hardencheck.models import Severity, BinaryAnalysis, BannedFunctionHit
from hardencheck.constants.binary import BANNED_FUNCTIONS, LOW_RISK_FUNCTIONS
from hardencheck.core.base import BaseAnalyzer
from hardencheck.core.utils import safe_read_file


class BannedFunctionScanner(BaseAnalyzer):
    """Scan for dangerous function usage in binaries and source."""

    def scan_banned_functions_binary(self, binaries: List[BinaryAnalysis]) -> List[BannedFunctionHit]:
        """Scan binaries for dangerous function imports (high severity only)."""
        hits = []

        if "readelf" not in self.tools:
            return hits

        patterns = {}
        for func in BANNED_FUNCTIONS:
            patterns[func] = re.compile(rf"\s{re.escape(func)}(?:@|$|\s)", re.MULTILINE)

        for binary in binaries:
            filepath = self.target / binary.path
            ret, out, _ = self._run_command(
                [self.tools["readelf"], "-W", "--dyn-syms", str(filepath)], timeout=10
            )

            if ret != 0:
                continue

            for func, (alternative, severity, compliance) in BANNED_FUNCTIONS.items():
                if severity.value < Severity.MEDIUM.value:
                    continue
                if patterns[func].search(out):
                    hits.append(BannedFunctionHit(
                        function=func,
                        file=binary.path,
                        line=0,
                        snippet="(imported symbol)",
                        severity=severity,
                        alternative=alternative,
                        compliance=compliance
                    ))

        return hits

    def scan_banned_functions_source(self, sources: List[Path]) -> List[BannedFunctionHit]:
        """Scan source files for banned function calls."""
        hits = []

        all_functions = {**BANNED_FUNCTIONS, **LOW_RISK_FUNCTIONS}

        patterns = {}
        for func in all_functions:
            patterns[func] = re.compile(rf"(?<![_a-zA-Z0-9]){re.escape(func)}\s*\(")

        for source_path in sources:
            content = safe_read_file(source_path)
            if not content:
                continue

            content_clean = re.sub(r"//[^\n]*", "", content)
            content_clean = re.sub(r"/\*.*?\*/", "", content_clean, flags=re.DOTALL)

            try:
                rel_path = str(source_path.relative_to(self.target))
            except ValueError:
                rel_path = str(source_path)

            lines = content.split("\n")
            lines_clean = content_clean.split("\n")

            for line_num, (original, cleaned) in enumerate(zip(lines, lines_clean), start=1):
                stripped = original.strip()
                if stripped.startswith("//") or stripped.startswith("/*") or stripped.startswith("*"):
                    continue

                for func, (alternative, severity, compliance) in all_functions.items():
                    if severity == Severity.INFO:
                        continue
                    if patterns[func].search(cleaned):
                        hits.append(BannedFunctionHit(
                            function=func,
                            file=rel_path,
                            line=line_num,
                            snippet=original.strip()[:60],
                            severity=severity,
                            alternative=alternative,
                            compliance=compliance
                        ))

        return hits
