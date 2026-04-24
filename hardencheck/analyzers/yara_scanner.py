"""YARA rule scanning via the `yara` CLI.

HardenCheck is a pure-stdlib project, so this module shells out to the
`yara` binary (install via `apt install yara` or equivalent) rather than
taking a yara-python dependency. If the binary is missing or no rule
directory is provided, scanning is skipped silently.
"""
import json
import shutil
import subprocess
from pathlib import Path
from typing import List, Optional

from hardencheck.models import Severity, YaraMatch
from hardencheck.core.base import BaseAnalyzer


_SEVERITY_MAP = {
    "critical": Severity.CRITICAL,
    "high": Severity.HIGH,
    "medium": Severity.MEDIUM,
    "low": Severity.LOW,
    "info": Severity.INFO,
}


class YaraScanner(BaseAnalyzer):
    """Scan firmware files against a directory of YARA rules."""

    def scan(self, rules_dir: Optional[Path]) -> List[YaraMatch]:
        if not rules_dir:
            return []
        rules_dir = Path(rules_dir)
        if not rules_dir.is_dir():
            if not self.ctx.quiet:
                print(f"      YARA rules directory not found: {rules_dir}")
            return []

        yara_bin = shutil.which("yara")
        if not yara_bin:
            if not self.ctx.quiet:
                print("      YARA CLI not installed (apt install yara) — skipping")
            return []

        rule_files = sorted(
            list(rules_dir.rglob("*.yar")) + list(rules_dir.rglob("*.yara"))
        )
        if not rule_files:
            return []

        matches: List[YaraMatch] = []
        roots = getattr(self.ctx, "roots", [self.ctx.target])

        for rule_file in rule_files:
            for root in roots:
                try:
                    proc = subprocess.run(
                        [yara_bin, "-r", "-w", "-g", "-m", "-s",
                         str(rule_file), str(root)],
                        capture_output=True, text=True, timeout=120,
                    )
                except (subprocess.TimeoutExpired, OSError) as e:
                    if self.ctx.verbose:
                        print(f"      YARA error on {rule_file.name}: {e}")
                    continue
                matches.extend(
                    self._parse_output(proc.stdout, rule_file, root)
                )

        return matches

    def _parse_output(self, stdout: str, rule_file: Path, root: Path) -> List[YaraMatch]:
        """Parse `yara -m -g -s` output.

        Line format (one match):
            rulename [tag1,tag2] [meta=val,meta=val] /path/to/file
        Followed by optional string-hit lines (0xADDR:$name: content).
        We only consume header lines.
        """
        out: List[YaraMatch] = []
        for line in stdout.splitlines():
            line = line.rstrip()
            if not line or line.startswith("0x") or ":" in line[:10]:
                continue
            # Crude header parser — yara output is whitespace separated with
            # the file path always last.
            parts = line.rsplit(" ", 1)
            if len(parts) != 2:
                continue
            head, path = parts
            tokens = head.split()
            if not tokens:
                continue
            rule = tokens[0]
            tags: List[str] = []
            meta = {}
            for tok in tokens[1:]:
                if tok.startswith("[") and tok.endswith("]"):
                    body = tok[1:-1]
                    if "=" in body:
                        for kv in body.split(","):
                            if "=" in kv:
                                k, _, v = kv.partition("=")
                                meta[k.strip()] = v.strip().strip('"')
                    else:
                        tags = [t.strip() for t in body.split(",") if t.strip()]

            sev_name = (meta.get("severity", "") or meta.get("risk", "")).lower()
            severity = _SEVERITY_MAP.get(sev_name, Severity.MEDIUM)

            try:
                rel = str(Path(path).resolve().relative_to(root))
            except ValueError:
                rel = path

            out.append(YaraMatch(
                rule=rule,
                namespace=rule_file.stem,
                file=rel,
                tags=tags,
                meta=meta,
                severity=severity,
            ))
        return out
