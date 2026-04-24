"""Reachability pruning for CVE findings.

Cross-references CVE'd components against binary dependency graph.
A library-level CVE is only "reachable" if at least one binary on the
system NEEDS that library. Components not referenced anywhere in the
dependency tree are marked `not_reachable`, which downstream consumers
(VEX, HTML, SARIF) can use to suppress noise.

Heuristic — not a full symbol-level reachability analysis. For that we'd
need a CVE-to-vulnerable-symbol map (which doesn't exist in any public
feed at scale). The library-NEEDED check catches the biggest class of
false positives: libraries shipped in firmware but never linked.
"""
from typing import List

from hardencheck.models import (
    SBOMResult, SecurityTestFinding,
)
from hardencheck.core.base import BaseAnalyzer


class ReachabilityAnalyzer(BaseAnalyzer):
    """Annotate CVE findings with reachability verdicts."""

    def annotate(self, findings: List[SecurityTestFinding],
                 sbom: SBOMResult) -> List[SecurityTestFinding]:
        if not findings or not sbom:
            return findings

        # Build the set of libraries (by soname / basename) referenced by any
        # binary in the firmware's dependency tree.
        referenced: set = set()
        for _binary, needed in (sbom.dependency_tree or {}).items():
            for lib in needed or []:
                referenced.add(lib.lower())
                # also add name without version suffix
                base = lib.split(".so")[0].lower() if ".so" in lib else lib.lower()
                referenced.add(base)

        # Map component name -> common soname guesses
        for f in findings:
            if f.test_type not in ("live_cve", "cve"):
                continue
            comp = (f.component or "").lower()
            if not comp:
                continue

            candidates = {
                comp,
                f"lib{comp}",
                f"lib{comp}.so",
            }
            if any(any(c in r for c in candidates) for r in referenced):
                f.reachable = "reachable"
                f.reachability_reason = f"{comp} is NEEDED by at least one binary"
                continue

            # Application-type components (not libraries) are inherently reachable
            # if their affected_path points to an ELF in the firmware.
            if f.affected_path and not comp.startswith("lib"):
                f.reachable = "reachable"
                f.reachability_reason = "application component present in firmware"
                continue

            f.reachable = "not_reachable"
            f.reachability_reason = (
                f"{comp} not referenced by any binary's NEEDED list"
            )

        return findings
