import json
import re
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from hardencheck.models import BinaryType, BinaryAnalysis, DependencyRisk
from hardencheck.core.base import BaseAnalyzer
from hardencheck.analyzers.aslr_entropy import ASLREntropyAnalyzer


class BinaryAnalyzer(BaseAnalyzer):
    """Analyze binary hardening with multi-tool confidence tracking."""

    def __init__(self, ctx):
        super().__init__(ctx)
        self.aslr_analyzer = ASLREntropyAnalyzer(self.tools)

    def _analyze_with_rabin2(self, filepath: Path) -> Optional[Dict]:
        """Analyze binary with rabin2."""
        if "rabin2" not in self.tools:
            return None

        ret, out, _ = self._run_command(
            [self.tools["rabin2"], "-Ij", str(filepath)], timeout=15
        )

        if ret != 0:
            return None

        try:
            data = json.loads(out)
            return data.get("info", {})
        except (json.JSONDecodeError, KeyError):
            return None

    def _analyze_with_readelf(self, filepath: Path) -> Dict:
        """Analyze binary with readelf - explicit field parsing for reliability."""
        result = {
            "nx": None, "canary": None, "pie": None,
            "relro": "none", "stripped": None, "rpath": "",
            "has_interp": False, "is_shared_lib": False
        }

        if "readelf" not in self.tools:
            return result

        readelf = self.tools["readelf"]

        ret, header_out, _ = self._run_command([readelf, "-W", "-h", str(filepath)], timeout=10)
        elf_type = None
        if ret == 0:
            type_match = re.search(r'Type:\s+(\w+)', header_out)
            if type_match:
                elf_type = type_match.group(1)

        ret, out, _ = self._run_command([readelf, "-W", "-l", str(filepath)], timeout=10)
        if ret == 0:
            if "GNU_STACK" in out:
                for line in out.split("\n"):
                    if "GNU_STACK" in line:
                        parts = line.split()
                        for part in parts:
                            if re.match(r'^R?W?E?$', part) and len(part) <= 3 and len(part) > 0:
                                result["nx"] = 'E' not in part
                                break
                        if result["nx"] is None:
                            result["nx"] = "RWE" not in line
                        break

            if "GNU_RELRO" in out:
                result["relro"] = "partial"

            has_interp = "INTERP" in out
            result["has_interp"] = has_interp

            if elf_type == "DYN":
                if has_interp:
                    result["pie"] = True
                else:
                    result["pie"] = False
                    result["is_shared_lib"] = True
            elif elf_type == "EXEC":
                result["pie"] = False

        ret, out, _ = self._run_command([readelf, "-W", "-d", str(filepath)], timeout=10)
        if ret == 0:
            if "BIND_NOW" in out or "(NOW)" in out:
                result["relro"] = "full"

            rpath_match = re.search(r'(?:RPATH|RUNPATH)[^\[]*\[([^\]]+)\]', out)
            if rpath_match:
                result["rpath"] = rpath_match.group(1)

        ret, out, _ = self._run_command([readelf, "-W", "--dyn-syms", str(filepath)], timeout=10)
        if ret == 0:
            result["canary"] = "__stack_chk_fail" in out

        ret, out, _ = self._run_command([readelf, "-W", "-S", str(filepath)], timeout=10)
        if ret == 0:
            result["stripped"] = ".symtab" not in out

        return result

    def _analyze_with_hardening_check(self, filepath: Path) -> Dict:
        """Analyze binary with hardening-check."""
        result = {"fortify": None, "stack_clash": "unknown", "cfi": "unknown"}

        if "hardening-check" not in self.tools:
            return result

        ret, out, _ = self._run_command(
            [self.tools["hardening-check"], str(filepath)], timeout=15
        )

        if ret not in (0, 1):
            return result

        out_lower = out.lower()

        if "fortify source functions: yes" in out_lower:
            result["fortify"] = True
        elif "fortify source functions: no" in out_lower:
            result["fortify"] = False

        if "stack clash protection: yes" in out_lower:
            result["stack_clash"] = "yes"
        elif "stack clash protection: no" in out_lower:
            result["stack_clash"] = "no"

        if "control flow integrity: yes" in out_lower:
            result["cfi"] = "yes"
        elif "control flow integrity: no" in out_lower:
            result["cfi"] = "no"

        return result

    def _analyze_with_scanelf(self, filepath: Path) -> Dict:
        """Analyze binary with scanelf."""
        result = {"textrel": False}

        if "scanelf" not in self.tools:
            return result

        ret, out, _ = self._run_command(
            [self.tools["scanelf"], "-T", str(filepath)], timeout=10
        )

        if ret == 0 and "TEXTREL" in out:
            result["textrel"] = True

        return result

    def analyze_binary(self, filepath: Path, binary_type: BinaryType) -> BinaryAnalysis:
        """Perform complete binary analysis with improved confidence tracking."""
        try:
            rel_path = str(filepath.relative_to(self.target))
        except ValueError:
            rel_path = str(filepath)

        analysis = BinaryAnalysis(
            path=rel_path,
            filename=filepath.name,
            size=filepath.stat().st_size,
            sha256=self._compute_sha256(filepath),
            binary_type=binary_type
        )

        rabin2_data = self._analyze_with_rabin2(filepath)
        readelf_data = self._analyze_with_readelf(filepath)
        hardening_data = self._analyze_with_hardening_check(filepath)
        scanelf_data = self._analyze_with_scanelf(filepath)

        confidence = 100
        tools_used = []
        unknown_fields = []
        tool_disagreements = []

        if rabin2_data and "nx" in rabin2_data:
            analysis.nx = rabin2_data.get("nx", False)
            tools_used.append("rabin2")
            if readelf_data["nx"] is not None and rabin2_data.get("nx") != readelf_data["nx"]:
                confidence -= 15
                tool_disagreements.append("nx")
        elif readelf_data["nx"] is not None:
            analysis.nx = readelf_data["nx"]
            tools_used.append("readelf")
        else:
            unknown_fields.append("nx")
            confidence -= 10

        if rabin2_data and "canary" in rabin2_data:
            analysis.canary = rabin2_data.get("canary", False)
            if readelf_data["canary"] is not None and rabin2_data.get("canary") != readelf_data["canary"]:
                confidence -= 15
                tool_disagreements.append("canary")
        elif readelf_data["canary"] is not None:
            analysis.canary = readelf_data["canary"]
        else:
            unknown_fields.append("canary")
            confidence -= 10

        if rabin2_data and "pic" in rabin2_data:
            analysis.pie = rabin2_data.get("pic", False)
        elif readelf_data["pie"] is not None:
            analysis.pie = readelf_data["pie"]
        else:
            unknown_fields.append("pie")
            confidence -= 10

        if rabin2_data and rabin2_data.get("relro"):
            analysis.relro = rabin2_data.get("relro", "none")
        else:
            analysis.relro = readelf_data["relro"]

        if rabin2_data and "stripped" in rabin2_data:
            analysis.stripped = rabin2_data.get("stripped", False)
        elif readelf_data["stripped"] is not None:
            analysis.stripped = readelf_data["stripped"]
        else:
            unknown_fields.append("stripped")

        if rabin2_data:
            rpath = rabin2_data.get("rpath", "NONE")
            analysis.rpath = "" if rpath == "NONE" else rpath
        else:
            analysis.rpath = readelf_data["rpath"]

        analysis.fortify = hardening_data["fortify"]
        if hardening_data["fortify"] is None:
            unknown_fields.append("fortify")

        if self.ctx.extended:
            analysis.stack_clash = hardening_data["stack_clash"]
            analysis.cfi = hardening_data["cfi"]
        else:
            analysis.stack_clash = "skipped"
            analysis.cfi = "skipped"

        analysis.textrel = scanelf_data["textrel"]

        analysis.confidence = max(confidence, 50)
        analysis.tools_used = tools_used
        analysis.unknown_fields = unknown_fields
        analysis.tool_disagreements = tool_disagreements

        if analysis.pie is True and binary_type == BinaryType.EXECUTABLE:
            analysis.aslr_analysis = self.aslr_analyzer.analyze(filepath, analysis)

        return analysis

    def analyze_dependencies(self, binaries: List[BinaryAnalysis]) -> List[DependencyRisk]:
        """Analyze dependency chain for insecure libraries."""
        risks = []

        if "readelf" not in self.tools:
            return risks

        insecure_libs = {}
        for binary in binaries:
            if binary.binary_type == BinaryType.SHARED_LIB:
                issues = []
                if binary.nx is False:
                    issues.append("No NX (executable stack)")
                if binary.textrel:
                    issues.append("TEXTREL (reduced ASLR)")
                if binary.relro == "none":
                    issues.append("No RELRO")

                if issues:
                    insecure_libs[binary.filename] = ", ".join(issues)

        if not insecure_libs:
            return risks

        lib_users = {lib: [] for lib in insecure_libs}

        for binary in binaries:
            if binary.binary_type != BinaryType.EXECUTABLE:
                continue

            filepath = self.target / binary.path
            ret, out, _ = self._run_command(
                [self.tools["readelf"], "-W", "-d", str(filepath)], timeout=10
            )

            if ret != 0:
                continue

            for lib in insecure_libs:
                lib_base = lib.split(".so")[0] if ".so" in lib else lib
                if lib in out or lib_base in out:
                    lib_users[lib].append(binary.filename)

        for lib, issue in insecure_libs.items():
            if lib_users[lib]:
                risks.append(DependencyRisk(
                    library=lib,
                    issue=issue,
                    used_by=lib_users[lib][:10]
                ))

        return risks
