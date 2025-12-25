#!/usr/bin/env python3
#
# HardenCheck - Firmware Hardening Checker
# Version: 2.1.0
# License: MIT
#
# Binary security analysis tool for embedded firmware
# Analyzes ELF binaries for security hardening flags
#

import os
import sys
import re
import json
import subprocess
import argparse
import hashlib
import shlex
from pathlib import Path
from datetime import datetime
from dataclasses import dataclass
from typing import List, Optional, Tuple
from enum import Enum
import xml.etree.ElementTree as ET
from concurrent.futures import ThreadPoolExecutor, as_completed
import threading


class Severity(Enum):
    CRITICAL = 4
    HIGH = 3
    MEDIUM = 2
    LOW = 1
    INFO = 0


class BinaryType(Enum):
    EXECUTABLE = "Executable"
    SHARED_LIB = "Shared Library"
    KERNEL_MODULE = "Kernel Module"
    STATIC_LIB = "Static Library"
    RELOCATABLE = "Relocatable"
    UNKNOWN = "Unknown"


@dataclass
class BinaryAnalysis:
    path: str
    filename: str
    size: int
    sha256: str
    arch: str
    bits: str
    endian: str
    binary_type: str
    relro: str
    canary: bool
    nx: bool
    pie: str
    rpath: str
    runpath: str
    symbols: bool
    stripped: bool
    debug_symbols: bool
    fortify: bool
    fortified: int
    fortifiable: int
    analysis_method: str


@dataclass
class CodeFinding:
    id: str
    severity: Severity
    file: str
    line: int
    column: int
    symbol: str
    message: str
    cwe: Optional[str]
    category: str
    verbose: str


@dataclass
class BannedFunctionHit:
    function: str
    file: str
    line: int
    snippet: str
    severity: Severity
    safe_alternative: str
    cwe: str


@dataclass
class AuditResult:
    target_path: str
    scan_start: datetime
    scan_end: datetime
    binaries: List[BinaryAnalysis]
    code_findings: List[CodeFinding]
    banned_functions: List[BannedFunctionHit]
    stats: dict
    skipped_files: List[str]


# Banned functions with alternatives and CWE references
BANNED_FUNCTIONS = {
    "gets": ("fgets", "CWE-120", Severity.CRITICAL),
    "strcpy": ("strlcpy or strncpy", "CWE-120", Severity.HIGH),
    "strcat": ("strlcat or strncat", "CWE-120", Severity.HIGH),
    "sprintf": ("snprintf", "CWE-134", Severity.HIGH),
    "vsprintf": ("vsnprintf", "CWE-134", Severity.HIGH),
    "scanf": ("fgets with sscanf", "CWE-120", Severity.HIGH),
    "sscanf": ("sscanf with field width", "CWE-120", Severity.MEDIUM),
    "system": ("execve or posix_spawn", "CWE-78", Severity.HIGH),
    "popen": ("pipe with fork and exec", "CWE-78", Severity.HIGH),
    "mktemp": ("mkstemp", "CWE-377", Severity.HIGH),
    "tmpnam": ("mkstemp", "CWE-377", Severity.HIGH),
    "tempnam": ("mkstemp", "CWE-377", Severity.HIGH),
    "rand": ("getrandom or arc4random", "CWE-330", Severity.MEDIUM),
    "srand": ("getrandom or arc4random", "CWE-330", Severity.MEDIUM),
    "getwd": ("getcwd", "CWE-120", Severity.HIGH),
    "strtok": ("strtok_r", "CWE-362", Severity.MEDIUM),
    "realpath": ("realpath with validation", "CWE-22", Severity.MEDIUM),
}


class HardenCheckScanner:
    
    def __init__(self, target: str, threads: int = 4, verbose: bool = False):
        self.target = Path(target).resolve()
        self.threads = min(threads, 16)  # cap threads
        self.verbose = verbose
        self.lock = threading.Lock()
        self.skipped = []
        self._init_tools()

    def _init_tools(self):
        self.has_checksec = self._cmd_exists('checksec')
        self.has_cppcheck = self._cmd_exists('cppcheck')
        self.has_readelf = self._cmd_exists('readelf')
        self.has_file = self._cmd_exists('file')
        
        if not self.has_readelf:
            sys.stderr.write("[ERROR] readelf not found\n")
            sys.exit(1)

    def _cmd_exists(self, cmd: str) -> bool:
        try:
            subprocess.run(
                [cmd, '--version'],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=5
            )
            return True
        except (subprocess.SubprocessError, FileNotFoundError, OSError):
            return False

    def _run_cmd(self, cmd: List[str], timeout: int = 30) -> Tuple[int, str, str]:
        try:
            proc = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout
            )
            return proc.returncode, proc.stdout, proc.stderr
        except subprocess.TimeoutExpired:
            return -1, "", "timeout"
        except (OSError, subprocess.SubprocessError) as e:
            return -1, "", str(e)

    def _log(self, msg: str, level: str = "INFO"):
        if self.verbose or level in ("ERROR", "WARN"):
            prefix = {"INFO": "[*]", "OK": "[+]", "WARN": "[!]", "ERROR": "[-]", "SKIP": "[~]"}
            print(f"  {prefix.get(level, '[*]')} {msg}")

    def _hash_file(self, path: Path) -> str:
        try:
            h = hashlib.sha256()
            with open(path, 'rb') as f:
                for chunk in iter(lambda: f.read(8192), b''):
                    h.update(chunk)
            return h.hexdigest()
        except (IOError, OSError):
            return ""

    def _detect_arch(self, path: Path) -> Tuple[str, str, str]:
        if not self.has_file:
            return "Unknown", "Unknown", "Unknown"
        
        ret, out, _ = self._run_cmd(['file', '-b', str(path)], timeout=10)
        if ret != 0:
            return "Unknown", "Unknown", "Unknown"
        
        arch = "Unknown"
        bits = "Unknown"
        endian = "Unknown"
        
        out_lower = out.lower()
        
        # Architecture detection
        if 'x86-64' in out or 'x86_64' in out:
            arch, bits = "x86_64", "64"
        elif 'intel 80386' in out_lower or 'i386' in out_lower or 'i686' in out_lower:
            arch, bits = "x86", "32"
        elif 'aarch64' in out_lower:
            arch, bits = "ARM64", "64"
        elif 'arm' in out_lower:
            arch, bits = "ARM", "32"
        elif 'mips64' in out_lower:
            arch, bits = "MIPS64", "64"
        elif 'mips' in out_lower:
            arch, bits = "MIPS", "32"
        elif 'powerpc64' in out_lower or 'ppc64' in out_lower:
            arch, bits = "PPC64", "64"
        elif 'powerpc' in out_lower or 'ppc' in out_lower:
            arch, bits = "PPC", "32"
        elif 'riscv' in out_lower or 'risc-v' in out_lower:
            arch = "RISCV"
            bits = "64" if '64' in out else "32"
        elif 'sparc' in out_lower:
            arch = "SPARC"
            bits = "64" if '64' in out else "32"
        
        # Endianness
        if 'lsb' in out_lower:
            endian = "LE"
        elif 'msb' in out_lower:
            endian = "BE"
        
        return arch, bits, endian

    def _detect_binary_type(self, path: Path) -> BinaryType:
        fname = path.name.lower()
        
        if fname.endswith('.ko'):
            return BinaryType.KERNEL_MODULE
        if fname.endswith('.a'):
            return BinaryType.STATIC_LIB
        
        try:
            with open(path, 'rb') as f:
                f.seek(16)
                e_type = int.from_bytes(f.read(2), 'little')
        except (IOError, OSError):
            return BinaryType.UNKNOWN
        
        if e_type == 1:
            return BinaryType.RELOCATABLE
        elif e_type == 2:
            return BinaryType.EXECUTABLE
        elif e_type == 3:
            if '.so' in fname or fname.startswith('lib'):
                return BinaryType.SHARED_LIB
            return BinaryType.EXECUTABLE
        
        return BinaryType.UNKNOWN

    def find_elf_files(self) -> List[Tuple[Path, BinaryType]]:
        results = []
        elf_magic = b'\x7fELF'
        
        for root, _, files in os.walk(self.target, followlinks=False):
            for fname in files:
                fpath = Path(root) / fname
                
                if fpath.is_symlink():
                    continue
                
                try:
                    with open(fpath, 'rb') as f:
                        if f.read(4) != elf_magic:
                            continue
                except (IOError, OSError, PermissionError):
                    continue
                
                btype = self._detect_binary_type(fpath)
                results.append((fpath, btype))
        
        return results

    def find_sources(self) -> List[Path]:
        exts = {'.c', '.cpp', '.cc', '.cxx', '.h', '.hpp', '.hxx', '.h++'}
        skip_dirs = {'.git', '.svn', '.hg', 'node_modules', '__pycache__', '.cache'}
        results = []
        
        for root, dirs, files in os.walk(self.target, followlinks=False):
            dirs[:] = [d for d in dirs if d not in skip_dirs]
            for fname in files:
                if Path(fname).suffix.lower() in exts:
                    results.append(Path(root) / fname)
        
        return results

    def _analyze_checksec(self, path: Path) -> Optional[dict]:
        if not self.has_checksec:
            return None
        
        ret, out, _ = self._run_cmd(['checksec', '--json', '--file', str(path)], timeout=30)
        if ret != 0 or not out.strip():
            return None
        
        try:
            data = json.loads(out)
            if isinstance(data, dict):
                for v in data.values():
                    if isinstance(v, dict):
                        return v
            return None
        except (json.JSONDecodeError, ValueError):
            return None

    def _analyze_readelf(self, path: Path) -> dict:
        result = {
            'relro': 'No RELRO',
            'canary': False,
            'nx': False,
            'pie': 'No PIE',
            'rpath': '',
            'runpath': '',
            'symbols': True,
            'stripped': False,
            'debug_symbols': False,
            'fortify': False,
            'fortified': 0,
            'fortifiable': 0
        }
        
        # Program headers
        ret, ph_out, _ = self._run_cmd(['readelf', '-W', '-l', str(path)])
        if ret == 0:
            # NX check - look for GNU_STACK without execute flag
            for line in ph_out.split('\n'):
                if 'GNU_STACK' in line:
                    parts = line.split()
                    for p in parts:
                        if re.match(r'^[RWE]+$', p):
                            result['nx'] = 'E' not in p
                            break
                    else:
                        # No explicit flags found, check for RW only
                        result['nx'] = 'RWE' not in line
            
            # RELRO check
            has_relro = 'GNU_RELRO' in ph_out
            
            # PIE check
            if 'Type:' in ph_out:
                if 'DYN' in ph_out and '.so' not in path.name.lower():
                    result['pie'] = 'PIE enabled'
                elif 'DYN' in ph_out:
                    result['pie'] = 'DSO'
        
        # Dynamic section
        ret, dyn_out, _ = self._run_cmd(['readelf', '-W', '-d', str(path)])
        if ret == 0:
            # Full RELRO needs BIND_NOW
            if has_relro:
                if 'BIND_NOW' in dyn_out or '(NOW)' in dyn_out:
                    result['relro'] = 'Full RELRO'
                else:
                    result['relro'] = 'Partial RELRO'
            
            # RPATH/RUNPATH
            rpath_m = re.search(r'RPATH[^\[]*\[([^\]]+)\]', dyn_out)
            if rpath_m:
                result['rpath'] = rpath_m.group(1)
            
            runpath_m = re.search(r'RUNPATH[^\[]*\[([^\]]+)\]', dyn_out)
            if runpath_m:
                result['runpath'] = runpath_m.group(1)
        
        # Dynamic symbols
        ret, sym_out, _ = self._run_cmd(['readelf', '-W', '--dyn-syms', str(path)])
        if ret == 0:
            # Stack canary
            result['canary'] = '__stack_chk_fail' in sym_out
            
            # FORTIFY
            fortified = set(re.findall(r'(\w+)_chk@', sym_out))
            if fortified:
                result['fortify'] = True
                result['fortified'] = len(fortified)
        
        # Section headers
        ret, sec_out, _ = self._run_cmd(['readelf', '-W', '-S', str(path)])
        if ret == 0:
            # Symbol table present?
            result['symbols'] = '.symtab' in sec_out
            
            # Debug sections
            debug_sects = ['.debug_info', '.debug_abbrev', '.debug_line', 
                         '.debug_str', '.debug_frame', '.debug_ranges']
            result['debug_symbols'] = any(s in sec_out for s in debug_sects)
        
        # File command for strip status (more reliable)
        if self.has_file:
            ret, file_out, _ = self._run_cmd(['file', '-b', str(path)], timeout=10)
            if ret == 0:
                file_lower = file_out.lower()
                if 'not stripped' in file_lower:
                    result['stripped'] = False
                    result['symbols'] = True
                elif 'stripped' in file_lower:
                    result['stripped'] = True
                    result['symbols'] = False
                else:
                    result['stripped'] = not result['symbols']
                
                if 'with debug_info' in file_lower:
                    result['debug_symbols'] = True
        else:
            result['stripped'] = not result['symbols']
        
        return result

    def analyze_binary(self, path: Path, btype: BinaryType) -> Optional[BinaryAnalysis]:
        try:
            rel_path = str(path.relative_to(self.target))
        except ValueError:
            rel_path = str(path)
        
        # Skip kernel modules
        if btype == BinaryType.KERNEL_MODULE:
            with self.lock:
                self.skipped.append(f"{rel_path} (kernel module)")
            return None
        
        # Skip relocatable objects
        if btype == BinaryType.RELOCATABLE:
            with self.lock:
                self.skipped.append(f"{rel_path} (relocatable)")
            return None
        
        try:
            size = path.stat().st_size
        except OSError:
            size = 0
        
        sha256 = self._hash_file(path)
        arch, bits, endian = self._detect_arch(path)
        
        # Try checksec first
        cs_data = self._analyze_checksec(path)
        
        if cs_data:
            method = "checksec"
            symbols_val = cs_data.get('symbols', 'No') == 'Yes'
            
            # Still check debug symbols via readelf
            debug_syms = False
            ret, sec_out, _ = self._run_cmd(['readelf', '-W', '-S', str(path)])
            if ret == 0:
                debug_syms = any(s in sec_out for s in ['.debug_info', '.debug_line'])
            
            return BinaryAnalysis(
                path=rel_path,
                filename=path.name,
                size=size,
                sha256=sha256,
                arch=arch,
                bits=bits,
                endian=endian,
                binary_type=btype.value,
                relro=cs_data.get('relro', 'Unknown'),
                canary=cs_data.get('canary', 'No') == 'Yes',
                nx=cs_data.get('nx', 'No') == 'Yes',
                pie=cs_data.get('pie', 'Unknown'),
                rpath=cs_data.get('rpath') or '',
                runpath=cs_data.get('runpath') or '',
                symbols=symbols_val,
                stripped=not symbols_val,
                debug_symbols=debug_syms,
                fortify=cs_data.get('fortify_source', 'No') == 'Yes',
                fortified=int(cs_data.get('fortified', 0) or 0),
                fortifiable=int(cs_data.get('fortify-able', 0) or 0),
                analysis_method=method
            )
        
        # Fallback to readelf
        method = "readelf"
        data = self._analyze_readelf(path)
        
        return BinaryAnalysis(
            path=rel_path,
            filename=path.name,
            size=size,
            sha256=sha256,
            arch=arch,
            bits=bits,
            endian=endian,
            binary_type=btype.value,
            relro=data['relro'],
            canary=data['canary'],
            nx=data['nx'],
            pie=data['pie'],
            rpath=data['rpath'],
            runpath=data['runpath'],
            symbols=data['symbols'],
            stripped=data['stripped'],
            debug_symbols=data['debug_symbols'],
            fortify=data['fortify'],
            fortified=data['fortified'],
            fortifiable=data['fortifiable'],
            analysis_method=method
        )

    def run_cppcheck(self) -> List[CodeFinding]:
        if not self.has_cppcheck:
            return []
        
        findings = []
        ret, _, err = self._run_cmd([
            'cppcheck', '--enable=all', '--force',
            '--xml', '--xml-version=2', '-q',
            str(self.target)
        ], timeout=600)
        
        if not err:
            return findings
        
        try:
            root = ET.fromstring(err)
        except ET.ParseError:
            return findings
        
        sev_map = {
            'error': Severity.HIGH,
            'warning': Severity.MEDIUM,
            'style': Severity.LOW,
            'performance': Severity.LOW,
            'portability': Severity.LOW,
            'information': Severity.INFO
        }
        
        for error in root.findall('.//error'):
            loc = error.find('location')
            if loc is None:
                continue
            
            fpath = loc.get('file', '')
            try:
                rel = str(Path(fpath).relative_to(self.target))
            except ValueError:
                rel = fpath
            
            findings.append(CodeFinding(
                id=error.get('id', ''),
                severity=sev_map.get(error.get('severity', ''), Severity.MEDIUM),
                file=rel,
                line=int(loc.get('line', 0)),
                column=int(loc.get('column', 0)),
                symbol=error.get('symbol', ''),
                message=error.get('msg', ''),
                cwe=error.get('cwe'),
                category=error.get('severity', ''),
                verbose=error.get('verbose', '')
            ))
        
        return findings

    def scan_banned_binary(self, binaries: List[BinaryAnalysis]) -> List[BannedFunctionHit]:
        hits = []
        pattern_cache = {}
        
        for func in BANNED_FUNCTIONS:
            pattern_cache[func] = re.compile(rf'\s{re.escape(func)}@')
        
        for binary in binaries:
            fpath = self.target / binary.path
            ret, out, _ = self._run_cmd(['readelf', '-W', '--dyn-syms', str(fpath)])
            if ret != 0:
                continue
            
            for func, (safe, cwe, sev) in BANNED_FUNCTIONS.items():
                if pattern_cache[func].search(out):
                    hits.append(BannedFunctionHit(
                        function=func,
                        file=binary.path,
                        line=0,
                        snippet="dynamic import",
                        severity=sev,
                        safe_alternative=safe,
                        cwe=cwe
                    ))
        
        return hits

    def scan_banned_source(self, sources: List[Path]) -> List[BannedFunctionHit]:
        hits = []
        
        # Precompile patterns
        patterns = {}
        for func in BANNED_FUNCTIONS:
            patterns[func] = re.compile(rf'(?<![_a-zA-Z0-9]){re.escape(func)}\s*\(')
        
        for src in sources:
            try:
                content = src.read_text(encoding='utf-8', errors='replace')
            except (IOError, OSError):
                continue
            
            # Strip comments
            content_clean = re.sub(r'//[^\n]*', '', content)
            content_clean = re.sub(r'/\*.*?\*/', '', content_clean, flags=re.DOTALL)
            
            lines = content.split('\n')
            lines_clean = content_clean.split('\n')
            
            try:
                rel = str(src.relative_to(self.target))
            except ValueError:
                rel = str(src)
            
            for i, (orig, clean) in enumerate(zip(lines, lines_clean), 1):
                for func, (safe, cwe, sev) in BANNED_FUNCTIONS.items():
                    if patterns[func].search(clean):
                        hits.append(BannedFunctionHit(
                            function=func,
                            file=rel,
                            line=i,
                            snippet=orig.strip()[:80],
                            severity=sev,
                            safe_alternative=safe,
                            cwe=cwe
                        ))
        
        return hits

    def run(self) -> AuditResult:
        t_start = datetime.now()
        
        print("\n" + "=" * 65)
        print("  HardenCheck - Firmware Hardening Checker")
        print("=" * 65)
        print(f"  Target:  {self.target}")
        print(f"  Started: {t_start.strftime('%Y-%m-%d %H:%M:%S')}")
        print("=" * 65 + "\n")
        
        # Discovery
        print("[1/5] Discovering files...")
        elf_files = self.find_elf_files()
        sources = self.find_sources()
        
        type_counts = {}
        for _, bt in elf_files:
            type_counts[bt.value] = type_counts.get(bt.value, 0) + 1
        
        print(f"      ELF files: {len(elf_files)}")
        for bt, cnt in sorted(type_counts.items()):
            print(f"        {bt}: {cnt}")
        print(f"      Source files: {len(sources)}\n")
        
        # Binary analysis
        print("[2/5] Analyzing binaries...")
        binaries = []
        cs_count = 0
        re_count = 0
        
        with ThreadPoolExecutor(max_workers=self.threads) as pool:
            futures = {pool.submit(self.analyze_binary, p, t): p for p, t in elf_files}
            for fut in as_completed(futures):
                res = fut.result()
                if res:
                    binaries.append(res)
                    if res.analysis_method == "checksec":
                        cs_count += 1
                    else:
                        re_count += 1
        
        print(f"      Analyzed: {len(binaries)}")
        print(f"        checksec: {cs_count}")
        print(f"        readelf:  {re_count}")
        print(f"        skipped:  {len(self.skipped)}\n")
        
        # cppcheck
        print("[3/5] Static analysis...")
        code_issues = self.run_cppcheck()
        print(f"      Issues: {len(code_issues)}\n")
        
        # Banned functions
        print("[4/5] Scanning binary imports...")
        banned_bin = self.scan_banned_binary(binaries)
        print(f"      Found: {len(banned_bin)}\n")
        
        print("[5/5] Scanning source code...")
        banned_src = self.scan_banned_source(sources)
        print(f"      Found: {len(banned_src)}\n")
        
        t_end = datetime.now()
        duration = (t_end - t_start).total_seconds()
        
        all_banned = banned_bin + banned_src
        
        stats = {
            'total_binaries': len(elf_files),
            'analyzed_binaries': len(binaries),
            'skipped_binaries': len(self.skipped),
            'source_files': len(sources),
            'code_findings': len(code_issues),
            'banned_functions': len(all_banned),
            'banned_in_binaries': len(banned_bin),
            'banned_in_source': len(banned_src),
            'scan_duration': duration,
            'nx_enabled': sum(1 for b in binaries if b.nx),
            'canary_enabled': sum(1 for b in binaries if b.canary),
            'pie_enabled': sum(1 for b in binaries if 'PIE' in b.pie or b.pie == 'DSO'),
            'full_relro': sum(1 for b in binaries if b.relro == 'Full RELRO'),
            'partial_relro': sum(1 for b in binaries if 'Partial' in b.relro),
            'no_relro': sum(1 for b in binaries if 'No' in b.relro),
            'fortified': sum(1 for b in binaries if b.fortify),
            'stripped': sum(1 for b in binaries if b.stripped),
            'not_stripped': sum(1 for b in binaries if not b.stripped),
            'debug_symbols': sum(1 for b in binaries if b.debug_symbols),
            'no_debug_symbols': sum(1 for b in binaries if not b.debug_symbols),
            'has_rpath': sum(1 for b in binaries if b.rpath),
        }
        
        print("=" * 65)
        print(f"  Completed in {duration:.1f}s")
        print(f"  Binaries: {len(binaries)} | Sources: {len(sources)}")
        print(f"  Banned functions: {len(all_banned)} | Code issues: {len(code_issues)}")
        print("=" * 65 + "\n")
        
        return AuditResult(
            target_path=str(self.target),
            scan_start=t_start,
            scan_end=t_end,
            binaries=binaries,
            code_findings=code_issues,
            banned_functions=all_banned,
            stats=stats,
            skipped_files=self.skipped
        )


def classify_security(b: BinaryAnalysis) -> Tuple[str, List[str], List[str]]:
    """Classify binary security posture"""
    enabled = []
    missing = []
    
    if b.nx:
        enabled.append("NX")
    else:
        missing.append("NX")
    
    if b.canary:
        enabled.append("Canary")
    else:
        missing.append("Canary")
    
    if 'PIE' in b.pie or b.pie == 'DSO':
        enabled.append("PIE")
    else:
        missing.append("PIE")
    
    if b.relro == 'Full RELRO':
        enabled.append("Full RELRO")
    elif 'Partial' in b.relro:
        enabled.append("Partial RELRO")
        missing.append("Full RELRO")
    else:
        missing.append("RELRO")
    
    if b.fortify:
        enabled.append("FORTIFY")
    else:
        missing.append("FORTIFY")
    
    if b.stripped:
        enabled.append("Stripped")
    else:
        missing.append("Stripped")
    
    if not b.debug_symbols:
        enabled.append("No Debug")
    else:
        missing.append("Has Debug")
    
    # Classification
    has_critical = not b.nx or not b.canary
    is_full = (b.nx and b.canary and ('PIE' in b.pie or b.pie == 'DSO') and
               b.relro == 'Full RELRO' and b.fortify and b.stripped and not b.debug_symbols)
    
    if is_full:
        return "SECURED", enabled, missing
    elif has_critical:
        return "INSECURE", enabled, missing
    else:
        return "PARTIAL", enabled, missing


def build_html(result: AuditResult) -> str:
    """Generate HTML report"""
    
    # Classify binaries
    secured = []
    partial = []
    insecure = []
    
    for b in result.binaries:
        level, en, mis = classify_security(b)
        if level == "SECURED":
            secured.append((b, en, mis))
        elif level == "PARTIAL":
            partial.append((b, en, mis))
        else:
            insecure.append((b, en, mis))
    
    # Score calculation
    total = max(1, result.stats['analyzed_binaries'])
    nx_pct = result.stats['nx_enabled'] / total
    canary_pct = result.stats['canary_enabled'] / total
    pie_pct = result.stats['pie_enabled'] / total
    relro_pct = result.stats['full_relro'] / total
    fortify_pct = result.stats['fortified'] / total
    
    score = 100
    score -= (1 - nx_pct) * 25
    score -= (1 - canary_pct) * 20
    score -= (1 - pie_pct) * 15
    score -= (1 - relro_pct) * 15
    score -= (1 - fortify_pct) * 10
    score -= min(15, result.stats['banned_functions'] * 2)
    score = max(0, int(score))
    
    if score >= 80:
        grade, grade_cls = "A", "grade-a"
    elif score >= 60:
        grade, grade_cls = "B", "grade-b"
    elif score >= 40:
        grade, grade_cls = "C", "grade-c"
    elif score >= 20:
        grade, grade_cls = "D", "grade-d"
    else:
        grade, grade_cls = "F", "grade-f"
    
    # Build binary table rows
    bin_rows = ""
    for b in sorted(result.binaries, key=lambda x: (x.binary_type != "Executable", x.filename)):
        nx_c = "ok" if b.nx else "bad"
        can_c = "ok" if b.canary else "bad"
        pie_c = "ok" if "PIE" in b.pie or b.pie == "DSO" else "bad"
        rel_c = "ok" if b.relro == "Full RELRO" else "warn" if "Partial" in b.relro else "bad"
        fort_c = "ok" if b.fortify else "bad"
        strip_c = "ok" if b.stripped else "bad"
        dbg_c = "bad" if b.debug_symbols else "ok"
        
        bin_rows += f'''<tr>
<td class="mono">{b.filename[:32]}</td>
<td><span class="tag tag-type">{b.binary_type[:8]}</span></td>
<td><span class="tag tag-arch">{b.arch}</span></td>
<td class="ctr"><span class="dot {nx_c}"></span></td>
<td class="ctr"><span class="dot {can_c}"></span></td>
<td class="ctr"><span class="dot {pie_c}"></span></td>
<td><span class="tag tag-{rel_c}">{b.relro.replace(' RELRO','')}</span></td>
<td class="ctr"><span class="dot {fort_c}"></span></td>
<td class="ctr"><span class="tag tag-{strip_c}">{'Yes' if b.stripped else 'No'}</span></td>
<td class="ctr"><span class="tag tag-{dbg_c}">{'Yes' if b.debug_symbols else 'No'}</span></td>
</tr>'''
    
    # Banned functions rows
    banned_rows = ""
    for h in sorted(result.banned_functions, key=lambda x: (-x.severity.value, x.function)):
        sev_c = h.severity.name.lower()
        loc = f"{h.file}:{h.line}" if h.line else h.file
        banned_rows += f'''<tr class="sev-{sev_c}">
<td><code class="fn-bad">{h.function}()</code></td>
<td class="mono">{loc[:45]}</td>
<td><code class="fn-ok">{h.safe_alternative}</code></td>
<td><a href="https://cwe.mitre.org/data/definitions/{h.cwe.split('-')[1]}.html" target="_blank">{h.cwe}</a></td>
<td><span class="sev sev-{sev_c}">{h.severity.name}</span></td>
</tr>'''
    
    # Code findings
    findings_html = ""
    if result.code_findings:
        by_sev = {}
        for f in result.code_findings:
            by_sev.setdefault(f.severity, []).append(f)
        
        for sev in [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW]:
            items = by_sev.get(sev, [])
            if not items:
                continue
            sc = sev.name.lower()
            findings_html += f'<div class="fgroup"><div class="fhead fhead-{sc}">{sev.name} ({len(items)})</div>'
            for f in items[:25]:
                findings_html += f'''<div class="fitem">
<span class="fid">{f.id}</span>
<span class="floc">{f.file}:{f.line}</span>
{f'<span class="fcwe">CWE-{f.cwe}</span>' if f.cwe else ''}
<div class="fmsg">{f.message}</div>
</div>'''
            if len(items) > 25:
                findings_html += f'<div class="fmore">... {len(items)-25} more</div>'
            findings_html += '</div>'
    
    # Classification sections
    def render_class(items, css_class):
        if not items:
            return '<div class="cempty">None</div>'
        html = ""
        for b, en, mis in items:
            en_tags = ''.join(f'<span class="ptag ok">{p}</span>' for p in en)
            mis_tags = ''.join(f'<span class="ptag bad">{p}</span>' for p in mis) if mis else '<span class="ptag na">-</span>'
            html += f'''<div class="citem {css_class}">
<div class="cname">{b.filename}</div>
<div class="cpath">{b.path}</div>
<div class="cprots"><span class="clbl">Enabled:</span> {en_tags}</div>
<div class="cprots"><span class="clbl">Missing:</span> {mis_tags}</div>
</div>'''
        return html

    return f'''<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>HardenCheck Report</title>
<style>
:root{{--bg:#0b1120;--card:#111a2e;--border:#1e3a5f;--text:#e2e8f0;--dim:#64748b;--ok:#10b981;--bad:#ef4444;--warn:#f59e0b;--accent:#00d4ff}}
*{{margin:0;padding:0;box-sizing:border-box}}
body{{font-family:system-ui,-apple-system,sans-serif;background:var(--bg);color:var(--text);line-height:1.5;font-size:14px}}
.wrap{{max-width:1400px;margin:0 auto;padding:1.5rem}}
.hdr{{background:var(--card);border:1px solid var(--border);border-radius:12px;padding:1.5rem;margin-bottom:1.5rem;display:flex;justify-content:space-between;align-items:center;flex-wrap:wrap;gap:1rem}}
.hdr h1{{font-size:1.4rem;color:var(--accent)}}
.hdr .sub{{color:var(--dim);font-size:.85rem}}
.meta{{text-align:right;font-size:.8rem;color:var(--dim)}}
.meta .tgt{{background:rgba(0,212,255,.1);color:var(--accent);padding:.3rem .6rem;border-radius:4px;font-family:monospace;display:inline-block;margin-bottom:.3rem}}
.row{{display:grid;grid-template-columns:180px 1fr;gap:1.5rem;margin-bottom:1.5rem}}
@media(max-width:900px){{.row{{grid-template-columns:1fr}}}}
.gcard{{background:var(--card);border:1px solid var(--border);border-radius:12px;padding:1.5rem;text-align:center}}
.gring{{width:90px;height:90px;border-radius:50%;border:4px solid var(--border);display:flex;align-items:center;justify-content:center;margin:0 auto 1rem}}
.gletter{{font-size:2.5rem;font-weight:700}}
.grade-a .gletter,.grade-a .gring{{color:#10b981;border-color:#10b981}}
.grade-b .gletter,.grade-b .gring{{color:#22c55e;border-color:#22c55e}}
.grade-c .gletter,.grade-c .gring{{color:#eab308;border-color:#eab308}}
.grade-d .gletter,.grade-d .gring{{color:#f97316;border-color:#f97316}}
.grade-f .gletter,.grade-f .gring{{color:#ef4444;border-color:#ef4444}}
.glbl{{color:var(--dim);font-size:.85rem}}
.gscore{{font-size:.9rem;margin-top:.3rem}}
.stats{{display:grid;grid-template-columns:repeat(auto-fit,minmax(120px,1fr));gap:.75rem}}
.stat{{background:var(--card);border:1px solid var(--border);border-radius:8px;padding:.75rem;text-align:center}}
.stat .val{{font-size:1.5rem;font-weight:700;color:var(--accent)}}
.stat .lbl{{font-size:.7rem;color:var(--dim);text-transform:uppercase}}
.stat.bad .val{{color:var(--bad)}}
.stat.warn .val{{color:var(--warn)}}
.stat.ok .val{{color:var(--ok)}}
.bars{{display:grid;grid-template-columns:repeat(auto-fit,minmax(130px,1fr));gap:.75rem;margin-bottom:1.5rem}}
.bar{{background:var(--card);border:1px solid var(--border);border-radius:8px;padding:.6rem}}
.bar .lbl{{font-size:.65rem;color:var(--dim);text-transform:uppercase;margin-bottom:.2rem}}
.bar .val{{font-size:1rem;font-weight:600;margin-bottom:.3rem}}
.bar .track{{height:3px;background:var(--bg);border-radius:2px}}
.bar .fill{{height:100%;background:var(--ok);border-radius:2px}}
.sec{{background:var(--card);border:1px solid var(--border);border-radius:12px;padding:1.25rem;margin-bottom:1.5rem}}
.sec-title{{font-size:1rem;font-weight:600;margin-bottom:1rem}}
table{{width:100%;border-collapse:collapse;font-size:.8rem}}
th{{background:var(--bg);color:var(--dim);font-weight:600;text-transform:uppercase;font-size:.65rem;padding:.6rem;text-align:left;border-bottom:2px solid var(--border)}}
td{{padding:.5rem .6rem;border-bottom:1px solid var(--border);vertical-align:middle}}
tr:hover td{{background:rgba(0,212,255,.02)}}
.mono{{font-family:monospace;font-size:.75rem}}
.ctr{{text-align:center}}
.tag{{display:inline-block;padding:.1rem .4rem;border-radius:3px;font-size:.65rem;font-weight:600}}
.tag-type{{background:rgba(139,92,246,.15);color:#8b5cf6}}
.tag-arch{{background:rgba(0,212,255,.15);color:var(--accent)}}
.tag-ok{{background:rgba(16,185,129,.15);color:var(--ok)}}
.tag-bad{{background:rgba(239,68,68,.15);color:var(--bad)}}
.tag-warn{{background:rgba(245,158,11,.15);color:var(--warn)}}
.dot{{width:16px;height:16px;border-radius:50%;display:inline-flex;align-items:center;justify-content:center;font-size:.6rem;font-weight:700}}
.dot.ok{{background:rgba(16,185,129,.2);color:var(--ok)}}
.dot.ok::after{{content:'✓'}}
.dot.bad{{background:rgba(239,68,68,.2);color:var(--bad)}}
.dot.bad::after{{content:'✗'}}
.fn-bad{{background:rgba(239,68,68,.15);color:var(--bad);padding:.1rem .3rem;border-radius:3px;font-size:.75rem}}
.fn-ok{{background:rgba(16,185,129,.15);color:var(--ok);padding:.1rem .3rem;border-radius:3px;font-size:.75rem}}
.sev{{padding:.1rem .4rem;border-radius:3px;font-size:.6rem;font-weight:600}}
.sev-critical{{background:rgba(239,68,68,.2);color:#ef4444}}
.sev-high{{background:rgba(249,115,22,.2);color:#f97316}}
.sev-medium{{background:rgba(234,179,8,.2);color:#eab308}}
.sev-low{{background:rgba(59,130,246,.2);color:#3b82f6}}
tr.sev-critical td{{border-left:3px solid #ef4444}}
tr.sev-high td{{border-left:3px solid #f97316}}
tr.sev-medium td{{border-left:3px solid #eab308}}
.fgroup{{margin-bottom:1rem}}
.fhead{{padding:.4rem .6rem;border-radius:6px;font-weight:600;font-size:.8rem;margin-bottom:.4rem}}
.fhead-critical{{background:rgba(239,68,68,.15);color:#ef4444}}
.fhead-high{{background:rgba(249,115,22,.15);color:#f97316}}
.fhead-medium{{background:rgba(234,179,8,.15);color:#eab308}}
.fhead-low{{background:rgba(59,130,246,.15);color:#3b82f6}}
.fitem{{background:var(--bg);padding:.5rem .6rem;border-radius:6px;margin-bottom:.3rem;font-size:.75rem}}
.fid{{color:var(--accent);font-weight:600;margin-right:.4rem}}
.floc{{color:var(--dim);font-family:monospace;font-size:.7rem;margin-right:.4rem}}
.fcwe{{background:rgba(139,92,246,.2);color:#8b5cf6;padding:.05rem .3rem;border-radius:3px;font-size:.65rem}}
.fmsg{{color:var(--dim);margin-top:.2rem}}
.fmore{{color:var(--dim);font-style:italic;padding:.4rem}}
.empty{{text-align:center;padding:1.5rem;color:var(--dim)}}
.csummary{{display:grid;grid-template-columns:repeat(3,1fr);gap:1rem;margin-bottom:1.5rem}}
.ccard{{text-align:center;padding:1.2rem;border-radius:10px;border:2px solid}}
.ccard .icon{{font-size:1.5rem;margin-bottom:.3rem}}
.ccard .cnt{{font-size:2rem;font-weight:700}}
.ccard .lbl{{font-size:.75rem;font-weight:600;text-transform:uppercase}}
.ccard.secured{{background:rgba(16,185,129,.1);border-color:var(--ok)}}
.ccard.secured .cnt{{color:var(--ok)}}
.ccard.partial{{background:rgba(245,158,11,.1);border-color:var(--warn)}}
.ccard.partial .cnt{{color:var(--warn)}}
.ccard.insecure{{background:rgba(239,68,68,.1);border-color:var(--bad)}}
.ccard.insecure .cnt{{color:var(--bad)}}
.csec{{margin-bottom:1.2rem}}
.chead{{padding:.6rem .8rem;border-radius:6px;margin-bottom:.4rem;font-weight:600;font-size:.85rem;display:flex;justify-content:space-between;flex-wrap:wrap;gap:.4rem}}
.chead-secured{{background:rgba(16,185,129,.15);color:var(--ok)}}
.chead-partial{{background:rgba(245,158,11,.15);color:var(--warn)}}
.chead-insecure{{background:rgba(239,68,68,.15);color:var(--bad)}}
.cdesc{{font-size:.7rem;font-weight:400;opacity:.8}}
.citem{{background:var(--bg);border-radius:6px;padding:.6rem .8rem;margin-bottom:.3rem;border-left:4px solid}}
.citem.c-secured{{border-left-color:var(--ok)}}
.citem.c-partial{{border-left-color:var(--warn)}}
.citem.c-insecure{{border-left-color:var(--bad)}}
.cname{{font-weight:600;font-size:.9rem;margin-bottom:.1rem}}
.cpath{{font-family:monospace;font-size:.7rem;color:var(--dim);margin-bottom:.4rem}}
.cprots{{display:flex;flex-wrap:wrap;gap:.2rem;align-items:center;margin-bottom:.2rem}}
.clbl{{font-size:.65rem;color:var(--dim);margin-right:.3rem}}
.ptag{{font-size:.6rem;padding:.1rem .35rem;border-radius:3px;font-weight:600}}
.ptag.ok{{background:rgba(16,185,129,.2);color:var(--ok)}}
.ptag.bad{{background:rgba(239,68,68,.2);color:var(--bad)}}
.ptag.na{{background:rgba(100,116,139,.2);color:var(--dim)}}
.cempty{{padding:.8rem;text-align:center;color:var(--dim);font-style:italic}}
.ftr{{text-align:center;padding:1.5rem;color:var(--dim);font-size:.8rem;border-top:1px solid var(--border);margin-top:1rem}}
a{{color:var(--accent);text-decoration:none}}
a:hover{{text-decoration:underline}}
</style>
</head>
<body>
<div class="wrap">
<header class="hdr">
<div><h1>HardenCheck</h1><div class="sub">Firmware Hardening Analysis</div></div>
<div class="meta"><div class="tgt">{Path(result.target_path).name}</div><div>{result.scan_start.strftime('%Y-%m-%d %H:%M')} | {result.stats['scan_duration']:.1f}s</div></div>
</header>

<div class="row">
<div class="gcard {grade_cls}">
<div class="gring"><span class="gletter">{grade}</span></div>
<div class="glbl">Security Grade</div>
<div class="gscore">{score}/100</div>
</div>
<div class="stats">
<div class="stat"><div class="val">{result.stats['analyzed_binaries']}</div><div class="lbl">Binaries</div></div>
<div class="stat"><div class="val">{result.stats['source_files']}</div><div class="lbl">Sources</div></div>
<div class="stat {'bad' if result.stats['banned_functions']>10 else 'warn' if result.stats['banned_functions']>0 else 'ok'}"><div class="val">{result.stats['banned_functions']}</div><div class="lbl">Banned Funcs</div></div>
<div class="stat {'bad' if result.stats['code_findings']>20 else 'warn' if result.stats['code_findings']>0 else 'ok'}"><div class="val">{result.stats['code_findings']}</div><div class="lbl">Code Issues</div></div>
<div class="stat {'ok' if nx_pct>.8 else 'warn' if nx_pct>.5 else 'bad'}"><div class="val">{int(nx_pct*100)}%</div><div class="lbl">NX</div></div>
<div class="stat {'ok' if canary_pct>.8 else 'warn' if canary_pct>.5 else 'bad'}"><div class="val">{int(canary_pct*100)}%</div><div class="lbl">Canary</div></div>
</div>
</div>

<div class="bars">
<div class="bar"><div class="lbl">NX/DEP</div><div class="val">{result.stats['nx_enabled']}/{total}</div><div class="track"><div class="fill" style="width:{nx_pct*100}%"></div></div></div>
<div class="bar"><div class="lbl">Stack Canary</div><div class="val">{result.stats['canary_enabled']}/{total}</div><div class="track"><div class="fill" style="width:{canary_pct*100}%"></div></div></div>
<div class="bar"><div class="lbl">PIE</div><div class="val">{result.stats['pie_enabled']}/{total}</div><div class="track"><div class="fill" style="width:{pie_pct*100}%"></div></div></div>
<div class="bar"><div class="lbl">Full RELRO</div><div class="val">{result.stats['full_relro']}/{total}</div><div class="track"><div class="fill" style="width:{relro_pct*100}%"></div></div></div>
<div class="bar"><div class="lbl">FORTIFY</div><div class="val">{result.stats['fortified']}/{total}</div><div class="track"><div class="fill" style="width:{fortify_pct*100}%"></div></div></div>
<div class="bar"><div class="lbl">Stripped</div><div class="val">{result.stats['stripped']}/{total}</div><div class="track"><div class="fill" style="width:{result.stats['stripped']/total*100}%"></div></div></div>
<div class="bar"><div class="lbl">No Debug</div><div class="val">{result.stats['no_debug_symbols']}/{total}</div><div class="track"><div class="fill" style="width:{result.stats['no_debug_symbols']/total*100}%"></div></div></div>
</div>

<section class="sec">
<div class="sec-title">Binary Protection Matrix ({len(result.binaries)})</div>
{f'<div style="overflow-x:auto"><table><thead><tr><th>Binary</th><th>Type</th><th>Arch</th><th>NX</th><th>Canary</th><th>PIE</th><th>RELRO</th><th>Fortify</th><th>Stripped</th><th>Debug</th></tr></thead><tbody>{bin_rows}</tbody></table></div>' if result.binaries else '<div class="empty">No binaries</div>'}
</section>

<section class="sec">
<div class="sec-title">Banned Functions ({len(result.banned_functions)})</div>
{f'<div style="overflow-x:auto"><table><thead><tr><th>Function</th><th>Location</th><th>Alternative</th><th>CWE</th><th>Severity</th></tr></thead><tbody>{banned_rows}</tbody></table></div>' if result.banned_functions else '<div class="empty">No banned functions detected</div>'}
</section>

<section class="sec">
<div class="sec-title">Static Analysis ({len(result.code_findings)})</div>
{findings_html if findings_html else '<div class="empty">No issues</div>'}
</section>

<section class="sec">
<div class="sec-title">Security Classification</div>
<div class="csummary">
<div class="ccard secured"><div class="icon">&#x1F6E1;</div><div class="cnt">{len(secured)}</div><div class="lbl">Secured</div></div>
<div class="ccard partial"><div class="icon">&#x26A0;</div><div class="cnt">{len(partial)}</div><div class="lbl">Partial</div></div>
<div class="ccard insecure"><div class="icon">&#x1F6A8;</div><div class="cnt">{len(insecure)}</div><div class="lbl">Insecure</div></div>
</div>
<div class="csec">
<div class="chead chead-secured"><span>SECURED ({len(secured)})</span><span class="cdesc">All protections enabled</span></div>
{render_class(secured, 'c-secured')}
</div>
<div class="csec">
<div class="chead chead-partial"><span>PARTIAL ({len(partial)})</span><span class="cdesc">Some protections missing</span></div>
{render_class(partial, 'c-partial')}
</div>
<div class="csec">
<div class="chead chead-insecure"><span>INSECURE ({len(insecure)})</span><span class="cdesc">Missing NX or Canary</span></div>
{render_class(insecure, 'c-insecure')}
</div>
</section>

<footer class="ftr">
<p>HardenCheck | {result.scan_end.strftime('%Y-%m-%d %H:%M:%S')}</p>
</footer>
</div>
</body>
</html>'''


def main():
    parser = argparse.ArgumentParser(description='HardenCheck - Firmware Hardening Checker')
    parser.add_argument('target', help='Target directory')
    parser.add_argument('-o', '--output', default='hardencheck_report.html', help='Output file')
    parser.add_argument('-t', '--threads', type=int, default=4, help='Thread count')
    parser.add_argument('-v', '--verbose', action='store_true', help='Verbose output')
    parser.add_argument('--json', action='store_true', help='Generate JSON report')
    
    args = parser.parse_args()
    
    if not os.path.isdir(args.target):
        sys.stderr.write(f"Error: {args.target} is not a directory\n")
        sys.exit(1)
    
    scanner = HardenCheckScanner(args.target, threads=args.threads, verbose=args.verbose)
    result = scanner.run()
    
    html = build_html(result)
    
    try:
        with open(args.output, 'w', encoding='utf-8') as f:
            f.write(html)
        print(f"[+] Report: {args.output}")
    except IOError as e:
        sys.stderr.write(f"Error writing report: {e}\n")
        sys.exit(1)
    
    if args.json:
        json_file = args.output.rsplit('.', 1)[0] + '.json'
        try:
            with open(json_file, 'w', encoding='utf-8') as f:
                json.dump({
                    'target': result.target_path,
                    'timestamp': result.scan_start.isoformat(),
                    'duration': result.stats['scan_duration'],
                    'stats': result.stats,
                    'binaries': [
                        {k: v for k, v in vars(b).items()}
                        for b in result.binaries
                    ],
                    'banned_functions': [
                        {'function': h.function, 'file': h.file, 'line': h.line,
                         'alternative': h.safe_alternative, 'cwe': h.cwe,
                         'severity': h.severity.name}
                        for h in result.banned_functions
                    ],
                    'code_findings': [
                        {'id': f.id, 'file': f.file, 'line': f.line,
                         'message': f.message, 'severity': f.severity.name,
                         'cwe': f.cwe}
                        for f in result.code_findings
                    ]
                }, f, indent=2, default=str)
            print(f"[+] JSON: {json_file}")
        except IOError as e:
            sys.stderr.write(f"Error writing JSON: {e}\n")


if __name__ == '__main__':
    main()
