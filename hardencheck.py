#!/usr/bin/env python3
"""
HardenCheck - Firmware Binary Security Analyzer

Tools: rabin2, hardening-check, scanelf, eu-readelf, file, cppcheck
"""

import os, sys, json, hashlib, argparse, shutil, subprocess, re
from pathlib import Path
from dataclasses import dataclass
from typing import List, Dict, Tuple, Optional
from enum import Enum
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime

VERSION = "3.0.0"

class Severity(Enum):
    CRITICAL = 4
    HIGH = 3
    MEDIUM = 2
    LOW = 1

class BinaryType(Enum):
    EXECUTABLE = "Executable"
    SHARED_LIB = "Shared Library"
    RELOCATABLE = "Relocatable"
    KERNEL_MODULE = "Kernel Module"
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
    binary_type: BinaryType
    nx: bool = False
    canary: bool = False
    pie: bool = False
    relro: str = "none"
    fortify: bool = False
    stripped: bool = False
    stack_clash: str = "unknown"
    cfi: str = "unknown"
    bind_now: bool = False
    asan: bool = False
    textrel: bool = False
    rpath: str = ""
    debug_symbols: bool = False
    tool_used: str = ""

@dataclass
class BannedHit:
    function: str
    file: str
    line: int
    snippet: str
    severity: Severity
    alternative: str
    impact: str

@dataclass
class CodeFinding:
    id: str
    file: str
    line: int
    message: str
    severity: Severity

@dataclass
class ScanResult:
    target: str
    scan_time: str
    duration: float
    tools: Dict[str, str]
    binaries: List[BinaryAnalysis]
    banned: List[BannedHit]
    findings: List[CodeFinding]
    sources: List[str]

BANNED = {
    "gets": ("fgets", Severity.CRITICAL, "No bounds, guaranteed overflow"),
    "strcpy": ("strlcpy/strncpy", Severity.HIGH, "No length limit, overflow"),
    "strcat": ("strlcat/strncat", Severity.HIGH, "No length limit, overflow"),
    "sprintf": ("snprintf", Severity.HIGH, "No output limit, overflow"),
    "vsprintf": ("vsnprintf", Severity.HIGH, "Variadic overflow risk"),
    "scanf": ("fgets+sscanf", Severity.HIGH, "Unbounded %s input"),
    "system": ("execve", Severity.HIGH, "Shell injection risk"),
    "popen": ("fork+exec", Severity.HIGH, "Command injection"),
    "mktemp": ("mkstemp", Severity.HIGH, "Race condition"),
    "tmpnam": ("mkstemp", Severity.HIGH, "Predictable path"),
    "rand": ("getrandom", Severity.MEDIUM, "Weak PRNG"),
    "strtok": ("strtok_r", Severity.MEDIUM, "Not thread-safe"),
}

class HardenCheck:
    def __init__(self, target: Path, threads: int = 4, verbose: bool = False):
        self.target = target
        self.threads = min(threads, 16)
        self.verbose = verbose
        self.tools = self._detect_tools()
    
    def _detect_tools(self) -> Dict[str, str]:
        tools = {}
        for cmd in ['radare2.rabin2', 'rabin2']:
            if shutil.which(cmd):
                tools['rabin2'] = cmd
                break
        for name, cmd in [('hardening-check', 'hardening-check'), ('scanelf', 'scanelf'),
                          ('checksec', 'checksec'), ('cppcheck', 'cppcheck'), ('file', 'file')]:
            if shutil.which(cmd):
                tools[name] = cmd
        if shutil.which('eu-readelf'):
            tools['readelf'] = 'eu-readelf'
        elif shutil.which('readelf'):
            tools['readelf'] = 'readelf'
        return tools
    
    def _run(self, cmd: List[str], timeout: int = 30) -> Tuple[int, str, str]:
        try:
            r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
            return r.returncode, r.stdout, r.stderr
        except:
            return -1, "", ""
    
    def _hash(self, f: Path) -> str:
        h = hashlib.sha256()
        try:
            with open(f, 'rb') as fp:
                for c in iter(lambda: fp.read(65536), b''):
                    h.update(c)
            return h.hexdigest()
        except:
            return ""
    
    def _is_elf(self, f: Path) -> bool:
        try:
            with open(f, 'rb') as fp:
                return fp.read(4) == b'\x7fELF'
        except:
            return False
    
    def _get_type(self, f: Path) -> BinaryType:
        try:
            with open(f, 'rb') as fp:
                fp.seek(16)
                t = int.from_bytes(fp.read(2), 'little')
            n = f.name.lower()
            if t == 1:
                return BinaryType.KERNEL_MODULE if n.endswith('.ko') else BinaryType.RELOCATABLE
            elif t == 2:
                return BinaryType.EXECUTABLE
            elif t == 3:
                return BinaryType.SHARED_LIB if '.so' in n else BinaryType.EXECUTABLE
            return BinaryType.UNKNOWN
        except:
            return BinaryType.UNKNOWN
    
    def find_files(self) -> Tuple[List[Tuple[Path, BinaryType]], List[Path]]:
        bins, srcs = [], []
        for root, dirs, files in os.walk(self.target):
            dirs[:] = [d for d in dirs if not d.startswith('.')]
            for fn in files:
                fp = Path(root) / fn
                if fp.is_symlink():
                    continue
                if self._is_elf(fp):
                    bins.append((fp, self._get_type(fp)))
                elif fp.suffix.lower() in {'.c', '.cpp', '.h', '.hpp'}:
                    srcs.append(fp)
        return bins, srcs
    
    def _rabin2(self, f: Path) -> Optional[Dict]:
        if 'rabin2' not in self.tools:
            return None
        ret, out, _ = self._run([self.tools['rabin2'], '-Ij', str(f)])
        if ret != 0:
            return None
        try:
            return json.loads(out).get('info', {})
        except:
            return None
    
    def _hardening_check(self, f: Path) -> Dict:
        r = {'fortify': False, 'stack_clash': 'unknown', 'cfi': 'unknown', 'bind_now': False}
        if 'hardening-check' not in self.tools:
            return r
        ret, out, _ = self._run([self.tools['hardening-check'], str(f)])
        if ret not in [0, 1]:
            return r
        o = out.lower()
        if 'fortify source functions: yes' in o:
            r['fortify'] = True
        if 'stack clash protection: yes' in o:
            r['stack_clash'] = 'yes'
        elif 'stack clash protection: no' in o:
            r['stack_clash'] = 'no'
        if 'control flow integrity: yes' in o:
            r['cfi'] = 'yes'
        elif 'control flow integrity: no' in o:
            r['cfi'] = 'no'
        if 'immediate binding: yes' in o:
            r['bind_now'] = True
        return r
    
    def _scanelf(self, f: Path) -> Dict:
        r = {'textrel': False, 'bind_now': False}
        if 'scanelf' not in self.tools:
            return r
        ret, out, _ = self._run([self.tools['scanelf'], '-a', str(f)])
        if ret != 0:
            return r
        if 'TEXTREL' in out and out.count('-') < out.count('TEXTREL'):
            r['textrel'] = True
        if 'NOW' in out:
            r['bind_now'] = True
        return r
    
    def _readelf(self, f: Path) -> Dict:
        r = {'nx': False, 'canary': False, 'pie': False, 'relro': 'none',
             'stripped': False, 'debug': False, 'rpath': ''}
        if 'readelf' not in self.tools:
            return r
        cmd = self.tools['readelf']
        
        ret, out, _ = self._run([cmd, '-W', '-l', str(f)])
        if ret == 0:
            if 'GNU_STACK' in out:
                for ln in out.split('\n'):
                    if 'GNU_STACK' in ln:
                        r['nx'] = 'E' not in ln
                        break
            if 'GNU_RELRO' in out:
                r['relro'] = 'partial'
            if 'DYN' in out:
                r['pie'] = True
        
        ret, out, _ = self._run([cmd, '-W', '-d', str(f)])
        if ret == 0:
            if 'BIND_NOW' in out:
                r['relro'] = 'full'
            m = re.search(r'RPATH.*\[(.*?)\]', out)
            if m:
                r['rpath'] = m.group(1)
        
        ret, out, _ = self._run([cmd, '-W', '--dyn-syms', str(f)])
        if ret == 0 and '__stack_chk_fail' in out:
            r['canary'] = True
        
        ret, out, _ = self._run([cmd, '-W', '-S', str(f)])
        if ret == 0:
            r['stripped'] = '.symtab' not in out
            r['debug'] = '.debug_info' in out
        return r
    
    def _arch(self, f: Path) -> Tuple[str, str, str]:
        if 'file' not in self.tools:
            return "?", "?", "?"
        ret, out, _ = self._run([self.tools['file'], str(f)])
        if ret != 0:
            return "?", "?", "?"
        o = out.lower()
        arch, bits, end = "?", "?", "?"
        if 'x86-64' in o or 'x86_64' in o:
            arch, bits = "x86_64", "64"
        elif 'x86' in o or 'i386' in o:
            arch, bits = "x86", "32"
        elif 'aarch64' in o:
            arch, bits = "arm64", "64"
        elif 'arm' in o:
            arch, bits = "arm", "32"
        elif 'mips' in o:
            arch = "mips"
            bits = "64" if '64' in o else "32"
        if '64-bit' in o:
            bits = "64"
        elif '32-bit' in o:
            bits = "32"
        end = "LE" if 'lsb' in o else "BE" if 'msb' in o else "?"
        return arch, bits, end
    
    def analyze(self, f: Path, t: BinaryType) -> BinaryAnalysis:
        try:
            p = str(f.relative_to(self.target))
        except:
            p = str(f)
        arch, bits, end = self._arch(f)
        a = BinaryAnalysis(path=p, filename=f.name, size=f.stat().st_size,
                          sha256=self._hash(f), arch=arch, bits=bits,
                          endian=end, binary_type=t)
        
        rb = self._rabin2(f)
        if rb:
            a.tool_used = "rabin2"
            a.nx = rb.get('nx', False)
            a.canary = rb.get('canary', False)
            a.pie = rb.get('pic', False)
            a.relro = rb.get('relro', 'none')
            a.stripped = rb.get('stripped', False)
            a.asan = rb.get('sanitize', False)
            rp = rb.get('rpath', 'NONE')
            a.rpath = '' if rp == 'NONE' else rp
            if rb.get('arch'):
                a.arch = rb['arch']
            if rb.get('bits'):
                a.bits = str(rb['bits'])
        else:
            re_data = self._readelf(f)
            a.tool_used = "readelf"
            a.nx = re_data['nx']
            a.canary = re_data['canary']
            a.pie = re_data['pie']
            a.relro = re_data['relro']
            a.stripped = re_data['stripped']
            a.debug_symbols = re_data['debug']
            a.rpath = re_data['rpath']
        
        hc = self._hardening_check(f)
        a.fortify = hc['fortify']
        a.stack_clash = hc['stack_clash']
        a.cfi = hc['cfi']
        if hc['bind_now']:
            a.bind_now = True
        
        se = self._scanelf(f)
        a.textrel = se['textrel']
        if se['bind_now']:
            a.bind_now = True
        return a
    
    def scan_banned_bin(self, bins: List[BinaryAnalysis]) -> List[BannedHit]:
        hits = []
        if 'readelf' not in self.tools:
            return hits
        pats = {f: re.compile(rf'\s{re.escape(f)}[@\s]') for f in BANNED}
        for b in bins:
            ret, out, _ = self._run([self.tools['readelf'], '-W', '--dyn-syms', str(self.target / b.path)])
            if ret != 0:
                continue
            for f, (alt, sev, imp) in BANNED.items():
                if pats[f].search(out):
                    hits.append(BannedHit(f, b.path, 0, "(import)", sev, alt, imp))
        return hits
    
    def scan_banned_src(self, srcs: List[Path]) -> List[BannedHit]:
        hits = []
        pats = {f: re.compile(rf'(?<![_a-zA-Z0-9]){re.escape(f)}\s*\(') for f in BANNED}
        for s in srcs:
            try:
                c = s.read_text(errors='replace')
            except:
                continue
            c2 = re.sub(r'//[^\n]*', '', c)
            c2 = re.sub(r'/\*.*?\*/', '', c2, flags=re.DOTALL)
            try:
                rel = str(s.relative_to(self.target))
            except:
                rel = str(s)
            for i, (orig, clean) in enumerate(zip(c.split('\n'), c2.split('\n')), 1):
                for f, (alt, sev, imp) in BANNED.items():
                    if pats[f].search(clean):
                        hits.append(BannedHit(f, rel, i, orig.strip()[:50], sev, alt, imp))
        return hits
    
    def run_cppcheck(self) -> List[CodeFinding]:
        findings = []
        if 'cppcheck' not in self.tools:
            return findings
        ret, out, err = self._run([self.tools['cppcheck'], '--enable=warning', '--force',
                                   '--quiet', '--xml', '--xml-version=2', str(self.target)], 120)
        try:
            import xml.etree.ElementTree as ET
            root = ET.fromstring(err)
            smap = {'error': Severity.HIGH, 'warning': Severity.MEDIUM}
            for e in root.findall('.//error'):
                loc = e.find('location')
                if loc is None:
                    continue
                findings.append(CodeFinding(e.get('id',''), loc.get('file',''),
                               int(loc.get('line',0)), e.get('msg',''),
                               smap.get(e.get('severity',''), Severity.LOW)))
        except:
            pass
        return findings
    
    def scan(self) -> ScanResult:
        start = datetime.now()
        print(f"\n{'='*55}")
        print(f"  HardenCheck v{VERSION}")
        print(f"{'='*55}")
        print(f"  Target: {self.target}")
        print(f"  Time:   {start.strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"{'='*55}\n")
        
        print("[*] Tools:")
        for n, c in self.tools.items():
            print(f"    + {n}: {c}")
        print()
        
        print("[1/5] Finding files...")
        bins, srcs = self.find_files()
        print(f"      Binaries: {len(bins)}, Sources: {len(srcs)}\n")
        
        print("[2/5] Analyzing binaries...")
        analyzed = []
        tc = {'rabin2': 0, 'readelf': 0}
        with ThreadPoolExecutor(max_workers=self.threads) as ex:
            futs = {ex.submit(self.analyze, f, t): f for f, t in bins}
            for fut in as_completed(futs):
                try:
                    r = fut.result()
                    analyzed.append(r)
                    if r.tool_used in tc:
                        tc[r.tool_used] += 1
                except:
                    pass
        print(f"      Done: {len(analyzed)} (rabin2: {tc['rabin2']}, readelf: {tc['readelf']})\n")
        
        print("[3/5] Running cppcheck...")
        findings = self.run_cppcheck()
        print(f"      Issues: {len(findings)}\n")
        
        print("[4/5] Scanning binary imports...")
        bb = self.scan_banned_bin(analyzed)
        print(f"      Found: {len(bb)}\n")
        
        print("[5/5] Scanning source...")
        bs = self.scan_banned_src(srcs)
        print(f"      Found: {len(bs)}\n")
        
        dur = (datetime.now() - start).total_seconds()
        print(f"{'='*55}")
        print(f"  Done in {dur:.1f}s")
        print(f"  Binaries: {len(analyzed)}, Banned: {len(bb)+len(bs)}")
        print(f"{'='*55}\n")
        
        return ScanResult(str(self.target), start.isoformat(), dur, self.tools,
                         analyzed, bb + bs, findings, [str(s) for s in srcs])


def classify(b: BinaryAnalysis) -> str:
    if not b.nx or not b.canary:
        return "INSECURE"
    if (b.nx and b.canary and b.pie and b.relro == 'full' and b.fortify and
        b.stripped and b.stack_clash == 'yes' and b.cfi == 'yes' and
        not b.textrel and not b.rpath):
        return "SECURED"
    return "PARTIAL"


def grade(bins: List[BinaryAnalysis]) -> Tuple[str, int]:
    if not bins:
        return "N/A", 0
    n = len(bins)
    s = 0
    for b in bins:
        if b.nx: s += 15
        if b.canary: s += 15
        if b.pie: s += 15
        if b.relro == 'full': s += 15
        elif b.relro == 'partial': s += 7
        if b.fortify: s += 10
        if b.stripped: s += 5
        if b.stack_clash == 'yes': s += 10
        if b.cfi == 'yes': s += 10
        if not b.textrel: s += 5
        if not b.rpath: s += 5
    avg = s / n
    if avg >= 90: return "A", int(avg)
    if avg >= 80: return "B", int(avg)
    if avg >= 70: return "C", int(avg)
    if avg >= 60: return "D", int(avg)
    return "F", int(avg)


def html(res: ScanResult, out: Path):
    n = len(res.binaries) or 1
    nx = sum(1 for b in res.binaries if b.nx)
    can = sum(1 for b in res.binaries if b.canary)
    pie = sum(1 for b in res.binaries if b.pie)
    rel = sum(1 for b in res.binaries if b.relro == 'full')
    fort = sum(1 for b in res.binaries if b.fortify)
    strp = sum(1 for b in res.binaries if b.stripped)
    sc = sum(1 for b in res.binaries if b.stack_clash == 'yes')
    cfi = sum(1 for b in res.binaries if b.cfi == 'yes')
    
    sec = [b for b in res.binaries if classify(b) == "SECURED"]
    par = [b for b in res.binaries if classify(b) == "PARTIAL"]
    ins = [b for b in res.binaries if classify(b) == "INSECURE"]
    g, gs = grade(res.binaries)
    
    rows = ""
    for b in sorted(res.binaries, key=lambda x: x.filename):
        c = classify(b)
        rc = "rb" if c == "INSECURE" else "rw" if c == "PARTIAL" else ""
        rows += f'<tr class="{rc}"><td class="fn">{b.filename}</td><td>{b.arch}/{b.bits}</td>'
        rows += f'<td class="{"ok" if b.nx else "bad"}">{"Y" if b.nx else "N"}</td>'
        rows += f'<td class="{"ok" if b.canary else "bad"}">{"Y" if b.canary else "N"}</td>'
        rows += f'<td class="{"ok" if b.pie else "bad"}">{"Y" if b.pie else "N"}</td>'
        rows += f'<td class="{"ok" if b.relro=="full" else "warn" if b.relro=="partial" else "bad"}">{b.relro}</td>'
        rows += f'<td class="{"ok" if b.fortify else "bad"}">{"Y" if b.fortify else "N"}</td>'
        rows += f'<td class="{"ok" if b.stripped else "bad"}">{"Y" if b.stripped else "N"}</td>'
        rows += f'<td class="{"ok" if b.stack_clash=="yes" else "warn" if b.stack_clash=="unknown" else "bad"}">{b.stack_clash[0].upper()}</td>'
        rows += f'<td class="{"ok" if b.cfi=="yes" else "warn" if b.cfi=="unknown" else "bad"}">{b.cfi[0].upper()}</td>'
        rows += f'<td class="{"bad" if b.textrel else "ok"}">{"-" if not b.textrel else "!"}</td>'
        rows += f'<td class="{"bad" if b.rpath else "ok"}">{b.rpath[:12] if b.rpath else "-"}</td></tr>'
    
    brows = ""
    for h in sorted(res.banned, key=lambda x: (-x.severity.value, x.function)):
        loc = f"{h.file}:{h.line}" if h.line else h.file
        brows += f'<tr><td class="fb">{h.function}()</td><td class="loc">{loc[:30]}</td>'
        brows += f'<td class="fg">{h.alternative}</td><td class="imp">{h.impact}</td>'
        brows += f'<td class="s{h.severity.name[0].lower()}">{h.severity.name}</td></tr>'
    
    def csec(title, items, cls):
        if not items:
            return ""
        c = ""
        for b in items[:15]:
            miss = []
            if not b.nx: miss.append("NX")
            if not b.canary: miss.append("Canary")
            if not b.pie: miss.append("PIE")
            if b.relro != 'full': miss.append("RELRO")
            if not b.fortify: miss.append("Fortify")
            if b.stack_clash != 'yes': miss.append("SClash")
            if b.cfi != 'yes': miss.append("CFI")
            c += f'<div class="ci"><b>{b.filename}</b><span class="cp">{b.path}</span><span class="cm">{", ".join(miss) or "OK"}</span></div>'
        return f'<div class="cs {cls}"><div class="ct">{title} ({len(items)})</div>{c}</div>'
    
    h = f'''<!DOCTYPE html><html><head>
<meta charset="UTF-8"><title>HardenCheck</title>
<link href="https://fonts.googleapis.com/css2?family=Fira+Code:wght@400;600&display=swap" rel="stylesheet">
<style>
*{{margin:0;padding:0;box-sizing:border-box}}
:root{{--bg:#0a0a0a;--c:#111;--bd:#222;--t:#e0e0e0;--d:#666;--ok:#0c6;--bad:#f33;--w:#fa0}}
body{{font-family:'Fira Code',monospace;background:var(--bg);color:var(--t);font-size:12px;padding:20px}}
.x{{max-width:1400px;margin:0 auto}}
h1{{font-size:18px;margin-bottom:5px}}
.m{{color:var(--d);font-size:11px;margin-bottom:20px}}
.cd{{background:var(--c);border:1px solid var(--bd);padding:15px;margin-bottom:15px}}
.ct{{font-size:13px;font-weight:600;margin-bottom:12px;padding-bottom:8px;border-bottom:1px solid var(--bd)}}
.gr{{font-size:42px;font-weight:600;display:inline-block;margin-right:20px}}
.ga{{color:var(--ok)}}.gb{{color:#6c6}}.gc{{color:var(--w)}}.gd{{color:#f60}}.gf{{color:var(--bad)}}
.sm{{display:grid;grid-template-columns:repeat(3,1fr);gap:10px;margin-bottom:15px}}
.sc{{background:var(--c);border:1px solid var(--bd);padding:12px;text-align:center}}
.sc.se{{border-color:var(--ok)}}.sc.pa{{border-color:var(--w)}}.sc.in{{border-color:var(--bad)}}
.sn{{font-size:24px;font-weight:600}}.sn.se{{color:var(--ok)}}.sn.pa{{color:var(--w)}}.sn.in{{color:var(--bad)}}
.sl{{font-size:10px;color:var(--d);text-transform:uppercase}}
.pi{{display:flex;align-items:center;margin-bottom:8px}}
.pl{{width:90px;font-size:11px}}.pb{{flex:1;height:6px;background:var(--bd);margin:0 8px}}
.pf{{height:100%;background:var(--ok)}}.pf.lo{{background:var(--bad)}}.pf.me{{background:var(--w)}}
.pv{{width:50px;font-size:10px;text-align:right;color:var(--d)}}
table{{width:100%;border-collapse:collapse;font-size:11px}}
th{{text-align:left;padding:6px;border-bottom:1px solid var(--bd);color:var(--d);font-weight:500}}
td{{padding:6px;border-bottom:1px solid var(--bd)}}
.fn{{font-weight:500}}.ok{{color:var(--ok)}}.bad{{color:var(--bad)}}.warn{{color:var(--w)}}
.rb{{background:rgba(255,51,51,0.1)}}.rw{{background:rgba(255,170,0,0.05)}}
.fb{{color:var(--bad);font-weight:500}}.fg{{color:var(--ok)}}
.loc{{color:var(--d);font-size:10px}}.imp{{font-size:10px;color:var(--d);max-width:150px}}
.sc{{color:#f00;font-weight:600}}.sh{{color:#f60}}.sm{{color:var(--w)}}.sl{{color:var(--d)}}
.cs{{margin-bottom:10px;border:1px solid var(--bd)}}
.cs.se .ct{{border-left:3px solid var(--ok)}}.cs.pa .ct{{border-left:3px solid var(--w)}}.cs.in .ct{{border-left:3px solid var(--bad)}}
.ci{{padding:6px 12px;border-bottom:1px solid var(--bd)}}.ci:last-child{{border-bottom:none}}
.ci b{{display:block}}.cp{{font-size:10px;color:var(--d);display:block}}.cm{{font-size:10px;color:var(--bad)}}
.tl{{display:flex;flex-wrap:wrap;gap:8px}}.to{{background:var(--bd);padding:3px 8px;font-size:10px}}
</style></head><body><div class="x">
<h1>HardenCheck Report</h1>
<div class="m">{res.target} | {res.scan_time} | {res.duration:.1f}s | v{VERSION}</div>

<div class="cd"><div class="ct">Grade</div>
<span class="gr g{g.lower()}">{g}</span><span style="color:var(--d)">Score: {gs}/110</span></div>

<div class="sm">
<div class="sc se"><div class="sn se">{len(sec)}</div><div class="sl">Secured</div></div>
<div class="sc pa"><div class="sn pa">{len(par)}</div><div class="sl">Partial</div></div>
<div class="sc in"><div class="sn in">{len(ins)}</div><div class="sl">Insecure</div></div>
</div>

<div class="cd"><div class="ct">Coverage</div>
<div class="pi"><span class="pl">NX</span><div class="pb"><div class="pf{" lo" if nx/n<0.5 else " me" if nx/n<0.8 else ""}" style="width:{nx/n*100:.0f}%"></div></div><span class="pv">{nx}/{n}</span></div>
<div class="pi"><span class="pl">Canary</span><div class="pb"><div class="pf{" lo" if can/n<0.5 else " me" if can/n<0.8 else ""}" style="width:{can/n*100:.0f}%"></div></div><span class="pv">{can}/{n}</span></div>
<div class="pi"><span class="pl">PIE</span><div class="pb"><div class="pf{" lo" if pie/n<0.5 else " me" if pie/n<0.8 else ""}" style="width:{pie/n*100:.0f}%"></div></div><span class="pv">{pie}/{n}</span></div>
<div class="pi"><span class="pl">Full RELRO</span><div class="pb"><div class="pf{" lo" if rel/n<0.5 else " me" if rel/n<0.8 else ""}" style="width:{rel/n*100:.0f}%"></div></div><span class="pv">{rel}/{n}</span></div>
<div class="pi"><span class="pl">Fortify</span><div class="pb"><div class="pf{" lo" if fort/n<0.5 else " me" if fort/n<0.8 else ""}" style="width:{fort/n*100:.0f}%"></div></div><span class="pv">{fort}/{n}</span></div>
<div class="pi"><span class="pl">Stripped</span><div class="pb"><div class="pf{" lo" if strp/n<0.5 else " me" if strp/n<0.8 else ""}" style="width:{strp/n*100:.0f}%"></div></div><span class="pv">{strp}/{n}</span></div>
<div class="pi"><span class="pl">Stack Clash</span><div class="pb"><div class="pf{" lo" if sc/n<0.5 else " me" if sc/n<0.8 else ""}" style="width:{sc/n*100:.0f}%"></div></div><span class="pv">{sc}/{n}</span></div>
<div class="pi"><span class="pl">CFI</span><div class="pb"><div class="pf{" lo" if cfi/n<0.5 else " me" if cfi/n<0.8 else ""}" style="width:{cfi/n*100:.0f}%"></div></div><span class="pv">{cfi}/{n}</span></div>
</div>

<div class="cd"><div class="ct">Binaries ({len(res.binaries)})</div>
<div style="overflow-x:auto"><table>
<tr><th>Name</th><th>Arch</th><th>NX</th><th>Can</th><th>PIE</th><th>RELRO</th><th>Fort</th><th>Strp</th><th>SC</th><th>CFI</th><th>TEX</th><th>RPATH</th></tr>
{rows}</table></div></div>

<div class="cd"><div class="ct">Banned ({len(res.banned)})</div>
{"<table><tr><th>Func</th><th>Location</th><th>Alternative</th><th>Impact</th><th>Sev</th></tr>"+brows+"</table>" if res.banned else "<div style='color:var(--d)'>None</div>"}
</div>

<div class="cd"><div class="ct">Classification</div>
{csec("SECURED", sec, "se")}
{csec("PARTIAL", par, "pa")}
{csec("INSECURE", ins, "in")}
</div>

<div class="cd"><div class="ct">Tools</div>
<div class="tl">{" ".join(f'<span class="to">{k}: {v}</span>' for k,v in res.tools.items())}</div>
</div>
</div></body></html>'''
    out.write_text(h)


def jsn(res: ScanResult, out: Path):
    d = {'version': VERSION, 'target': res.target, 'time': res.scan_time, 'duration': res.duration,
         'tools': res.tools,
         'summary': {'total': len(res.binaries),
                     'secured': sum(1 for b in res.binaries if classify(b) == "SECURED"),
                     'partial': sum(1 for b in res.binaries if classify(b) == "PARTIAL"),
                     'insecure': sum(1 for b in res.binaries if classify(b) == "INSECURE")},
         'binaries': [{'path': b.path, 'nx': b.nx, 'canary': b.canary, 'pie': b.pie,
                       'relro': b.relro, 'fortify': b.fortify, 'stack_clash': b.stack_clash,
                       'cfi': b.cfi, 'class': classify(b)} for b in res.binaries],
         'banned': [{'func': h.function, 'file': h.file, 'line': h.line,
                     'alt': h.alternative, 'sev': h.severity.name} for h in res.banned]}
    out.write_text(json.dumps(d, indent=2))


def main():
    p = argparse.ArgumentParser(description='HardenCheck v3.0')
    p.add_argument('target', help='Directory to scan')
    p.add_argument('-o', '--output', default='hardencheck_report.html')
    p.add_argument('-t', '--threads', type=int, default=4)
    p.add_argument('-v', '--verbose', action='store_true')
    p.add_argument('--json', action='store_true')
    p.add_argument('--version', action='version', version=f'v{VERSION}')
    a = p.parse_args()
    
    tgt = Path(a.target)
    if not tgt.exists():
        print(f"Error: {tgt} not found")
        sys.exit(1)
    
    s = HardenCheck(tgt, a.threads, a.verbose)
    r = s.scan()
    
    out = Path(a.output)
    html(r, out)
    print(f"[+] HTML: {out}")
    
    if a.json:
        jo = out.with_suffix('.json')
        jsn(r, jo)
        print(f"[+] JSON: {jo}")


if __name__ == '__main__':
    main()
