import re
import struct
import subprocess
from pathlib import Path
from typing import Dict, List, Tuple, Optional

from hardencheck.models import ASLRAnalysis, ASLRRating, BinaryAnalysis
from hardencheck.constants.core import SECURE_ENV
from hardencheck.constants.binary import ARCH_ASLR_ENTROPY
from hardencheck.core.utils import safe_read_binary


class ASLREntropyAnalyzer:
    """Analyzes ASLR entropy effectiveness for PIE binaries."""

    ELF_MAGIC = b'\x7fELF'
    ET_DYN = 3
    PT_LOAD = 1
    PT_GNU_STACK = 0x6474e551

    def __init__(self, tools: Dict[str, str]):
        self.tools = tools

    def _set_resource_limits(self):
        """Set resource limits for child process to prevent DoS."""
        try:
            import resource
            resource.setrlimit(resource.RLIMIT_CPU, (60, 60))
            resource.setrlimit(resource.RLIMIT_AS, (512 * 1024 * 1024, 512 * 1024 * 1024))
            resource.setrlimit(resource.RLIMIT_FSIZE, (10 * 1024 * 1024, 10 * 1024 * 1024))
        except (ImportError, ValueError, OSError):
            pass

    def _run_command(self, cmd: List[str], timeout: int = 30) -> Tuple[int, str, str]:
        """Execute command securely with restricted environment and resource limits."""
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout,
                stdin=subprocess.DEVNULL,
                env=SECURE_ENV,
                close_fds=True,
                preexec_fn=self._set_resource_limits
            )
            return result.returncode, result.stdout, result.stderr
        except subprocess.TimeoutExpired:
            return -1, "", "Command timed out"
        except FileNotFoundError:
            return -1, "", "Command not found"
        except Exception as e:
            return -1, "", str(e)

    def _parse_elf_header(self, data: bytes) -> Optional[Dict]:
        """Parse ELF header to extract basic info."""
        if len(data) < 64 or data[:4] != self.ELF_MAGIC:
            return None

        info = {}
        info['class'] = data[4]
        info['bits'] = 64 if info['class'] == 2 else 32
        info['endian'] = '<' if data[5] == 1 else '>'
        info['machine'] = struct.unpack(info['endian'] + 'H', data[18:20])[0]

        machine_map = {
            3: "x86", 62: "x86_64", 40: "ARM", 183: "ARM64",
            8: "MIPS", 20: "PowerPC", 21: "PowerPC64", 243: "RISC-V",
        }
        info['arch'] = machine_map.get(info['machine'], f"Unknown({info['machine']})")

        if info['bits'] == 64:
            info['type'] = struct.unpack(info['endian'] + 'H', data[16:18])[0]
            info['entry'] = struct.unpack(info['endian'] + 'Q', data[24:32])[0]
            info['phoff'] = struct.unpack(info['endian'] + 'Q', data[32:40])[0]
            info['phentsize'] = struct.unpack(info['endian'] + 'H', data[54:56])[0]
            info['phnum'] = struct.unpack(info['endian'] + 'H', data[56:58])[0]
        else:
            info['type'] = struct.unpack(info['endian'] + 'H', data[16:18])[0]
            info['entry'] = struct.unpack(info['endian'] + 'I', data[24:28])[0]
            info['phoff'] = struct.unpack(info['endian'] + 'I', data[28:32])[0]
            info['phentsize'] = struct.unpack(info['endian'] + 'H', data[42:44])[0]
            info['phnum'] = struct.unpack(info['endian'] + 'H', data[44:46])[0]

        return info

    def _parse_program_headers(self, data: bytes, elf_info: Dict) -> List[Dict]:
        """Parse program headers from ELF."""
        headers = []
        endian = elf_info['endian']
        phoff = elf_info['phoff']
        phentsize = elf_info['phentsize']
        phnum = elf_info['phnum']
        is_64 = elf_info['bits'] == 64

        for i in range(phnum):
            offset = phoff + (i * phentsize)
            if offset + phentsize > len(data):
                break

            ph = {}
            if is_64:
                ph['type'] = struct.unpack(endian + 'I', data[offset:offset+4])[0]
                ph['flags'] = struct.unpack(endian + 'I', data[offset+4:offset+8])[0]
                ph['offset'] = struct.unpack(endian + 'Q', data[offset+8:offset+16])[0]
                ph['vaddr'] = struct.unpack(endian + 'Q', data[offset+16:offset+24])[0]
                ph['paddr'] = struct.unpack(endian + 'Q', data[offset+24:offset+32])[0]
                ph['filesz'] = struct.unpack(endian + 'Q', data[offset+32:offset+40])[0]
                ph['memsz'] = struct.unpack(endian + 'Q', data[offset+40:offset+48])[0]
                ph['align'] = struct.unpack(endian + 'Q', data[offset+48:offset+56])[0]
            else:
                ph['type'] = struct.unpack(endian + 'I', data[offset:offset+4])[0]
                ph['offset'] = struct.unpack(endian + 'I', data[offset+4:offset+8])[0]
                ph['vaddr'] = struct.unpack(endian + 'I', data[offset+8:offset+12])[0]
                ph['paddr'] = struct.unpack(endian + 'I', data[offset+12:offset+16])[0]
                ph['filesz'] = struct.unpack(endian + 'I', data[offset+16:offset+20])[0]
                ph['memsz'] = struct.unpack(endian + 'I', data[offset+20:offset+24])[0]
                ph['flags'] = struct.unpack(endian + 'I', data[offset+24:offset+28])[0]
                ph['align'] = struct.unpack(endian + 'I', data[offset+28:offset+32])[0]

            headers.append(ph)

        return headers

    def _check_dynamic_section(self, filepath: Path) -> Dict:
        """Check dynamic section for TEXTREL, RPATH using readelf."""
        result = {'has_textrel': False, 'has_rpath': False, 'rpath': ''}

        if 'readelf' not in self.tools:
            return result

        ret, out, _ = self._run_command(
            [self.tools['readelf'], '-W', '-d', str(filepath)], timeout=10
        )

        if ret != 0:
            return result

        if 'TEXTREL' in out:
            result['has_textrel'] = True

        rpath_match = re.search(r'(?:RPATH|RUNPATH).*?\[(.*?)\]', out)
        if rpath_match:
            result['has_rpath'] = True
            result['rpath'] = rpath_match.group(1)

        return result

    def _calculate_entropy_rating(self, effective_entropy: int, issues: List[str]) -> ASLRRating:
        """Calculate ASLR rating based on effective entropy and issues."""
        critical_issues = [i for i in issues if 'TEXTREL' in i or 'non-PIE' in i.lower()]

        if critical_issues or effective_entropy < 8:
            return ASLRRating.INEFFECTIVE
        elif effective_entropy < 15:
            return ASLRRating.WEAK
        elif effective_entropy < 20:
            return ASLRRating.MODERATE
        elif effective_entropy < 28:
            return ASLRRating.GOOD
        else:
            return ASLRRating.EXCELLENT

    def analyze(self, filepath: Path, binary_analysis: BinaryAnalysis) -> ASLRAnalysis:
        """Perform complete ASLR entropy analysis on a binary."""
        analysis = ASLRAnalysis(
            path=binary_analysis.path,
            filename=binary_analysis.filename,
            is_pie=binary_analysis.pie is True,
            arch="Unknown",
            bits=32
        )

        data = safe_read_binary(filepath, max_size=50 * 1024 * 1024)
        if not data:
            analysis.issues.append("Failed to read binary")
            return analysis

        elf_info = self._parse_elf_header(data)
        if not elf_info:
            analysis.issues.append("Invalid ELF format")
            return analysis

        analysis.arch = elf_info['arch']
        analysis.bits = elf_info['bits']
        analysis.entry_point = elf_info['entry']

        is_pie = elf_info['type'] == self.ET_DYN
        if not is_pie:
            analysis.is_pie = False
            analysis.rating = ASLRRating.NOT_APPLICABLE
            analysis.issues.append("Non-PIE executable (static addresses)")
            analysis.recommendations.append("Recompile with -fPIE -pie flags")
            return analysis

        analysis.is_pie = True

        phdrs = self._parse_program_headers(data, elf_info)
        load_segments = [ph for ph in phdrs if ph['type'] == self.PT_LOAD]
        analysis.num_load_segments = len(load_segments)

        if len(load_segments) >= 2:
            vaddrs = [ph['vaddr'] for ph in load_segments]

            deltas = [vaddrs[i+1] - vaddrs[i] for i in range(len(vaddrs)-1)]

            has_high_base = vaddrs[0] >= 0x400000

            if len(deltas) >= 2:
                delta_variance = max(deltas) - min(deltas)
                has_consistent_deltas = delta_variance < 0x100000
            else:
                has_consistent_deltas = False

            has_large_gaps = any(d > 0x10000000 for d in deltas)

            if has_high_base and (has_consistent_deltas or has_large_gaps):
                analysis.has_fixed_segments = True
                analysis.fixed_segment_addrs = vaddrs
                analysis.issues.append("Fixed segment layout detected (linker script pattern)")
            elif has_high_base and analysis.bits == 64:
                analysis.issues.append(f"High base address: 0x{vaddrs[0]:x} (verify PIE)")

        if load_segments:
            analysis.load_base = load_segments[0]['vaddr']
            analysis.text_vaddr = load_segments[0]['vaddr']
            if len(load_segments) > 1:
                analysis.data_vaddr = load_segments[1]['vaddr']

        for ph in phdrs:
            if ph['type'] == self.PT_GNU_STACK:
                if ph['flags'] & 0x1:
                    analysis.stack_executable = True
                    analysis.issues.append("Executable stack detected")

        dyn_info = self._check_dynamic_section(filepath)
        analysis.has_textrel = dyn_info['has_textrel'] or binary_analysis.textrel
        analysis.has_rpath = dyn_info['has_rpath']

        if analysis.has_textrel:
            analysis.issues.append("TEXTREL present - text relocations reduce ASLR effectiveness")

        if analysis.has_rpath:
            analysis.issues.append(f"RPATH/RUNPATH set: {dyn_info['rpath']}")

        arch_key = analysis.arch
        if arch_key not in ARCH_ASLR_ENTROPY:
            arch_key = "x86_64" if analysis.bits == 64 else "x86"

        user_bits, mmap_rand, stack_rand = ARCH_ASLR_ENTROPY.get(
            arch_key,
            (47 if analysis.bits == 64 else 32, 28 if analysis.bits == 64 else 8, 22 if analysis.bits == 64 else 8)
        )

        analysis.theoretical_entropy = mmap_rand
        analysis.page_offset_bits = 12
        analysis.available_entropy = mmap_rand

        analysis.issues.append(f"Entropy is theoretical estimate (kernel default: {mmap_rand} bits)")

        effective = analysis.available_entropy

        if analysis.has_textrel:
            effective -= 8
            analysis.recommendations.append("Remove TEXTREL by compiling with -fPIC")

        if analysis.has_fixed_segments:
            effective -= 4
            analysis.recommendations.append("Avoid fixed segment addresses in PIE")

        if analysis.stack_executable:
            effective -= 2
            analysis.recommendations.append("Disable executable stack with -z noexecstack")

        if analysis.bits == 32:
            effective = min(effective, 8)
            if effective < 12:
                analysis.issues.append("32-bit architecture has limited ASLR entropy")
                analysis.recommendations.append("Consider 64-bit build for better ASLR")

        analysis.effective_entropy = max(0, effective)

        analysis.rating = self._calculate_entropy_rating(
            analysis.effective_entropy,
            analysis.issues
        )

        if analysis.rating in (ASLRRating.WEAK, ASLRRating.INEFFECTIVE):
            if analysis.bits == 32:
                analysis.recommendations.append("Migrate to 64-bit for stronger ASLR")
            if binary_analysis.canary is not True:
                analysis.recommendations.append("Enable stack canaries as compensating control")
            if binary_analysis.fortify is not True:
                analysis.recommendations.append("Enable FORTIFY_SOURCE as compensating control")

        return analysis
