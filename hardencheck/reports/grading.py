from typing import List, Tuple

from hardencheck.models import BinaryType, BinaryAnalysis


def classify_binary(binary: BinaryAnalysis) -> str:
    """Classify binary security level.

    Treats shared libraries differently from executables:
    - Shared libs don't need PIE (they're already position-independent)
    - Shared libs have different security requirements
    """
    is_shared_lib = binary.binary_type == BinaryType.SHARED_LIB

    if is_shared_lib:
        if binary.nx is False:
            return "INSECURE"
        if binary.nx is True and binary.relro in ("full", "partial"):
            if binary.canary is True and binary.relro == "full":
                return "SECURED"
            return "PARTIAL"
        return "PARTIAL"

    if binary.nx is False or binary.canary is False:
        return "INSECURE"

    extended_ok = True
    if binary.stack_clash not in ("yes", "skipped"):
        extended_ok = False
    if binary.cfi not in ("yes", "skipped"):
        extended_ok = False

    all_protected = (
        binary.nx is True and
        binary.canary is True and
        binary.pie is True and
        binary.relro == "full" and
        binary.fortify is True and
        binary.stripped is True and
        extended_ok and
        not binary.textrel and
        not binary.rpath
    )

    if all_protected:
        return "SECURED"

    return "PARTIAL"


def calculate_grade(binaries: List[BinaryAnalysis]) -> Tuple[str, int]:
    """Calculate overall security grade.

    SCORING MODEL (documented for transparency):
    =============================================
    Per-binary score (max 110 points):
      - NX (No Execute):        15 pts  - Critical: prevents code execution on stack/heap
      - Stack Canary:           15 pts  - Critical: detects stack buffer overflows
      - PIE (Position Indep.):  15 pts  - High: enables full ASLR
      - Full RELRO:             15 pts  - High: protects GOT from overwrites
      - Partial RELRO:           7 pts  - Medium: partial GOT protection
      - Fortify Source:         10 pts  - Medium: compile-time buffer checks
      - Stack Clash Protection: 10 pts  - Medium: prevents stack-heap collision
      - CFI (Control Flow):     10 pts  - Medium: prevents ROP/JOP attacks
      - Stripped:                5 pts  - Low: removes debug info
      - No TEXTREL:              5 pts  - Low: allows better ASLR
      - No RPATH:                5 pts  - Low: prevents library hijacking

    Grade thresholds (average score):
      - A: >= 90  (Excellent - most protections enabled)
      - B: >= 80  (Good - strong protection)
      - C: >= 70  (Fair - basic protection)
      - D: >= 60  (Poor - minimal protection)
      - F: <  60  (Fail - inadequate protection)
    """
    if not binaries:
        return "N/A", 0

    total_score = 0

    for binary in binaries:
        score = 0
        if binary.nx is True:
            score += 15
        if binary.canary is True:
            score += 15
        if binary.pie is True:
            score += 15
        if binary.relro == "full":
            score += 15
        elif binary.relro == "partial":
            score += 7
        if binary.fortify is True:
            score += 10
        if binary.stripped is True:
            score += 5
        if binary.stack_clash == "yes":
            score += 10
        if binary.cfi == "yes":
            score += 10
        if not binary.textrel:
            score += 5
        if not binary.rpath:
            score += 5
        total_score += score

    average = total_score / len(binaries)

    if average >= 90:
        return "A", int(average)
    elif average >= 80:
        return "B", int(average)
    elif average >= 70:
        return "C", int(average)
    elif average >= 60:
        return "D", int(average)
    else:
        return "F", int(average)
