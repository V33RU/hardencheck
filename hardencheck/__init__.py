"""HardenCheck - Firmware Binary Security Analyzer."""

from hardencheck.constants.core import VERSION
from hardencheck.scanner import HardenCheck
from hardencheck.models import ScanResult
from hardencheck.cli import main

__all__ = ["HardenCheck", "ScanResult", "VERSION", "main"]
__version__ = VERSION
