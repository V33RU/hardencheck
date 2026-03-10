#!/usr/bin/env python3
"""HardenCheck - Firmware Binary Security Analyzer.

Backward-compatible wrapper: `python3 hardencheck.py` continues to work.
For new usage, prefer `python3 -m hardencheck`.
"""
from hardencheck.cli import main

if __name__ == "__main__":
    main()
