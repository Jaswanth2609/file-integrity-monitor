#!/usr/bin/env python3
"""
Main Entrypoint for File Integrity Monitor (FIM) v2.0.
Supports subcommands, legacy v1 arguments, and interactive menu mode.

Author: Jaswanth (Jaswanth2609)
Repository: https://github.com/Jaswanth2609/file-integrity-monitor
"""

import sys
from pathlib import Path

# Add project root and src to sys.path
BASE_DIR = Path(__file__).resolve().parent
SRC_DIR = BASE_DIR / "src"

if str(BASE_DIR) not in sys.path:
    sys.path.insert(0, str(BASE_DIR))
if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))

from fim.cli.commands import main_cli

def main():
    exit_code = main_cli()
    sys.exit(exit_code or 0)

if __name__ == "__main__":
    main()
