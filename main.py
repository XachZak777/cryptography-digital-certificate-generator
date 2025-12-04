#!/usr/bin/env python3
"""
Main Entry Point
Launches the CLI (Command Line Interface) menu system.
"""

import sys
from pathlib import Path

# Add cli directory to path
sys.path.insert(0, str(Path(__file__).parent))

from cli.main_menu import main

if __name__ == "__main__":
    main()

