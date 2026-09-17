#!/usr/bin/env python3
"""
DKSec Entrypoint Executable.
"""
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from dksec.cli import main

if __name__ == "__main__":
    main()
