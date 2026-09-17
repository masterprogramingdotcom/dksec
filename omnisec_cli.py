#!/usr/bin/env python3
"""
OmniSec Command Line Entrypoint.
"""
import sys
import os

# Ensure package root is in path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from omnisec.cli import main

if __name__ == "__main__":
    main()
