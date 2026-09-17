#!/usr/bin/env python3
"""
DKSec Unified Command Line Interface
"""
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# Auto-discover ~/.local/lib/python3.*/site-packages and .venv/lib/python3.*/site-packages
import glob
try:
    user_home = os.path.expanduser("~")
    repo_dir = os.path.dirname(os.path.abspath(__file__))
    patterns = [
        os.path.join(repo_dir, ".venv", "lib", "python3.*", "site-packages"),
        os.path.join(user_home, ".local", "lib", "python3.*", "site-packages"),
    ]
    for pattern in patterns:
        for sp in sorted(glob.glob(pattern), reverse=True):
            if os.path.isdir(sp) and sp not in sys.path:
                sys.path.insert(1, sp)
except Exception:
    pass

from dksec.cli import main

if __name__ == "__main__":
    main()
