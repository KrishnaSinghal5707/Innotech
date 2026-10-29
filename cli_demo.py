#!/usr/bin/env python3
"""CLI launcher. Usage: python cli_demo.py --help"""
import sys
from main import main

if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
