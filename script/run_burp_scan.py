#!/usr/bin/env python3
"""Simple CLI wrapper to run the Burp-based passive scanner.

Usage:
  python script/run_burp_scan.py https://example.com
"""
import json
import sys
import os
# Ensure project root is on sys.path so `utils` can be imported when running the script directly
proj_root = os.path.dirname(os.path.dirname(__file__))
if proj_root not in sys.path:
    sys.path.insert(0, proj_root)
from utils.burp_scanner import BurpScanner


def main():
    if len(sys.argv) < 2:
        print("Usage: run_burp_scan.py <target>")
        sys.exit(1)
    target = sys.argv[1]
    scanner = BurpScanner()
    results = scanner.scan_target(target)
    print(json.dumps(results, indent=2, ensure_ascii=False))


if __name__ == '__main__':
    main()
