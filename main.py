"""
Simple Port Scanner (Python)

This is the main entry point for the port scanner application.
It parses command-line arguments (target IP) and initiates the scanning process.

Usage: python main.py <target_ip_optional>
    <target_ip_optional>: The IP address or hostname to scan. Defaults to 127.0.0.1 (localhost).
"""

import sys
from scanner import run_full_scan

if __name__ == "__main__":
    # Determine the target IP from command-line arguments or default to localhost.
    target_ip = "127.0.0.1"
    if len(sys.argv) < 2:
        print("Usage: python main.py <target_ip>")
        print("Using default target: 127.0.0.1")
    else:
        target_ip = sys.argv[1]

    # Execute the full port scan logic.
    run_full_scan(target_ip)
