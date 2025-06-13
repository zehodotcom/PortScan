"""
Simple Port Scanner (Python)

This is the main entry point for the port scanner application.
It parses command-line arguments (target IP and port range/list)
and initiates the scanning process.

Usage examples:
  python main.py
  python main.py 192.168.1.1
  python main.py --ports 1-1000 192.168.1.1
  python main.py --ports 22,80,443 localhost
"""

import argparse
import sys
from scanner import run_full_scan


def main():
    """
    Parses command-line arguments for target IP and ports, then starts the scan.
    """
    parser = argparse.ArgumentParser(description="A simple multithreaded port scanner.")

    # Argument for target IP (positional, optional)
    parser.add_argument(
        "target_ip",
        nargs="?",  # '?' means 0 or 1 argument
        default="127.0.0.1",
        help="The IP address or hostname to scan. Defaults to 127.0.0.1 (localhost).",
    )

    # Argument for custom ports or range (optional, named)
    parser.add_argument(
        "-p",
        "--ports",
        dest="ports_arg",  # Store the value in 'ports_arg'
        help="Specify ports to scan. Can be a range (e.g., '1-1000') or a comma-separated list (e.g., '22,80,443'). If not specified, common ports will be scanned.",
    )

    args = parser.parse_args()

    target_ip = args.target_ip
    ports_to_scan = None  # Initialize as None, will be parsed later if provided

    # Check if a custom port argument was provided
    if args.ports_arg:
        # We'll parse this string into a list of integers in the next step.
        # For now, just pass the string to run_full_scan, which will handle the parsing.
        ports_to_scan = args.ports_arg

    # Call the main scanning function from the scanner module
    # We now pass ports_to_scan explicitly (it can be None if not provided)
    run_full_scan(target_ip, ports_to_scan)


if __name__ == "__main__":
    main()
