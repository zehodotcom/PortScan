"""
This module contains the core scanning logic for the port scanner.
It includes functions for scanning individual ports and orchestrating
the full scan process.
"""

import socket
import sys
import time

from utils import COLOR_BRIGHT_GREEN, COLOR_BRIGHT_RED, COLOR_RESET
from common_ports import COMMON_PORTS_INFO


def scan_single_port(target_ip: str, port: int) -> bool:
    """
    Attempts to establish a TCP connection to a specific port on a given IP address.

    This function uses a non-blocking connect_ex() method to determine the port state
    without raising an exception on connection failure, which is ideal for port scanning.

    Args:
        target_ip (str): The IP address of the target host (e.g., "127.0.0.1").
        port (int): The port number to scan (e.g., 80, 443).

    Returns:
        bool: True if the port is found to be open, False otherwise (closed/filtered).

    Exits:
        sys.exit() if a socket.gaierror (host resolution error) or a general
        socket.error occurs, as these indicate critical network or host issues.
    """
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

        # Set a timeout for the connection attempt to prevent indefinite hanging.
        s.settimeout(0.5)

        # connect_ex() returns 0 on success, or an error code otherwise.
        connection_result = s.connect_ex((target_ip, port))

        service_info = COMMON_PORTS_INFO.get(port, "Unknown Service")

        if connection_result == 0:
            print(
                f"{COLOR_BRIGHT_GREEN}Port {port} ({service_info}): Open{COLOR_RESET}"
            )
            return True
        else:
            print(
                f"{COLOR_BRIGHT_RED}Port {port} ({service_info}): Closed/Filtered{COLOR_RESET}"
            )
            return False

    except socket.gaierror:
        print(
            "Error: Hostname could not be resolved. Ensure the IP address is correct."
        )
        sys.exit(1)

    except socket.error as e:
        print(f"Connection error: {e}")
        sys.exit(1)

    finally:
        s.close()


def run_full_scan(target_ip: str):
    """
    Orchestrates the full port scanning process for common ports on a given IP.

    Args:
        target_ip (str): The IP address of the target host to scan.
    """
    ports_to_scan = sorted(list(COMMON_PORTS_INFO.keys()))

    print(f"Initiating common port scan on {target_ip}...")

    start_time = time.time()

    open_ports_count = 0
    closed_ports_count = 0
    detected_open_ports = []

    for port in ports_to_scan:
        is_open = scan_single_port(target_ip, port)
        if is_open:
            open_ports_count += 1
            detected_open_ports.append(
                (port, COMMON_PORTS_INFO.get(port, "Unknown Service"))
            )
        else:
            closed_ports_count += 1

    end_time = time.time()
    elapsed_time = end_time - start_time

    print("\n--- Scan Summary ---")
    print(f"Scanned IP: {target_ip}")
    print(f"Open Ports: {open_ports_count}")
    print(f"Closed/Filtered Ports: {closed_ports_count}")
    print(f"Total Ports Scanned: {len(ports_to_scan)}")
    print(f"Scan Time: {elapsed_time:.2f} seconds")

    if detected_open_ports:
        print("\n--- Details of Open Ports ---")
        for p, service in sorted(detected_open_ports):
            print(f"{COLOR_BRIGHT_GREEN}- {p} ({service}){COLOR_RESET}")
