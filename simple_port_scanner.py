import socket
import sys
import time

# ANSI escape codes for console output coloring.
COLOR_BRIGHT_GREEN = "\033[92m"  # Bright Green
COLOR_BRIGHT_RED = "\033[91m"  # Bright Red
COLOR_RESET = "\033[0m"  # Resets console color to default

# Dictionary mapping common port numbers to their associated service names.
COMMON_PORTS_INFO = {
    20: "FTP Data (File Transfer Protocol Data)",
    21: "FTP (File Transfer Protocol)",
    22: "SSH (Secure Shell)",
    23: "Telnet (Unencrypted Remote Access)",
    25: "SMTP (Simple Mail Transfer Protocol)",
    53: "DNS (Domain Name System)",
    67: "DHCP Server (Dynamic Host Configuration Protocol)",
    68: "DHCP Client (Dynamic Host Configuration Protocol)",
    80: "HTTP (Hypertext Transfer Protocol)",
    110: "POP3 (Post Office Protocol v3)",
    135: "RPC (Remote Procedure Call - Windows)",
    139: "NetBIOS/SMB (Windows File Sharing)",
    143: "IMAP (Internet Message Access Protocol)",
    161: "SNMP (Simple Network Management Protocol)",
    162: "SNMP Trap (Simple Network Management Protocol Trap)",
    389: "LDAP (Lightweight Directory Access Protocol)",
    443: "HTTPS (HTTP Secure)",
    445: "SMB/CIFS (Windows File Sharing)",
    465: "SMTPS (SMTP Secure - Legacy)",
    500: "ISAKMP/IKE (IPsec Key Exchange)",
    587: "SMTP (Message Submission - TLS/SSL)",
    636: "LDAPS (LDAP Secure)",
    993: "IMAPS (IMAP Secure)",
    995: "POP3S (POP3 Secure)",
    1433: "MSSQL (Microsoft SQL Server)",
    1521: "Oracle (Default Listener Port)",
    1701: "L2TP (Layer 2 Tunneling Protocol)",
    1723: "PPTP (Point-to-Point Tunneling Protocol)",
    3306: "MySQL (MariaDB/Percona)",
    3389: "RDP (Remote Desktop Protocol - Windows)",
    5432: "PostgreSQL (Database)",
    5900: "VNC (Virtual Network Computing)",
    8080: "HTTP Proxy/Alt (Alternate HTTP)",
    8443: "HTTPS Alt (Alternate HTTPS)",
    9000: "Web/API (Commonly used for web servers/APIs, e.g., Docker)",
    10000: "Webmin/Web Admin (Common for web-based administration tools)",
}


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


if __name__ == "__main__":
    # Allow target IP to be passed as a command-line argument, default to localhost.
    target_ip = "127.0.0.1" if len(sys.argv) < 2 else sys.argv[1]

    # Generate a sorted list of ports from the common ports dictionary.
    ports_to_scan = sorted(list(COMMON_PORTS_INFO.keys()))

    print(f"Initiating common port scan on {target_ip}...")

    start_time = time.time()

    open_ports_count = 0
    closed_ports_count = 0
    detected_open_ports = []

    # Iterate through each port and scan it sequentially.
    for port in ports_to_scan:
        is_open = scan_single_port(target_ip, port)
        if is_open:
            open_ports_count += 1
            # Store port details for final summary.
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
        # Sort detected open ports numerically for cleaner output.
        for p, service in sorted(detected_open_ports):
            print(f"{COLOR_BRIGHT_GREEN}- {p} ({service}){COLOR_RESET}")
