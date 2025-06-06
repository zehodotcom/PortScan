"""
This module defines a dictionary of commonly used TCP/UDP port numbers
and their associated service names.
This data is used by the port scanner to provide more descriptive output.
"""

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
