DANGEROUS_PORTS = {
    21: "FTP (Insecure - plaintext credentials)",
    22: "SSH (Brute-force target)",
    23: "Telnet (Insecure - plaintext)",
    25: "SMTP (Potential mail relay)",
    110: "POP3 (Plaintext email retrieval)",
    143: "IMAP (Plaintext email retrieval)",
    445: "SMB (EternalBlue/ransomware risk)",
    1433: "MSSQL (Database exposed to network)",
    1521: "Oracle DB (Database exposed to network)",
    3306: "MySQL (Database exposed to network)",
    3389: "RDP (Remote Desktop - brute-force risk)",
    5432: "PostgreSQL (Database exposed to network)",
    5900: "VNC (Often weakly secured)",
    6379: "Redis (Commonly unauthenticated)",
    27017: "MongoDB (Commonly unauthenticated)",
}

IMPORTANT_HEADERS = [
    "X-Frame-Options",
    "Content-Security-Policy",
    "Strict-Transport-Security",
    "X-Content-Type-Options",
    "Referrer-Policy",
]

HTTP_PORTS = {80, 8080, 8000, 3000, 5000, 8008}
HTTPS_PORTS = {443, 8443}


def get_dangerous_ports():
    return DANGEROUS_PORTS


def get_important_headers():
    return IMPORTANT_HEADERS


def get_http_ports():
    return HTTP_PORTS | HTTPS_PORTS


def is_https_port(port):
    return port in HTTPS_PORTS
