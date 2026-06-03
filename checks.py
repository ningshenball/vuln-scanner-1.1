DANGEROUS_PORTS = {
    23: "Telnet (Insecure)",
    21: "FTP (Insecure)",
    445: "SMB (Check for vulnerabilities)",
    3389: "RDP (Exposed Remote Desktop)",
    5900: "VNC (Often weakly secured)",
}

IMPORTANT_HEADERS = [
    "X-Frame-Options",
    "Content-Security-Policy",
    "Strict-Transport-Security",
    "X-Content-Type-Options",
    "Referrer-Policy",
]

def get_dangerous_ports():
    return DANGEROUS_PORTS

def get_important_headers():
    return IMPORTANT_HEADERS