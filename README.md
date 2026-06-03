# Vulnerability Scanner

A simple yet powerful network vulnerability scanner built in Python for educational and internship purposes.

## Description

This tool performs basic network reconnaissance by scanning ports, grabbing service banners, checking for missing HTTP security headers, and identifying potentially risky open ports. It is designed to be lightweight, fast, and easy to use.

## Features

- Multi-threaded port scanning (fast)
- Service banner grabbing
- HTTP Security Header analysis (for ports 80 & 443)
- Detection of commonly dangerous ports (Telnet, SMB, RDP, etc.)
- Clean and colored terminal output with progress bar
- Results displayed in a formatted table
- Option to save reports in both JSON and TXT format
- Supports both IP addresses and domain names

## Installation

### Prerequisites
- Python 3.10 or higher
- pip

### Setup

```bash
git clone <your-repo-link>
cd vuln_scanner

python -m venv venv
venv\Scripts\activate          # On Windows
# source venv/bin/activate     # On Mac/Linux

pip install -r requirements.txt

Usage
Basic Scan
Bashpython main.py 192.168.1.1 -p 1-500
Scan with Report Saving
Bashpython main.py scanme.nmap.org -p 1-1000 --save
Full Example
Bashpython main.py 192.168.1.1 -p 1-1000 --save
Example Output
textVulnerability Scanner

Target: 192.168.1.1   Ports: 1-1000

Scanning ports... 100% [████████████████████] 00:00:07

Port 53 OPEN → Normal service
Port 80 OPEN → Normal service
   Missing Headers: Content-Security-Policy, Strict-Transport-Security, X-Content-Type-Options, Referrer-Policy
Port 443 OPEN → Normal service

Scan Results
+------+--------+------------------+
| Port | Risk   | Notes            |
+------+--------+------------------+
| 53   | LOW    | Normal service   |
| 80   | LOW    | Normal service   |
| 443  | LOW    | Normal service   |
+------+--------+------------------+

Total open ports found: 3
Report saved as: report_2026-06-03_02-46-31.json + .txt
Project Structure
textvuln_scanner/
├── main.py          # Entry point and CLI
├── scanner.py       # Port scanning and banner grabbing
├── checks.py        # Dangerous ports and HTTP header checks
├── report.py        # Report generation (JSON + TXT)
├── requirements.txt
└── README.md