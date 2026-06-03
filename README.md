### Vulnerability Scanner v1.1

A simple bit improved powerful network vulnerability scanner with both **Command Line Interface (CLI)** and **Web Interface (Streamlit)**.

## Description

This tool helps users perform basic network reconnaissance by scanning ports, grabbing banners, checking for missing security headers, detecting dangerous HTTP methods, identifying server version leaks, and discovering sensitive paths. It is designed for educational purposes and cybersecurity learning.

## Features

- Multi-threaded port scanning with progress bar
- Service banner grabbing
- Detection of missing HTTP security headers
- Check for dangerous HTTP methods (TRACE, PUT, DELETE, etc.)
- Server header exposure detection
- Sensitive path discovery on web servers
- Basic SSL/TLS certificate information
- Clean and user-friendly Streamlit web interface
- Option to save scan reports (JSON + TXT)
- Supports both IP addresses and domain names

## Tech Stack

- Python 3
- Streamlit (Web Interface)
- Rich (Terminal UI)
- Requests + Socket (Network operations)

## Installation

### 1. Clone the repository

```
git clone https://github.com/ningshenball/vuln-scanner-1.1.git
cd vuln-scanner-1.1
```
### 2. Create virtual environment & install dependencies
```
Bashpython -m venv venv
venv\Scripts\activate          # Windows
# source venv/bin/activate     # Mac/Linux

pip install -r requirements.txt
Usage
CLI Version
Bashpython main.py 192.168.1.1 -p 1-500 --save
Streamlit Web Version
Bashstreamlit run app.py
Then open the link shown in the terminal (usually http://localhost:8501).
```
### Project Structure
textvuln-scanner-1.1/

├── main.py           # CLI version

├── app.py            # Streamlit web version

├── scanner.py        # Core scanning logic

├── checks.py         # Security checks

├── report.py         # Report generation

├── requirements.txt
├── .gitignore

└── README.md

### Example Output (Streamlit)
```
<img src="https://via.placeholder.com/800x400?text=Add+your+screenshot+here" alt="Streamlit Interface">
````
### Future Improvements
- Add more vulnerability checks (SQLi, XSS detection hints)
- Better service fingerprinting
- PDF/HTML report export
- Authentication & rate limiting for web version
- Docker support

### Built as part of Cyber Security learning 
