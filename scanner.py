import socket
from concurrent.futures import ThreadPoolExecutor, as_completed
import requests
import ssl
from datetime import datetime
from rich.progress import Progress, SpinnerColumn, BarColumn, TextColumn, TimeElapsedColumn
from checks import get_dangerous_ports, get_important_headers

def scan_port(target, port, timeout=1.5):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            return (port, s.connect_ex((target, port)) == 0)
    except:
        return (port, False)

def grab_banner(target, port, timeout=2.0):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            s.connect((target, port))
            if port in [80, 443]:
                s.send(b"HEAD / HTTP/1.0\r\n\r\n")
            banner = s.recv(1024).decode(errors="ignore").strip()
            return banner[:120] if banner else "No banner"
    except:
        return "No banner"

def check_http_headers(target, port):
    protocol = "https" if port == 443 else "http"
    url = f"{protocol}://{target}"
    try:
        response = requests.get(url, timeout=5, verify=False)
        headers = response.headers
        missing = [h for h in get_important_headers() if h not in headers]
        return missing
    except:
        return ["Could not retrieve headers"]

def check_ssl_certificate(target, port=443):
    try:
        context = ssl.create_default_context()
        with socket.create_connection((target, port), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=target) as ssock:
                cert = ssock.getpeercert()
                not_after = cert.get('notAfter')
                expiry_date = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
                days_left = (expiry_date - datetime.now()).days

                issuer = dict(x[0] for x in cert.get('issuer', []))
                subject = dict(x[0] for x in cert.get('subject', []))

                return {
                    "issuer": issuer.get('organizationName', 'Unknown'),
                    "common_name": subject.get('commonName', 'Unknown'),
                    "expiry_date": not_after,
                    "days_until_expiry": days_left,
                    "status": "Valid" if days_left > 0 else "Expired"
                }
    except Exception as e:
        return {"error": str(e)}

def check_http_methods(target, port):
    """Check for dangerous HTTP methods"""
    protocol = "https" if port == 443 else "http"
    url = f"{protocol}://{target}"
    
    dangerous_methods = ["TRACE", "PUT", "DELETE", "CONNECT"]
    enabled_methods = []

    try:
        response = requests.options(url, timeout=5, verify=False)
        allow_header = response.headers.get("Allow", "")

        for method in dangerous_methods:
            if method in allow_header:
                enabled_methods.append(method)

        try:
            trace_response = requests.request("TRACE", url, timeout=5, verify=False)
            if trace_response.status_code == 200:
                enabled_methods.append("TRACE")
        except:
            pass

        return enabled_methods if enabled_methods else ["No dangerous methods detected"]
    except:
        return ["Could not check HTTP methods"]

def check_server_header(target, port):
    """Check if server version is being exposed"""
    protocol = "https" if port == 443 else "http"
    url = f"{protocol}://{target}"
    
    try:
        response = requests.get(url, timeout=5, verify=False)
        server_header = response.headers.get("Server", "")
        
        if server_header:
            return {
                "exposed": True,
                "server": server_header,
                "risk": "Information Disclosure - Server version leaked"
            }
        else:
            return {
                "exposed": False,
                "server": "Hidden",
                "risk": "Good - Server version not exposed"
            }
    except:
        return {
            "exposed": False,
            "server": "Could not check",
            "risk": "Unknown"
        }

def check_sensitive_paths(target, port):
    """Check for common sensitive paths"""
    protocol = "https" if port == 443 else "http"
    
    sensitive_paths = [
        "/admin", "/login", "/dashboard", "/config", "/.env",
        "/backup", "/wp-admin", "/phpinfo.php", "/server-status"
    ]
    
    found_paths = []
    
    for path in sensitive_paths:
        try:
            url = f"{protocol}://{target}{path}"
            response = requests.get(url, timeout=4, verify=False, allow_redirects=False)
            
            if response.status_code == 200:
                found_paths.append({
                    "path": path,
                    "status": response.status_code,
                    "size": len(response.content)
                })
        except:
            continue
    
    return found_paths if found_paths else ["No sensitive paths found"]

def scan_target(target, start_port, end_port):
    open_ports = []
    ports = list(range(start_port, end_port + 1))

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
        TimeElapsedColumn(),
    ) as progress:
        task = progress.add_task("[cyan]Scanning ports...", total=len(ports))

        with ThreadPoolExecutor(max_workers=200) as executor:
            futures = {executor.submit(scan_port, target, p): p for p in ports}
            for future in as_completed(futures):
                port, is_open = future.result()
                if is_open:
                    open_ports.append(port)
                progress.update(task, advance=1)

    results = []
    for port in sorted(open_ports):
        banner = grab_banner(target, port)
        risk = get_dangerous_ports().get(port, "Normal service")

        header_issues = []
        if port in [80, 443]:
            header_issues = check_http_headers(target, port)

        ssl_info = None
        if port == 443:
            ssl_info = check_ssl_certificate(target, port)

        http_methods = []
        if port in [80, 443]:
            http_methods = check_http_methods(target, port)

        server_info = None
        if port in [80, 443]:
            server_info = check_server_header(target, port)

        sensitive_paths = []
        if port in [80, 443]:
            sensitive_paths = check_sensitive_paths(target, port)

        results.append({
            "port": port,
            "risk": risk,
            "banner": banner,
            "header_issues": header_issues,
            "ssl_info": ssl_info,
            "http_methods": http_methods,
            "server_info": server_info,
            "sensitive_paths": sensitive_paths
        })

    return results