import json
from datetime import datetime

def save_report(target, results, filename="report"):
    timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    
    json_data = {
        "target": target,
        "scan_time": timestamp,
        "total_open_ports": len(results),
        "results": results
    }
    with open(f"{filename}_{timestamp}.json", "w") as f:
        json.dump(json_data, f, indent=2)

    with open(f"{filename}_{timestamp}.txt", "w") as f:
        f.write(f"Vulnerability Scanner Report\n")
        f.write(f"Target: {target}\n")
        f.write(f"Scan Time: {timestamp}\n")
        f.write(f"Total Open Ports: {len(results)}\n\n")
        for r in results:
            f.write(f"Port {r['port']} - {r['risk']}\n")
            if r.get("header_issues"):
                f.write(f"Missing Headers: {', '.join(r['header_issues'])}\n")
            f.write("\n")

    return f"{filename}_{timestamp}"