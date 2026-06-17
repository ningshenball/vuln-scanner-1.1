#!/usr/bin/env python3
"""
Vulnerability Scanner
"""

import argparse
import socket
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from scanner import scan_target
from report import save_report
from checks import get_dangerous_ports

console = Console()


def resolve_target(target):
    try:
        return socket.gethostbyname(target)
    except socket.gaierror:
        console.print(f"[red]Error:[/red] Could not resolve domain '{target}'")
        return None


def parse_port_range(port_str):
    try:
        parts = port_str.split("-")
        if len(parts) != 2:
            raise ValueError
        start, end = int(parts[0]), int(parts[1])
        if not (1 <= start <= 65535 and 1 <= end <= 65535 and start <= end):
            raise ValueError
        return start, end
    except (ValueError, AttributeError):
        console.print(f"[yellow]Warning:[/yellow] Invalid port range '{port_str}', defaulting to 1-500")
        return 1, 500


def main():
    parser = argparse.ArgumentParser(description="Vulnerability Scanner")
    parser.add_argument("target", nargs="?", default="192.168.1.1")
    parser.add_argument("-p", "--ports", default="1-500")
    parser.add_argument("--save", action="store_true", help="Save report to file")
    args = parser.parse_args()

    ip = resolve_target(args.target)
    if not ip:
        return

    start, end = parse_port_range(args.ports)

    console.print(Panel.fit("[bold green]Vulnerability Scanner[/bold green]",
                            border_style="green", padding=(1, 2)))
    console.print(f"[cyan]Target:[/cyan] {args.target} ({ip})   [cyan]Ports:[/cyan] {start}-{end}\n")

    results = scan_target(ip, start, end)

    if results:
        table = Table(title="Scan Results")
        table.add_column("Port", style="cyan", justify="center")
        table.add_column("Risk", style="magenta")
        table.add_column("Notes")

        for r in results:
            table.add_row(str(r["port"]), r["level"], r["risk"])

        console.print(table)
        console.print(f"\n[bold green]Total open ports found: {len(results)}[/bold green]")

        if args.save:
            saved_name = save_report(args.target, results)
            console.print(f"[green]Report saved as:[/green] {saved_name}.json + .txt")
    else:
        console.print("[yellow]No open ports found.[/yellow]")


if __name__ == "__main__":
    main()
