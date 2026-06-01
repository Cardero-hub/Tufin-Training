#!/usr/bin/env python3
"""
Server Health Reporting Tool

What this script does:
- Collects system health information from the server
- Works on both macOS (Darwin) and Linux environments
- Generates a report in either TXT or JSON format

Arguments:
--format txt   -> saves human-readable report (default)
--format json  -> saves structured JSON report

Output:
- tufin-lab/logs/health-report.txt
- tufin-lab/logs/health-report.json
"""

import argparse
import subprocess
import json
import platform
from pathlib import Path


def run_command(command):
    """Run a shell command and return output safely."""
    try:
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            check=True
        )
        return result.stdout.strip()
    except Exception as e:
        return f"ERROR: {str(e)}"


def get_platform_commands():
    """Return OS-specific commands for compatibility."""
    system = platform.system()

    if system == "Darwin":  # macOS
        return {
            "memory": ["vm_stat"],
            "ports": ["lsof", "-i", "-P", "-n"]
        }
    else:  # Linux
        return {
            "memory": ["free", "-h"],
            "ports": ["ss", "-tuln"]
        }


def collect_health_data():
    """Collect system health information."""
    cmds = get_platform_commands()

    return {
        "hostname": run_command(["hostname"]),
        "uptime": run_command(["uptime"]),
        "disk_space": run_command(["df", "-h"]),
        "memory": run_command(cmds["memory"]),
        "listening_ports": run_command(cmds["ports"])
    }


def save_txt(data, path):
    """Save human-readable report."""
    with open(path, "w") as f:
        f.write("SERVER HEALTH REPORT\n")
        f.write("=" * 50 + "\n\n")

        for key, value in data.items():
            f.write(f"{key.upper()}:\n")
            f.write(f"{value}\n\n")


def save_json(data, path):
    """Save structured JSON report."""
    with open(path, "w") as f:
        json.dump(data, f, indent=4)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--format",
        choices=["txt", "json"],
        default="txt"
    )

    args = parser.parse_args()

    data = collect_health_data()

    output_dir = Path("tufin-lab/logs")
    output_dir.mkdir(parents=True, exist_ok=True)

    if args.format == "json":
        output_file = output_dir / "health-report.json"
        save_json(data, output_file)
    else:
        output_file = output_dir / "health-report.txt"
        save_txt(data, output_file)

    print(f"Report saved: {output_file} ({args.format})")


if __name__ == "__main__":
    main()
