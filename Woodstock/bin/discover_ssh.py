#!/usr/bin/env python3
"""scan -> inv"""
from __future__ import annotations

import argparse
import os
import re
import socket
import subprocess
import sys
from pathlib import Path

import yaml


def _read_banner(host: str, port: int, timeout: float) -> str:
    try:
        with socket.create_connection((host, port), timeout=timeout) as s:
            s.settimeout(timeout)
            data = s.recv(256)
            return data.decode("utf-8", errors="ignore").strip()
    except Exception:
        return ""


def _parse_rustscan_output(output: str, port: int) -> list[str]:
    """Parse rustscan output format: '198.18.0.1 -> [22]'"""
    hosts: list[str] = []
    # Match lines like: "198.18.0.1 -> [22]" or "198.18.0.1 -> [22,80]"
    pattern = re.compile(r"^(\d+\.\d+\.\d+\.\d+)\s*->\s*\[([0-9,]+)\]")

    for line in output.splitlines():
        line = line.strip()
        if not line:
            continue

        match = pattern.match(line)
        if match:
            ip = match.group(1)
            ports_str = match.group(2)
            # Check if our target port is in the list of open ports
            open_ports = [int(p.strip()) for p in ports_str.split(",")]
            if port in open_ports:
                hosts.append(ip)

    return hosts


def _write_inventory(out_path: Path, group: str, hosts: list[str]) -> None:
    def host_map() -> dict[str, dict[str, str]]:
        return {h: {"ansible_host": h} for h in hosts}

    children: dict[str, dict] = {
        group: {
            "hosts": host_map(),
        }
    }
    if group != "linux":
        children["linux"] = {
            "hosts": host_map(),
        }

    inv = {
        "all": {
            "children": children
        }
    }
    out_path.parent.mkdir(parents=True, exist_ok=True)
    with out_path.open("w", encoding="utf-8") as f:
        yaml.safe_dump(inv, f, default_flow_style=False, sort_keys=False)


def main(argv: list[str]) -> int:
    p = argparse.ArgumentParser(description="Discover SSH hosts via rustscan and write a YAML inventory.")
    p.add_argument("--targets", nargs="+", required=True, help="CIDRs or targets (e.g. 10.0.0.0/24)")
    p.add_argument("--out", required=True, help="Output YAML inventory path")
    p.add_argument("--port", type=int, default=22, help="SSH port (default: 22)")
    p.add_argument("--group", default="discovered_linux", help="Inventory group name (default: discovered_linux)")
    p.add_argument("--timeout", type=float, default=1.5, help="Banner read timeout seconds (default: 1.5)")
    p.add_argument("--batch-size", type=int, default=4500, help="Rustscan batch size (default: 4500)")
    args = p.parse_args(argv)

    # if not shutil_which("rustscan"):
    #     print("error: rustscan not found in PATH", file=sys.stderr)
    #     return 2

    # Build rustscan command
    # -a: addresses (comma-separated)
    # -p: ports
    # -g: greppable output format
    # --no-banner: suppress rustscan ASCII art
    # -b: batch size for faster scanning
    targets = ",".join(args.targets)
    cmd = [
        "rustscan",
        "-a", targets,
        "-p", str(args.port),
        "-g",
        "--no-banner",
        "-b", str(args.batch_size),
    ]

    proc = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    if proc.returncode != 0:
        sys.stderr.write(proc.stderr)
        print("error: rustscan failed", file=sys.stderr)
        return 2

    hosts = _parse_rustscan_output(proc.stdout, port=args.port)
    if not hosts:
        print("warning: no hosts found with open SSH ports", file=sys.stderr)

    linux_hosts: list[str] = []
    windows_hosts: list[str] = []

    # Read SSH banners to distinguish Windows vs Linux
    for h in hosts:
        banner = _read_banner(h, args.port, timeout=args.timeout)
        if "OpenSSH_for_Windows" in banner:
            windows_hosts.append(h)
            continue
        linux_hosts.append(h)

    out_path = Path(args.out)
    _write_inventory(out_path, args.group, linux_hosts)

    print(f"discovered: total={len(hosts)} linux={len(linux_hosts)} windows_ssh={len(windows_hosts)}")
    if windows_hosts:
        print("windows_ssh_hosts:")
        for h in windows_hosts:
            print(f"  - {h}")
    return 0


def shutil_which(cmd: str) -> str | None:
    for p in os.environ.get("PATH", "").split(os.pathsep):
        cand = Path(p) / cmd
        if cand.exists() and os.access(cand, os.X_OK):
            return str(cand)
    return None


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
