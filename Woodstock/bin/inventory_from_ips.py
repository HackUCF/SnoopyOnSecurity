#!/usr/bin/env python3
"""no scan just gen inv from known IPs"""
from __future__ import annotations

import argparse
from pathlib import Path

import yaml


def parse_ips(raw: str) -> list[str]:
    parts = [p.strip() for p in raw.split(",")]
    hosts = [p for p in parts if p]
    deduped: list[str] = []
    seen: set[str] = set()
    for h in hosts:
        if h in seen:
            continue
        seen.add(h)
        deduped.append(h)
    return deduped


def write_inventory(out_path: Path, group: str, hosts: list[str]) -> None:
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


def main() -> int:
    p = argparse.ArgumentParser(description="Write a YAML inventory from comma-separated IPs.")
    p.add_argument("--ips", required=True, help="Comma-separated IPs or hostnames (e.g. 10.0.0.10,10.0.0.11)")
    p.add_argument("--out", required=True, help="Output YAML inventory path")
    p.add_argument("--group", default="discovered_linux", help="Inventory group name (default: discovered_linux)")
    args = p.parse_args()

    hosts = parse_ips(args.ips)
    if not hosts:
        raise SystemExit("error: --ips produced no hosts")

    out_path = Path(args.out)
    write_inventory(out_path, args.group, hosts)
    print(f"wrote inventory: {out_path} hosts={len(hosts)} group={args.group}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
