#!/usr/bin/env python3
"""Read fingerprints JSON and generate categorized inventory."""
from __future__ import annotations

import argparse
import json
from pathlib import Path

import yaml


def load_fingerprints(path: Path) -> list[dict]:
    with path.open("r", encoding="utf-8") as f:
        return json.load(f)


def categorize_hosts(fingerprints: list[dict]) -> dict[str, list[dict]]:
    """Categorize hosts based on fingerprint data."""
    categories: dict[str, list[dict]] = {
        "web": [],
        "db": [],
        "dns": [],
        "mail": [],
        "uncategorized": [],
    }

    for fp in fingerprints:
        host_info = {
            "host": fp["host"],
            "ansible_host": fp.get("ansible_host", fp["host"]),
        }

        # Add db_type as host var if it's a db host
        if fp.get("is_db"):
            host_info["db_type"] = fp.get("db_type", "none")

        categorized = False

        if fp.get("is_web"):
            categories["web"].append(host_info.copy())
            categorized = True

        if fp.get("is_db"):
            categories["db"].append(host_info.copy())
            categorized = True

        if fp.get("is_dns"):
            categories["dns"].append(host_info.copy())
            categorized = True

        if fp.get("is_mail"):
            categories["mail"].append(host_info.copy())
            categorized = True

        if not categorized:
            categories["uncategorized"].append(host_info.copy())

    return categories


def build_inventory(categories: dict[str, list[dict]]) -> dict:
    """Build Ansible inventory structure from categorized hosts."""

    def hosts_dict(hosts: list[dict]) -> dict:
        result = {}
        for h in hosts:
            host_vars = {"ansible_host": h["ansible_host"]}
            if "db_type" in h:
                host_vars["db_type"] = h["db_type"]
            result[h["host"]] = host_vars
        return result

    # Build linux group with all hosts
    all_hosts: list[dict] = []
    for cat_hosts in categories.values():
        for h in cat_hosts:
            if h not in all_hosts:
                all_hosts.append(h)

    children = {
        "web": {"hosts": hosts_dict(categories["web"])},
        "db": {"hosts": hosts_dict(categories["db"])},
        "dns": {"hosts": hosts_dict(categories["dns"])},
        "mail": {"hosts": hosts_dict(categories["mail"])},
    }

    # Add uncategorized if any
    if categories["uncategorized"]:
        children["uncategorized"] = {"hosts": hosts_dict(categories["uncategorized"])}

    return {
        "all": {
            "children": {
                "linux": {
                    "hosts": hosts_dict(all_hosts),
                    "children": children,
                }
            }
        }
    }


def write_inventory(inv: dict, path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as f:
        yaml.safe_dump(inv, f, default_flow_style=False, sort_keys=False)


def main() -> int:
    p = argparse.ArgumentParser(
        description="Generate categorized inventory from fingerprints JSON."
    )
    p.add_argument(
        "--fingerprints",
        required=True,
        help="Path to fingerprints.json from fingerprint_services.yml",
    )
    p.add_argument(
        "--out",
        required=True,
        help="Output YAML inventory path",
    )
    args = p.parse_args()

    fp_path = Path(args.fingerprints)
    if not fp_path.exists():
        raise SystemExit(f"error: fingerprints file not found: {fp_path}")

    fingerprints = load_fingerprints(fp_path)
    if not fingerprints:
        raise SystemExit("error: no fingerprints found in file")

    categories = categorize_hosts(fingerprints)
    inventory = build_inventory(categories)

    out_path = Path(args.out)
    write_inventory(inventory, out_path)

    # Summary
    print(f"wrote inventory: {out_path}")
    print(f"  total hosts: {sum(len(h) for h in categories.values())}")
    print(f"  web: {len(categories['web'])}")
    print(f"  db: {len(categories['db'])}")
    print(f"  dns: {len(categories['dns'])}")
    print(f"  mail: {len(categories['mail'])}")
    print(f"  uncategorized: {len(categories['uncategorized'])}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
