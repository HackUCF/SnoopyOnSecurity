#!/usr/bin/env python3
import sys
import os
import base64
import hashlib
import argparse


def parse_arguments(args=None):
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(
        description="Verify checksums of installed APK files",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
    %(prog)s -s                     # Silent mode, only report errors
    %(prog)s -c                     # Report only changed files
    %(prog)s -r /mnt/rootfs         # Check files in alternative root
    %(prog)s -m /path/to/checksums  # Use alternative checksums file
        """)

    parser.add_argument('-c', '--changed',
                        action='store_true',
                        help='Report changed file list to stdout (implies -s)')

    parser.add_argument('-s', '--silent',
                        action='store_true',
                        help='Only report errors')

    parser.add_argument('-m', '--md5sums',
                        metavar='file',
                        default='/lib/apk/db/installed',
                        help='Read list of checksums from file')

    parser.add_argument('-r', '--root',
                        metavar='dir',
                        default='/',
                        help='Root directory to check (default /)')

    return parser.parse_args(args)

def verify_checksums(checksums, args):
    """Verify file checksums against the database."""
    ok_count = 0
    failed_count = 0
    missing_count = 0

    for filepath, info in sorted(checksums.items()):
        stored_hash = info['checksum']
        package_name = info['package']
        full_path = os.path.join(args.root, filepath.lstrip('/'))

        if not os.path.exists(full_path):
            if not args.silent:
                print(f"MISSING: {filepath} (from {package_name})", file=sys.stderr)
            missing_count += 1
            continue

        calculated_hash = calculate_sha1(full_path)
        if calculated_hash is None:
            if not args.silent:
                print(f"ERROR: Cannot read {filepath} (from {package_name})", file=sys.stderr)
            failed_count += 1
        elif calculated_hash != stored_hash:
            if args.changed:
                print(f"{filepath} (from {package_name})")
            elif not args.silent:
                if os.path.islink(full_path):
                    target = os.readlink(full_path)
                    print(f"FAILED: {filepath} -> {target} (from {package_name})", file=sys.stderr)
                else:
                    print(f"FAILED: {filepath} (from {package_name})", file=sys.stderr)
                print(f"  Expected: {stored_hash}", file=sys.stderr)
                print(f"  Got:      {calculated_hash}", file=sys.stderr)
            failed_count += 1
        else:
            if not args.silent and not args.changed:
                if os.path.islink(full_path):
                    target = os.readlink(full_path)
                    print(f"OK: {filepath} -> {target} (from {package_name})")
                else:
                    print(f"OK: {filepath} (from {package_name})")
            ok_count += 1

    if not args.silent and not args.changed:
        print("\nSummary:", file=sys.stderr)
        print(f"OK: {ok_count}", file=sys.stderr)
        print(f"Failed: {failed_count}", file=sys.stderr)
        print(f"Missing: {missing_count}", file=sys.stderr)

    return failed_count == 0 and missing_count == 0

def read_installed_db(db_path):
    """Parse the installed database and extract file checksums."""
    checksums = {}

    with open(db_path) as f:
        package_lines = []
        for line in f:
            if line.strip():
                package_lines.append(line.strip())
            else:
                if package_lines:
                    process_package(package_lines, checksums)
                package_lines = []

        if package_lines:
            process_package(package_lines, checksums)

    return checksums

def process_package(package_lines, checksums):
    """Process a single package entry."""
    current_dir = None
    current_file = None
    package_name = None

    for line in package_lines:
        key, value = line[0], line[2:]

        if key == 'P':  # Package name
            package_name = value
        elif key == 'F':  # Directory
            current_dir = value
        elif key == 'R':  # Regular file
            current_file = value
        elif key == 'Z':  # Checksum
            if value.startswith('Q1') and current_dir and current_file and package_name:
                full_path = os.path.join(current_dir, current_file)
                checksums[full_path] = {
                    'checksum': value[2:],  # Remove Q1 prefix
                    'package': package_name
                }
                current_file = None
            else:
                print(f"Error package {package_name} uses unsupported hash.", package_name, file=sys.stderr)

def calculate_sha1(filepath):
    """Calculate SHA1 hash of a file or symlink."""
    sha1 = hashlib.sha1()
    try:
        if os.path.islink(filepath):
            # For symlinks, hash the target path
            target = os.readlink(filepath)
            sha1.update(target.encode('utf-8'))
        else:
            # For regular files, hash the contents
            with open(filepath, 'rb') as f:
                for chunk in iter(lambda: f.read(4096), b''):
                    sha1.update(chunk)
        return base64.b64encode(sha1.digest()).decode('ascii')
    except (IOError, OSError) as e:
        print(f"Error reading {filepath}: {e}", file=sys.stderr)
        return None


def main():
    args = parse_arguments()

    # --changed implies --silent
    if args.changed:
        args.silent = True

    if not args.silent:
        print(f"Reading package database from {args.md5sums}...", file=sys.stderr)

    try:
        checksums = read_installed_db(args.md5sums)
    except FileNotFoundError:
        print(f"Error: Could not open checksums file: {args.md5sums}", file=sys.stderr)
        sys.exit(1)

    if not args.silent:
        print(f"Verifying file checksums (root: {args.root})...", file=sys.stderr)

    success = verify_checksums(checksums, args)
    sys.exit(0 if success else 1)

# Keep existing read_installed_db(), process_package(), and calculate_sha1() functions as they are

if __name__ == "__main__":
    main()
