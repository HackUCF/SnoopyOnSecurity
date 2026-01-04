#!/bin/bash
set -e
mkdir -p rules
tar -xJf windows-yara.tar.xz -C rules
cargo build --release