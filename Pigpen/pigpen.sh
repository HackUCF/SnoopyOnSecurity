#!/bin/bash

chmod +x rg
# Threshold for awk filtering
THRESHOLD=3

# Define directories to exclude from all searches
declare -a EXCLUDES=(
    "/proc"
    "/dev"
    "/sys"
    "/boot"
    "/snap"
    "/usr/share"
    "/usr/bin"
    "/usr/lib"
    "/usr/lib64"
    "/usr/include"
    "/usr/src"
    "/usr/src/kernels"
    "/etc/ssh/moduli"
    "/var/cache"
    "/var/log"
    "/var/snap"
    "/var/lib/apt"
    "/var/lib/dpkg"
    "/var/lib/ucf"
    "/usr/local/lib"
    "/usr/local/share"
    "/usr/local/bin"
    "/var/db"
    "/run/systemd"
    "/run/snapd"
    "/var/backups/dpkg.status.0"
    "/var/lib/yum"
    # service-specific
    "/var/www/html/roundcubemail/program/lib"
    "/opt/gitlab"
    "/etc/httpd/conf/magic"
    "/etc/apache2/magic"
    "**/*/composer.lock"
    # redbaron
    "/etc/redbaron"
    "/opt/redbaronedr"
)

# Define regex patterns to search for
declare -A REGEX_PATTERNS
REGEX_PATTERNS["SSNs"]='[0-9]{3}-[0-9]{2}-[0-9]{4}'
REGEX_PATTERNS["Emails"]='[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,6}'
REGEX_PATTERNS["PhoneNumbers"]='(\([0-9]{3}\) |[0-9]{3}[ -])[0-9]{3}[ -]?[0-9]{4}'
REGEX_PATTERNS["CreditCards"]='(?:\d{4}-?){3}\d{4}|(?:\d{4}\s?){3}\d{4}|(?:\d{4}){4}'

# Construct the exclusion glob for ripgrep
EXCLUDE_GLOB=""
for EXCLUDE in "${EXCLUDES[@]}"; do
    EXCLUDE_GLOB+="${EXCLUDE},"
done
EXCLUDE_GLOB="--glob=!{${EXCLUDE_GLOB%,}}"

IFS="|"
REGEX="${REGEX_PATTERNS[*]}"
unset IFS

mapfile -t filenames_array < <(./rg $EXCLUDE_GLOB --no-follow "$REGEX" -o -c / | awk -v threshold="$THRESHOLD" -F: '$2 > threshold && $1 !~ /\.(h|rb|c|js|js.map|py|pem|po)$/ {print}')

# ANSI escape codes for colors
RED='\033[0;31m'
NC='\033[0m'  # No Color

for filename in "${filenames_array[@]}"; do
    FILENAME=$(echo $filename | cut -d':' -f1)
    echo -e "${RED}Processing file: ${FILENAME}${NC}" # Colored output here

    for PATTERN_NAME in "${!REGEX_PATTERNS[@]}"; do
        REGEX="${REGEX_PATTERNS[$PATTERN_NAME]}"
        output=$(./rg $EXCLUDE_GLOB --no-follow "$REGEX" -o ${FILENAME} | head -n3)
    if [ -n "$output" ]; then
            echo "Found $PATTERN_NAME:"
        echo "$output"
        fi
        
    done
done
