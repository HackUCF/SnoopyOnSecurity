#!/bin/bash

# Set the directory to search
dir="/home"

# Define regular expressions for detecting PII
creditCardRegex='\b(?:[0-9][ -]*?){13,16}\b'
addressRegex='\b[0-9]+\s\w+\s\w+\b'
ssnRegex='\b[0-9]{3}-[0-9]{2}-[0-9]{4}\b'
phoneNumberRegex='\b(?:\([0-9]{3}\)\s?|[0-9]{3}[-.]?)?[0-9]{3}[-.]?[0-9]{4}\b'

# Function to search for PII in a file
searchFileForPII() {
    filePath="$1"
    matches=()

    if grep -Pq "$creditCardRegex" "$filePath"; then
        matches+=("Credit Card Numbers: $(grep -Po "$creditCardRegex" "$filePath")")
    fi

    if grep -Pq "$addressRegex" "$filePath"; then
        matches+=("Addresses: $(grep -Po "$addressRegex" "$filePath")")
    fi

    if grep -Pq "$ssnRegex" "$filePath"; then
        matches+=("Social Security Numbers: $(grep -Po "$ssnRegex" "$filePath")")
    fi

    if grep -Pq "$phoneNumberRegex" "$filePath"; then
        matches+=("Phone Numbers: $(grep -Po "$phoneNumberRegex" "$filePath")")
    fi

    for match in "${matches[@]}"; do
        echo "File: $filePath"
        echo "$match"
        echo "------------------------"
    done
}

export -f searchFileForPII
export creditCardRegex addressRegex ssnRegex phoneNumberRegex

# Recursively search for PII in files within the /home directory
find "$dir" -type f -exec bash -c 'searchFileForPII "$0"' {} \;
