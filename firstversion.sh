#!/bin/bash

# This script is designed to collect cron-related artifacts for forensic analysis.
# It gathers system-wide and user-specific cron jobs and places them in a specified directory.

# --- Usage Validation ---
# Ensures that the user provides a destination directory when running the script.
if [ -z "$1" ]; then
    echo "Usage: $0 <output_directory>"
    echo "Please provide a directory name to store the collected artifacts."
    exit 1
fi

# --- Directory Setup ---
# Assigns the first command-line argument to the OUTPUT_DIR variable and creates it.
OUTPUT_DIR=$1
echo " [+] Creating output directory: $OUTPUT_DIR"
mkdir -p "$OUTPUT_DIR"

# --- Artifact Collection ---
echo " [+] Starting collection of cron artifacts..."

# Define the locations to check.
CRON_LOCATIONS=(
    "/etc/crontab"
    "/var/spool/cron"
    "/etc/cron.d"
    "/etc/cron.hourly"
    "/etc/cron.daily"
    "/etc/cron.weekly"
    "/etc/cron.monthly"
)

# Loop through each location to check for its existence and copy it.
for location in "${CRON_LOCATIONS[@]}"; do
    if [ -e "$location" ]; then
        echo "   -> Found: $location. Copying..."
        # The cp command uses the -R flag to copy directories recursively and preserves permissions with -p.
        cp -Rp "$location" "$OUTPUT_DIR/"
    else
        echo "   -> Not Found: $location."
    fi
done

echo
echo " [+] Collection complete. All findings are located in the '$OUTPUT_DIR' directory."

