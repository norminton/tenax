#!/bin/bash

# ==============================================================================
# Comprehensive Linux Persistence Artifact Collector
#
# This script is designed for forensic analysis to gather files and directories
# commonly used for persistence on Linux systems.
#
# USAGE: ./collect_persistence.sh <output_directory>
# ==============================================================================

# --- Usage Validation ---
if [ -z "$1" ]; then
    echo "Usage: $0 <output_directory>"
    echo "Please provide a directory name to store the collected artifacts."
    exit 1
fi

# --- Global Variables & Setup ---
OUTPUT_DIR=$1
echo " [+] Creating base output directory: $OUTPUT_DIR"
mkdir -p "$OUTPUT_DIR"
echo

# --- Function Definitions ---

# Function to copy artifacts
# Usage: copy_artifact "category" "/path/to/artifact"
copy_artifact() {
    local category=$1
    local source_path=$2
    local dest_dir="$OUTPUT_DIR/$category"

    # Expand user-specific paths
    if [[ "$source_path" == "~/"* ]]; then
        # This handles paths for the user running the script
        source_path="${HOME}/${source_path:2}"
    fi

    if [ -e "$source_path" ]; then
        echo "   -> Found: $source_path"
        mkdir -p "$dest_dir"
        cp -Rp "$source_path" "$dest_dir/"
    else
        echo "   -> Not Found: $source_path"
    fi
}

# --- Artifact Collection ---

echo " [+] Starting collection of persistence artifacts..."
echo "---------------------------------------------------"

# 1. Cron & Timed Jobs
echo " [+] Collecting Cron, Anacron, and At jobs..."
CRON_LOCATIONS=(
    "/etc/crontab" "/var/spool/cron" "/etc/cron.d" "/etc/cron.hourly"
    "/etc/cron.daily" "/etc/cron.weekly" "/etc/cron.monthly"
    "/var/spool/cron/crontabs" "/var/spool/at" "/var/spool/anacron"
)
for item in "${CRON_LOCATIONS[@]}"; do
    copy_artifact "cron_jobs" "$item"
done
echo

# 2. Systemd & Init Systems
echo " [+] Collecting Systemd, Init.d, and RC scripts..."
INIT_LOCATIONS=(
    "/etc/systemd/system" "/usr/lib/systemd/system" "/lib/systemd/system"
    "/var/lib/systemd/" "/etc/init.d" "/etc/rc.local" "/etc/rc0.d" "/etc/rc1.d"
    "/etc/rc2.d" "/etc/rc3.d" "/etc/rc4.d" "/etc/rc5.d" "/etc/rc6.d"
)
for item in "${INIT_LOCATIONS[@]}"; do
    copy_artifact "init_systems" "$item"
done
echo

# 3. Shell Configuration & Startup Scripts
echo " [+] Collecting system-wide and user-specific shell configurations..."
SHELL_CONFIGS=(
    "/etc/profile" "/etc/profile.d" "/etc/bash.bashrc" "/etc/environment"
)
for item in "${SHELL_CONFIGS[@]}"; do
    copy_artifact "shell_configs" "$item"
done
# User-specific shell files
for user_home in /home/*; do
    if [ -d "$user_home" ]; then
        USER_SHELL_FILES=(".bashrc" ".bash_profile" ".profile" ".zshrc")
        for shell_file in "${USER_SHELL_FILES[@]}"; do
            copy_artifact "shell_configs/users/$(basename "$user_home")" "$user_home/$shell_file"
        done
    fi
done
# Root user's shell files
ROOT_SHELL_FILES=("/root/.bashrc" "/root/.bash_profile" "/root/.profile" "/root/.zshrc")
for shell_file in "${ROOT_SHELL_FILES[@]}"; do
    copy_artifact "shell_configs/users/root" "$shell_file"
done
echo

# 4. SSH & Sudoers
echo " [+] Collecting SSH keys/config and Sudoers files..."
SSH_SUDO_LOCATIONS=(
    "/etc/ssh/sshd_config" "/etc/sudoers" "/etc/sudoers.d"
)
for item in "${SSH_SUDO_LOCATIONS[@]}"; do
    copy_artifact "ssh_sudo" "$item"
done
# Authorized keys
copy_artifact "ssh_sudo/users/root" "/root/.ssh/authorized_keys"
for user_home in /home/*; do
    if [ -d "$user_home" ]; then
        copy_artifact "ssh_sudo/users/$(basename "$user_home")" "$user_home/.ssh/authorized_keys"
    fi
done
echo

# 5. User & Password Files
echo " [+] Collecting user and password hashes..."
USER_PASS_LOCATIONS=("/etc/passwd" "/etc/shadow")
for item in "${USER_PASS_LOCATIONS[@]}"; do
    copy_artifact "users" "$item"
done
echo

# 6. Shared Libraries & Modules
echo " [+] Collecting shared library preloads, kernel modules, and configs..."
LIB_MOD_LOCATIONS=(
    "/etc/ld.so.preload" "/etc/ld.so.conf" "/etc/ld.so.conf.d" "/etc/modules"
    "/etc/modules-load.d" "/etc/modprobe.d"
)
for item in "${LIB_MOD_LOCATIONS[@]}"; do
    copy_artifact "libs_and_modules" "$item"
done
echo

# 7. Network Scripts
echo " [+] Collecting network interface scripts..."
NETWORK_SCRIPTS=(
    "/etc/network/if-up.d" "/etc/network/if-down.d"
    "/etc/network/if-pre-up.d" "/etc/network/if-post-down.d"
)
for item in "${NETWORK_SCRIPTS[@]}"; do
    copy_artifact "network_scripts" "$item"
done
echo

# 8. World-Writable & Common Exploit Directories
echo " [+] Collecting contents of common target directories..."
COMMON_TARGETS=(
    "/usr/local/bin" "/usr/local/sbin" "/opt" "/var/tmp" "/tmp" "/dev/shm"
)
for item in "${COMMON_TARGETS[@]}"; do
    copy_artifact "common_targets" "$item"
done
echo

# 9. Miscellaneous & Other
echo " [+] Collecting miscellaneous persistence locations..."
MISC_LOCATIONS=(
    "/etc/logrotate.d" "/boot"
)
for item in "${MISC_LOCATIONS[@]}"; do
    copy_artifact "misc" "$item"
done
# Autostart applications
for user_home in /home/*; do
    if [ -d "$user_home" ]; then
        copy_artifact "misc/users/$(basename "$user_home")" "$user_home/.config/autostart"
    fi
done
copy_artifact "misc/users/root" "/root/.config/autostart"
echo

# --- Completion ---
echo "---------------------------------------------------"
echo " [+] Collection complete. All findings are located in categorized subdirectories within '$OUTPUT_DIR'."
echo " [+] Remember to review the script's output for any 'Not Found' messages."
