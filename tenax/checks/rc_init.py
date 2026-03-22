from __future__ import annotations

import hashlib
import os
import pwd
import re
import stat
from pathlib import Path
from typing import Any

from tenax.utils import is_file_safe, path_exists

RC_ANALYZE_PATHS = [
    Path("/etc/rc.local"),
    Path("/etc/init.d"),
    Path("/etc/rc0.d"),
    Path("/etc/rc1.d"),
    Path("/etc/rc2.d"),
    Path("/etc/rc3.d"),
    Path("/etc/rc4.d"),
    Path("/etc/rc5.d"),
    Path("/etc/rc6.d"),
]

SAFE_SYMLINK_PREFIXES = (
    "/etc/init.d/",
    "/lib/",
    "/lib64/",
    "/usr/lib/",
    "/usr/lib64/",
    "/usr/sbin/",
    "/usr/bin/",
    "/bin/",
    "/sbin/",
)

SUSPICIOUS_TARGET_PREFIXES = (
    "/tmp/",
    "/var/tmp/",
    "/dev/shm/",
    "/run/user/",
    "/home/",
    "/root/",
)

TEMP_PATH_REGEX = re.compile(r"(/tmp/|/var/tmp/|/dev/shm/|/run/user/\d+/)", re.IGNORECASE)
HOME_PATH_REGEX = re.compile(r"(/home/[^/\s]+/|/root/)", re.IGNORECASE)

SHEBANG_REGEX = re.compile(
    r"^#!\s*(/bin/sh|/bin/bash|/usr/bin/sh|/usr/bin/bash|/bin/dash|/usr/bin/dash)(\s|$)",
    re.IGNORECASE,
)

DOWNLOAD_EXEC_PATTERNS: list[tuple[re.Pattern[str], int, str]] = [
    (
        re.compile(r"\bcurl\b[^\n|;]*\|\s*(sh|bash)\b", re.IGNORECASE),
        85,
        "Download-and-execute pattern via curl piped to shell",
    ),
    (
        re.compile(r"\bwget\b[^\n|;]*-O-\s*\|\s*(sh|bash)\b", re.IGNORECASE),
        85,
        "Download-and-execute pattern via wget piped to shell",
    ),
    (
        re.compile(r"\b(curl|wget)\b[^\n;]*\b(/tmp/|/var/tmp/|/dev/shm/)", re.IGNORECASE),
        60,
        "Downloader writes into a temporary execution path",
    ),
]

NETWORK_TOOL_PATTERNS: list[tuple[re.Pattern[str], int, str]] = [
    (
        re.compile(r"(^|[^\w])(nc|ncat|netcat)([^\w]|$)", re.IGNORECASE),
        35,
        "Netcat execution logic present",
    ),
    (
        re.compile(r"(^|[^\w])(socat)([^\w]|$)", re.IGNORECASE),
        40,
        "Socat execution logic present",
    ),
    (
        re.compile(r"(^|[^\w])(curl)([^\w]|$)", re.IGNORECASE),
        18,
        "Curl usage present in init artifact",
    ),
    (
        re.compile(r"(^|[^\w])(wget)([^\w]|$)", re.IGNORECASE),
        18,
        "Wget usage present in init artifact",
    ),
    (
        re.compile(r"\b(tftp|ftp)\b", re.IGNORECASE),
        30,
        "Legacy network retrieval utility present",
    ),
]

ENCODING_OBFUSCATION_PATTERNS: list[tuple[re.Pattern[str], int, str]] = [
    (
        re.compile(r"\bbase64\b", re.IGNORECASE),
        25,
        "Base64-related content present",
    ),
    (
        re.compile(r"\bopenssl\s+enc\b", re.IGNORECASE),
        30,
        "OpenSSL encoded payload handling present",
    ),
    (
        re.compile(r"\bxxd\s+-r\b", re.IGNORECASE),
        25,
        "Hex decoding logic present",
    ),
]

EXECUTION_PATTERNS: list[tuple[re.Pattern[str], int, str]] = [
    (
        re.compile(r"\bbash\s+-c\b", re.IGNORECASE),
        30,
        "Bash command execution present",
    ),
    (
        re.compile(r"\bsh\s+-c\b", re.IGNORECASE),
        30,
        "Shell command execution present",
    ),
    (
        re.compile(r"\bpython(?:2|3)?\b.*\s-c\s", re.IGNORECASE),
        35,
        "Inline Python command execution present",
    ),
    (
        re.compile(r"\bperl\b.*\s-e\s", re.IGNORECASE),
        35,
        "Inline Perl command execution present",
    ),
    (
        re.compile(r"\bnohup\b", re.IGNORECASE),
        18,
        "Detached execution via nohup present",
    ),
    (
        re.compile(r"\bsetsid\b", re.IGNORECASE),
        18,
        "Detached session execution present",
    ),
    (
        re.compile(r"\b(disown)\b", re.IGNORECASE),
        18,
        "Shell disown logic present",
    ),
]

FILE_SYSTEM_ABUSE_PATTERNS: list[tuple[re.Pattern[str], int, str]] = [
    (
        re.compile(r"\bchmod\s+(777|666|755|u\+s|g\+s|a\+x)\b", re.IGNORECASE),
        25,
        "Permission modification logic present",
    ),
    (
        re.compile(r"\bchown\b", re.IGNORECASE),
        18,
        "Ownership modification logic present",
    ),
    (
        re.compile(r"\bchattr\s+\+i\b", re.IGNORECASE),
        40,
        "File immutability logic present",
    ),
    (
        re.compile(r"\bmv\b[^\n;]*(/tmp/|/var/tmp/|/dev/shm/)", re.IGNORECASE),
        35,
        "Temporary-path file movement logic present",
    ),
]

PERSISTENCE_CHAIN_PATTERNS: list[tuple[re.Pattern[str], int, str]] = [
    (
        re.compile(r"\b(crontab|/etc/cron\.|/var/spool/cron)\b", re.IGNORECASE),
        30,
        "Init artifact references cron persistence locations",
    ),
    (
        re.compile(r"\b(systemctl|service)\b", re.IGNORECASE),
        10,
        "Service management logic present",
    ),
    (
        re.compile(r"\b(ld_preload|/etc/ld\.so\.preload)\b", re.IGNORECASE),
        45,
        "Init artifact references LD_PRELOAD persistence",
    ),
    (
        re.compile(r"\bauthorized_keys\b", re.IGNORECASE),
        45,
        "Init artifact references SSH authorized_keys persistence",
    ),
]

ALL_LINE_PATTERNS = (
    DOWNLOAD_EXEC_PATTERNS
    + NETWORK_TOOL_PATTERNS
    + ENCODING_OBFUSCATION_PATTERNS
    + EXECUTION_PATTERNS
    + FILE_SYSTEM_ABUSE_PATTERNS
    + PERSISTENCE_CHAIN_PATTERNS
)

BENIGN_LINE_PATTERNS: list[re.Pattern[str]] = [
    re.compile(r'^\s*DESC="', re.IGNORECASE),
    re.compile(r'^\s*NAME="', re.IGNORECASE),
    re.compile(r'^\s*DAEMON=', re.IGNORECASE),
    re.compile(r'^\s*PIDFILE=', re.IGNORECASE),
    re.compile(r'^\s*SCRIPTNAME=', re.IGNORECASE),
    re.compile(r'^\s*\. /lib/lsb/init-functions', re.IGNORECASE),
    re.compile(r'^\s*start-stop-daemon\b', re.IGNORECASE),
    re.compile(r'^\s*log_(daemon_msg|end_msg|success_msg|warning_msg|failure_msg)\b', re.IGNORECASE),
    re.compile(r'^\s*status_of_proc\b', re.IGNORECASE),
]

RC_NAME_REGEX = re.compile(r"^[SK]\d{2}.+")


def analyze_rc_init_locations() -> list[dict