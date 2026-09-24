"""Dangerous command definitions, blocked patterns, and sensitive target paths.

Used by the SecurityValidator to detect destructive, malicious, or state-destroying commands.
"""

import re
from typing import List, Pattern, Set

# Commands that are unconditionally blocked
UNCONDITIONALLY_BLOCKED_BINARIES: Set[str] = {
    "mkfs",
    "fdisk",
    "sfdisk",
    "cfdisk",
    "parted",
    "gdisk",
    "reboot",
    "shutdown",
    "poweroff",
    "halt",
    "init",
}

# Sensitive paths where read/write/delete operations are forbidden
SENSITIVE_PATHS: Set[str] = {
    "/etc/shadow",
    "/etc/gshadow",
    "/etc/sudoers",
    "/etc/sudoers.d",
    "/root",
    "/boot",
    "/dev",
    "/proc/kcore",
    "/sys/firmware",
}

# Broad root / parent paths that must NEVER be recursively deleted
BLOCKED_DELETE_TARGETS: Set[str] = {
    "/",
    "/*",
    "/bin",
    "/boot",
    "/dev",
    "/etc",
    "/home",
    "/lib",
    "/lib64",
    "/opt",
    "/proc",
    "/root",
    "/sys",
    "/usr",
    "/var",
    "~",
    "~/",
    "$HOME",
}

# Substrings or patterns indicating deliberate exploits or shell attacks
MALICIOUS_SHELL_PATTERNS: List[str] = [
    ":(){ :|:& };:",    # Fork bomb
    ":(){:|:&};:",      # Fork bomb compact
    ">/dev/sda",        # Raw disk overwrite
    ">/dev/nvme",       # Raw NVMe overwrite
    "dd if=",           # Dangerous dd
    "mkfs.",            # Filesystem formatting
]

# Regex patterns detecting unsafe shell piping
MALICIOUS_SHELL_REGEXES: List[Pattern] = [
    re.compile(r"(?:curl|wget)\b.*?\|\s*(?:sudo\s+)?(?:bash|sh|zsh|dash)\b", re.IGNORECASE),
]
