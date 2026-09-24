"""Permissions classification, risk models, and command allow/confirm lists."""

from enum import Enum
from typing import Dict, List, Optional, Set
from pydantic import BaseModel, Field


class RiskTier(str, Enum):
    """Security risk classification for tool and command operations."""

    SAFE = "safe"          # Read-only, safe to run automatically
    CONFIRM = "confirm"    # Modifies system/files, requires user approval
    BLOCKED = "blocked"    # Dangerous or destructive, prohibited


class CommandRiskClassification(BaseModel):
    """Structured security risk classification for a shell command."""

    tier: RiskTier
    command_str: str
    reason: str
    risk_description: str
    is_sudo: bool = False
    subcommands: List[List[str]] = Field(default_factory=list)


# Read-only binaries considered SAFE when invoked without destructive flags or redirections
SAFE_BINARIES: Set[str] = {
    "pwd",
    "ls",
    "cat",
    "head",
    "tail",
    "grep",
    "egrep",
    "fgrep",
    "df",
    "du",
    "free",
    "uptime",
    "uname",
    "whoami",
    "ps",
    "top",
    "ip",
    "which",
    "whereis",
    "date",
    "hostname",
    "id",
    "wc",
    "stat",
    "file",
    "diff",
    "find",
    "echo",
    "sort",
    "uniq",
    "cut",
    "awk",
    "sed",
    "systemctl",     # SAFE only with 'status', 'is-active', etc.
    "git",           # SAFE only with 'status', 'log', 'diff', 'show'
    "sleep",         # Safe waiting utility
}

# Modifying binaries requiring explicit CONFIRMATION
CONFIRM_BINARIES: Set[str] = {
    "touch",
    "mkdir",
    "cp",
    "mv",
    "rm",
    "chmod",
    "chown",
    "chgrp",
    "apt",
    "apt-get",
    "dpkg",
    "dnf",
    "yum",
    "pacman",
    "zypper",
    "pip",
    "npm",
    "systemctl",
    "service",
    "git",
    "tar",
    "gzip",
    "unzip",
    "curl",
    "wget",
}
