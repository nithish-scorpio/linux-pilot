"""Security validator implementing argv-level command parsing and risk tier classification."""

import re
import shlex
from pathlib import Path
from typing import List, Tuple

from pilot.security.dangerous_commands import (
    BLOCKED_DELETE_TARGETS,
    MALICIOUS_SHELL_PATTERNS,
    MALICIOUS_SHELL_REGEXES,
    SENSITIVE_PATHS,
    UNCONDITIONALLY_BLOCKED_BINARIES,
)
from pilot.security.permissions import (
    CONFIRM_BINARIES,
    SAFE_BINARIES,
    CommandRiskClassification,
    RiskTier,
)


class SecurityValidator:
    """Validates and classifies proposed terminal commands into Safe, Confirm, or Blocked tiers."""

    @classmethod
    def split_subcommands(cls, command_str: str) -> List[List[str]]:
        """Split a compound shell command (pipes, &&, ||, ;) into parsed argument lists."""
        # Replace shell operators with a unique delimiter for splitting
        cmd = command_str.strip()
        # Protect escaped operators if any, then split on pipeline or chained operators
        tokens = re.split(r"(\&\&|\|\||;|\|)", cmd)
        subcmds: List[List[str]] = []

        for part in tokens:
            part = part.strip()
            if not part or part in ("&&", "||", ";", "|"):
                continue
            try:
                argv = shlex.split(part)
                if argv:
                    subcmds.append(argv)
            except ValueError:
                # Malformed shell syntax
                subcmds.append(part.split())
        return subcmds

    @classmethod
    def classify_command(
        cls,
        command_str: str,
        reason: str = "",
    ) -> CommandRiskClassification:
        """Analyze and classify a command into SAFE, CONFIRM, or BLOCKED."""
        cmd = command_str.strip()

        # 1. Check for raw malicious shell patterns and regexes
        for pattern in MALICIOUS_SHELL_PATTERNS:
            if pattern in cmd:
                return CommandRiskClassification(
                    tier=RiskTier.BLOCKED,
                    command_str=command_str,
                    reason=reason,
                    risk_description=f"Contains prohibited exploit or destructive pattern: '{pattern}'",
                )

        for rx in MALICIOUS_SHELL_REGEXES:
            if rx.search(cmd):
                return CommandRiskClassification(
                    tier=RiskTier.BLOCKED,
                    command_str=command_str,
                    reason=reason,
                    risk_description=f"Contains prohibited exploit or destructive pipe: '{cmd}'",
                )

        # 2. Check for output redirections (write operations)
        has_redirection = bool(re.search(r"(?:>>?|2>&1|&>)", cmd))

        # Check if redirection targets sensitive paths
        if has_redirection:
            for s_path in SENSITIVE_PATHS:
                if s_path in cmd:
                    return CommandRiskClassification(
                        tier=RiskTier.BLOCKED,
                        command_str=command_str,
                        reason=reason,
                        risk_description=f"Attempting to overwrite sensitive path: '{s_path}'",
                    )

        # 3. Parse subcommands at argv level
        subcommands = cls.split_subcommands(cmd)
        if not subcommands:
            return CommandRiskClassification(
                tier=RiskTier.BLOCKED,
                command_str=command_str,
                reason=reason,
                risk_description="Empty or unparseable command",
            )

        worst_tier = RiskTier.SAFE
        reasons_list: List[str] = []
        is_sudo_present = False

        for argv in subcommands:
            tier, is_sudo, desc = cls._classify_single_argv(argv, cmd)
            if is_sudo:
                is_sudo_present = True

            if tier == RiskTier.BLOCKED:
                return CommandRiskClassification(
                    tier=RiskTier.BLOCKED,
                    command_str=command_str,
                    reason=reason,
                    risk_description=desc,
                    is_sudo=is_sudo_present,
                    subcommands=subcommands,
                )
            elif tier == RiskTier.CONFIRM:
                worst_tier = RiskTier.CONFIRM
                reasons_list.append(desc)

        # If redirection was present on what would otherwise be SAFE, escalate to CONFIRM
        if has_redirection and worst_tier == RiskTier.SAFE:
            worst_tier = RiskTier.CONFIRM
            reasons_list.append("Command contains file redirection (writes or appends to a file)")

        if is_sudo_present and worst_tier == RiskTier.SAFE:
            worst_tier = RiskTier.CONFIRM
            reasons_list.append("Elevated privileges requested via sudo")

        final_desc = "; ".join(reasons_list) if reasons_list else "Read-only inspection command"
        return CommandRiskClassification(
            tier=worst_tier,
            command_str=command_str,
            reason=reason,
            risk_description=final_desc,
            is_sudo=is_sudo_present,
            subcommands=subcommands,
        )

    @classmethod
    def _classify_single_argv(
        cls,
        argv: List[str],
        full_cmd: str,
    ) -> Tuple[RiskTier, bool, str]:
        """Classify a single argument vector."""
        if not argv:
            return RiskTier.SAFE, False, ""

        is_sudo = False
        idx = 0

        # Handle sudo prefix
        if argv[0] == "sudo":
            is_sudo = True
            idx = 1
            # Skip sudo options (e.g. -u user, -E, -n)
            while idx < len(argv) and argv[idx].startswith("-"):
                idx += 1
            if idx >= len(argv):
                return RiskTier.CONFIRM, True, "Raw sudo execution without command"

        binary = Path(argv[idx]).name.lower()
        args = argv[idx + 1 :]

        # 1. Unconditionally blocked binaries
        if binary in UNCONDITIONALLY_BLOCKED_BINARIES:
            return (
                RiskTier.BLOCKED,
                is_sudo,
                f"Binary '{binary}' is unconditionally prohibited by security policy",
            )

        # 2. Check for sensitive path access
        for arg in args:
            clean_arg = arg.strip("'\"")
            for sp in SENSITIVE_PATHS:
                if clean_arg == sp or clean_arg.startswith(f"{sp}/"):
                    # Check if read vs write or dangerous
                    if binary in ("cat", "tail", "head", "less", "more", "grep") and sp in ("/etc/shadow", "/etc/gshadow"):
                        return RiskTier.BLOCKED, is_sudo, f"Prohibited credential access: '{sp}'"
                    elif binary in CONFIRM_BINARIES or binary in ("rm", "cp", "mv", "chmod", "chown"):
                        return RiskTier.BLOCKED, is_sudo, f"Prohibited modification of sensitive path: '{sp}'"

        # 3. Check destructive delete commands (rm -rf /)
        if binary == "rm":
            has_recursive = any(flag in args for flag in ("-r", "-R", "--recursive")) or any(
                f.startswith("-") and ("r" in f or "R" in f) for f in args if f.startswith("-") and not f.startswith("--")
            )
            has_force = any(flag in args for flag in ("-f", "--force")) or any(
                f.startswith("-") and ("f" in f) for f in args if f.startswith("-") and not f.startswith("--")
            )

            # Check targets
            targets = [a for a in args if not a.startswith("-")]
            for target in targets:
                clean_target = target.strip("'\"").rstrip("/")
                if clean_target in BLOCKED_DELETE_TARGETS or clean_target == "":
                    return (
                        RiskTier.BLOCKED,
                        is_sudo,
                        f"Refusing broad destructive delete on system root: 'rm {target}'",
                    )
            # Non-blocked rm requires confirmation
            return RiskTier.CONFIRM, is_sudo, f"File deletion: 'rm {' '.join(args)}'"

        # 4. Check find with destructive flags
        if binary == "find":
            if "-delete" in args or "-exec" in args:
                return RiskTier.CONFIRM, is_sudo, "find command with execution or deletion flags"

        # 5. Specialized checks for systemctl
        if binary == "systemctl":
            sub = next((a for a in args if not a.startswith("-")), "")
            if sub in ("status", "is-active", "is-enabled", "is-failed", "list-units", "list-unit-files"):
                return RiskTier.SAFE, is_sudo, f"Systemctl read-only status query ({sub})"
            return RiskTier.CONFIRM, is_sudo, f"Service state modification via systemctl ({sub})"

        # 6. Specialized checks for git
        if binary == "git":
            sub = next((a for a in args if not a.startswith("-")), "")
            if sub in ("status", "log", "diff", "show", "branch", "rev-parse"):
                return RiskTier.SAFE, is_sudo, f"Git read-only inspection ({sub})"
            return RiskTier.CONFIRM, is_sudo, f"Git repository modification ({sub})"

        # 7. Check if binary is in SAFE set
        if binary in SAFE_BINARIES:
            if is_sudo:
                return RiskTier.CONFIRM, True, f"Running safe binary '{binary}' with sudo privilege"
            return RiskTier.SAFE, False, f"Safe read-only binary: '{binary}'"

        # 8. Check if binary is in CONFIRM set
        if binary in CONFIRM_BINARIES:
            return RiskTier.CONFIRM, is_sudo, f"Modifying operation via '{binary}'"

        # 9. Unknown binary -> Conservative default to CONFIRM
        return RiskTier.CONFIRM, is_sudo, f"Unrecognized binary '{binary}' requires user approval"
