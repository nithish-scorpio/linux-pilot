"""Filesystem path boundary enforcement and canonicalization."""

from pathlib import Path
from typing import List, Optional, Tuple

from pilot.config import get_settings
from pilot.security.dangerous_commands import SENSITIVE_PATHS

# Paths and patterns that cannot be modified even if located in allowed directories
TAMPER_PROTECTED_FILES = {
    ".env",
    ".env.local",
}


def validate_path_access(
    path: str,
    allowed_paths: Optional[List[str]] = None,
    for_write: bool = False,
) -> Tuple[bool, Optional[str], Path]:
    """Validate and canonicalize a filesystem path against security restrictions.

    Args:
        path: Path string to validate.
        allowed_paths: Optional list of directory roots permitted for access.
        for_write: Whether the path will be modified/written to.

    Returns:
        Tuple of (is_allowed, error_message_if_denied, canonical_resolved_path)
    """
    settings = get_settings()
    configured_roots = allowed_paths or settings.allowed_paths

    # 1. Expand user and resolve canonical absolute path
    raw_path = Path(path).expanduser()
    try:
        resolved_path = raw_path.resolve()
    except Exception as e:
        return False, f"Failed to resolve path: {e}", raw_path

    resolved_str = str(resolved_path)

    # 2. Prevent access to sensitive system paths (/etc/shadow, /root, /boot, etc.)
    for sp in SENSITIVE_PATHS:
        if resolved_str == sp or resolved_str.startswith(f"{sp}/"):
            return False, f"Access to sensitive path '{resolved_str}' is strictly prohibited", resolved_path

    # 3. Check against SSH keys and private credentials
    if ".ssh" in resolved_path.parts:
        for part in resolved_path.parts:
            if part.startswith("id_") or part.endswith(".pem") or part.endswith(".key"):
                return False, f"Access to SSH/private key '{resolved_path.name}' is prohibited", resolved_path

    # 4. If for write: prevent tampering with pilot's own security code or .env files
    if for_write:
        if resolved_path.name in TAMPER_PROTECTED_FILES:
            return False, f"Modifying protected configuration file '{resolved_path.name}' is prohibited", resolved_path

        # Prohibit self-modification of the security layer
        if "pilot" in resolved_path.parts and "security" in resolved_path.parts:
            return False, "Modifying the security layer codebase is strictly prohibited", resolved_path

    # 5. Check if path resides within at least one ALLOWED_PATHS directory
    resolved_roots = [Path(root).expanduser().resolve() for root in configured_roots]
    is_within_allowed = any(
        resolved_path == root or root in resolved_path.parents
        for root in resolved_roots
    )

    if not is_within_allowed:
        roots_str = ", ".join(str(r) for r in resolved_roots)
        return (
            False,
            f"Path '{resolved_str}' is outside allowed directories: [{roots_str}]",
            resolved_path,
        )

    return True, None, resolved_path
