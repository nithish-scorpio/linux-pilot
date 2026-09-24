"""Package manager abstraction and tools for Linux Command Pilot.

Supports Ubuntu/Debian (apt), Fedora (dnf), and Arch Linux (pacman).
Enforces input validation on package names and strict confirmation for modifying operations.
"""

from dataclasses import dataclass
import os
from pathlib import Path
import re
import shutil
import subprocess
import time
from typing import Any, Callable, Dict, List, Optional, Protocol, runtime_checkable

from pilot.security.permissions import RiskTier
from pilot.tools.base import BaseTool, ToolResult
from pilot.ui.terminal import confirm_prompt, console

# Valid package name pattern (alphanumeric, plus, dot, hyphen, underscore, at)
PACKAGE_NAME_REGEX = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9_\+\.\@\-]*$")


def validate_package_name(name: str) -> bool:
    """Validate that a package name contains only permitted, safe characters."""
    if not name or not isinstance(name, str):
        return False
    # Max length guard and regex matching
    if len(name) > 128:
        return False
    return bool(PACKAGE_NAME_REGEX.match(name.strip()))


@dataclass
class PackageResult:
    """Structured result from a package manager operation."""

    success: bool
    message: str
    command: Optional[str] = None
    stdout: Optional[str] = None
    stderr: Optional[str] = None
    exit_code: Optional[int] = None
    data: Optional[Dict[str, Any]] = None


# Alias Result to PackageResult to match protocol specification in Section 10
Result = PackageResult


@runtime_checkable
class PackageManager(Protocol):
    """Protocol for distro-independent package managers."""

    def install(self, name: str, reason: str = "") -> Result:
        """Install a package by name."""
        ...

    def remove(self, name: str, reason: str = "") -> Result:
        """Remove a package by name."""
        ...

    def search(self, name: str) -> Result:
        """Search repositories for packages matching name or query."""
        ...

    def update(self, reason: str = "") -> Result:
        """Refresh repository metadata and package indexes."""
        ...

    def is_installed(self, name: str) -> bool:
        """Check if a package is installed locally on the system."""
        ...


class BasePackageManager:
    """Base implementation providing shared confirmation and execution utilities."""

    name: str = "generic"
    distro: str = "linux"

    def __init__(self, confirm_handler: Optional[Callable[[str, str, str], bool]] = None):
        self.confirm_handler = confirm_handler or confirm_prompt

    def _run_cmd(
        self,
        cmd: List[str],
        timeout: float = 60.0,
        env: Optional[Dict[str, str]] = None,
    ) -> subprocess.CompletedProcess:
        """Run command list directly without shell interpolation."""
        full_env = os.environ.copy()
        if env:
            full_env.update(env)
        return subprocess.run(
            cmd,
            shell=False,
            capture_output=True,
            text=True,
            timeout=timeout,
            stdin=subprocess.DEVNULL,
            env=full_env,
            check=False,
        )


class AptPackageManager(BasePackageManager):
    """Ubuntu / Debian package manager using apt, dpkg-query, and apt-cache."""

    name = "apt"
    distro = "debian/ubuntu"

    def is_installed(self, name: str) -> bool:
        """Check if package is installed via dpkg-query."""
        if not validate_package_name(name):
            return False
        cmd = ["dpkg-query", "-W", "-f=${Status}", name]
        try:
            res = self._run_cmd(cmd, timeout=10.0)
            return res.returncode == 0 and "install ok installed" in res.stdout
        except Exception:
            return False

    def search(self, name: str) -> Result:
        """Search packages via apt-cache search."""
        if not validate_package_name(name) and not re.match(r"^[a-zA-Z0-9_\-\.\*]+$", name):
            return Result(success=False, message="Invalid search query pattern")

        cmd = ["apt-cache", "search", name]
        try:
            res = self._run_cmd(cmd, timeout=30.0)
            if res.returncode != 0:
                return Result(
                    success=False,
                    message=f"apt-cache search failed with exit code {res.returncode}",
                    stderr=res.stderr,
                    exit_code=res.returncode,
                )

            packages = []
            for line in res.stdout.strip().splitlines()[:50]:
                if " - " in line:
                    pkg, desc = line.split(" - ", 1)
                    packages.append({"name": pkg.strip(), "description": desc.strip()})
                elif line.strip():
                    packages.append({"name": line.strip(), "description": ""})

            return Result(
                success=True,
                message=f"Found {len(packages)} packages matching '{name}'",
                command=" ".join(cmd),
                stdout=res.stdout,
                exit_code=res.returncode,
                data={"query": name, "count": len(packages), "packages": packages},
            )
        except Exception as e:
            return Result(success=False, message=f"Search failed: {e}")

    def install(self, name: str, reason: str = "") -> Result:
        """Install package via apt-get install after confirmation."""
        if not validate_package_name(name):
            return Result(success=False, message=f"Security violation: Invalid package name '{name}'")

        cmd = ["sudo", "DEBIAN_FRONTEND=noninteractive", "apt-get", "install", "-y", name]
        cmd_str = f"sudo apt-get install -y {name}"
        reason_str = reason or f"Install package '{name}'"
        risk_str = f"Modifies system packages; installs '{name}' and its dependencies with root privileges"

        approved = self.confirm_handler(cmd_str, reason_str, risk_str)
        if not approved:
            return Result(success=False, message=f"Operation cancelled: User rejected installing '{name}'")

        try:
            res = self._run_cmd(
                ["sudo", "apt-get", "install", "-y", name],
                env={"DEBIAN_FRONTEND": "noninteractive"},
                timeout=180.0,
            )
            success = (res.returncode == 0)
            return Result(
                success=success,
                message=f"Successfully installed '{name}'" if success else f"Installation failed with code {res.returncode}",
                command=cmd_str,
                stdout=res.stdout,
                stderr=res.stderr,
                exit_code=res.returncode,
            )
        except Exception as e:
            return Result(success=False, message=f"Execution error: {e}")

    def remove(self, name: str, reason: str = "") -> Result:
        """Remove package via apt-get remove after confirmation."""
        if not validate_package_name(name):
            return Result(success=False, message=f"Security violation: Invalid package name '{name}'")

        cmd_str = f"sudo apt-get remove -y {name}"
        reason_str = reason or f"Remove package '{name}'"
        risk_str = f"Removes package '{name}' and potentially packages depending on it"

        approved = self.confirm_handler(cmd_str, reason_str, risk_str)
        if not approved:
            return Result(success=False, message=f"Operation cancelled: User rejected removing '{name}'")

        try:
            res = self._run_cmd(
                ["sudo", "apt-get", "remove", "-y", name],
                env={"DEBIAN_FRONTEND": "noninteractive"},
                timeout=120.0,
            )
            success = (res.returncode == 0)
            return Result(
                success=success,
                message=f"Successfully removed '{name}'" if success else f"Removal failed with code {res.returncode}",
                command=cmd_str,
                stdout=res.stdout,
                stderr=res.stderr,
                exit_code=res.returncode,
            )
        except Exception as e:
            return Result(success=False, message=f"Execution error: {e}")

    def update(self, reason: str = "") -> Result:
        """Refresh package indexes via apt-get update after confirmation."""
        cmd_str = "sudo apt-get update"
        reason_str = reason or "Refresh system package repository indexes"
        risk_str = "Downloads updated package lists from repository mirrors"

        approved = self.confirm_handler(cmd_str, reason_str, risk_str)
        if not approved:
            return Result(success=False, message="Operation cancelled: User rejected updating package index")

        try:
            res = self._run_cmd(["sudo", "apt-get", "update"], timeout=120.0)
            success = (res.returncode == 0)
            return Result(
                success=success,
                message="Package repositories updated successfully" if success else f"Update failed with code {res.returncode}",
                command=cmd_str,
                stdout=res.stdout,
                stderr=res.stderr,
                exit_code=res.returncode,
            )
        except Exception as e:
            return Result(success=False, message=f"Execution error: {e}")


class DnfPackageManager(BasePackageManager):
    """Fedora / RHEL package manager using dnf and rpm."""

    name = "dnf"
    distro = "fedora/rhel"

    def is_installed(self, name: str) -> bool:
        """Check if package is installed via rpm -q."""
        if not validate_package_name(name):
            return False
        cmd = ["rpm", "-q", name]
        try:
            res = self._run_cmd(cmd, timeout=10.0)
            return res.returncode == 0
        except Exception:
            return False

    def search(self, name: str) -> Result:
        """Search packages via dnf search."""
        if not validate_package_name(name) and not re.match(r"^[a-zA-Z0-9_\-\.\*]+$", name):
            return Result(success=False, message="Invalid search query pattern")

        cmd = ["dnf", "search", name]
        try:
            res = self._run_cmd(cmd, timeout=30.0)
            if res.returncode != 0:
                return Result(
                    success=False,
                    message=f"dnf search failed with exit code {res.returncode}",
                    stderr=res.stderr,
                    exit_code=res.returncode,
                )

            packages = []
            for line in res.stdout.strip().splitlines()[:50]:
                if " : " in line:
                    pkg, desc = line.split(" : ", 1)
                    packages.append({"name": pkg.strip(), "description": desc.strip()})
                elif line.strip() and not line.startswith("="):
                    packages.append({"name": line.strip(), "description": ""})

            return Result(
                success=True,
                message=f"Found {len(packages)} packages matching '{name}'",
                command=" ".join(cmd),
                stdout=res.stdout,
                exit_code=res.returncode,
                data={"query": name, "count": len(packages), "packages": packages},
            )
        except Exception as e:
            return Result(success=False, message=f"Search failed: {e}")

    def install(self, name: str, reason: str = "") -> Result:
        """Install package via dnf install after confirmation."""
        if not validate_package_name(name):
            return Result(success=False, message=f"Security violation: Invalid package name '{name}'")

        cmd_str = f"sudo dnf install -y {name}"
        reason_str = reason or f"Install package '{name}'"
        risk_str = f"Modifies system packages; installs '{name}' and dependencies with root privileges"

        approved = self.confirm_handler(cmd_str, reason_str, risk_str)
        if not approved:
            return Result(success=False, message=f"Operation cancelled: User rejected installing '{name}'")

        try:
            res = self._run_cmd(["sudo", "dnf", "install", "-y", name], timeout=180.0)
            success = (res.returncode == 0)
            return Result(
                success=success,
                message=f"Successfully installed '{name}'" if success else f"Installation failed with code {res.returncode}",
                command=cmd_str,
                stdout=res.stdout,
                stderr=res.stderr,
                exit_code=res.returncode,
            )
        except Exception as e:
            return Result(success=False, message=f"Execution error: {e}")

    def remove(self, name: str, reason: str = "") -> Result:
        """Remove package via dnf remove after confirmation."""
        if not validate_package_name(name):
            return Result(success=False, message=f"Security violation: Invalid package name '{name}'")

        cmd_str = f"sudo dnf remove -y {name}"
        reason_str = reason or f"Remove package '{name}'"
        risk_str = f"Removes package '{name}' and any orphaned dependencies"

        approved = self.confirm_handler(cmd_str, reason_str, risk_str)
        if not approved:
            return Result(success=False, message=f"Operation cancelled: User rejected removing '{name}'")

        try:
            res = self._run_cmd(["sudo", "dnf", "remove", "-y", name], timeout=120.0)
            success = (res.returncode == 0)
            return Result(
                success=success,
                message=f"Successfully removed '{name}'" if success else f"Removal failed with code {res.returncode}",
                command=cmd_str,
                stdout=res.stdout,
                stderr=res.stderr,
                exit_code=res.returncode,
            )
        except Exception as e:
            return Result(success=False, message=f"Execution error: {e}")

    def update(self, reason: str = "") -> Result:
        """Refresh package metadata via dnf check-update after confirmation."""
        cmd_str = "sudo dnf check-update"
        reason_str = reason or "Check for package updates"
        risk_str = "Queries repository mirrors for available package upgrades"

        approved = self.confirm_handler(cmd_str, reason_str, risk_str)
        if not approved:
            return Result(success=False, message="Operation cancelled: User rejected checking updates")

        try:
            # dnf check-update returns 100 if updates are available, 0 if clean
            res = self._run_cmd(["sudo", "dnf", "check-update"], timeout=120.0)
            success = res.returncode in (0, 100)
            return Result(
                success=success,
                message="Metadata updated successfully" if success else f"Check-update returned code {res.returncode}",
                command=cmd_str,
                stdout=res.stdout,
                stderr=res.stderr,
                exit_code=res.returncode,
            )
        except Exception as e:
            return Result(success=False, message=f"Execution error: {e}")


class PacmanPackageManager(BasePackageManager):
    """Arch Linux package manager using pacman."""

    name = "pacman"
    distro = "arch"

    def is_installed(self, name: str) -> bool:
        """Check if package is installed via pacman -Qq."""
        if not validate_package_name(name):
            return False
        cmd = ["pacman", "-Qq", name]
        try:
            res = self._run_cmd(cmd, timeout=10.0)
            return res.returncode == 0
        except Exception:
            return False

    def search(self, name: str) -> Result:
        """Search packages via pacman -Ss."""
        if not validate_package_name(name) and not re.match(r"^[a-zA-Z0-9_\-\.\*]+$", name):
            return Result(success=False, message="Invalid search query pattern")

        cmd = ["pacman", "-Ss", name]
        try:
            res = self._run_cmd(cmd, timeout=30.0)
            if res.returncode != 0:
                return Result(
                    success=False,
                    message=f"pacman search failed with exit code {res.returncode}",
                    stderr=res.stderr,
                    exit_code=res.returncode,
                )

            packages = []
            lines = res.stdout.strip().splitlines()
            # Pacman outputs in two-line pairs: repo/name version\n    description
            for i in range(0, len(lines), 2):
                header = lines[i]
                desc = lines[i + 1].strip() if i + 1 < len(lines) else ""
                pkg_name = header.split()[0].split("/")[-1] if "/" in header else header.split()[0]
                packages.append({"name": pkg_name, "description": desc})
                if len(packages) >= 50:
                    break

            return Result(
                success=True,
                message=f"Found {len(packages)} packages matching '{name}'",
                command=" ".join(cmd),
                stdout=res.stdout,
                exit_code=res.returncode,
                data={"query": name, "count": len(packages), "packages": packages},
            )
        except Exception as e:
            return Result(success=False, message=f"Search failed: {e}")

    def install(self, name: str, reason: str = "") -> Result:
        """Install package via pacman -S after confirmation."""
        if not validate_package_name(name):
            return Result(success=False, message=f"Security violation: Invalid package name '{name}'")

        cmd_str = f"sudo pacman -S --noconfirm {name}"
        reason_str = reason or f"Install package '{name}'"
        risk_str = f"Modifies system packages; installs '{name}' and dependencies with root privileges"

        approved = self.confirm_handler(cmd_str, reason_str, risk_str)
        if not approved:
            return Result(success=False, message=f"Operation cancelled: User rejected installing '{name}'")

        try:
            res = self._run_cmd(["sudo", "pacman", "-S", "--noconfirm", name], timeout=180.0)
            success = (res.returncode == 0)
            return Result(
                success=success,
                message=f"Successfully installed '{name}'" if success else f"Installation failed with code {res.returncode}",
                command=cmd_str,
                stdout=res.stdout,
                stderr=res.stderr,
                exit_code=res.returncode,
            )
        except Exception as e:
            return Result(success=False, message=f"Execution error: {e}")

    def remove(self, name: str, reason: str = "") -> Result:
        """Remove package via pacman -R after confirmation."""
        if not validate_package_name(name):
            return Result(success=False, message=f"Security violation: Invalid package name '{name}'")

        cmd_str = f"sudo pacman -R --noconfirm {name}"
        reason_str = reason or f"Remove package '{name}'"
        risk_str = f"Removes package '{name}' from system"

        approved = self.confirm_handler(cmd_str, reason_str, risk_str)
        if not approved:
            return Result(success=False, message=f"Operation cancelled: User rejected removing '{name}'")

        try:
            res = self._run_cmd(["sudo", "pacman", "-R", "--noconfirm", name], timeout=120.0)
            success = (res.returncode == 0)
            return Result(
                success=success,
                message=f"Successfully removed '{name}'" if success else f"Removal failed with code {res.returncode}",
                command=cmd_str,
                stdout=res.stdout,
                stderr=res.stderr,
                exit_code=res.returncode,
            )
        except Exception as e:
            return Result(success=False, message=f"Execution error: {e}")

    def update(self, reason: str = "") -> Result:
        """Refresh package database via pacman -Sy after confirmation."""
        cmd_str = "sudo pacman -Sy"
        reason_str = reason or "Refresh pacman package database"
        risk_str = "Synchronizes repository databases with remote mirrors"

        approved = self.confirm_handler(cmd_str, reason_str, risk_str)
        if not approved:
            return Result(success=False, message="Operation cancelled: User rejected synchronizing databases")

        try:
            res = self._run_cmd(["sudo", "pacman", "-Sy"], timeout=120.0)
            success = (res.returncode == 0)
            return Result(
                success=success,
                message="Package databases synchronized successfully" if success else f"Sync failed with code {res.returncode}",
                command=cmd_str,
                stdout=res.stdout,
                stderr=res.stderr,
                exit_code=res.returncode,
            )
        except Exception as e:
            return Result(success=False, message=f"Execution error: {e}")


def detect_package_manager(
    confirm_handler: Optional[Callable[[str, str, str], bool]] = None,
    os_release_path: Optional[str] = None,
) -> PackageManager:
    """Detect Linux distribution and return the appropriate PackageManager instance."""
    release_path = Path(os_release_path or "/etc/os-release")
    distro_id = ""
    distro_like = ""

    if release_path.exists():
        try:
            with open(release_path, "r", encoding="utf-8") as f:
                for line in f:
                    if line.startswith("ID="):
                        distro_id = line.strip().split("=", 1)[1].strip('"').strip("'").lower()
                    elif line.startswith("ID_LIKE="):
                        distro_like = line.strip().split("=", 1)[1].strip('"').strip("'").lower()
        except Exception:
            pass

    # Match based on /etc/os-release ID or ID_LIKE
    combined = f"{distro_id} {distro_like}"
    if any(k in combined for k in ("ubuntu", "debian", "linuxmint", "pop", "kali")):
        return AptPackageManager(confirm_handler=confirm_handler)
    if any(k in combined for k in ("fedora", "rhel", "centos", "rocky", "alma")):
        return DnfPackageManager(confirm_handler=confirm_handler)
    if any(k in combined for k in ("arch", "manjaro", "endeavouros")):
        return PacmanPackageManager(confirm_handler=confirm_handler)

    # Fallback to checking available binaries on system PATH
    if shutil.which("apt-get"):
        return AptPackageManager(confirm_handler=confirm_handler)
    if shutil.which("dnf"):
        return DnfPackageManager(confirm_handler=confirm_handler)
    if shutil.which("pacman"):
        return PacmanPackageManager(confirm_handler=confirm_handler)

    # Default to AptPackageManager
    return AptPackageManager(confirm_handler=confirm_handler)


# =====================================================================
# Dedicated Agent Tools Exposing Package Operations
# =====================================================================


class PackageCheckInstalledTool(BaseTool):
    """Check if a specific package is installed locally."""

    name = "is_package_installed"
    description = (
        "Check whether a specific software package is installed on the local system. "
        "Returns boolean status without modifying system state."
    )
    risk_tier = RiskTier.SAFE

    def __init__(self, pkg_manager: Optional[PackageManager] = None):
        self.pkg_manager = pkg_manager or detect_package_manager()

    @property
    def parameters_schema(self) -> Dict[str, Any]:
        return {
            "type": "object",
            "properties": {
                "package_name": {
                    "type": "string",
                    "description": "Name of the package to check (e.g. 'nginx', 'python3', 'curl')",
                }
            },
            "required": ["package_name"],
        }

    def run(self, arguments: Dict[str, Any], timeout: float = 30.0) -> ToolResult:
        pkg_name = arguments.get("package_name", "")
        if not validate_package_name(pkg_name):
            return ToolResult(
                success=False,
                error=f"Invalid package name '{pkg_name}'. Package names must be alphanumeric with standard separators.",
            )

        installed = self.pkg_manager.is_installed(pkg_name)
        status_str = "installed" if installed else "not installed"
        return ToolResult(
            success=True,
            data={"package_name": pkg_name, "installed": installed},
            stdout=f"Package '{pkg_name}' is {status_str}.",
        )


class PackageSearchTool(BaseTool):
    """Search repositories for packages."""

    name = "package_search"
    description = (
        "Search distribution repositories for packages matching a name or keyword. "
        "Safe read-only operation."
    )
    risk_tier = RiskTier.SAFE

    def __init__(self, pkg_manager: Optional[PackageManager] = None):
        self.pkg_manager = pkg_manager or detect_package_manager()

    @property
    def parameters_schema(self) -> Dict[str, Any]:
        return {
            "type": "object",
            "properties": {
                "query": {
                    "type": "string",
                    "description": "Keyword or package name to search for",
                }
            },
            "required": ["query"],
        }

    def run(self, arguments: Dict[str, Any], timeout: float = 30.0) -> ToolResult:
        query = arguments.get("query", "")
        res = self.pkg_manager.search(query)
        if not res.success:
            return ToolResult(success=False, error=res.message, stderr=res.stderr)

        data = res.data or {}
        packages = data.get("packages", [])
        lines = [f"Search results for '{query}':"]
        for p in packages[:25]:
            lines.append(f"  • {p['name']}: {p['description']}")

        return ToolResult(
            success=True,
            data=data,
            stdout="\n".join(lines),
        )


class PackageInstallTool(BaseTool):
    """Install a package with confirmation."""

    name = "package_install"
    description = (
        "Install a software package on the system. "
        "Requires explicit confirmation before modifying system state."
    )
    risk_tier = RiskTier.CONFIRM

    def __init__(self, pkg_manager: Optional[PackageManager] = None):
        self.pkg_manager = pkg_manager or detect_package_manager()

    @property
    def parameters_schema(self) -> Dict[str, Any]:
        return {
            "type": "object",
            "properties": {
                "package_name": {
                    "type": "string",
                    "description": "Name of the package to install",
                },
                "reason": {
                    "type": "string",
                    "description": "Explanation of why this package is needed",
                },
            },
            "required": ["package_name"],
        }

    def run(self, arguments: Dict[str, Any], timeout: float = 30.0) -> ToolResult:
        pkg_name = arguments.get("package_name", "")
        reason = arguments.get("reason", f"Install package {pkg_name}")
        res = self.pkg_manager.install(pkg_name, reason=reason)
        return ToolResult(
            success=res.success,
            data={"package_name": pkg_name, "exit_code": res.exit_code},
            stdout=res.stdout or res.message,
            stderr=res.stderr,
            error=res.message if not res.success else None,
            exit_code=res.exit_code,
        )


class PackageRemoveTool(BaseTool):
    """Remove a package with confirmation."""

    name = "package_remove"
    description = (
        "Remove a software package from the system. "
        "Requires explicit confirmation before modifying system state."
    )
    risk_tier = RiskTier.CONFIRM

    def __init__(self, pkg_manager: Optional[PackageManager] = None):
        self.pkg_manager = pkg_manager or detect_package_manager()

    @property
    def parameters_schema(self) -> Dict[str, Any]:
        return {
            "type": "object",
            "properties": {
                "package_name": {
                    "type": "string",
                    "description": "Name of the package to remove",
                },
                "reason": {
                    "type": "string",
                    "description": "Explanation of why this package is being removed",
                },
            },
            "required": ["package_name"],
        }

    def run(self, arguments: Dict[str, Any], timeout: float = 30.0) -> ToolResult:
        pkg_name = arguments.get("package_name", "")
        reason = arguments.get("reason", f"Remove package {pkg_name}")
        res = self.pkg_manager.remove(pkg_name, reason=reason)
        return ToolResult(
            success=res.success,
            data={"package_name": pkg_name, "exit_code": res.exit_code},
            stdout=res.stdout or res.message,
            stderr=res.stderr,
            error=res.message if not res.success else None,
            exit_code=res.exit_code,
        )


class PackageUpdateTool(BaseTool):
    """Update package index repositories with confirmation."""

    name = "package_update"
    description = (
        "Refresh distribution package indexes and repositories. "
        "Requires confirmation before execution."
    )
    risk_tier = RiskTier.CONFIRM

    def __init__(self, pkg_manager: Optional[PackageManager] = None):
        self.pkg_manager = pkg_manager or detect_package_manager()

    @property
    def parameters_schema(self) -> Dict[str, Any]:
        return {
            "type": "object",
            "properties": {
                "reason": {
                    "type": "string",
                    "description": "Explanation of why repository update is needed",
                }
            },
        }

    def run(self, arguments: Dict[str, Any], timeout: float = 30.0) -> ToolResult:
        reason = arguments.get("reason", "Refresh package repository indexes")
        res = self.pkg_manager.update(reason=reason)
        return ToolResult(
            success=res.success,
            data={"exit_code": res.exit_code},
            stdout=res.stdout or res.message,
            stderr=res.stderr,
            error=res.message if not res.success else None,
            exit_code=res.exit_code,
        )
