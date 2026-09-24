"""Unit tests for Phase 9 package manager abstraction and tools."""

import subprocess
from unittest.mock import MagicMock, patch
import pytest

from pilot.security.permissions import RiskTier
from pilot.tools.packages import (
    AptPackageManager,
    DnfPackageManager,
    PackageManager,
    PackageCheckInstalledTool,
    PackageInstallTool,
    PackageRemoveTool,
    PackageResult,
    PackageSearchTool,
    PackageUpdateTool,
    PacmanPackageManager,
    detect_package_manager,
    validate_package_name,
)
from pilot.tools.registry import ToolRegistry


def test_package_manager_protocol_conformance():
    """Verify concrete package manager classes conform to the PackageManager protocol."""
    apt = AptPackageManager()
    dnf = DnfPackageManager()
    pacman = PacmanPackageManager()

    assert isinstance(apt, PackageManager)
    assert isinstance(dnf, PackageManager)
    assert isinstance(pacman, PackageManager)


def test_validate_package_name():
    """Verify package name validator blocks injection attempts while allowing valid names."""
    valid_names = [
        "python3",
        "curl",
        "build-essential",
        "g++",
        "libssl-dev",
        "xorg-x11-drv-libinput",
        "glibc@2.35",
        "linux-headers-6.8.0-40-generic",
    ]
    for name in valid_names:
        assert validate_package_name(name) is True, f"Expected {name} to be valid"

    invalid_names = [
        "",
        "   ",
        "python; rm -rf /",
        "curl | sh",
        "htop `reboot`",
        "package$(whoami)",
        "pkg\nexploit",
        "pkg&bg",
        "../traversal",
        "/bin/ls",
        "-option",  # starts with dash
        "a" * 150,  # exceeds max length
    ]
    for name in invalid_names:
        assert validate_package_name(name) is False, f"Expected {name} to be invalid"


def test_detect_package_manager(tmp_path):
    """Verify detect_package_manager parses /etc/os-release correctly."""
    # Test Ubuntu / Debian
    ubuntu_release = tmp_path / "os-release-ubuntu"
    ubuntu_release.write_text('NAME="Ubuntu"\nID=ubuntu\nID_LIKE=debian\n')
    pm = detect_package_manager(os_release_path=str(ubuntu_release))
    assert isinstance(pm, AptPackageManager)

    # Test Fedora / RHEL
    fedora_release = tmp_path / "os-release-fedora"
    fedora_release.write_text('NAME="Fedora Linux"\nID=fedora\n')
    pm = detect_package_manager(os_release_path=str(fedora_release))
    assert isinstance(pm, DnfPackageManager)

    # Test Arch Linux
    arch_release = tmp_path / "os-release-arch"
    arch_release.write_text('NAME="Arch Linux"\nID=arch\n')
    pm = detect_package_manager(os_release_path=str(arch_release))
    assert isinstance(pm, PacmanPackageManager)


def test_apt_package_manager_is_installed():
    """Verify AptPackageManager is_installed checks dpkg-query."""
    apt = AptPackageManager()

    # Installed case
    with patch.object(apt, "_run_cmd") as mock_run:
        mock_run.return_value = subprocess.CompletedProcess(
            args=["dpkg-query"], returncode=0, stdout="install ok installed\n", stderr=""
        )
        assert apt.is_installed("curl") is True
        mock_run.assert_called_once()
        assert mock_run.call_args[0][0] == ["dpkg-query", "-W", "-f=${Status}", "curl"]

    # Not installed case
    with patch.object(apt, "_run_cmd") as mock_run:
        mock_run.return_value = subprocess.CompletedProcess(
            args=["dpkg-query"], returncode=1, stdout="", stderr="dpkg-query: no packages found"
        )
        assert apt.is_installed("unknown-pkg") is False

    # Invalid name rejected without running command
    assert apt.is_installed("pkg; evil") is False


def test_apt_package_manager_search():
    """Verify AptPackageManager search parses apt-cache output."""
    apt = AptPackageManager()
    fake_output = (
        "htop - interactive processes viewer\n"
        "atop - Monitor for system resources\n"
    )
    with patch.object(apt, "_run_cmd") as mock_run:
        mock_run.return_value = subprocess.CompletedProcess(
            args=["apt-cache"], returncode=0, stdout=fake_output, stderr=""
        )
        res = apt.search("top")
        assert res.success is True
        assert len(res.data["packages"]) == 2
        assert res.data["packages"][0]["name"] == "htop"
        assert res.data["packages"][0]["description"] == "interactive processes viewer"


def test_apt_package_manager_install_approved():
    """Verify AptPackageManager install executes when confirmed."""
    handler = MagicMock(return_value=True)
    apt = AptPackageManager(confirm_handler=handler)

    with patch.object(apt, "_run_cmd") as mock_run:
        mock_run.return_value = subprocess.CompletedProcess(
            args=["sudo", "apt-get", "install"], returncode=0, stdout="Setting up nginx...", stderr=""
        )
        res = apt.install("nginx", reason="Web server setup")

        assert res.success is True
        assert "Successfully installed" in res.message
        handler.assert_called_once()
        assert "nginx" in handler.call_args[0][0]
        mock_run.assert_called_once()


def test_apt_package_manager_install_denied():
    """Verify AptPackageManager install aborts when user rejects confirmation."""
    handler = MagicMock(return_value=False)
    apt = AptPackageManager(confirm_handler=handler)

    with patch.object(apt, "_run_cmd") as mock_run:
        res = apt.install("nginx", reason="Web server setup")
        assert res.success is False
        assert "User rejected" in res.message
        mock_run.assert_not_called()


def test_apt_package_manager_remove_and_update():
    """Verify AptPackageManager remove and update workflows."""
    handler = MagicMock(return_value=True)
    apt = AptPackageManager(confirm_handler=handler)

    # Remove
    with patch.object(apt, "_run_cmd") as mock_run:
        mock_run.return_value = subprocess.CompletedProcess(args=[], returncode=0, stdout="Removed.", stderr="")
        res = apt.remove("curl")
        assert res.success is True
        assert "Successfully removed" in res.message

    # Update
    with patch.object(apt, "_run_cmd") as mock_run:
        mock_run.return_value = subprocess.CompletedProcess(args=[], returncode=0, stdout="Hit:1 http...", stderr="")
        res = apt.update()
        assert res.success is True
        assert "updated successfully" in res.message


def test_dnf_package_manager_operations():
    """Verify DnfPackageManager methods for Fedora systems."""
    handler = MagicMock(return_value=True)
    dnf = DnfPackageManager(confirm_handler=handler)

    # is_installed
    with patch.object(dnf, "_run_cmd") as mock_run:
        mock_run.return_value = subprocess.CompletedProcess(args=[], returncode=0, stdout="git-2.43.0\n", stderr="")
        assert dnf.is_installed("git") is True

    # search
    with patch.object(dnf, "_run_cmd") as mock_run:
        mock_run.return_value = subprocess.CompletedProcess(
            args=[], returncode=0, stdout="git.x86_64 : Fast Version Control System\n", stderr=""
        )
        res = dnf.search("git")
        assert res.success is True
        assert res.data["packages"][0]["name"] == "git.x86_64"

    # install
    with patch.object(dnf, "_run_cmd") as mock_run:
        mock_run.return_value = subprocess.CompletedProcess(args=[], returncode=0, stdout="Complete!", stderr="")
        res = dnf.install("git")
        assert res.success is True


def test_pacman_package_manager_operations():
    """Verify PacmanPackageManager methods for Arch systems."""
    handler = MagicMock(return_value=True)
    pacman = PacmanPackageManager(confirm_handler=handler)

    # is_installed
    with patch.object(pacman, "_run_cmd") as mock_run:
        mock_run.return_value = subprocess.CompletedProcess(args=[], returncode=0, stdout="tmux\n", stderr="")
        assert pacman.is_installed("tmux") is True

    # search
    with patch.object(pacman, "_run_cmd") as mock_run:
        mock_run.return_value = subprocess.CompletedProcess(
            args=[], returncode=0, stdout="extra/tmux 3.4-1\n    Terminal multiplexer\n", stderr=""
        )
        res = pacman.search("tmux")
        assert res.success is True
        assert res.data["packages"][0]["name"] == "tmux"
        assert res.data["packages"][0]["description"] == "Terminal multiplexer"

    # install
    with patch.object(pacman, "_run_cmd") as mock_run:
        mock_run.return_value = subprocess.CompletedProcess(args=[], returncode=0, stdout="installed", stderr="")
        res = pacman.install("tmux")
        assert res.success is True


def test_package_tools_with_registry():
    """Verify dedicated package tools execute and integrate into ToolRegistry."""
    mock_pm = MagicMock(spec=PackageManager)
    mock_pm.is_installed.return_value = True
    mock_pm.search.return_value = PackageResult(
        success=True,
        message="Found 1 match",
        data={"query": "nano", "packages": [{"name": "nano", "description": "Small editor"}]},
    )
    mock_pm.install.return_value = PackageResult(success=True, message="Installed nano", exit_code=0)
    mock_pm.remove.return_value = PackageResult(success=True, message="Removed nano", exit_code=0)
    mock_pm.update.return_value = PackageResult(success=True, message="Updated repos", exit_code=0)

    check_tool = PackageCheckInstalledTool(pkg_manager=mock_pm)
    search_tool = PackageSearchTool(pkg_manager=mock_pm)
    install_tool = PackageInstallTool(pkg_manager=mock_pm)
    remove_tool = PackageRemoveTool(pkg_manager=mock_pm)
    update_tool = PackageUpdateTool(pkg_manager=mock_pm)

    # Check risk tiers
    assert check_tool.risk_tier == RiskTier.SAFE
    assert search_tool.risk_tier == RiskTier.SAFE
    assert install_tool.risk_tier == RiskTier.CONFIRM
    assert remove_tool.risk_tier == RiskTier.CONFIRM
    assert update_tool.risk_tier == RiskTier.CONFIRM

    # Run check
    res = check_tool.execute({"package_name": "nano"})
    assert res.success is True
    assert res.data["installed"] is True

    # Run search
    res = search_tool.execute({"query": "nano"})
    assert res.success is True
    assert "nano" in res.stdout

    # Run install
    res = install_tool.execute({"package_name": "nano", "reason": "Text editing"})
    assert res.success is True

    # Run remove
    res = remove_tool.execute({"package_name": "nano", "reason": "No longer needed"})
    assert res.success is True

    # Run update
    res = update_tool.execute({"reason": "Sync indexes"})
    assert res.success is True

    # Register into fresh ToolRegistry
    reg = ToolRegistry()
    reg.register(check_tool)
    reg.register(search_tool)
    reg.register(install_tool)
    reg.register(remove_tool)
    reg.register(update_tool)

    assert "is_package_installed" in reg
    assert "package_search" in reg
    assert "package_install" in reg
    assert "package_remove" in reg
    assert "package_update" in reg
