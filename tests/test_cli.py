"""Unit tests for the Typer-based CLI skeleton and UI components."""

from pathlib import Path
import pytest
from typer.testing import CliRunner
from pilot.main import app, __version__
from pilot.ui.terminal import confirm_prompt

runner = CliRunner()


def test_cli_help():
    """Verify that --help exits cleanly and lists subcommands."""
    result = runner.invoke(app, ["--help"])
    assert result.exit_code == 0
    assert "Linux Command Pilot" in result.stdout
    assert "doctor" in result.stdout
    assert "config" in result.stdout
    assert "tools" in result.stdout
    assert "explain" in result.stdout
    assert "history" in result.stdout
    assert "reset-memory" in result.stdout


def test_cli_version():
    """Verify that --version exits cleanly with version string."""
    result = runner.invoke(app, ["--version"])
    assert result.exit_code == 0
    assert f"v{__version__}" in result.stdout


def test_cli_doctor_success(mocker):
    """Verify doctor command passes when services and config are healthy."""
    mocker.patch(
        "pilot.config.Settings.check_ollama_connection",
        return_value={
            "connected": True,
            "models": ["qwen3:4b"],
            "configured_model_found": True,
            "error": None,
        },
    )
    result = runner.invoke(app, ["doctor"])
    assert result.exit_code == 0
    assert "Linux Command Pilot is ready" in result.stdout
    assert "Python" in result.stdout
    assert "Ollama Service" in result.stdout
    assert "Model (qwen3:4b)" in result.stdout


def test_cli_doctor_failure(mocker):
    """Verify doctor command returns exit code 1 when Ollama is offline."""
    mocker.patch(
        "pilot.config.Settings.check_ollama_connection",
        return_value={
            "connected": False,
            "models": [],
            "configured_model_found": False,
            "error": "Connection refused",
        },
    )
    result = runner.invoke(app, ["doctor"])
    assert result.exit_code == 1
    assert "Some health checks failed" in result.stdout


def test_cli_config():
    """Verify config subcommand outputs settings table."""
    result = runner.invoke(app, ["config"])
    assert result.exit_code == 0
    assert "Linux Command Pilot Configuration" in result.stdout
    assert "MODEL" in result.stdout
    assert "OLLAMA_HOST" in result.stdout
    assert "MAX_AGENT_STEPS" in result.stdout


def test_cli_tools():
    """Verify tools subcommand lists registered baseline tools."""
    result = runner.invoke(app, ["tools"])
    assert result.exit_code == 0
    assert "Available Tools" in result.stdout
    assert "system_info" in result.stdout
    assert "disk_usage" in result.stdout
    assert "write_file" in result.stdout
    assert "execute_command" in result.stdout


def test_cli_explain_safe_command():
    """Verify explain output for read-only inspection command."""
    result = runner.invoke(app, ["explain", "ls -la"])
    assert result.exit_code == 0
    assert "Command Analysis: ls -la" in result.stdout
    assert "Binary: ls" in result.stdout
    assert "Low / Read-only inspection" in result.stdout


def test_cli_explain_risky_command():
    """Verify explain output for destructive command."""
    result = runner.invoke(app, ["explain", "rm -rf /var/log"])
    assert result.exit_code == 0
    assert "Command Analysis: rm -rf /var/log" in result.stdout
    assert "Binary: rm" in result.stdout
    assert "High / State-modifying" in result.stdout
    assert "Warning" in result.stdout


def test_cli_reset_memory(tmp_path, monkeypatch):
    """Verify reset-memory deletes sqlite db file."""
    fake_db = tmp_path / "test.db"
    fake_db.touch()
    assert fake_db.exists()

    monkeypatch.setenv("DB_PATH", str(fake_db))
    result = runner.invoke(app, ["reset-memory"])
    assert result.exit_code == 0
    assert not fake_db.exists()
    assert "reset successfully" in result.stdout


def test_cli_interactive_exit():
    """Verify interactive REPL exits on 'exit'."""
    result = runner.invoke(app, [], input="exit\n")
    assert result.exit_code == 0
    assert "Exiting Linux Command Pilot" in result.stdout


def test_confirm_prompt_yes(monkeypatch):
    """Test security confirm prompt user approving."""
    monkeypatch.setattr("rich.console.Console.input", lambda self, prompt: "y")
    approved = confirm_prompt("apt install curl", "Install HTTP client", "Installs system packages")
    assert approved is True


def test_confirm_prompt_no(monkeypatch):
    """Test security confirm prompt user rejecting."""
    monkeypatch.setattr("rich.console.Console.input", lambda self, prompt: "n")
    approved = confirm_prompt("rm -rf /tmp/data", "Clean temp files", "Deletes files permanently")
    assert approved is False
