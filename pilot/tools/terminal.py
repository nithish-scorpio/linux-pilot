"""Terminal tool: execute_command with 3-tier security enforcement."""

import subprocess
import time
from typing import Any, Callable, Dict, Optional

from pilot.security.permissions import CommandRiskClassification, RiskTier
from pilot.security.validator import SecurityValidator
from pilot.tools.base import BaseTool, ToolResult
from pilot.ui.terminal import confirm_prompt


class ExecuteCommandTool(BaseTool):
    """Execute a validated shell command under strict security policy controls."""

    name = "execute_command"
    description = (
        "Execute a shell command with strict security validation. "
        "Commands are classified into SAFE (runs automatically), "
        "CONFIRM (prompts the user with reason and risk), or BLOCKED (refused outright). "
        "Use this only when no dedicated tool exists."
    )
    risk_tier = RiskTier.CONFIRM

    def __init__(self, confirm_handler: Optional[Callable[[str, str, str], bool]] = None):
        self.confirm_handler = confirm_handler or confirm_prompt

    @property
    def parameters_schema(self) -> Dict[str, Any]:
        return {
            "type": "object",
            "properties": {
                "command": {
                    "type": "string",
                    "description": "The exact shell command line to execute",
                },
                "reason": {
                    "type": "string",
                    "description": "Explanation of why this command is needed",
                },
            },
            "required": ["command"],
        }

    def run(self, arguments: Dict[str, Any], timeout: float = 30.0) -> ToolResult:
        command = arguments.get("command", "").strip()
        reason = arguments.get("reason", "No reason provided")

        if not command:
            return ToolResult(success=False, error="Command cannot be empty")

        # 1. Security Classification & Validation
        classification: CommandRiskClassification = SecurityValidator.classify_command(
            command_str=command,
            reason=reason,
        )

        # 2. BLOCKED tier: Refused outright with zero prompt
        if classification.tier == RiskTier.BLOCKED:
            return ToolResult(
                success=False,
                error=f"SECURITY ERROR: Command BLOCKED by policy: {classification.risk_description}",
            )

        # 3. CONFIRM tier: Require explicit user approval
        if classification.tier == RiskTier.CONFIRM:
            approved = self.confirm_handler(
                command,
                reason,
                classification.risk_description,
            )
            if not approved:
                return ToolResult(
                    success=False,
                    error=f"Operation cancelled: User denied permission to execute '{command}'",
                )

        # 4. Safe or Confirmed: Execute bounded by timeout and without interactive stdin
        start_time = time.perf_counter()
        try:
            res = subprocess.run(
                command,
                shell=True,
                capture_output=True,
                text=True,
                timeout=timeout,
                stdin=subprocess.DEVNULL,
                check=False,
            )
            duration = round(time.perf_counter() - start_time, 4)
            success = (res.returncode == 0)

            return ToolResult(
                success=success,
                exit_code=res.returncode,
                stdout=res.stdout,
                stderr=res.stderr,
                error=f"Process exited with code {res.returncode}" if not success else None,
                duration=duration,
            )
        except subprocess.TimeoutExpired:
            duration = round(time.perf_counter() - start_time, 4)
            return ToolResult(
                success=False,
                error=f"Command timed out after {timeout} seconds: '{command}'",
                duration=duration,
            )
        except Exception as e:
            duration = round(time.perf_counter() - start_time, 4)
            return ToolResult(
                success=False,
                error=f"Execution failed with unexpected error: {e}",
                duration=duration,
            )
