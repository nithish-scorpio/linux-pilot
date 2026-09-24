"""Unit tests for BaseTool and ToolRegistry."""

import time
from typing import Any, Dict
import pytest

from pilot.tools import BaseTool, RiskTier, ToolRegistry, ToolResult


class DummyEchoTool(BaseTool):
    """Test tool that echoes an input message."""

    name = "echo_tool"
    description = "Echoes a given message string."
    risk_tier = RiskTier.SAFE

    @property
    def parameters_schema(self) -> Dict[str, Any]:
        return {
            "type": "object",
            "properties": {
                "message": {"type": "string", "description": "The message to echo"}
            },
            "required": ["message"],
        }

    def run(self, arguments: Dict[str, Any], timeout: float = 30.0) -> ToolResult:
        msg = arguments.get("message", "")
        return ToolResult(success=True, data={"echo": msg}, stdout=f"Echo: {msg}")


class DummyFailingTool(BaseTool):
    """Test tool that raises an unexpected exception."""

    name = "failing_tool"
    description = "Always raises an exception."
    risk_tier = RiskTier.SAFE

    @property
    def parameters_schema(self) -> Dict[str, Any]:
        return {"type": "object", "properties": {}}

    def run(self, arguments: Dict[str, Any], timeout: float = 30.0) -> ToolResult:
        raise ValueError("Simulated unexpected failure")


class DummySlowTool(BaseTool):
    """Test tool that exceeds timeout."""

    name = "slow_tool"
    description = "Sleeps longer than allowed."
    risk_tier = RiskTier.SAFE

    @property
    def parameters_schema(self) -> Dict[str, Any]:
        return {"type": "object", "properties": {}}

    def run(self, arguments: Dict[str, Any], timeout: float = 30.0) -> ToolResult:
        raise TimeoutError("Operation timed out")


def test_tool_result_formatting():
    """Verify ToolResult JSON serialization and LLM text formatting."""
    res_success = ToolResult(success=True, data={"status": "ok"}, stdout="All systems normal")
    assert "All systems normal" in res_success.format_for_llm()
    assert '"success":true' in res_success.to_json().replace(" ", "")

    res_err = ToolResult(success=False, error="File not found")
    assert "Error: File not found" in res_err.format_for_llm()

    res_data_only = ToolResult(success=True, data={"cpu": 15})
    assert '"cpu": 15' in res_data_only.format_for_llm()


def test_base_tool_execution_success():
    """Verify standard tool execution and duration calculation."""
    tool = DummyEchoTool()
    res = tool.execute({"message": "Hello Linux"})

    assert res.success is True
    assert res.data == {"echo": "Hello Linux"}
    assert res.stdout == "Echo: Hello Linux"
    assert res.duration >= 0.0


def test_base_tool_validation_failure():
    """Verify missing required parameter produces validation error without running tool."""
    tool = DummyEchoTool()
    res = tool.execute({})

    assert res.success is False
    assert "Validation failed" in res.error
    assert "Missing required parameter: 'message'" in res.error


def test_base_tool_exception_handling():
    """Verify uncaught exception in run() is converted to a failed ToolResult."""
    tool = DummyFailingTool()
    res = tool.execute({})

    assert res.success is False
    assert "Simulated unexpected failure" in res.error
    assert res.duration >= 0.0


def test_base_tool_timeout_handling():
    """Verify TimeoutError is caught and returned cleanly."""
    tool = DummySlowTool()
    res = tool.execute({}, timeout=0.1)

    assert res.success is False
    assert "timed out" in res.error.lower()


def test_base_tool_to_definition():
    """Verify conversion to LLM ToolDefinition."""
    tool = DummyEchoTool()
    defn = tool.to_tool_definition()

    assert defn.type == "function"
    assert defn.function.name == "echo_tool"
    assert defn.function.description == "Echoes a given message string."
    assert "message" in defn.function.parameters.properties
    assert defn.function.parameters.required == ["message"]


def test_tool_registry_management():
    """Verify registration, lookup, listing, and clearing."""
    registry = ToolRegistry()
    tool = DummyEchoTool()

    assert registry.contains("echo_tool") is False
    registry.register(tool)
    assert registry.contains("echo_tool") is True
    assert registry.get("echo_tool") is tool
    assert len(registry.list_tools()) == 1

    definitions = registry.get_tool_definitions()
    assert len(definitions) == 1
    assert definitions[0].function.name == "echo_tool"

    # Execution through registry
    res = registry.execute_tool("echo_tool", {"message": "ping"})
    assert res.success is True
    assert res.stdout == "Echo: ping"

    # Unregistered tool execution
    res_missing = registry.execute_tool("nonexistent", {})
    assert res_missing.success is False
    assert "is not registered" in res_missing.error

    # Unregister & Clear
    unreg = registry.unregister("echo_tool")
    assert unreg is tool
    assert registry.contains("echo_tool") is False

    registry.register(tool)
    registry.clear()
    assert len(registry.list_tools()) == 0
