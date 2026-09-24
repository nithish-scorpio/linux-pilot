"""Tool system package."""

from pilot.tools.base import BaseTool, RiskTier, ToolResult
from pilot.tools.network import NetworkInfoTool
from pilot.tools.registry import ToolRegistry, default_registry
from pilot.tools.system import (
    DiskUsageTool,
    MemoryUsageTool,
    ProcessListTool,
    SystemInfoTool,
)
from pilot.tools.terminal import ExecuteCommandTool


def register_safe_tools(registry: ToolRegistry) -> None:
    """Register all baseline safe read-only tools."""
    registry.register(SystemInfoTool())
    registry.register(DiskUsageTool())
    registry.register(MemoryUsageTool())
    registry.register(ProcessListTool())
    registry.register(NetworkInfoTool())


def register_all_baseline_tools(registry: ToolRegistry) -> None:
    """Register baseline safe tools and terminal command tool."""
    register_safe_tools(registry)
    registry.register(ExecuteCommandTool())


# Auto-populate the global default registry with baseline tools
register_all_baseline_tools(default_registry)

__all__ = [
    "BaseTool",
    "RiskTier",
    "ToolResult",
    "ToolRegistry",
    "default_registry",
    "SystemInfoTool",
    "DiskUsageTool",
    "MemoryUsageTool",
    "ProcessListTool",
    "NetworkInfoTool",
    "ExecuteCommandTool",
    "register_safe_tools",
    "register_all_baseline_tools",
]
