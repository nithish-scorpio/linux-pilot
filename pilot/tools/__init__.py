"""Tool system package."""

from pilot.tools.base import BaseTool, RiskTier, ToolResult
from pilot.tools.filesystem import (
    ListDirectoryTool,
    ReadFileTool,
    SearchFilesTool,
    WriteFileTool,
)
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
    registry.register(ListDirectoryTool())
    registry.register(ReadFileTool())
    registry.register(SearchFilesTool())


def register_all_baseline_tools(registry: ToolRegistry) -> None:
    """Register all 10 baseline MVP tools."""
    register_safe_tools(registry)
    registry.register(WriteFileTool())
    registry.register(ExecuteCommandTool())


# Auto-populate the global default registry with all 10 baseline tools
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
    "ListDirectoryTool",
    "ReadFileTool",
    "SearchFilesTool",
    "WriteFileTool",
    "ExecuteCommandTool",
    "register_safe_tools",
    "register_all_baseline_tools",
]
