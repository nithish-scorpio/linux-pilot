"""Tool system package."""

from pilot.tools.base import BaseTool, RiskTier, ToolResult
from pilot.tools.filesystem import (
    ListDirectoryTool,
    ReadFileTool,
    SearchFilesTool,
    WriteFileTool,
)
from pilot.tools.network import NetworkInfoTool
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
    Result,
    detect_package_manager,
    validate_package_name,
)
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
    registry.register(PackageCheckInstalledTool())
    registry.register(PackageSearchTool())


def register_package_tools(registry: ToolRegistry) -> None:
    """Register package manager inspection and management tools."""
    registry.register(PackageCheckInstalledTool())
    registry.register(PackageSearchTool())
    registry.register(PackageInstallTool())
    registry.register(PackageRemoveTool())
    registry.register(PackageUpdateTool())


def register_all_baseline_tools(registry: ToolRegistry) -> None:
    """Register all baseline and package tools."""
    register_safe_tools(registry)
    registry.register(WriteFileTool())
    registry.register(PackageInstallTool())
    registry.register(PackageRemoveTool())
    registry.register(PackageUpdateTool())
    registry.register(ExecuteCommandTool())


# Auto-populate the global default registry with all tools
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
    "PackageManager",
    "PackageResult",
    "Result",
    "AptPackageManager",
    "DnfPackageManager",
    "PacmanPackageManager",
    "detect_package_manager",
    "validate_package_name",
    "PackageCheckInstalledTool",
    "PackageSearchTool",
    "PackageInstallTool",
    "PackageRemoveTool",
    "PackageUpdateTool",
    "register_safe_tools",
    "register_package_tools",
    "register_all_baseline_tools",
]
