"""Tool registry for registering, looking up, and executing tools."""

import logging
from typing import Any, Dict, List, Optional

from pilot.llm.client import ToolDefinition
from pilot.tools.base import BaseTool, ToolResult

logger = logging.getLogger(__name__)


class ToolRegistry:
    """Central registry for all available tools in Linux Command Pilot."""

    def __init__(self):
        self._tools: Dict[str, BaseTool] = {}

    def register(self, tool: BaseTool) -> None:
        """Register a tool instance."""
        if tool.name in self._tools:
            logger.warning("Overwriting existing tool registration: %s", tool.name)
        self._tools[tool.name] = tool
        logger.debug("Registered tool: %s (%s)", tool.name, tool.risk_tier.value)

    def unregister(self, name: str) -> Optional[BaseTool]:
        """Unregister and return a tool by name."""
        return self._tools.pop(name, None)

    def get(self, name: str) -> Optional[BaseTool]:
        """Retrieve a registered tool by name."""
        return self._tools.get(name)

    def contains(self, name: str) -> bool:
        """Check if a tool is registered."""
        return name in self._tools

    def __contains__(self, name: str) -> bool:
        """Support 'name in registry' syntax."""
        return self.contains(name)

    def list_tools(self) -> List[BaseTool]:
        """Return a list of all registered tools."""
        return list(self._tools.values())

    def get_tool_definitions(self) -> List[ToolDefinition]:
        """Generate LLM-compatible ToolDefinition objects for all registered tools."""
        return [tool.to_tool_definition() for tool in self._tools.values()]

    def execute_tool(
        self,
        name: str,
        arguments: Dict[str, Any],
        timeout: float = 30.0,
    ) -> ToolResult:
        """Look up and execute a tool by name with parameter validation and timeout."""
        tool = self.get(name)
        if not tool:
            return ToolResult(
                success=False,
                error=f"Tool '{name}' is not registered. Available tools: {list(self._tools.keys())}",
            )

        return tool.execute(arguments=arguments, timeout=timeout)

    def clear(self) -> None:
        """Clear all registered tools."""
        self._tools.clear()


# Shared global default registry instance
default_registry = ToolRegistry()
