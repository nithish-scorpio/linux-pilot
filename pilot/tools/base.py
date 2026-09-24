"""Base tool interface and result schemas.

Every tool in Linux Command Pilot implements the BaseTool interface.
"""

from abc import ABC, abstractmethod
from enum import Enum
import json
import time
from typing import Any, Dict, List, Optional, Tuple
from pydantic import BaseModel, Field

from pilot.llm.client import ToolDefinition, ToolFunctionSchema, ToolParametersSchema


class RiskTier(str, Enum):
    """Security risk classification for tool operations."""

    SAFE = "safe"          # Read-only, safe to run automatically
    CONFIRM = "confirm"    # Modifies system/files, requires user approval
    BLOCKED = "blocked"    # Dangerous or destructive, prohibited


class ToolResult(BaseModel):
    """Structured, JSON-serializable tool execution result."""

    success: bool
    data: Optional[Any] = None
    error: Optional[str] = None
    exit_code: Optional[int] = None
    stdout: Optional[str] = None
    stderr: Optional[str] = None
    duration: float = Field(default=0.0)

    def to_json(self) -> str:
        """Serialize result to a clean JSON string."""
        return self.model_dump_json(exclude_none=True)

    def format_for_llm(self) -> str:
        """Format the result as a concise text response for the LLM context."""
        if not self.success:
            return f"Error: {self.error or 'Tool execution failed'}"
        if self.stdout is not None:
            return self.stdout if self.stdout.strip() else "(Command produced no output)"
        if self.data is not None:
            if isinstance(self.data, (dict, list)):
                return json.dumps(self.data, indent=2)
            return str(self.data)
        return "Success"


class BaseTool(ABC):
    """Abstract base class for all pilot tools."""

    name: str
    description: str
    risk_tier: RiskTier = RiskTier.SAFE

    @property
    @abstractmethod
    def parameters_schema(self) -> Dict[str, Any]:
        """JSON Schema dictionary describing accepted parameters."""
        pass

    def validate_args(self, arguments: Dict[str, Any]) -> Tuple[bool, Optional[str]]:
        """Validate input arguments before execution.

        Subclasses may override this for parameter type and bounds checking.
        Returns:
            Tuple of (is_valid, optional_error_message)
        """
        # Default implementation checks required properties defined in schema
        schema = self.parameters_schema
        required = schema.get("required", [])
        for req in required:
            if req not in arguments:
                return False, f"Missing required parameter: '{req}'"
        return True, None

    @abstractmethod
    def run(self, arguments: Dict[str, Any], timeout: float = 30.0) -> ToolResult:
        """Perform the actual tool operation.

        Implementations must handle expected operation errors and return ToolResult.
        """
        pass

    def execute(self, arguments: Dict[str, Any], timeout: float = 30.0) -> ToolResult:
        """Public execution entrypoint wrapping validation, timing, and exception safety."""
        start_time = time.perf_counter()

        # 1. Parameter validation
        is_valid, val_err = self.validate_args(arguments)
        if not is_valid:
            duration = round(time.perf_counter() - start_time, 4)
            return ToolResult(
                success=False,
                error=f"Validation failed for tool '{self.name}': {val_err}",
                duration=duration,
            )

        # 2. Execution wrapped in uncaught exception protection
        try:
            result = self.run(arguments, timeout=timeout)
            result.duration = round(time.perf_counter() - start_time, 4)
            return result
        except TimeoutError as te:
            duration = round(time.perf_counter() - start_time, 4)
            return ToolResult(
                success=False,
                error=f"Tool '{self.name}' timed out after {timeout} seconds: {te}",
                duration=duration,
            )
        except Exception as e:
            duration = round(time.perf_counter() - start_time, 4)
            return ToolResult(
                success=False,
                error=f"Tool '{self.name}' raised an unexpected exception: {e}",
                duration=duration,
            )

    def to_tool_definition(self) -> ToolDefinition:
        """Convert this tool into an LLM-compatible ToolDefinition."""
        schema = self.parameters_schema
        return ToolDefinition(
            type="function",
            function=ToolFunctionSchema(
                name=self.name,
                description=self.description,
                parameters=ToolParametersSchema(
                    type=schema.get("type", "object"),
                    properties=schema.get("properties", {}),
                    required=schema.get("required"),
                ),
            ),
        )
