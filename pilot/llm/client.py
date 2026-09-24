"""LLM provider abstraction and data models.

Defines standard schemas for messages, tool definitions, tool calls,
and the abstract base class for LLM providers.
"""

from abc import ABC, abstractmethod
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class FunctionCall(BaseModel):
    """Function call requested by the model."""

    name: str
    arguments: Dict[str, Any] = Field(default_factory=dict)


class ToolCall(BaseModel):
    """Tool call payload."""

    id: Optional[str] = None
    type: str = "function"
    function: FunctionCall


class Message(BaseModel):
    """Conversation message."""

    role: str  # system, user, assistant, tool
    content: Optional[str] = None
    thinking: Optional[str] = None
    tool_calls: Optional[List[ToolCall]] = None
    tool_call_id: Optional[str] = None
    name: Optional[str] = None


class ToolParametersSchema(BaseModel):
    """JSON schema for tool parameters."""

    type: str = "object"
    properties: Dict[str, Any] = Field(default_factory=dict)
    required: Optional[List[str]] = None


class ToolFunctionSchema(BaseModel):
    """Function schema definition for tools."""

    name: str
    description: str
    parameters: ToolParametersSchema


class ToolDefinition(BaseModel):
    """Tool definition exposed to the LLM."""

    type: str = "function"
    function: ToolFunctionSchema


class LLMResponse(BaseModel):
    """Normalized response from an LLM provider."""

    content: Optional[str] = None
    thinking: Optional[str] = None
    tool_calls: List[ToolCall] = Field(default_factory=list)
    finish_reason: Optional[str] = None
    raw: Optional[Dict[str, Any]] = None

    @property
    def has_tool_calls(self) -> bool:
        """Check if response requested one or more tool calls."""
        return len(self.tool_calls) > 0

    @property
    def tool_call(self) -> Optional[ToolCall]:
        """Convenience accessor for the first tool call."""
        return self.tool_calls[0] if self.tool_calls else None


class LLMProviderError(Exception):
    """Base exception for LLM provider errors."""

    pass


class LLMConnectionError(LLMProviderError):
    """Raised when the LLM provider daemon/endpoint is unreachable."""

    pass


class LLMProvider(ABC):
    """Abstract interface for local or remote LLM backends."""

    @abstractmethod
    def chat(
        self,
        messages: List[Message],
        tools: Optional[List[ToolDefinition]] = None,
        temperature: float = 0.0,
        **kwargs: Any,
    ) -> LLMResponse:
        """Send chat messages and optional tool definitions to the LLM.

        Args:
            messages: List of conversation messages.
            tools: Optional list of available tool definitions.
            temperature: Sampling temperature (default 0.0 for deterministic agent behavior).
            **kwargs: Extra runtime options.

        Returns:
            Normalized LLMResponse.
        """
        pass

    @abstractmethod
    def is_available(self) -> bool:
        """Check if the provider daemon/service is active and healthy."""
        pass
