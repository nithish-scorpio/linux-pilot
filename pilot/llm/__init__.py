"""LLM abstraction package."""

from pilot.llm.client import (
    FunctionCall,
    LLMConnectionError,
    LLMProvider,
    LLMProviderError,
    LLMResponse,
    Message,
    ToolCall,
    ToolDefinition,
    ToolFunctionSchema,
    ToolParametersSchema,
)
from pilot.llm.models import OllamaProvider, get_llm_provider

__all__ = [
    "FunctionCall",
    "ToolCall",
    "Message",
    "ToolDefinition",
    "ToolFunctionSchema",
    "ToolParametersSchema",
    "LLMResponse",
    "LLMProvider",
    "LLMProviderError",
    "LLMConnectionError",
    "OllamaProvider",
    "get_llm_provider",
]
