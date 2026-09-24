"""Tests for LLM provider abstraction and Ollama implementation."""

import pytest
import httpx
from pilot.llm import (
    FunctionCall,
    LLMConnectionError,
    LLMProviderError,
    LLMResponse,
    Message,
    OllamaProvider,
    ToolCall,
    ToolDefinition,
    ToolFunctionSchema,
    ToolParametersSchema,
    get_llm_provider,
)
from pilot.config import get_settings


def test_message_and_tool_call_schemas():
    """Verify serialization of messages and tool calls."""
    tc = ToolCall(
        id="call_123",
        function=FunctionCall(name="disk_usage", arguments={"path": "/"}),
    )
    assert tc.function.name == "disk_usage"
    assert tc.function.arguments == {"path": "/"}

    msg = Message(role="assistant", content="Checking disk space", tool_calls=[tc])
    dump = msg.model_dump()
    assert dump["role"] == "assistant"
    assert dump["tool_calls"][0]["function"]["name"] == "disk_usage"


def test_tool_definition_schema():
    """Verify tool definition JSON schema format."""
    tool = ToolDefinition(
        function=ToolFunctionSchema(
            name="system_info",
            description="Get system specifications",
            parameters=ToolParametersSchema(
                properties={"verbose": {"type": "boolean"}},
                required=["verbose"],
            ),
        )
    )
    data = tool.model_dump()
    assert data["type"] == "function"
    assert data["function"]["name"] == "system_info"
    assert "verbose" in data["function"]["parameters"]["properties"]


def test_ollama_provider_text_response(mocker):
    """Test standard text response without tool calls."""
    mock_post = mocker.patch("httpx.Client.post")
    mock_post.return_value.status_code = 200
    mock_post.return_value.json.return_value = {
        "message": {
            "role": "assistant",
            "content": "Your system is healthy.",
            "thinking": "Analyzing health metrics...",
        },
        "done": True,
        "done_reason": "stop",
    }

    provider = OllamaProvider()
    response = provider.chat([Message(role="user", content="How is my laptop?")])

    assert isinstance(response, LLMResponse)
    assert response.content == "Your system is healthy."
    assert response.thinking == "Analyzing health metrics..."
    assert response.has_tool_calls is False


def test_ollama_provider_native_tool_call(mocker):
    """Test parsing of native Ollama tool call output."""
    mock_post = mocker.patch("httpx.Client.post")
    mock_post.return_value.status_code = 200
    mock_post.return_value.json.return_value = {
        "message": {
            "role": "assistant",
            "content": "",
            "tool_calls": [
                {
                    "function": {
                        "name": "disk_usage",
                        "arguments": {"path": "/var"},
                    }
                }
            ],
        },
        "done": True,
        "done_reason": "stop",
    }

    provider = OllamaProvider()
    response = provider.chat([Message(role="user", content="Check /var disk space")])

    assert response.has_tool_calls is True
    assert response.tool_call.function.name == "disk_usage"
    assert response.tool_call.function.arguments == {"path": "/var"}


def test_ollama_provider_fallback_tool_call(mocker):
    """Test fallback extraction when tool call is in markdown JSON block."""
    mock_post = mocker.patch("httpx.Client.post")
    mock_post.return_value.status_code = 200
    mock_post.return_value.json.return_value = {
        "message": {
            "role": "assistant",
            "content": "Let me check memory usage:\n```json\n{\n  \"name\": \"memory_usage\",\n  \"arguments\": {\"unit\": \"MB\"}\n}\n```",
        },
        "done": True,
        "done_reason": "stop",
    }

    provider = OllamaProvider()
    response = provider.chat([Message(role="user", content="Check memory")])

    assert response.has_tool_calls is True
    assert response.tool_call.function.name == "memory_usage"
    assert response.tool_call.function.arguments == {"unit": "MB"}


def test_ollama_provider_connect_error(mocker):
    """Test connection error raises LLMConnectionError."""
    mocker.patch("httpx.Client.post", side_effect=httpx.ConnectError("Daemon offline"))

    provider = OllamaProvider()
    with pytest.raises(LLMConnectionError):
        provider.chat([Message(role="user", content="test")])


def test_ollama_provider_http_error(mocker):
    """Test non-200 HTTP code raises LLMProviderError."""
    mock_post = mocker.patch("httpx.Client.post")
    mock_post.return_value.status_code = 500
    mock_post.return_value.text = "Internal server error"

    provider = OllamaProvider()
    with pytest.raises(LLMProviderError, match="HTTP 500"):
        provider.chat([Message(role="user", content="test")])


def test_ollama_provider_is_available(mocker):
    """Test is_available health check."""
    mock_get = mocker.patch("httpx.Client.get")
    mock_get.return_value.status_code = 200

    provider = OllamaProvider()
    assert provider.is_available() is True

    mock_get.side_effect = httpx.ConnectError("Unreachable")
    assert provider.is_available() is False


@pytest.mark.integration
def test_live_ollama_provider_tool_selection():
    """Live test verifying OllamaProvider correctly extracts tool calls from the running model."""
    settings = get_settings()
    provider = get_llm_provider(settings)

    tools = [
        ToolDefinition(
            function=ToolFunctionSchema(
                name="disk_usage",
                description="Check filesystem disk space usage",
                parameters=ToolParametersSchema(
                    properties={"path": {"type": "string", "description": "Mount path to check"}},
                ),
            )
        )
    ]

    messages = [
        Message(
            role="user",
            content="Check my disk usage.",
        )
    ]

    response = provider.chat(messages=messages, tools=tools)
    assert response.has_tool_calls is True
    assert response.tool_call.function.name == "disk_usage"
