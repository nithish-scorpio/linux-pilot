"""Concrete implementations of LLM providers.

Currently implements OllamaProvider with native tool calling and thinking token support.
"""

import json
import logging
import re
from typing import Any, Dict, List, Optional
import httpx

from pilot.config import Settings, get_settings
from pilot.llm.client import (
    FunctionCall,
    LLMConnectionError,
    LLMProvider,
    LLMProviderError,
    LLMResponse,
    Message,
    ToolCall,
    ToolDefinition,
)

logger = logging.getLogger(__name__)


class OllamaProvider(LLMProvider):
    """LLM Provider for local Ollama instances."""

    def __init__(
        self,
        model: str = "qwen3:4b",
        host: str = "http://localhost:11434",
        timeout: float = 180.0,
    ):
        self.model = model
        self.host = host.rstrip("/")
        self.timeout = timeout

    def is_available(self) -> bool:
        """Verify reachability of the Ollama service."""
        try:
            with httpx.Client(timeout=3.0) as client:
                res = client.get(f"{self.host}/api/tags")
                return res.status_code == 200
        except Exception:
            return False

    def chat(
        self,
        messages: List[Message],
        tools: Optional[List[ToolDefinition]] = None,
        temperature: float = 0.0,
        **kwargs: Any,
    ) -> LLMResponse:
        """Execute chat request against Ollama /api/chat with tool calling support."""
        url = f"{self.host}/api/chat"

        # Format messages for Ollama API
        formatted_messages = []
        for msg in messages:
            msg_dict: Dict[str, Any] = {
                "role": msg.role,
                "content": msg.content or "",
            }
            if msg.tool_calls:
                msg_dict["tool_calls"] = [tc.model_dump() for tc in msg.tool_calls]
            formatted_messages.append(msg_dict)

        payload: Dict[str, Any] = {
            "model": self.model,
            "messages": formatted_messages,
            "stream": False,
            "options": {
                "temperature": temperature,
            },
        }

        # Allow caller kwargs to override or extend options
        if "num_predict" in kwargs:
            payload["options"]["num_predict"] = kwargs["num_predict"]

        if tools:
            payload["tools"] = [t.model_dump() for t in tools]

        try:
            with httpx.Client(timeout=self.timeout) as client:
                response = client.post(url, json=payload)
        except httpx.ConnectError as e:
            raise LLMConnectionError(f"Failed to connect to Ollama at {self.host}: {e}") from e
        except httpx.TimeoutException as e:
            raise LLMProviderError(f"Ollama request timed out after {self.timeout}s: {e}") from e
        except Exception as e:
            raise LLMProviderError(f"Unexpected error communicating with Ollama: {e}") from e

        if response.status_code != 200:
            raise LLMProviderError(
                f"Ollama API returned HTTP {response.status_code}: {response.text}"
            )

        data = response.json()
        return self._parse_ollama_response(data)

    def _parse_ollama_response(self, data: Dict[str, Any]) -> LLMResponse:
        """Parse and normalize the JSON response from Ollama."""
        message_data = data.get("message", {})
        content = message_data.get("content") or None
        thinking = message_data.get("thinking") or None
        raw_tool_calls = message_data.get("tool_calls") or []

        parsed_tool_calls: List[ToolCall] = []

        # 1. Parse native tool calls
        for item in raw_tool_calls:
            func = item.get("function", {})
            name = func.get("name", "")
            args = func.get("arguments", {})
            if isinstance(args, str):
                try:
                    args = json.loads(args)
                except json.JSONDecodeError:
                    args = {"raw": args}

            if name:
                parsed_tool_calls.append(
                    ToolCall(
                        id=item.get("id"),
                        type="function",
                        function=FunctionCall(name=name, arguments=args),
                    )
                )

        # 2. Fallback: Check if model generated tool call JSON inside markdown content
        if not parsed_tool_calls and content:
            fallback = self._extract_json_tool_call(content)
            if fallback:
                parsed_tool_calls.append(fallback)

        return LLMResponse(
            content=content,
            thinking=thinking,
            tool_calls=parsed_tool_calls,
            finish_reason=data.get("done_reason"),
            raw=data,
        )

    def _extract_json_tool_call(self, text: str) -> Optional[ToolCall]:
        """Attempt to extract tool call from markdown JSON block when native parsing is absent."""
        json_pattern = r"```(?:json)?\s*(\{[\s\S]*?\})\s*```"
        match = re.search(json_pattern, text)
        if match:
            candidate = match.group(1)
            try:
                data = json.loads(candidate)
                if isinstance(data, dict):
                    # Schema 1: {"name": "tool_name", "arguments": {...}}
                    if "name" in data and ("arguments" in data or "parameters" in data):
                        args = data.get("arguments") or data.get("parameters") or {}
                        return ToolCall(
                            function=FunctionCall(name=data["name"], arguments=args)
                        )
                    # Schema 2: {"tool": "tool_name", "args": {...}}
                    if "tool" in data and ("args" in data or "parameters" in data):
                        args = data.get("args") or data.get("parameters") or {}
                        return ToolCall(
                            function=FunctionCall(name=data["tool"], arguments=args)
                        )
            except Exception:
                pass
        return None


def get_llm_provider(settings: Optional[Settings] = None) -> LLMProvider:
    """Factory to retrieve the configured LLM provider instance."""
    cfg = settings or get_settings()
    timeout = max(180.0, float(cfg.command_timeout * 3))
    return OllamaProvider(
        model=cfg.model,
        host=cfg.ollama_host,
        timeout=timeout,
    )
