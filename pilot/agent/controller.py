"""Agent Controller orchestrating the iterative LLM - Tool execution loop."""

import logging
from typing import Any, Callable, Dict, List, Optional
from pydantic import BaseModel, Field

from pilot.agent.prompts import build_system_prompt
from pilot.config import Settings, get_settings
from pilot.llm.client import LLMProvider, Message, ToolCall
from pilot.llm.models import get_llm_provider
from pilot.tools.base import RiskTier, ToolResult
from pilot.tools.registry import ToolRegistry, default_registry

logger = logging.getLogger(__name__)


class ExecutedToolRecord(BaseModel):
    """Record of a tool call and its execution result."""

    step: int
    tool_name: str
    arguments: Dict[str, Any]
    result: ToolResult


class AgentResponse(BaseModel):
    """Structured response returned by the AgentController upon completion."""

    final_answer: str
    steps_taken: int
    tool_calls_made: List[ExecutedToolRecord] = Field(default_factory=list)
    completed: bool
    messages: List[Message] = Field(default_factory=list)


class AgentController:
    """Manages the agent reasoning, tool calling, and response synthesis loop."""

    def __init__(
        self,
        llm_provider: Optional[LLMProvider] = None,
        tool_registry: Optional[ToolRegistry] = None,
        settings: Optional[Settings] = None,
        on_tool_start: Optional[Callable[[str, Dict[str, Any]], None]] = None,
        on_tool_end: Optional[Callable[[str, ToolResult], None]] = None,
        on_thinking: Optional[Callable[[str], None]] = None,
    ):
        self.settings = settings or get_settings()
        self.llm_provider = llm_provider or get_llm_provider(self.settings)
        self.tool_registry = tool_registry or default_registry
        self.on_tool_start = on_tool_start
        self.on_tool_end = on_tool_end
        self.on_thinking = on_thinking

    def run(
        self,
        user_request: str,
        history: Optional[List[Message]] = None,
        dry_run: Optional[bool] = None,
        verbose: Optional[bool] = None,
    ) -> AgentResponse:
        """Run the bounded agent loop to address the user request.

        Args:
            user_request: Natural language command or query.
            history: Optional prior conversation message history.
            dry_run: Force dry-run plan-only mode (overriding settings).
            verbose: Enable verbose logging of intermediate steps.

        Returns:
            AgentResponse containing the final answer, steps taken, and tool history.
        """
        is_dry_run = dry_run if dry_run is not None else self.settings.dry_run
        is_verbose = verbose if verbose is not None else self.settings.verbose
        max_steps = self.settings.max_agent_steps

        # Initialize conversation messages
        messages: List[Message] = []
        if history:
            messages.extend(history)
        else:
            system_prompt = build_system_prompt(dry_run=is_dry_run)
            messages.append(Message(role="system", content=system_prompt))

        messages.append(Message(role="user", content=user_request))

        tool_definitions = self.tool_registry.get_tool_definitions()
        executed_tools: List[ExecutedToolRecord] = []
        step = 0

        while step < max_steps:
            step += 1
            if is_verbose:
                logger.info("Agent Step %d/%d for query: %s", step, max_steps, user_request)

            try:
                response = self.llm_provider.chat(
                    messages=messages,
                    tools=tool_definitions if tool_definitions else None,
                )
            except Exception as e:
                logger.error("LLM Provider failure on step %d: %s", step, e)
                return AgentResponse(
                    final_answer=f"Error communicating with local LLM: {e}",
                    steps_taken=step,
                    tool_calls_made=executed_tools,
                    completed=False,
                    messages=messages,
                )

            # Emit thinking tokens if requested
            if response.thinking and self.on_thinking:
                self.on_thinking(response.thinking)

            # If no tool calls requested, we have the final synthesis
            if not response.has_tool_calls:
                final_text = response.content or "(Completed with no response)"
                messages.append(Message(role="assistant", content=final_text))
                return AgentResponse(
                    final_answer=final_text,
                    steps_taken=step,
                    tool_calls_made=executed_tools,
                    completed=True,
                    messages=messages,
                )

            # Process tool calls
            messages.append(
                Message(
                    role="assistant",
                    content=response.content or "",
                    tool_calls=response.tool_calls,
                )
            )

            for tc in response.tool_calls:
                tool_name = tc.function.name
                tool_args = tc.function.arguments

                if self.on_tool_start:
                    self.on_tool_start(tool_name, tool_args)

                # Dry-run check for modifying operations
                tool_obj = self.tool_registry.get(tool_name)
                if is_dry_run and tool_obj and tool_obj.risk_tier != RiskTier.SAFE:
                    tool_result = ToolResult(
                        success=True,
                        stdout=f"[DRY-RUN] Simulated execution of {tool_name}({tool_args}). No changes made.",
                    )
                else:
                    tool_result = self.tool_registry.execute_tool(
                        name=tool_name,
                        arguments=tool_args,
                        timeout=float(self.settings.command_timeout),
                    )

                if self.on_tool_end:
                    self.on_tool_end(tool_name, tool_result)

                executed_tools.append(
                    ExecutedToolRecord(
                        step=step,
                        tool_name=tool_name,
                        arguments=tool_args,
                        result=tool_result,
                    )
                )

                # Append tool result to context
                messages.append(
                    Message(
                        role="tool",
                        name=tool_name,
                        tool_call_id=tc.id or f"call_{step}",
                        content=tool_result.format_for_llm(),
                    )
                )

        # Loop bounded: maximum steps exceeded
        logger.warning("Agent exceeded maximum step limit (%d)", max_steps)
        limit_msg = (
            f"The agent reached the maximum allowed execution limit ({max_steps} steps) "
            "before completing the task. Operation stopped to prevent infinite loops."
        )
        return AgentResponse(
            final_answer=limit_msg,
            steps_taken=step,
            tool_calls_made=executed_tools,
            completed=False,
            messages=messages,
        )
