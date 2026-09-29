"""Agent Controller orchestrating the iterative LLM - Tool execution loop."""

import concurrent.futures
import logging
import time
from typing import Any, Callable, Dict, List, Optional, Set, Tuple
from pydantic import BaseModel, Field

from pilot.agent.fast_path import FastPathRouter
from pilot.agent.prompts import build_system_prompt
from pilot.config import Settings, get_settings
from pilot.llm.client import LLMProvider, Message, ToolCall, ToolDefinition
from pilot.llm.models import get_llm_provider
from pilot.security.redactor import redact_secrets
from pilot.telemetry import record_step_metric
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


def truncate_tool_output(content: str, max_length: int = 1500) -> str:
    """Truncate excessively large tool outputs preserving head and tail."""
    if len(content) <= max_length:
        return content
    head = content[:800]
    tail = content[-400:]
    truncated_count = len(content) - 1200
    return f"{head}\n\n... [truncated {truncated_count} characters of output] ...\n\n{tail}"


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

    def _filter_relevant_tools(self, user_request: str) -> List[ToolDefinition]:
        """Send only query-relevant tool schemas to minimize prompt eval tokens."""
        lower = user_request.lower()
        all_defs = self.tool_registry.get_tool_definitions()

        # If user explicitly asks for shell execution or general troubleshooting, provide all
        if any(w in lower for w in ("command", "run", "troubleshoot", "why", "error", "fail", "slow")):
            return all_defs

        package_words = ("package", "install", "remove", "update", "apt", "dnf", "pacman", "repo")
        fs_words = ("file", "directory", "dir", "read", "search", "find", "write", "content", "lines")

        is_pkg = any(w in lower for w in package_words)
        is_fs = any(w in lower for w in fs_words)

        if is_pkg and not is_fs:
            return [
                t for t in all_defs
                if t.function.name in (
                    "is_package_installed", "package_search", "package_install",
                    "package_remove", "package_update", "execute_command"
                )
            ]
        elif is_fs and not is_pkg:
            return [
                t for t in all_defs
                if t.function.name in (
                    "list_directory", "read_file", "search_files", "write_file", "execute_command"
                )
            ]

        # Default: return safe system inspection tools and execute_command
        return all_defs

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
        loop_start_time = time.perf_counter()

        # Initialize conversation messages
        messages: List[Message] = []
        if history:
            messages.extend(history)
        else:
            system_prompt = build_system_prompt(dry_run=is_dry_run)
            messages.append(Message(role="system", content=system_prompt))

        messages.append(Message(role="user", content=user_request))

        # -------------------------------------------------------------
        # FAST PATH: Deterministic routing for unambiguous queries
        # -------------------------------------------------------------
        fast_path_actions = FastPathRouter.match(user_request)
        if fast_path_actions is not None:
            if is_verbose:
                logger.info("Fast-path activated for query: %s -> %s", user_request, fast_path_actions)

            executed_tools: List[ExecutedToolRecord] = []
            final_outputs: List[str] = []

            # Check if all tools are SAFE so they can run in parallel
            all_safe = all(
                (self.tool_registry.get(name) is not None and self.tool_registry.get(name).risk_tier == RiskTier.SAFE)
                for name, _ in fast_path_actions
            )

            if len(fast_path_actions) > 1 and all_safe and not is_dry_run:
                # Parallel execution of independent SAFE tools
                def _exec_single(tool_name: str, tool_args: Dict[str, Any]) -> Tuple[str, Dict[str, Any], ToolResult]:
                    if self.on_tool_start:
                        self.on_tool_start(tool_name, tool_args)
                    res = self.tool_registry.execute_tool(
                        name=tool_name,
                        arguments=tool_args,
                        timeout=float(self.settings.command_timeout),
                    )
                    if self.on_tool_end:
                        self.on_tool_end(tool_name, res)
                    return tool_name, tool_args, res

                with concurrent.futures.ThreadPoolExecutor(max_workers=len(fast_path_actions)) as executor:
                    futures = [executor.submit(_exec_single, name, args) for name, args in fast_path_actions]
                    for fut in concurrent.futures.as_completed(futures):
                        t_name, t_args, t_res = fut.result()
                        executed_tools.append(
                            ExecutedToolRecord(
                                step=1,
                                tool_name=t_name,
                                arguments=t_args,
                                result=t_res,
                            )
                        )
                        output_str = t_res.stdout or t_res.error or ""
                        final_outputs.append(redact_secrets(output_str))
            else:
                for tool_name, tool_args in fast_path_actions:
                    if self.on_tool_start:
                        self.on_tool_start(tool_name, tool_args)

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
                            step=1,
                            tool_name=tool_name,
                            arguments=tool_args,
                            result=tool_result,
                        )
                    )
                    output_str = tool_result.stdout or tool_result.error or ""
                    final_outputs.append(redact_secrets(output_str))

            combined_answer = "\n\n".join(filter(None, final_outputs)) or "Operation completed successfully."
            messages.append(Message(role="assistant", content=combined_answer))

            total_tool_duration = sum(et.result.duration for et in executed_tools)
            record_step_metric(
                step=1,
                llm_time=0.0,
                ttft=0.001,
                prompt_tokens=0,
                output_tokens=0,
                tool_time=total_tool_duration,
                tools_called=[et.tool_name for et in executed_tools],
            )
            return AgentResponse(
                final_answer=combined_answer,
                steps_taken=1,
                tool_calls_made=executed_tools,
                completed=True,
                messages=messages,
            )

        # -------------------------------------------------------------
        # LLM REASONING LOOP (Fallback for complex/ambiguous queries)
        # -------------------------------------------------------------
        tool_definitions = self._filter_relevant_tools(user_request)
        executed_tools: List[ExecutedToolRecord] = []
        executed_signatures: Set[str] = set()
        step = 0

        while step < max_steps:
            # Hard 8.0s cap check: prevent exceeding latency budget
            elapsed = time.perf_counter() - loop_start_time
            if elapsed >= 8.0 and executed_tools:
                logger.warning("Hard 8.0s latency cap reached (%.2fs elapsed); synthesizing answer.", elapsed)
                break

            step += 1
            if is_verbose:
                logger.info("Agent Step %d/%d for query: %s", step, max_steps, user_request)

            step_llm_start = time.perf_counter()
            try:
                # Use short output cap for tool selection
                num_predict = 120 if step == 1 else 300
                response = self.llm_provider.chat(
                    messages=messages,
                    tools=tool_definitions if tool_definitions else None,
                    num_predict=num_predict,
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

            step_llm_duration = time.perf_counter() - step_llm_start
            raw_data = response.raw or {}
            p_tokens = raw_data.get("prompt_eval_count", 0)
            o_tokens = raw_data.get("eval_count", 0)

            # Emit thinking tokens if requested
            if response.thinking and self.on_thinking:
                self.on_thinking(response.thinking)

            # If no tool calls requested, we have the final synthesis
            if not response.has_tool_calls:
                final_text = response.content or "(Completed with no response)"
                messages.append(Message(role="assistant", content=final_text))
                record_step_metric(
                    step=step,
                    llm_time=step_llm_duration,
                    ttft=step_llm_duration if step == 1 else 0.0,
                    prompt_tokens=p_tokens,
                    output_tokens=o_tokens,
                    tool_time=0.0,
                )
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

            step_tool_time = 0.0
            tools_called_this_step = []

            for tc in response.tool_calls:
                tool_name = tc.function.name
                tool_args = tc.function.arguments
                sig = f"{tool_name}:{sorted(tool_args.items())}"

                # Loop guard: Break immediately if repeated tool call
                if sig in executed_signatures:
                    logger.warning("Loop guard triggered: Duplicate tool call %s detected.", tool_name)
                    break
                executed_signatures.add(sig)

                if self.on_tool_start:
                    self.on_tool_start(tool_name, tool_args)

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

                step_tool_time += tool_result.duration
                tools_called_this_step.append(tool_name)
                executed_tools.append(
                    ExecutedToolRecord(
                        step=step,
                        tool_name=tool_name,
                        arguments=tool_args,
                        result=tool_result,
                    )
                )

                # Sanitize and truncate tool result before appending to message history
                formatted_output = tool_result.format_for_llm()
                truncated_output = truncate_tool_output(formatted_output)
                clean_output = redact_secrets(truncated_output)

                messages.append(
                    Message(
                        role="tool",
                        name=tool_name,
                        tool_call_id=tc.id or f"call_{step}",
                        content=clean_output,
                    )
                )

            record_step_metric(
                step=step,
                llm_time=step_llm_duration,
                ttft=step_llm_duration if step == 1 else 0.0,
                prompt_tokens=p_tokens,
                output_tokens=o_tokens,
                tool_time=step_tool_time,
                tools_called=tools_called_this_step,
            )

        # Check if exited due to exceeding max steps limit
        if step >= max_steps:
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

        # Hard-cap exit: Synthesize final answer from existing tool outputs
        if executed_tools:
            collected_outputs = [
                et.result.stdout or et.result.error or "" for et in executed_tools
            ]
            fallback_answer = "\n\n".join(filter(None, collected_outputs)) or "Task completed."
            messages.append(Message(role="assistant", content=fallback_answer))
            return AgentResponse(
                final_answer=fallback_answer,
                steps_taken=step,
                tool_calls_made=executed_tools,
                completed=True,
                messages=messages,
            )
