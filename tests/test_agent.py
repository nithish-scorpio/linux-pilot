"""Unit tests for Phase 6 Agent Controller and Planning."""

import pytest
from pilot.agent import (
    AgentController,
    BASE_SYSTEM_PROMPT,
    Plan,
    PlanStep,
    build_system_prompt,
)
from pilot.config import Settings
from pilot.llm import (
    FunctionCall,
    LLMConnectionError,
    LLMProvider,
    LLMResponse,
    Message,
    ToolCall,
)
from pilot.tools import BaseTool, RiskTier, ToolRegistry, ToolResult


class MockEchoTool(BaseTool):
    name = "mock_echo"
    description = "Echo tool"
    risk_tier = RiskTier.SAFE

    @property
    def parameters_schema(self):
        return {"type": "object", "properties": {"msg": {"type": "string"}}}

    def run(self, arguments, timeout=30.0):
        return ToolResult(success=True, stdout=f"Echo: {arguments.get('msg')}")


class MockModifyingTool(BaseTool):
    name = "mock_modify"
    description = "Modifying tool"
    risk_tier = RiskTier.CONFIRM

    @property
    def parameters_schema(self):
        return {"type": "object", "properties": {}}

    def run(self, arguments, timeout=30.0):
        return ToolResult(success=True, stdout="System modified")


class MockScriptedLLM(LLMProvider):
    """Mock LLM returning a predetermined sequence of LLMResponses."""

    def __init__(self, responses):
        self.responses = list(responses)
        self.call_count = 0
        self.received_messages = []

    def is_available(self):
        return True

    def chat(self, messages, tools=None, temperature=0.0, **kwargs):
        self.call_count += 1
        self.received_messages.append(messages)
        if not self.responses:
            return LLMResponse(content="Default mock final answer")
        return self.responses.pop(0)


def test_system_prompt_builder():
    """Verify system prompt contains mandated instructions and dry-run notice."""
    prompt_normal = build_system_prompt(dry_run=False)
    assert BASE_SYSTEM_PROMPT in prompt_normal
    assert "Host Environment:" in prompt_normal
    assert "OPERATIONAL MODE: DRY-RUN" not in prompt_normal

    prompt_dry = build_system_prompt(dry_run=True)
    assert "OPERATIONAL MODE: DRY-RUN" in prompt_dry
    assert "You must NOT execute modifying actions" in prompt_dry


def test_plan_schema():
    """Verify Plan model formatting."""
    plan = Plan(
        goal="Install Node.js",
        steps=[
            PlanStep(step_number=1, description="Detect distro", is_modifying=False),
            PlanStep(step_number=2, description="Install nodejs package", is_modifying=True),
        ],
    )
    text = plan.format_text()
    assert "Plan for: Install Node.js" in text
    assert "1. Detect distro" in text
    assert "2. Install nodejs package [Modifies System]" in text


def test_agent_direct_answer():
    """Verify agent completes in 1 step when model provides direct answer without tools."""
    mock_llm = MockScriptedLLM([
        LLMResponse(content="Ubuntu is a Debian-based Linux distribution.")
    ])
    registry = ToolRegistry()
    controller = AgentController(llm_provider=mock_llm, tool_registry=registry)

    response = controller.run("What is Ubuntu?")
    assert response.completed is True
    assert response.steps_taken == 1
    assert "Ubuntu is a Debian-based" in response.final_answer
    assert len(response.tool_calls_made) == 0


def test_agent_tool_execution_flow():
    """Verify agent invokes tool, appends result, and completes with synthesis."""
    mock_llm = MockScriptedLLM([
        # Turn 1: request tool
        LLMResponse(
            content="",
            tool_calls=[
                ToolCall(
                    id="call_1",
                    function=FunctionCall(name="mock_echo", arguments={"msg": "Hello Agent"}),
                )
            ],
        ),
        # Turn 2: final synthesis
        LLMResponse(content="The tool output was: Echo: Hello Agent"),
    ])

    registry = ToolRegistry()
    registry.register(MockEchoTool())

    controller = AgentController(llm_provider=mock_llm, tool_registry=registry)
    response = controller.run("Run echo")

    assert response.completed is True
    assert response.steps_taken == 2
    assert len(response.tool_calls_made) == 1
    assert response.tool_calls_made[0].tool_name == "mock_echo"
    assert "Echo: Hello Agent" in response.tool_calls_made[0].result.stdout
    assert "The tool output was: Echo: Hello Agent" in response.final_answer


def test_agent_max_steps_guard():
    """Verify infinite loop guard stops execution when max_agent_steps is reached."""
    # LLM always returns a tool call
    endless_responses = [
        LLMResponse(
            content="",
            tool_calls=[
                ToolCall(
                    id=f"call_{i}",
                    function=FunctionCall(name="mock_echo", arguments={"msg": f"step_{i}"}),
                )
            ],
        )
        for i in range(10)
    ]
    mock_llm = MockScriptedLLM(endless_responses)

    registry = ToolRegistry()
    registry.register(MockEchoTool())

    settings = Settings(MAX_AGENT_STEPS=3)
    controller = AgentController(
        llm_provider=mock_llm,
        tool_registry=registry,
        settings=settings,
    )

    response = controller.run("Loop forever")
    assert response.completed is False
    assert response.steps_taken == 3
    assert len(response.tool_calls_made) == 3
    assert "reached the maximum allowed execution limit (3 steps)" in response.final_answer


def test_agent_dry_run_simulation():
    """Verify that in dry-run mode, modifying tools are simulated and not executed."""
    mock_llm = MockScriptedLLM([
        LLMResponse(
            content="",
            tool_calls=[
                ToolCall(
                    id="call_mod",
                    function=FunctionCall(name="mock_modify", arguments={}),
                )
            ],
        ),
        LLMResponse(content="Simulation complete."),
    ])

    registry = ToolRegistry()
    registry.register(MockModifyingTool())

    controller = AgentController(llm_provider=mock_llm, tool_registry=registry)
    response = controller.run("Perform modification", dry_run=True)

    assert response.completed is True
    assert len(response.tool_calls_made) == 1
    # Check that tool returned simulated stdout and did not execute the real modifying action
    assert "[DRY-RUN] Simulated execution" in response.tool_calls_made[0].result.stdout


def test_agent_llm_exception_handling():
    """Verify graceful handling when LLM communication raises an exception."""
    class BrokenLLM(LLMProvider):
        def is_available(self):
            return False

        def chat(self, messages, tools=None, temperature=0.0, **kwargs):
            raise LLMConnectionError("Ollama daemon unreachable")

    controller = AgentController(llm_provider=BrokenLLM(), tool_registry=ToolRegistry())
    response = controller.run("Hello")

    assert response.completed is False
    assert "Error communicating with local LLM" in response.final_answer
