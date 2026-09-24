"""Planner module for structuring multi-step agent actions."""

from typing import List, Optional
from pydantic import BaseModel, Field


class PlanStep(BaseModel):
    """An individual action step in an execution plan."""

    step_number: int
    description: str
    tool_name: Optional[str] = None
    arguments: Optional[dict] = None
    is_modifying: bool = False


class Plan(BaseModel):
    """Structured sequence of plan steps."""

    goal: str
    steps: List[PlanStep] = Field(default_factory=list)

    def format_text(self) -> str:
        """Format the plan as a clean numbered list."""
        if not self.steps:
            return "No steps planned."
        lines = [f"Plan for: {self.goal}"]
        for s in self.steps:
            mod_flag = " [Modifies System]" if s.is_modifying else ""
            lines.append(f"{s.step_number}. {s.description}{mod_flag}")
        return "\n".join(lines)
