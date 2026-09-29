"""Performance and latency telemetry module for Linux Command Pilot.

Provides zero-overhead context hooks to record:
- Time to first token (TTFT)
- LLM time per step and total
- Tool execution time
- Security validation time
- Secret redaction time
- SQLite database persistence time
- Prompt and output token counts
"""

from contextlib import contextmanager
from dataclasses import dataclass, field
import threading
import time
from typing import Generator, List, Optional


@dataclass
class StepMetric:
    """Metrics for a single agent step."""

    step: int
    llm_time: float = 0.0
    ttft: float = 0.0
    prompt_tokens: int = 0
    output_tokens: int = 0
    tool_time: float = 0.0
    tools_called: List[str] = field(default_factory=list)


@dataclass
class QueryMetrics:
    """End-to-end latency and resource breakdown for a single query."""

    query: str = ""
    total_time: float = 0.0
    ttft: float = 0.0
    steps: int = 0
    llm_time: float = 0.0
    tool_time: float = 0.0
    security_time: float = 0.0
    redaction_time: float = 0.0
    sqlite_time: float = 0.0
    prompt_tokens: int = 0
    output_tokens: int = 0
    step_metrics: List[StepMetric] = field(default_factory=list)
    success: bool = True
    error: Optional[str] = None


class _TelemetryContext:
    """Thread-local storage for active query telemetry."""

    def __init__(self):
        self._local = threading.local()

    @property
    def current(self) -> Optional[QueryMetrics]:
        return getattr(self._local, "current", None)

    @current.setter
    def current(self, value: Optional[QueryMetrics]) -> None:
        self._local.current = value


_context = _TelemetryContext()


def get_current_metrics() -> Optional[QueryMetrics]:
    """Retrieve active QueryMetrics if tracking is enabled."""
    return _context.current


@contextmanager
def track_query(query: str = "") -> Generator[QueryMetrics, None, None]:
    """Context manager to measure end-to-end query execution metrics."""
    metrics = QueryMetrics(query=query)
    prev = _context.current
    _context.current = metrics
    start_time = time.perf_counter()
    try:
        yield metrics
    finally:
        metrics.total_time = round(time.perf_counter() - start_time, 4)
        # If ttft was not set during LLM streaming or fast-path, default to total or first llm time
        if metrics.ttft == 0.0 and metrics.total_time > 0.0:
            if metrics.step_metrics and metrics.step_metrics[0].ttft > 0.0:
                metrics.ttft = metrics.step_metrics[0].ttft
            else:
                metrics.ttft = metrics.total_time
        _context.current = prev


@contextmanager
def record_security() -> Generator[None, None, None]:
    """Record duration spent in security validation."""
    metrics = _context.current
    if metrics is None:
        yield
        return
    t0 = time.perf_counter()
    try:
        yield
    finally:
        metrics.security_time += time.perf_counter() - t0


@contextmanager
def record_redaction() -> Generator[None, None, None]:
    """Record duration spent in secret redaction."""
    metrics = _context.current
    if metrics is None:
        yield
        return
    t0 = time.perf_counter()
    try:
        yield
    finally:
        metrics.redaction_time += time.perf_counter() - t0


@contextmanager
def record_sqlite() -> Generator[None, None, None]:
    """Record duration spent in SQLite database operations."""
    metrics = _context.current
    if metrics is None:
        yield
        return
    t0 = time.perf_counter()
    try:
        yield
    finally:
        metrics.sqlite_time += time.perf_counter() - t0


@contextmanager
def record_tool() -> Generator[None, None, None]:
    """Record duration spent in tool execution."""
    metrics = _context.current
    if metrics is None:
        yield
        return
    t0 = time.perf_counter()
    try:
        yield
    finally:
        metrics.tool_time += time.perf_counter() - t0


def record_tokens(prompt_tokens: int, output_tokens: int) -> None:
    """Record prompt and output token counts."""
    metrics = _context.current
    if metrics:
        metrics.prompt_tokens += prompt_tokens
        metrics.output_tokens += output_tokens


def record_step_metric(
    step: int,
    llm_time: float,
    ttft: float,
    prompt_tokens: int,
    output_tokens: int,
    tool_time: float = 0.0,
    tools_called: Optional[List[str]] = None,
) -> None:
    """Record detailed metric for an individual step."""
    metrics = _context.current
    if metrics:
        metrics.steps = max(metrics.steps, step)
        metrics.llm_time += llm_time
        if metrics.ttft == 0.0 and ttft > 0.0:
            metrics.ttft = ttft
        metrics.prompt_tokens += prompt_tokens
        metrics.output_tokens += output_tokens
        metrics.step_metrics.append(
            StepMetric(
                step=step,
                llm_time=llm_time,
                ttft=ttft,
                prompt_tokens=prompt_tokens,
                output_tokens=output_tokens,
                tool_time=tool_time,
                tools_called=tools_called or [],
            )
        )
