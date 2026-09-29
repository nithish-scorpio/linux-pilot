"""Unit tests for telemetry and latency tracking."""

import time
from pilot.telemetry import (
    get_current_metrics,
    record_redaction,
    record_security,
    record_sqlite,
    record_step_metric,
    record_tokens,
    record_tool,
    track_query,
)


def test_track_query_context():
    """Verify track_query captures overall duration and fine-grained metrics."""
    with track_query("test query") as m:
        assert get_current_metrics() is m
        time.sleep(0.01)

        with record_security():
            time.sleep(0.005)

        with record_redaction():
            time.sleep(0.005)

        with record_sqlite():
            time.sleep(0.005)

        with record_tool():
            time.sleep(0.005)

        record_tokens(prompt_tokens=10, output_tokens=5)
        record_step_metric(
            step=1,
            llm_time=0.02,
            ttft=0.01,
            prompt_tokens=10,
            output_tokens=5,
            tool_time=0.01,
            tools_called=["system_info"],
        )

    assert m.total_time >= 0.01
    assert m.security_time >= 0.004
    assert m.redaction_time >= 0.004
    assert m.sqlite_time >= 0.004
    assert m.tool_time >= 0.004
    assert m.llm_time == 0.02
    assert m.steps == 1
    assert get_current_metrics() is None
