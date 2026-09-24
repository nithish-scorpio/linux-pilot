"""Unit tests for Phase 5 safe read-only Linux tools."""

import pytest
from pilot.tools import (
    DiskUsageTool,
    MemoryUsageTool,
    NetworkInfoTool,
    ProcessListTool,
    SystemInfoTool,
    default_registry,
)


def test_system_info_tool():
    """Verify system_info collects valid host OS and hardware details."""
    tool = SystemInfoTool()
    assert tool.name == "system_info"
    assert tool.risk_tier.value == "safe"

    res = tool.execute({})
    assert res.success is True
    assert res.data["os"] == "Linux"
    assert res.data["kernel"] != ""
    assert res.data["arch"] != ""
    assert "cpu" in res.data
    assert res.data["cpu"]["cores"] >= 1
    assert res.data["total_ram_mb"] > 0
    assert "OS:" in res.stdout
    assert "CPU:" in res.stdout


def test_disk_usage_tool_root():
    """Verify disk_usage checks root filesystem."""
    tool = DiskUsageTool()
    assert tool.name == "disk_usage"
    assert tool.risk_tier.value == "safe"

    res = tool.execute({"path": "/"})
    assert res.success is True
    assert "target" in res.data
    assert res.data["target"]["total_gb"] > 0
    assert res.data["target"]["free_gb"] > 0
    assert 0 <= res.data["target"]["percent_used"] <= 100
    assert "Total:" in res.stdout


def test_disk_usage_tool_invalid_path():
    """Verify disk_usage gracefully reports non-existent path."""
    tool = DiskUsageTool()
    res = tool.execute({"path": "/nonexistent_path_xyz_12345"})
    assert res.success is False
    assert "does not exist" in res.error


def test_memory_usage_tool():
    """Verify memory_usage reads /proc/meminfo metrics."""
    tool = MemoryUsageTool()
    assert tool.name == "memory_usage"
    assert tool.risk_tier.value == "safe"

    res = tool.execute({})
    assert res.success is True
    assert res.data["total_mb"] > 0
    assert res.data["available_mb"] > 0
    assert 0 <= res.data["used_percent"] <= 100
    assert "RAM:" in res.stdout


def test_process_list_tool_cpu():
    """Verify process_list returns top CPU processes."""
    tool = ProcessListTool()
    assert tool.name == "process_list"
    assert tool.risk_tier.value == "safe"

    res = tool.execute({"sort_by": "cpu", "limit": 5})
    assert res.success is True
    assert "processes" in res.data
    assert len(res.data["processes"]) <= 5
    assert len(res.data["processes"]) > 0

    first = res.data["processes"][0]
    assert "pid" in first
    assert "user" in first
    assert "cpu_percent" in first
    assert "command" in first
    assert "PID" in res.stdout


def test_process_list_tool_memory():
    """Verify process_list sort_by memory."""
    tool = ProcessListTool()
    res = tool.execute({"sort_by": "memory", "limit": 3})
    assert res.success is True
    assert len(res.data["processes"]) <= 3


def test_network_info_tool():
    """Verify network_info returns interfaces and default routes."""
    tool = NetworkInfoTool()
    assert tool.name == "network_info"
    assert tool.risk_tier.value == "safe"

    res = tool.execute({})
    assert res.success is True
    assert "interfaces" in res.data
    assert len(res.data["interfaces"]) > 0

    # Ensure loopback interface is found
    ifnames = [i["interface"] for i in res.data["interfaces"]]
    assert "lo" in ifnames


def test_safe_tools_registered_in_default_registry():
    """Verify all 5 safe tools are loaded in default_registry."""
    tools = default_registry.list_tools()
    tool_names = [t.name for t in tools]

    expected = ["system_info", "disk_usage", "memory_usage", "process_list", "network_info"]
    for exp in expected:
        assert exp in tool_names
        assert default_registry.get(exp).risk_tier.value == "safe"
