"""System inspection tools: system_info, disk_usage, memory_usage, process_list.

All tools in this module belong to the SAFE risk tier and are strictly read-only.
"""

import os
import platform
import shutil
import subprocess
import time
from pathlib import Path
from typing import Any, Dict, List, Optional

from pilot.tools.base import BaseTool, RiskTier, ToolResult


class SystemInfoTool(BaseTool):
    """Inspect core system attributes: OS, distro, kernel, CPU, RAM, uptime."""

    name = "system_info"
    description = (
        "Inspect Linux host system information including distribution, kernel version, "
        "architecture, CPU model, core count, total RAM, and system uptime."
    )
    risk_tier = RiskTier.SAFE

    @property
    def parameters_schema(self) -> Dict[str, Any]:
        return {
            "type": "object",
            "properties": {},
        }

    def run(self, arguments: Dict[str, Any], timeout: float = 30.0) -> ToolResult:
        data: Dict[str, Any] = {
            "os": platform.system(),
            "kernel": platform.release(),
            "arch": platform.machine(),
            "hostname": platform.node(),
        }

        # Distro details from /etc/os-release
        distro_name = "Linux"
        distro_version = ""
        os_release = Path("/etc/os-release")
        if os_release.exists():
            try:
                with open(os_release, "r", encoding="utf-8") as f:
                    for line in f:
                        if line.startswith("PRETTY_NAME="):
                            distro_name = line.strip().split("=", 1)[1].strip('"')
                        elif line.startswith("VERSION_ID="):
                            distro_version = line.strip().split("=", 1)[1].strip('"')
            except Exception:
                pass
        data["distro"] = distro_name
        data["distro_version"] = distro_version

        # CPU info
        cpu_cores = os.cpu_count() or 1
        cpu_model = "Unknown"
        cpu_info = Path("/proc/cpuinfo")
        if cpu_info.exists():
            try:
                with open(cpu_info, "r", encoding="utf-8") as f:
                    for line in f:
                        if "model name" in line:
                            cpu_model = line.split(":", 1)[1].strip()
                            break
            except Exception:
                pass
        data["cpu"] = {
            "model": cpu_model,
            "cores": cpu_cores,
        }

        # Memory total (from /proc/meminfo)
        total_ram_mb = 0
        meminfo = Path("/proc/meminfo")
        if meminfo.exists():
            try:
                with open(meminfo, "r", encoding="utf-8") as f:
                    for line in f:
                        if line.startswith("MemTotal:"):
                            total_kb = int(line.split()[1])
                            total_ram_mb = round(total_kb / 1024, 1)
                            break
            except Exception:
                pass
        data["total_ram_mb"] = total_ram_mb

        # System uptime
        uptime_seconds = 0
        uptime_file = Path("/proc/uptime")
        if uptime_file.exists():
            try:
                with open(uptime_file, "r", encoding="utf-8") as f:
                    uptime_seconds = int(float(f.readline().split()[0]))
            except Exception:
                pass
        hours, rem = divmod(uptime_seconds, 3600)
        minutes, seconds = divmod(rem, 60)
        days, hours = divmod(hours, 24)
        uptime_str = f"{days}d {hours}h {minutes}m {seconds}s" if days else f"{hours}h {minutes}m {seconds}s"
        data["uptime_seconds"] = uptime_seconds
        data["uptime"] = uptime_str

        # Format summary output
        lines = [
            f"OS: {distro_name} ({platform.system()} {platform.release()} {platform.machine()})",
            f"Hostname: {data['hostname']}",
            f"CPU: {cpu_model} ({cpu_cores} cores)",
            f"Total RAM: {total_ram_mb} MB",
            f"Uptime: {uptime_str}",
        ]
        return ToolResult(
            success=True,
            data=data,
            stdout="\n".join(lines),
        )


class DiskUsageTool(BaseTool):
    """Inspect disk space utilization and mounted filesystems."""

    name = "disk_usage"
    description = (
        "Inspect filesystem disk usage, mount points, capacity, and percentage used. "
        "Optionally accepts a mount path (default: '/')."
    )
    risk_tier = RiskTier.SAFE

    @property
    def parameters_schema(self) -> Dict[str, Any]:
        return {
            "type": "object",
            "properties": {
                "path": {
                    "type": "string",
                    "description": "Path or mount point to inspect (default: '/')",
                }
            },
        }

    def run(self, arguments: Dict[str, Any], timeout: float = 30.0) -> ToolResult:
        check_path = arguments.get("path") or "/"
        resolved_path = Path(check_path).resolve()
        if not resolved_path.exists():
            return ToolResult(
                success=False,
                error=f"Specified path does not exist: {check_path}",
            )

        # 1. Targeted path usage via shutil
        usage = shutil.disk_usage(str(resolved_path))
        total_gb = round(usage.total / (1024**3), 2)
        used_gb = round(usage.used / (1024**3), 2)
        free_gb = round(usage.free / (1024**3), 2)
        pct_used = round((usage.used / usage.total) * 100, 1) if usage.total > 0 else 0.0

        target_data = {
            "path": str(resolved_path),
            "total_gb": total_gb,
            "used_gb": used_gb,
            "free_gb": free_gb,
            "percent_used": pct_used,
        }

        # 2. General filesystem mounts via df -hP
        mounts: List[Dict[str, str]] = []
        try:
            res = subprocess.run(
                ["df", "-hP"],
                capture_output=True,
                text=True,
                timeout=timeout,
                check=False,
            )
            if res.returncode == 0:
                lines = res.stdout.strip().split("\n")
                for line in lines[1:]:
                    parts = line.split()
                    if len(parts) >= 6:
                        mounts.append({
                            "filesystem": parts[0],
                            "size": parts[1],
                            "used": parts[2],
                            "avail": parts[3],
                            "percent": parts[4],
                            "mount": parts[5],
                        })
        except Exception:
            pass

        data = {
            "target": target_data,
            "mounts": mounts,
        }

        lines = [
            f"Disk Usage for {target_data['path']}:",
            f"  Total: {total_gb} GB | Used: {used_gb} GB ({pct_used}%) | Free: {free_gb} GB",
        ]
        if mounts:
            lines.append("\nMounted Filesystems:")
            lines.append(f"{'Filesystem':<20} {'Size':<8} {'Used':<8} {'Avail':<8} {'Use%':<6} {'Mounted on'}")
            for m in mounts[:10]:
                lines.append(f"{m['filesystem']:<20} {m['size']:<8} {m['used']:<8} {m['avail']:<8} {m['percent']:<6} {m['mount']}")

        return ToolResult(
            success=True,
            data=data,
            stdout="\n".join(lines),
        )


class MemoryUsageTool(BaseTool):
    """Inspect RAM and swap utilization statistics."""

    name = "memory_usage"
    description = (
        "Inspect memory statistics including total, used, free, available, buffers, "
        "and cached RAM, as well as swap utilization."
    )
    risk_tier = RiskTier.SAFE

    @property
    def parameters_schema(self) -> Dict[str, Any]:
        return {
            "type": "object",
            "properties": {},
        }

    def run(self, arguments: Dict[str, Any], timeout: float = 30.0) -> ToolResult:
        meminfo_path = Path("/proc/meminfo")
        if not meminfo_path.exists():
            return ToolResult(
                success=False,
                error="/proc/meminfo is not available on this platform",
            )

        fields: Dict[str, int] = {}
        with open(meminfo_path, "r", encoding="utf-8") as f:
            for line in f:
                parts = line.split(":")
                if len(parts) == 2:
                    key = parts[0].strip()
                    val_parts = parts[1].strip().split()
                    if val_parts and val_parts[0].isdigit():
                        fields[key] = int(val_parts[0])

        total_kb = fields.get("MemTotal", 0)
        free_kb = fields.get("MemFree", 0)
        avail_kb = fields.get("MemAvailable", free_kb)
        buffers_kb = fields.get("Buffers", 0)
        cached_kb = fields.get("Cached", 0)

        swap_total_kb = fields.get("SwapTotal", 0)
        swap_free_kb = fields.get("SwapFree", 0)
        swap_used_kb = swap_total_kb - swap_free_kb

        used_kb = total_kb - avail_kb if total_kb >= avail_kb else total_kb - free_kb
        used_pct = round((used_kb / total_kb) * 100, 1) if total_kb > 0 else 0.0
        swap_pct = round((swap_used_kb / swap_total_kb) * 100, 1) if swap_total_kb > 0 else 0.0

        def to_mb(kb: int) -> float:
            return round(kb / 1024, 1)

        data = {
            "total_mb": to_mb(total_kb),
            "used_mb": to_mb(used_kb),
            "free_mb": to_mb(free_kb),
            "available_mb": to_mb(avail_kb),
            "buffers_mb": to_mb(buffers_kb),
            "cached_mb": to_mb(cached_kb),
            "used_percent": used_pct,
            "swap_total_mb": to_mb(swap_total_kb),
            "swap_used_mb": to_mb(swap_used_kb),
            "swap_free_mb": to_mb(swap_free_kb),
            "swap_percent": swap_pct,
        }

        lines = [
            f"RAM:  Total: {data['total_mb']} MB | Used: {data['used_mb']} MB ({used_pct}%) | Available: {data['available_mb']} MB",
            f"Swap: Total: {data['swap_total_mb']} MB | Used: {data['swap_used_mb']} MB ({swap_pct}%) | Free: {data['swap_free_mb']} MB",
        ]

        return ToolResult(
            success=True,
            data=data,
            stdout="\n".join(lines),
        )


class ProcessListTool(BaseTool):
    """List running processes sorted by resource consumption."""

    name = "process_list"
    description = (
        "List running processes sorted by CPU or memory usage. "
        "Returns PID, user, CPU%, memory%, and process name."
    )
    risk_tier = RiskTier.SAFE

    @property
    def parameters_schema(self) -> Dict[str, Any]:
        return {
            "type": "object",
            "properties": {
                "sort_by": {
                    "type": "string",
                    "enum": ["cpu", "memory"],
                    "description": "Metric to sort by: 'cpu' (default) or 'memory'",
                },
                "limit": {
                    "type": "integer",
                    "description": "Maximum number of processes to return (default: 15, max: 50)",
                },
            },
        }

    def run(self, arguments: Dict[str, Any], timeout: float = 30.0) -> ToolResult:
        sort_by = arguments.get("sort_by", "cpu").lower()
        limit = min(max(int(arguments.get("limit") or 15), 1), 50)

        sort_flag = "-%mem" if sort_by == "memory" else "-%cpu"
        cmd = ["ps", "-eo", "pid,user,%cpu,%mem,comm", f"--sort={sort_flag}"]

        try:
            res = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout,
                check=False,
            )
        except Exception as e:
            return ToolResult(success=False, error=f"Failed to execute ps: {e}")

        if res.returncode != 0:
            return ToolResult(
                success=False,
                error=f"ps exited with status {res.returncode}: {res.stderr}",
            )

        raw_lines = [line.strip() for line in res.stdout.strip().split("\n") if line.strip()]
        header = raw_lines[0] if raw_lines else ""
        proc_lines = raw_lines[1 : limit + 1]

        processes: List[Dict[str, Any]] = []
        for line in proc_lines:
            parts = line.split(None, 4)
            if len(parts) >= 5:
                processes.append({
                    "pid": int(parts[0]) if parts[0].isdigit() else parts[0],
                    "user": parts[1],
                    "cpu_percent": float(parts[2]) if parts[2].replace(".", "", 1).isdigit() else 0.0,
                    "mem_percent": float(parts[3]) if parts[3].replace(".", "", 1).isdigit() else 0.0,
                    "command": parts[4],
                })

        # Formatted output table
        lines = [f"{'PID':<8} {'USER':<12} {'%CPU':<6} {'%MEM':<6} {'COMMAND'}"]
        for p in processes:
            lines.append(f"{str(p['pid']):<8} {p['user']:<12} {p['cpu_percent']:<6.1f} {p['mem_percent']:<6.1f} {p['command']}")

        return ToolResult(
            success=True,
            data={"count": len(processes), "processes": processes},
            stdout="\n".join(lines),
        )
