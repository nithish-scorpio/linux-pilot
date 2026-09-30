"""Network inspection tool: network_info.

Safe, read-only network interface and routing inspector.
"""

import json
import subprocess
from typing import Any, Dict, List

from pilot.tools.base import BaseTool, RiskTier, ToolResult


class NetworkInfoTool(BaseTool):
    """Inspect network interfaces, IP addresses, and routing."""

    name = "network_info"
    description = (
        "Inspect network interfaces, operational status (UP/DOWN), MAC addresses, "
        "assigned IPv4/IPv6 addresses, default gateway routes, or listening sockets for a specific port."
    )
    risk_tier = RiskTier.SAFE

    @property
    def parameters_schema(self) -> Dict[str, Any]:
        return {
            "type": "object",
            "properties": {
                "port": {
                    "type": "integer",
                    "description": "Optional port number to inspect for listening processes and socket status",
                }
            },
        }

    def _inspect_port(self, port: int, timeout: float = 10.0) -> ToolResult:
        """Inspect listening processes and socket status for a specific port."""
        if not (1 <= port <= 65535):
            return ToolResult(success=False, error=f"Invalid port number: {port}. Port must be between 1 and 65535.")

        lines: List[str] = []
        try:
            res_ss = subprocess.run(
                ["ss", "-tulpn", f"sport = :{port}"],
                capture_output=True,
                text=True,
                timeout=timeout,
                check=False,
            )
            if res_ss.returncode == 0:
                raw_lines = [ln.strip() for ln in res_ss.stdout.splitlines() if ln.strip()]
                if len(raw_lines) > 1:
                    lines = raw_lines
        except Exception:
            pass

        lsof_lines: List[str] = []
        try:
            res_lsof = subprocess.run(
                ["lsof", "-i", f":{port}"],
                capture_output=True,
                text=True,
                timeout=timeout,
                check=False,
            )
            if res_lsof.returncode == 0 and res_lsof.stdout.strip():
                lsof_lines = [ln.strip() for ln in res_lsof.stdout.splitlines() if ln.strip()]
        except Exception:
            pass

        if not lines and not lsof_lines:
            return ToolResult(
                success=True,
                stdout=f"No process is currently listening on or using port {port}.",
                data={"port": port, "in_use": False},
            )

        output_parts = [f"Port {port} is in use:\n"]
        if lines:
            output_parts.append("\n".join(lines))
        elif lsof_lines:
            output_parts.append("\n".join(lsof_lines))

        return ToolResult(
            success=True,
            stdout="\n".join(output_parts),
            data={"port": port, "in_use": True, "raw_ss": lines, "raw_lsof": lsof_lines},
        )

    def run(self, arguments: Dict[str, Any], timeout: float = 30.0) -> ToolResult:
        port = arguments.get("port")
        if port is not None:
            try:
                return self._inspect_port(int(port), timeout=timeout)
            except (ValueError, TypeError):
                return ToolResult(success=False, error=f"Invalid port argument: {port}")

        interfaces: List[Dict[str, Any]] = []
        routes: List[Dict[str, Any]] = []

        # 1. Query interfaces via ip -j addr (modern Linux)
        try:
            res_addr = subprocess.run(
                ["ip", "-j", "addr"],
                capture_output=True,
                text=True,
                timeout=timeout,
                check=False,
            )
            if res_addr.returncode == 0:
                raw_json = json.loads(res_addr.stdout)
                for item in raw_json:
                    ifname = item.get("ifname", "")
                    operstate = item.get("operstate", "UNKNOWN")
                    mac = item.get("address", "")
                    addr_info = item.get("addr_info", [])

                    ipv4_list = [
                        f"{a.get('local')}/{a.get('prefixlen')}"
                        for a in addr_info
                        if a.get("family") == "inet"
                    ]
                    ipv6_list = [
                        f"{a.get('local')}/{a.get('prefixlen')}"
                        for a in addr_info
                        if a.get("family") == "inet6"
                    ]

                    interfaces.append({
                        "interface": ifname,
                        "state": operstate,
                        "mac": mac,
                        "ipv4": ipv4_list,
                        "ipv6": ipv6_list,
                    })
        except Exception:
            pass

        # 2. Query default routes via ip -j route
        try:
            res_route = subprocess.run(
                ["ip", "-j", "route"],
                capture_output=True,
                text=True,
                timeout=timeout,
                check=False,
            )
            if res_route.returncode == 0:
                raw_json = json.loads(res_route.stdout)
                for item in raw_json:
                    if item.get("dst") == "default" or item.get("gateway"):
                        routes.append({
                            "destination": item.get("dst", "default"),
                            "gateway": item.get("gateway", "none"),
                            "interface": item.get("dev", "unknown"),
                            "protocol": item.get("protocol", "unknown"),
                        })
        except Exception:
            pass

        # Fallback if ip -j was empty
        if not interfaces:
            try:
                res_plain = subprocess.run(
                    ["ip", "addr"],
                    capture_output=True,
                    text=True,
                    timeout=timeout,
                    check=False,
                )
                if res_plain.returncode == 0:
                    return ToolResult(
                        success=True,
                        data={"raw": res_plain.stdout},
                        stdout=res_plain.stdout,
                    )
            except Exception as e:
                return ToolResult(success=False, error=f"Failed to inspect network: {e}")

        # Formatted output
        lines = ["Network Interfaces:"]
        lines.append(f"{'Interface':<14} {'State':<8} {'IPv4 Addresses':<24} {'MAC'}")
        for iface in interfaces:
            ipv4_str = ", ".join(iface["ipv4"]) if iface["ipv4"] else "(none)"
            lines.append(f"{iface['interface']:<14} {iface['state']:<8} {ipv4_str:<24} {iface['mac']}")

        if routes:
            lines.append("\nDefault Routes:")
            for r in routes:
                lines.append(f"  via {r['gateway']} dev {r['interface']} (dest: {r['destination']})")

        return ToolResult(
            success=True,
            data={"interfaces": interfaces, "routes": routes},
            stdout="\n".join(lines),
        )
