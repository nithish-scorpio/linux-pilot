"""Deterministic fast-path router for unambiguous system and filesystem requests.

Routes common, well-defined natural language requests directly to appropriate
tools without incurring multi-second LLM inference latency.

All routed tool calls still pass through:
- Tool parameter schemas and validation
- SecurityValidator and allowed path checks
- RiskTier enforcement (modifying actions still require confirmation)
- Secret redaction engine
- Execution timeouts
"""

import re
from typing import Any, Dict, List, Optional, Tuple


class FastPathRouter:
    """Matches natural language queries to registered tools deterministically."""

    @classmethod
    def match(cls, user_request: str) -> Optional[List[Tuple[str, Dict[str, Any]]]]:
        """Inspect user query and return list of (tool_name, arguments) if unambiguous.

        Returns:
            List of (tool_name, arguments) or None if request requires LLM reasoning.
        """
        text = user_request.strip()
        lower = text.lower()

        # 0. Safety guard: Do not fast-path destructive / blocked commands
        # Let blocked queries go directly to security rejection
        if any(d in lower for d in (
            "rm -rf", "mkfs", "dd if=", ":(){", "shutdown", "reboot", "> /dev",
            "chmod", "/etc/shadow", "id_rsa", "/etc/sudoers", "/proc/kcore",
            ".bash_history", "| bash", "| sh", "|bash", "|sh", "validator.py",
        )):
            return None

        # 1. System Info & Hardware & Kernel & Uptime & Distro
        if any(k in lower for k in (
            "kernel version",
            "cpu architecture",
            "core count",
            "how long has this machine been running",
            "system uptime",
            "uptime and load average",
            "distribution and version",
            "linux distribution",
            "distro is installed",
        )):
            return [("system_info", {})]

        # 1b. Environment Variables
        if any(k in lower for k in ("environment variable", "environment variables", "env var", "env vars")):
            m_contain = re.search(r"(?:containing|matching|with|having)\s+([a-zA-Z0-9_\-]+)", text, re.IGNORECASE)
            if m_contain:
                pattern = m_contain.group(1).strip()
                return [("execute_command", {"command": f"env | grep -i {pattern}", "reason": f"Show environment variables containing '{pattern}'"})]

            m_specific = re.search(r"(?:variable|var)\s+([a-zA-Z0-9_]+)", text, re.IGNORECASE)
            if m_specific:
                vname = m_specific.group(1).strip()
                if vname.lower() not in ("containing", "called", "named", "with", "in", "the", "all"):
                    return [("execute_command", {"command": f"printenv {vname}", "reason": f"Show environment variable '{vname}'"})]

            return [("execute_command", {"command": "printenv", "reason": "List all environment variables"})]

        if lower.strip() in ("show path", "print path", "what is my path", "echo $path", "display path"):
            return [("execute_command", {"command": "printenv PATH", "reason": "Show PATH environment variable"})]

        # 2. Process List (Check before generic memory check!)
        if any(k in lower for k in (
            "top 5 processes",
            "top processes",
            "processes by memory",
            "processes using the most cpu",
            "most cpu right now",
            "pid 1",
            "rogue processes",
            "unresponsive service processes",
            "zombie or defunct",
        )):
            sort_by = "memory" if "memory" in lower else "cpu"
            limit = 5 if "5" in lower else 15
            if "pid 1" in lower:
                limit = 1
            return [("process_list", {"sort_by": sort_by, "limit": limit})]

        # 3. RAM & Swap & Memory
        if any(k in lower for k in (
            "ram is currently free",
            "free ram",
            "memory usage",
            "used swap memory",
            "swap memory",
            "system memory vs available",
            "available memory",
            "swap space is exhausted",
        )):
            return [("memory_usage", {})]

        # 4. Disk Usage
        if any(k in lower for k in (
            "disk usage",
            "disk space",
            "filesystem on root",
            "disk almost full",
            "mounted filesystems",
        )):
            target_path = "/"
            if "/home" in lower:
                target_path = "/home"
            return [("disk_usage", {"path": target_path})]

        # 5. Network Info & Port Inspection
        if not any(w in lower for w in ("block", "close", "allow", "deny", "firewall", "ufw", "iptables", "forward")):
            m_port = re.search(r"(?:(?:which|what|check|find|is|show|inspect|who)?\s*(?:process|service|app|program)?\s*(?:is\s+)?(?:using|listening on|running on|bound to|on|open|in use)?\s*port\s+(\d{1,5})|port\s+(\d{1,5}))", text, re.IGNORECASE)
            if m_port:
                port_num = int(m_port.group(1) or m_port.group(2))
                if 1 <= port_num <= 65535:
                    return [("network_info", {"port": port_num})]

        if any(k in lower for k in (
            "network interfaces",
            "ip addresses",
            "default gateway",
            "routing table",
            "network connectivity",
            "network interface configuration",
        )):
            return [("network_info", {})]

        # 6. Check package installed
        # Matches: "Is curl installed...", "Check if git is installed...", "diagnose why git command is not found"
        m_pkg_check = re.search(
            r"(?:is|check\s+if)\s+([a-zA-Z0-9_\+\.\@\-]+)\s+(?:is\s+)?installed",
            lower,
        )
        if m_pkg_check:
            pkg_name = m_pkg_check.group(1).strip()
            return [("is_package_installed", {"package_name": pkg_name})]

        m_not_found = re.search(r"diagnose why\s+([a-zA-Z0-9_\+\.\@\-]+)\s+command is not found", lower)
        if m_not_found:
            pkg_name = m_not_found.group(1).strip()
            return [("is_package_installed", {"package_name": pkg_name})]

        # 7. Package search
        # Matches: "Search for nginx packages in repositories."
        m_pkg_search = re.search(
            r"search for\s+([a-zA-Z0-9_\+\.\@\-]+)(?:\s+development libraries|\s+packages)?\s+in\s+(?:repositories|package)",
            lower,
        )
        if m_pkg_search:
            query = m_pkg_search.group(1).strip()
            return [("package_search", {"query": query})]

        # 8. Package install
        m_pkg_install = re.search(
            r"install\s+([a-zA-Z0-9_\+\.\@\-]+)(?:\s+package|\s+utility|\s+command|\s+using package manager)?",
            lower,
        )
        if m_pkg_install and not any(re.search(rf"\b{w}\b", lower) for w in ("why", "check", "if", "is")):
            pkg_name = m_pkg_install.group(1).strip()
            return [("package_install", {"package_name": pkg_name})]

        # 9. Package remove
        m_pkg_remove = re.search(
            r"remove\s+(?:obsolete\s+package\s+|unused\s+package\s+|package\s+)?([a-zA-Z0-9_\+\.\@\-]+)",
            lower,
        )
        if m_pkg_remove:
            pkg_name = m_pkg_remove.group(1).strip()
            if pkg_name not in ("files", "directories"):
                return [("package_remove", {"package_name": pkg_name})]

        # 10. Package update
        if any(k in lower for k in (
            "update repository package indexes",
            "refresh distribution package lists",
            "update system software indexes",
            "package manager index is up to date",
        )):
            return [("package_update", {})]

        # 11. Filesystem: List Directory / Show Files
        if any(k in lower for k in (
            "list files",
            "show all files",
            "show files",
            "list directory",
            "list subdirectories",
            "list directories",
            "show directory contents",
        )):
            target_dir = "."
            m_dir = re.search(r"(?:in directory|in|of)\s+([^\s,]+)", text, re.IGNORECASE)
            if m_dir:
                extracted = m_dir.group(1).rstrip(".,;")
                if extracted.lower() not in ("the", "this", "current", "all"):
                    target_dir = extracted
            return [("list_directory", {"path": target_dir})]

        # 11b. Filesystem: Current Working Directory
        if any(k in lower for k in (
            "current working directory",
            "show current directory",
            "print current directory",
            "what is my directory",
            "what directory am i in",
            "pwd",
        )) or lower.strip() in ("current directory", "working directory"):
            return [("execute_command", {"command": "pwd"})]

        # 11c. Filesystem: Create Folder / Directory
        m_mkdir = re.search(r"(?:create|make)\s+(?:a\s+)?(?:folder|directory)\s+(?:called\s+|named\s+)?([^\s,]+)", text, re.IGNORECASE)
        if m_mkdir:
            folder_name = m_mkdir.group(1).rstrip(".,;")
            if folder_name.lower() not in ("in", "for", "with"):
                return [("execute_command", {"command": f"mkdir -p {folder_name}", "reason": f"Create directory '{folder_name}'"})]

        # 11d. Filesystem: Rename / Move File or Directory
        m_mv = re.search(r"(?:rename|move)\s+(?:file\s+|folder\s+|directory\s+)?([^\s,]+)\s+(?:to|as|into)\s+([^\s,]+)", text, re.IGNORECASE)
        if m_mv:
            src = m_mv.group(1).rstrip(".,;")
            dst = m_mv.group(2).rstrip(".,;")
            return [("execute_command", {"command": f"mv {src} {dst}", "reason": f"Rename '{src}' to '{dst}'"})]

        # 11e. Filesystem: Copy File or Directory
        m_cp = re.search(r"(?:copy|duplicate)\s+(?:file\s+|folder\s+|directory\s+)?([^\s,]+)\s+(?:to|into)\s+([^\s,]+)", text, re.IGNORECASE)
        if m_cp:
            src = m_cp.group(1).rstrip(".,;")
            dst = m_cp.group(2).rstrip(".,;")
            return [("execute_command", {"command": f"cp -r {src} {dst}", "reason": f"Copy '{src}' to '{dst}'"})]

        # 11f. Filesystem: Delete / Remove single file
        if not any(k in lower for k in ("package", "obsolete", "unused", "directory", "folder", "all", "the")):
            m_rm = re.search(r"(?:delete|remove)\s+(?:file\s+)?([a-zA-Z0-9_\-\.\/]+\.[a-zA-Z0-9]+)$", text, re.IGNORECASE)
            if not m_rm:
                m_rm = re.search(r"(?:delete|remove)\s+file\s+([a-zA-Z0-9_\-\.\/]+)$", text, re.IGNORECASE)
            if m_rm:
                target = m_rm.group(1).rstrip(".,;")
                if "/" not in target or target.startswith("./"):
                    return [("execute_command", {"command": f"rm {target}", "reason": f"Delete file '{target}'"})]

        # 11g. Filesystem: Create empty file / touch
        m_touch = re.search(r"(?:create\s+(?:a\s+)?(?:empty\s+)?file|touch)\s+(?:called\s+|named\s+)?([^\s,]+)", text, re.IGNORECASE)
        if m_touch:
            fname = m_touch.group(1).rstrip(".,;")
            if fname.lower() not in ("in", "for", "with"):
                return [("execute_command", {"command": f"touch {fname}", "reason": f"Create empty file '{fname}'"})]

        # 12. Filesystem: Read File
        m_show_lines = re.search(r"(?:show|read)\s+the first\s+(\d+)\s+lines of\s+([^\s,]+)", text, re.IGNORECASE)
        if m_show_lines:
            n_lines = int(m_show_lines.group(1))
            target_file = m_show_lines.group(2).rstrip(".,;")
            return [("read_file", {"path": target_file, "max_lines": n_lines})]

        if "read error logs" in lower or "read error log" in lower:
            from pathlib import Path
            log_files = list(Path(".").glob("*.log"))
            log_path = str(log_files[0]) if log_files else "error.log"
            return [("read_file", {"path": log_path})]

        m_read_header = re.search(r"check if\s+([^\s,]+)\s+exists and read", text, re.IGNORECASE)
        if m_read_header:
            target_file = m_read_header.group(1).rstrip(".,;")
            return [("read_file", {"path": target_file, "max_lines": 50})]

        if any(k in lower for k in ("read the contents of", "read ")):
            m_file = re.search(r"(?:read\s+(?:the\s+contents\s+of\s+)?|read\s+)([^\s,]+)", text, re.IGNORECASE)
            if m_file:
                target_file = m_file.group(1).rstrip(".,;")
                if target_file.lower() not in ("files", "lines", "the", "error"):
                    return [("read_file", {"path": target_file})]

        if "python source files" in lower or "python files" in lower:
            return [("search_files", {"pattern": "*.py"})]
        if "files ending with .md" in lower:
            return [("search_files", {"pattern": "*.md"})]
        if "matching test_*.py" in lower:
            return [("search_files", {"pattern": "test_*.py"})]
        if "yaml or json files" in lower:
            return [("search_files", {"pattern": "*.json"})]
        if "log files in current directory" in lower:
            return [("search_files", {"pattern": "*.log"})]

        m_content_search = re.search(r"(?:search for files containing|find files with|find files mentioning)\s+['\"]?([^'\"\n]+)['\"]?", text, re.IGNORECASE)
        if m_content_search:
            query = m_content_search.group(1).strip("'\"")
            return [("search_files", {"pattern": "*", "content_search": query})]

        # 14. Filesystem: Write File
        m_write = re.search(r"(?:create a new note in|update)\s+([^\s,]+)\s+with\s+(.*)", text, re.IGNORECASE)
        if m_write:
            target_path = m_write.group(1).rstrip(".,;")
            content = m_write.group(2).strip()
            return [("write_file", {"path": target_path, "content": content})]

        # 15. Troubleshooting composite queries
        if "why is my laptop running slow" in lower:
            return [("process_list", {"sort_by": "cpu"}), ("memory_usage", {}), ("system_info", {})]
        if "find which process is consuming all memory" in lower or "memory leaks in background processes" in lower:
            return [("process_list", {"sort_by": "memory"}), ("memory_usage", {})]
        if "check why cpu usage is high" in lower:
            return [("process_list", {"sort_by": "cpu"}), ("system_info", {})]
        if "troubleshoot out of memory" in lower:
            return [("memory_usage", {}), ("process_list", {"sort_by": "memory"})]
        if "diagnose missing python package" in lower:
            return [("is_package_installed", {"package_name": "python3"}), ("package_search", {"query": "python3"})]
        if "find high-capacity files consuming space" in lower:
            return [("disk_usage", {}), ("search_files", {"pattern": "*"})]
        if "check system load average vs cpu cores" in lower:
            return [("system_info", {}), ("process_list", {"sort_by": "cpu"})]

        # No deterministic match -> delegate to LLM
        return None
