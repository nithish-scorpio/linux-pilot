"""Filesystem tools: list_directory, read_file, search_files, write_file.

Enforces allowed path boundaries, secret redaction, diff display, and file backup.
"""

import difflib
import fnmatch
import os
import shutil
import time
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional

from pilot.config import get_settings
from pilot.security.path_checker import validate_path_access
from pilot.security.permissions import RiskTier
from pilot.security.redactor import redact_secrets
from pilot.tools.base import BaseTool, ToolResult
from pilot.ui.terminal import confirm_prompt, console


class ListDirectoryTool(BaseTool):
    """List directory entries within allowed paths."""

    name = "list_directory"
    description = (
        "List files and directories at a given path within permitted directories. "
        "Returns names, file types, sizes in bytes, and modification dates."
    )
    risk_tier = RiskTier.SAFE

    @property
    def parameters_schema(self) -> Dict[str, Any]:
        return {
            "type": "object",
            "properties": {
                "path": {
                    "type": "string",
                    "description": "Directory path to list (default: current directory '.')",
                }
            },
        }

    def run(self, arguments: Dict[str, Any], timeout: float = 30.0) -> ToolResult:
        req_path = arguments.get("path") or "."
        allowed, err, resolved = validate_path_access(req_path, for_write=False)
        if not allowed:
            return ToolResult(success=False, error=f"Access denied: {err}")

        if not resolved.exists():
            return ToolResult(success=False, error=f"Directory does not exist: {req_path}")

        if not resolved.is_dir():
            return ToolResult(success=False, error=f"Path is not a directory: {req_path}")

        entries: List[Dict[str, Any]] = []
        try:
            for item in sorted(resolved.iterdir(), key=lambda x: (not x.is_dir(), x.name.lower())):
                stat = item.stat()
                entries.append({
                    "name": item.name,
                    "is_dir": item.is_dir(),
                    "size_bytes": stat.st_size if not item.is_dir() else 0,
                    "modified": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(stat.st_mtime)),
                })
        except PermissionError as pe:
            return ToolResult(success=False, error=f"Permission denied accessing directory: {pe}")

        lines = [f"Contents of {resolved}:"]
        lines.append(f"{'Type':<6} {'Size (B)':<10} {'Modified':<20} {'Name'}")
        for e in entries:
            t = "DIR" if e["is_dir"] else "FILE"
            lines.append(f"{t:<6} {e['size_bytes']:<10} {e['modified']:<20} {e['name']}")

        return ToolResult(
            success=True,
            data={"path": str(resolved), "count": len(entries), "entries": entries},
            stdout="\n".join(lines),
        )


class ReadFileTool(BaseTool):
    """Read contents of a text file within allowed paths with secret redaction."""

    name = "read_file"
    description = (
        "Read text content from a file within permitted directories. "
        "Supports line offset and line limit parameters. Automatically redacts secrets."
    )
    risk_tier = RiskTier.SAFE

    @property
    def parameters_schema(self) -> Dict[str, Any]:
        return {
            "type": "object",
            "properties": {
                "path": {
                    "type": "string",
                    "description": "Path to the text file to read",
                },
                "max_lines": {
                    "type": "integer",
                    "description": "Maximum number of lines to read (default: 500)",
                },
                "offset": {
                    "type": "integer",
                    "description": "Line number offset to start reading from (0-indexed, default: 0)",
                },
            },
            "required": ["path"],
        }

    def run(self, arguments: Dict[str, Any], timeout: float = 30.0) -> ToolResult:
        req_path = arguments.get("path", "")
        max_lines = int(arguments.get("max_lines") or 500)
        offset = max(int(arguments.get("offset") or 0), 0)

        allowed, err, resolved = validate_path_access(req_path, for_write=False)
        if not allowed:
            return ToolResult(success=False, error=f"Access denied: {err}")

        if not resolved.exists():
            return ToolResult(success=False, error=f"File not found: {req_path}")

        if not resolved.is_file():
            return ToolResult(success=False, error=f"Path is not a regular file: {req_path}")

        try:
            with open(resolved, "r", encoding="utf-8", errors="replace") as f:
                all_lines = f.readlines()
        except Exception as e:
            return ToolResult(success=False, error=f"Failed to read file: {e}")

        total_lines = len(all_lines)
        selected_lines = all_lines[offset : offset + max_lines]
        raw_text = "".join(selected_lines)

        # Run text through redaction engine before returning to context
        clean_text = redact_secrets(raw_text)

        header = f"--- {resolved} ({len(selected_lines)}/{total_lines} lines shown) ---\n"
        return ToolResult(
            success=True,
            data={
                "path": str(resolved),
                "total_lines": total_lines,
                "lines_read": len(selected_lines),
                "offset": offset,
            },
            stdout=header + clean_text,
        )


class SearchFilesTool(BaseTool):
    """Find files matching filename patterns or containing specific text."""

    name = "search_files"
    description = (
        "Search for files within permitted directories by name pattern (glob) "
        "and optional content substring."
    )
    risk_tier = RiskTier.SAFE

    @property
    def parameters_schema(self) -> Dict[str, Any]:
        return {
            "type": "object",
            "properties": {
                "pattern": {
                    "type": "string",
                    "description": "Filename glob pattern to match (e.g. '*.py', '*.json')",
                },
                "path": {
                    "type": "string",
                    "description": "Base directory to start search (default: '.')",
                },
                "content_search": {
                    "type": "string",
                    "description": "Optional substring to search for inside file contents",
                },
                "max_results": {
                    "type": "integer",
                    "description": "Maximum number of results to return (default: 50)",
                },
            },
            "required": ["pattern"],
        }

    def run(self, arguments: Dict[str, Any], timeout: float = 30.0) -> ToolResult:
        pattern = arguments.get("pattern", "*")
        base_dir = arguments.get("path") or "."
        content_query = arguments.get("content_search")
        max_results = int(arguments.get("max_results") or 50)

        allowed, err, resolved_base = validate_path_access(base_dir, for_write=False)
        if not allowed:
            return ToolResult(success=False, error=f"Access denied: {err}")

        matches: List[Dict[str, Any]] = []
        ignored_dirs = {".git", ".venv", "__pycache__", "node_modules", ".pytest_cache"}

        for root, dirs, files in os.walk(str(resolved_base)):
            # Prune ignored directories
            dirs[:] = [d for d in dirs if d not in ignored_dirs]

            for fname in files:
                if fnmatch.fnmatch(fname, pattern):
                    fpath = Path(root) / fname
                    match_item: Dict[str, Any] = {"path": str(fpath), "matches": []}

                    if content_query:
                        try:
                            with open(fpath, "r", encoding="utf-8", errors="ignore") as f:
                                for line_no, line in enumerate(f, 1):
                                    if content_query.lower() in line.lower():
                                        clean_snippet = redact_secrets(line.strip())
                                        match_item["matches"].append({
                                            "line": line_no,
                                            "text": clean_snippet[:120],
                                        })
                        except Exception:
                            continue
                        if match_item["matches"]:
                            matches.append(match_item)
                    else:
                        matches.append(match_item)

                if len(matches) >= max_results:
                    break
            if len(matches) >= max_results:
                break

        lines = [f"Found {len(matches)} matches for pattern '{pattern}' in {resolved_base}:"]
        for m in matches:
            lines.append(f"  • {m['path']}")
            for c in m.get("matches", []):
                lines.append(f"    Line {c['line']}: {c['text']}")

        return ToolResult(
            success=True,
            data={"count": len(matches), "matches": matches},
            stdout="\n".join(lines),
        )


class WriteFileTool(BaseTool):
    """Write or modify file contents with diff review, confirmation, backup, and verification."""

    name = "write_file"
    description = (
        "Write, update, or create a file within permitted directories. "
        "Shows a diff before applying changes, backs up original files, and verifies changes."
    )
    risk_tier = RiskTier.CONFIRM

    def __init__(self, confirm_handler: Optional[Callable[[str, str, str], bool]] = None):
        self.confirm_handler = confirm_handler or confirm_prompt

    @property
    def parameters_schema(self) -> Dict[str, Any]:
        return {
            "type": "object",
            "properties": {
                "path": {
                    "type": "string",
                    "description": "Path of the file to create or modify",
                },
                "content": {
                    "type": "string",
                    "description": "New content to write to the file",
                },
                "reason": {
                    "type": "string",
                    "description": "Explanation of why this file change is necessary",
                },
            },
            "required": ["path", "content"],
        }

    def run(self, arguments: Dict[str, Any], timeout: float = 30.0) -> ToolResult:
        req_path = arguments.get("path", "")
        new_content = arguments.get("content", "")
        reason = arguments.get("reason", "File modification requested")

        # 1. Path Security Check
        allowed, err, resolved = validate_path_access(req_path, for_write=True)
        if not allowed:
            return ToolResult(success=False, error=f"Security violation: {err}")

        # 2. Compute unified diff if file exists
        old_content = ""
        is_new_file = not resolved.exists()
        if not is_new_file:
            try:
                with open(resolved, "r", encoding="utf-8", errors="replace") as f:
                    old_content = f.read()
            except Exception as e:
                return ToolResult(success=False, error=f"Failed to read existing file for diff: {e}")

        diff_lines = list(
            difflib.unified_diff(
                old_content.splitlines(keepends=True),
                new_content.splitlines(keepends=True),
                fromfile=f"a/{resolved.name}",
                tofile=f"b/{resolved.name}",
            )
        )
        diff_str = "".join(diff_lines) if diff_lines else "(No content differences)"

        # 3. Present confirmation prompt with risk description
        action_desc = f"Create new file '{resolved}'" if is_new_file else f"Modify existing file '{resolved}'"
        risk_desc = (
            f"Overwriting {len(old_content)} characters in '{resolved.name}'"
            if not is_new_file
            else f"Creating new file with {len(new_content)} characters"
        )

        console.print(f"\n[bold]Diff Preview for {resolved}:[/bold]")
        for dline in diff_lines[:30]:
            if dline.startswith("+"):
                console.print(f"[green]{dline.rstrip()}[/green]")
            elif dline.startswith("-"):
                console.print(f"[red]{dline.rstrip()}[/red]")
            else:
                console.print(f"[dim]{dline.rstrip()}[/dim]")
        if len(diff_lines) > 30:
            console.print(f"[dim]... (+{len(diff_lines) - 30} more diff lines)[/dim]")

        approved = self.confirm_handler(
            f"write_file '{resolved}'",
            reason,
            risk_desc,
        )
        if not approved:
            return ToolResult(
                success=False,
                error=f"Operation cancelled: User rejected modifying '{resolved}'",
            )

        # 4. Create backup if existing file
        backup_path_str = None
        if not is_new_file:
            timestamp = int(time.time())
            backup_file = resolved.with_name(f"{resolved.name}.bak.{timestamp}")
            try:
                shutil.copy2(resolved, backup_file)
                backup_path_str = str(backup_file)
            except Exception as e:
                return ToolResult(success=False, error=f"Failed to create file backup: {e}")

        # 5. Apply the write operation
        try:
            resolved.parent.mkdir(parents=True, exist_ok=True)
            with open(resolved, "w", encoding="utf-8") as f:
                f.write(new_content)
        except Exception as e:
            return ToolResult(success=False, error=f"Failed to write file: {e}")

        # 6. Verify result actually landed on disk
        try:
            with open(resolved, "r", encoding="utf-8") as f:
                verified_content = f.read()
            if verified_content != new_content:
                return ToolResult(
                    success=False,
                    error="Verification failed: Content on disk does not match intended content",
                )
        except Exception as e:
            return ToolResult(success=False, error=f"Verification read failed: {e}")

        summary = f"Successfully wrote {len(new_content)} characters to '{resolved}'"
        if backup_path_str:
            summary += f" (Backup created: {backup_path_str})"

        return ToolResult(
            success=True,
            data={
                "path": str(resolved),
                "bytes_written": len(new_content),
                "backup_path": backup_path_str,
            },
            stdout=summary,
        )
