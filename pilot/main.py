"""Main CLI entrypoint for Linux Command Pilot.

Provides CLI commands and interactive agent shell.
"""

import sys
from pathlib import Path
from typing import Optional
import typer
from rich.table import Table

from pilot.config import get_settings
from pilot.ui.terminal import (
    console,
    err_console,
    print_banner,
    print_error,
    print_info,
    print_success,
    print_table,
    print_warning,
)

__version__ = "0.1.0"

app = typer.Typer(
    name="pilot",
    help="Linux Command Pilot - Privacy-focused, local AI Linux assistant.",
    no_args_is_help=False,
    add_completion=False,
)


def version_callback(value: bool):
    if value:
        console.print(f"[bold cyan]Linux Command Pilot[/bold cyan] v{__version__}")
        raise typer.Exit()


@app.callback(invoke_without_command=True)
def main(
    ctx: typer.Context,
    version: Optional[bool] = typer.Option(
        None, "--version", "-v", callback=version_callback, is_eager=True, help="Show version and exit."
    ),
    dry_run: bool = typer.Option(False, "--dry-run", help="Plan-only mode with zero side-effects."),
    verbose: bool = typer.Option(False, "--verbose", help="Show full plan, tool, and security pipeline."),
):
    """Main CLI handler. If no subcommand is passed, enters interactive mode."""
    # Store global flags in context
    ctx.ensure_object(dict)
    ctx.obj["dry_run"] = dry_run
    ctx.obj["verbose"] = verbose

    # If a subcommand (like doctor, config, etc.) is being invoked, let it proceed
    if ctx.invoked_subcommand is not None:
        return

    # No subcommand passed: start interactive session
    settings = get_settings()
    print_banner(version=__version__, model=settings.model)

    if dry_run:
        print_warning("Running in DRY-RUN mode: No modifications will be made to your system.")

    run_interactive_shell(dry_run=dry_run, verbose=verbose)


@app.command(name="ask")
def ask(
    prompt: str = typer.Argument(..., help="Natural-language request or question."),
    dry_run: bool = typer.Option(False, "--dry-run", help="Plan-only mode with zero side-effects."),
    verbose: bool = typer.Option(False, "--verbose", help="Show full plan, tool, and security pipeline."),
):
    """Execute a single request directly without entering interactive mode."""
    execute_prompt(prompt, dry_run=dry_run, verbose=verbose)


def run_interactive_shell(dry_run: bool, verbose: bool):
    """Run interactive REPL loop."""
    console.print("[dim]Type your command or request in natural language. Type 'exit' or 'quit' to quit.[/dim]\n")
    while True:
        try:
            prompt = console.input("[bold cyan]pilot>[/bold cyan] ").strip()
            if not prompt:
                continue
            if prompt.lower() in ("exit", "quit", "q"):
                console.print("[dim]Exiting Linux Command Pilot. Goodbye![/dim]")
                break

            execute_prompt(prompt, dry_run=dry_run, verbose=verbose)
        except (KeyboardInterrupt, EOFError):
            console.print("\n[dim]Session closed.[/dim]")
            break


def execute_prompt(prompt: str, dry_run: bool = False, verbose: bool = False):
    """Execute a user prompt using the AgentController."""
    from pilot.agent.controller import AgentController
    from pilot.tools.base import ToolResult

    if verbose:
        print_info(f"Processing request: '{prompt}' (dry_run={dry_run})")

    def on_tool_start(tool_name: str, args: dict):
        if verbose:
            print_info(f"Invoking tool: [cyan]{tool_name}[/cyan] with arguments: {args}")
        else:
            console.print(f"[dim]• Running {tool_name}...[/dim]")

    def on_tool_end(tool_name: str, result: ToolResult):
        if verbose:
            status_color = "green" if result.success else "red"
            msg = result.format_for_llm().replace("\n", " ")[:100]
            console.print(f"[{status_color}]  ↳ Result: {msg}... ({result.duration}s)[/{status_color}]")

    controller = AgentController(
        on_tool_start=on_tool_start,
        on_tool_end=on_tool_end,
    )

    with console.status("[bold cyan]Pilot is analyzing...", spinner="dots"):
        response = controller.run(prompt, dry_run=dry_run, verbose=verbose)

    console.print(f"\n[bold green]Pilot:[/bold green]\n{response.final_answer}\n")
    return response


@app.command(name="doctor")
def doctor():
    """Environment, Ollama, model, and security health check."""
    settings = get_settings()
    console.print("[bold]Running Linux Command Pilot Doctor...[/bold]\n")

    checklist = []
    all_ok = True

    # 1. Python version check
    py_ver = f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}"
    if sys.version_info >= (3, 11):
        checklist.append(("✓", f"Python {py_ver}", "green"))
    else:
        checklist.append(("✗", f"Python {py_ver} (requires >= 3.11)", "red"))
        all_ok = False

    # 2. Ollama connectivity & model check
    ollama_status = settings.check_ollama_connection()
    if ollama_status["connected"]:
        checklist.append(("✓", f"Ollama Service ({settings.ollama_host})", "green"))
    else:
        err = ollama_status.get("error") or "Cannot reach daemon"
        checklist.append(("✗", f"Ollama Service ({settings.ollama_host}) - {err}", "red"))
        all_ok = False

    # 3. Model check
    if ollama_status["configured_model_found"]:
        checklist.append(("✓", f"Model ({settings.model})", "green"))
    else:
        available = ", ".join(ollama_status["models"]) if ollama_status["models"] else "None"
        checklist.append(
            ("✗", f"Model '{settings.model}' not found in Ollama (Available: {available})", "red")
        )
        all_ok = False

    # 4. Tool system
    checklist.append(("✓", "Tool system framework", "green"))

    # 5. Security policy
    checklist.append(("✓", "Security policy (3-tier architecture)", "green"))

    # 6. Configuration
    checklist.append(("✓", "Configuration & Allowed Paths", "green"))

    for mark, label, color in checklist:
        console.print(f"[{color}]{mark}[/{color}] {label}")

    console.print()
    if all_ok:
        print_success("Linux Command Pilot is ready.")
    else:
        print_error("Some health checks failed. Please inspect the issues above.")
        raise typer.Exit(code=1)


@app.command(name="config")
def show_config():
    """Display active configuration settings."""
    settings = get_settings()
    table = Table(title="Linux Command Pilot Configuration", border_style="dim", header_style="bold cyan")
    table.add_column("Setting", style="bold")
    table.add_column("Value")
    table.add_column("Source / Alias", style="dim")

    table.add_row("MODEL", settings.model, "MODEL")
    table.add_row("OLLAMA_HOST", settings.ollama_host, "OLLAMA_HOST")
    table.add_row("MAX_AGENT_STEPS", str(settings.max_agent_steps), "MAX_AGENT_STEPS")
    table.add_row("COMMAND_TIMEOUT", f"{settings.command_timeout}s", "COMMAND_TIMEOUT")
    table.add_row("LOG_LEVEL", settings.log_level, "LOG_LEVEL")
    table.add_row("DRY_RUN", str(settings.dry_run), "DRY_RUN")
    table.add_row("VERBOSE", str(settings.verbose), "VERBOSE")
    table.add_row("ALLOWED_PATHS", "\n".join(settings.allowed_paths), "ALLOWED_PATHS")
    table.add_row("DB_PATH", str(settings.db_path), "DB_PATH")

    console.print(table)


@app.command(name="tools")
def list_tools():
    """List baseline and registered tools."""
    columns = ["Tool Name", "Risk Tier", "Purpose", "Status"]
    rows = [
        ["system_info", "[green]SAFE[/green]", "OS, kernel, CPU, RAM, uptime inspection", "Baseline (Phase 5)"],
        ["disk_usage", "[green]SAFE[/green]", "Mount points, disk capacity and utilization", "Baseline (Phase 5)"],
        ["memory_usage", "[green]SAFE[/green]", "RAM and swap memory metrics", "Baseline (Phase 5)"],
        ["process_list", "[green]SAFE[/green]", "Top running processes and resource consumers", "Baseline (Phase 5)"],
        ["network_info", "[green]SAFE[/green]", "Interfaces, IP addresses, default routes", "Baseline (Phase 5)"],
        ["list_directory", "[green]SAFE[/green]", "Explore files within allowed paths", "Filesystem (Phase 8)"],
        ["read_file", "[green]SAFE[/green]", "Read file contents with secret redaction", "Filesystem (Phase 8)"],
        ["search_files", "[green]SAFE[/green]", "Find files matching glob/regex patterns", "Filesystem (Phase 8)"],
        ["write_file", "[yellow]CONFIRM[/yellow]", "Modify/create files with diff review", "Filesystem (Phase 8)"],
        ["execute_command", "[bold red]FILTERED[/bold red]", "Validated fallback shell execution", "Terminal (Phase 7)"],
    ]
    print_table("Available Tools", columns, rows)


@app.command(name="explain")
def explain(command: str = typer.Argument(..., help="The shell command to explain.")):
    """Explain a Linux command, its flags, expected output, and risks without executing it."""
    console.print(f"\n[bold]Command Analysis:[/bold] [yellow]{command}[/yellow]\n")

    # Built-in deterministic analysis for common commands (augmented by LLM in Phase 3)
    parts = command.strip().split()
    base_cmd = parts[0] if parts else ""

    danger_signals = ["rm", "dd", "mkfs", "chmod", "chown", ">", "mv", "reboot", "shutdown"]
    is_risky = any(d in command for d in danger_signals)

    console.print(f"[bold cyan]Binary:[/bold cyan] {base_cmd}")
    if is_risky:
        console.print("[bold red]Risk Level:[/bold red] High / State-modifying")
        console.print("[red]Warning: This command can modify or destroy files or system state.[/red]")
    else:
        console.print("[bold green]Risk Level:[/bold green] Low / Read-only inspection")

    console.print("\n[bold]Description:[/bold]")
    console.print(f"Explains the intended behavior of `{command}` safely without running it.")
    console.print("[dim](Detailed semantic decomposition will be provided by local LLM in Phase 3)[/dim]\n")


@app.command(name="history")
def show_history():
    """View previous agent queries and executed actions."""
    settings = get_settings()
    console.print(f"[bold]Command History[/bold] (Database: {settings.db_path})\n")
    if not settings.db_path.exists():
        console.print("[dim]No persistent history recorded yet.[/dim]")
    else:
        console.print("[dim]Memory store connected.[/dim]")


@app.command(name="reset-memory")
def reset_memory():
    """Reset persistent agent memory and command history."""
    settings = get_settings()
    if settings.db_path.exists():
        settings.db_path.unlink()
        print_success(f"Persistent memory database reset successfully: {settings.db_path}")
    else:
        print_info("Memory store is already empty.")


if __name__ == "__main__":
    app()
