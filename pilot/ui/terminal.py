"""Terminal UI module for Linux Command Pilot using Rich.

Provides consistent styling, banners, panels, status output, and confirmation prompts.
"""

import sys
from typing import Any, List, Optional
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

# Shared console instance
console = Console()
err_console = Console(stderr=True)


def print_banner(version: str = "0.1.0", model: str = "") -> None:
    """Print the Linux Command Pilot application banner."""
    panel = Panel(
        Text.from_markup(
            f"[bold cyan]Linux Command Pilot[/bold cyan] [dim]v{version}[/dim]\n"
            f"[dim]Local OS Intelligence • 3-Tier Security • Zero Cloud Leakage[/dim]"
            + (f"\n[dim]Active Model:[/dim] [yellow]{model}[/yellow]" if model else "")
        ),
        border_style="cyan",
        expand=False,
    )
    console.print(panel)


def print_info(message: str) -> None:
    """Print an informational message."""
    console.print(f"[blue]ℹ[/blue] {message}")


def print_success(message: str) -> None:
    """Print a success message."""
    console.print(f"[bold green]✓[/bold green] {message}")


def print_warning(message: str) -> None:
    """Print a warning message."""
    console.print(f"[bold yellow]⚠[/bold yellow] {message}")


def print_error(message: str, to_stderr: bool = False) -> None:
    """Print an error message."""
    target = err_console if to_stderr else console
    target.print(f"[bold red]✗[/bold red] {message}")


def print_plan(steps: List[str]) -> None:
    """Print a structured action plan."""
    console.print("\n[bold]PLAN[/bold]")
    for idx, step in enumerate(steps, 1):
        console.print(f"  [cyan]{idx}.[/cyan] {step}")
    console.print()


def print_table(title: str, columns: List[str], rows: List[List[Any]]) -> None:
    """Print a formatted Rich table."""
    table = Table(title=title, border_style="dim", header_style="bold magenta")
    for col in columns:
        table.add_column(col)
    for row in rows:
        table.add_row(*[str(item) for item in row])
    console.print(table)


def confirm_prompt(command: str, reason: str, risk: str) -> bool:
    """Display standard security confirmation prompt.

    Format required:
    Command: <command>
    Reason:  <why the agent wants to run this>
    Risk:    <what could go wrong>
    Allow? [y/N]
    """
    console.print()
    content = (
        f"[bold]Command:[/bold] [yellow]{command}[/yellow]\n"
        f"[bold]Reason:[/bold]  {reason}\n"
        f"[bold]Risk:[/bold]    [red]{risk}[/red]"
    )
    console.print(Panel(content, title="[bold red]Security Confirmation Required[/bold red]", border_style="red"))

    try:
        response = console.input("[bold yellow]Allow? [y/N]: [/bold yellow]").strip().lower()
        return response in ("y", "yes")
    except (KeyboardInterrupt, EOFError):
        console.print("\n[dim]Aborted by user.[/dim]")
        return False
