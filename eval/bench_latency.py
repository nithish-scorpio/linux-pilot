"""Latency Benchmark script for Linux Command Pilot.

Measures and records per-query:
- Time to first token (TTFT)
- LLM time per step and total LLM time
- Tool execution time
- Security check time
- Redaction time
- SQLite time
- Number of agent steps
- Prompt tokens and output tokens

Computes p50 and p95 latency percentiles overall and per category,
and lists every task exceeding the 10.0-second budget.

Usage:
    python eval/bench_latency.py
    python eval/bench_latency.py --category safe --limit 5
    python eval/bench_latency.py --output eval/baseline_latency.json
"""

import argparse
import json
from pathlib import Path
import statistics
import sys
import time
from typing import Any, Dict, List, Optional

# Ensure project root is in sys.path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from rich.console import Console
from rich.table import Table

from pilot.agent.controller import AgentController
from pilot.config import get_settings
from pilot.security.permissions import RiskTier
from pilot.security.validator import SecurityValidator
from pilot.telemetry import QueryMetrics, track_query

console = Console()


def compute_percentiles(values: List[float]) -> Dict[str, float]:
    """Compute p50, p90, p95, and p99 percentiles."""
    if not values:
        return {"p50": 0.0, "p90": 0.0, "p95": 0.0, "p99": 0.0, "avg": 0.0, "min": 0.0, "max": 0.0}
    sorted_vals = sorted(values)
    n = len(sorted_vals)

    def percentile(p: float) -> float:
        if n == 1:
            return sorted_vals[0]
        k = (n - 1) * (p / 100.0)
        f = int(k)
        c = f + 1 if f + 1 < n else f
        return sorted_vals[f] + (k - f) * (sorted_vals[c] - sorted_vals[f])

    return {
        "p50": round(percentile(50.0), 3),
        "p90": round(percentile(90.0), 3),
        "p95": round(percentile(95.0), 3),
        "p99": round(percentile(99.0), 3),
        "avg": round(statistics.mean(values), 3),
        "min": round(min(values), 3),
        "max": round(max(values), 3),
    }


def run_benchmark(
    dataset_path: Path,
    category: Optional[str] = None,
    limit: Optional[int] = None,
    output_path: Optional[Path] = None,
    warmup: bool = True,
) -> Dict[str, Any]:
    """Execute latency benchmark across dataset tasks."""
    settings = get_settings()

    # Load tasks from JSONL
    tasks = []
    with open(dataset_path, "r", encoding="utf-8") as f:
        for line in f:
            if not line.strip():
                continue
            item = json.loads(line)
            if category is None or item["category"] == category:
                tasks.append(item)

    if limit:
        tasks = tasks[:limit]

    console.print(f"[bold cyan]Linux Command Pilot — Latency Benchmark[/bold cyan]")
    console.print(f"Dataset: [green]{dataset_path}[/green] ({len(tasks)} tasks selected)")
    console.print(f"Model: [yellow]{settings.model}[/yellow] | Host: {settings.ollama_host}\n")

    # Controller for execution
    controller = AgentController()

    # Warmup query if requested
    if warmup and tasks:
        console.print("[dim]Performing warm-up ping...[/dim]")
        try:
            with track_query("warmup"):
                controller.run("echo pilot-warmup", dry_run=True)
            console.print("[dim]Warm-up complete.[/dim]\n")
        except Exception as e:
            console.print(f"[yellow]Warning: Warm-up failed: {e}[/yellow]\n")

    results: List[Dict[str, Any]] = []
    exceeded_10s: List[Dict[str, Any]] = []

    for i, t in enumerate(tasks, 1):
        task_id = t["id"]
        cat = t["category"]
        query = t["input"]
        expected_tools = t.get("expected_tools", [])

        console.print(f"[{i}/{len(tasks)}] [bold]{task_id}[/bold] ({cat}): [dim]{query[:60]}[/dim]")

        # For blocked tasks, test via security validator
        if cat == "blocked":
            cmd = t.get("proposed_command") or query
            with track_query(cmd) as m:
                classification = SecurityValidator.classify_command(cmd)
                blocked = (classification.tier == RiskTier.BLOCKED)

            m.success = blocked
            record = {
                "id": task_id,
                "category": cat,
                "query": query,
                "total_time": m.total_time,
                "ttft": m.ttft,
                "llm_time": m.llm_time,
                "tool_time": m.tool_time,
                "security_time": m.security_time,
                "redaction_time": m.redaction_time,
                "sqlite_time": m.sqlite_time,
                "steps": m.steps,
                "prompt_tokens": m.prompt_tokens,
                "output_tokens": m.output_tokens,
                "success": blocked,
                "tools_used": [],
                "error": None if blocked else "FAILED_TO_BLOCK",
            }
        else:
            with track_query(query) as m:
                try:
                    resp = controller.run(query, dry_run=True)
                    tools_used = [tc.tool_name for tc in resp.tool_calls_made]
                    m.success = resp.completed
                except Exception as e:
                    m.success = False
                    m.error = str(e)
                    tools_used = []

            record = {
                "id": task_id,
                "category": cat,
                "query": query,
                "total_time": m.total_time,
                "ttft": m.ttft,
                "llm_time": m.llm_time,
                "tool_time": m.tool_time,
                "security_time": m.security_time,
                "redaction_time": m.redaction_time,
                "sqlite_time": m.sqlite_time,
                "steps": m.steps,
                "prompt_tokens": m.prompt_tokens,
                "output_tokens": m.output_tokens,
                "success": m.success,
                "tools_used": tools_used,
                "error": m.error,
            }

        color = "green" if record["total_time"] <= 10.0 else "bold red"
        console.print(
            f"   ↳ [{color}]{record['total_time']:.3f}s[/{color}] "
            f"(TTFT: {record['ttft']:.3f}s, LLM: {record['llm_time']:.3f}s, "
            f"Tools: {record['tool_time']:.3f}s, Sec: {record['security_time']:.4f}s, "
            f"Steps: {record['steps']}, Tokens: {record['prompt_tokens']}p/{record['output_tokens']}o)"
        )

        results.append(record)
        if record["total_time"] > 10.0:
            exceeded_10s.append(record)

    # Compute breakdown per category
    categories = sorted(list(set(r["category"] for r in results)))
    cat_summary = {}

    for c in categories:
        cat_records = [r for r in results if r["category"] == c]
        times = [r["total_time"] for r in cat_records]
        ttfts = [r["ttft"] for r in cat_records]
        llm_times = [r["llm_time"] for r in cat_records]
        tool_times = [r["tool_time"] for r in cat_records]
        sec_times = [r["security_time"] for r in cat_records]
        redact_times = [r["redaction_time"] for r in cat_records]
        sqlite_times = [r["sqlite_time"] for r in cat_records]

        cat_summary[c] = {
            "count": len(cat_records),
            "latency": compute_percentiles(times),
            "ttft": compute_percentiles(ttfts),
            "llm_time": compute_percentiles(llm_times),
            "tool_time": compute_percentiles(tool_times),
            "security_time_avg": round(statistics.mean(sec_times), 5) if sec_times else 0.0,
            "redaction_time_avg": round(statistics.mean(redact_times), 5) if redact_times else 0.0,
            "sqlite_time_avg": round(statistics.mean(sqlite_times), 5) if sqlite_times else 0.0,
            "exceeded_10s": sum(1 for r in cat_records if r["total_time"] > 10.0),
        }

    all_times = [r["total_time"] for r in results]
    overall_latency = compute_percentiles(all_times)

    # Output table
    table = Table(title="Latency Benchmark Results", border_style="cyan", header_style="bold magenta")
    table.add_column("Category", style="bold")
    table.add_column("Tasks", justify="right")
    table.add_column("p50 (s)", justify="right")
    table.add_column("p95 (s)", justify="right")
    table.add_column("Max (s)", justify="right")
    table.add_column("Avg TTFT (s)", justify="right")
    table.add_column("Avg LLM (s)", justify="right")
    table.add_column(">10s", justify="right")

    for c, stats in cat_summary.items():
        exceeded_style = "bold red" if stats["exceeded_10s"] > 0 else "green"
        table.add_row(
            c.capitalize(),
            str(stats["count"]),
            f"{stats['latency']['p50']:.3f}",
            f"{stats['latency']['p95']:.3f}",
            f"{stats['latency']['max']:.3f}",
            f"{stats['ttft']['avg']:.3f}",
            f"{stats['llm_time']['avg']:.3f}",
            f"[{exceeded_style}]{stats['exceeded_10s']}[/{exceeded_style}]",
        )

    console.print("\n")
    console.print(table)

    console.print(f"\n[bold]Overall p50 Latency:[/bold] {overall_latency['p50']:.3f}s")
    console.print(f"[bold]Overall p95 Latency:[/bold] {overall_latency['p95']:.3f}s")
    console.print(f"[bold]Total Tasks > 10.0s:[/bold] {len(exceeded_10s)} / {len(results)}\n")

    if exceeded_10s:
        console.print("[bold red]Tasks Exceeding 10s Budget:[/bold red]")
        for ex in exceeded_10s:
            console.print(f" • [{ex['id']}] {ex['total_time']:.2f}s (LLM: {ex['llm_time']:.2f}s) - {ex['query']}")

    report_data = {
        "timestamp": time.time(),
        "model": settings.model,
        "total_tasks": len(results),
        "overall_latency": overall_latency,
        "category_summary": cat_summary,
        "tasks_exceeding_10s": exceeded_10s,
        "records": results,
    }

    if output_path:
        output_path.parent.mkdir(parents=True, exist_ok=True)
        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(report_data, f, indent=2)
        console.print(f"\n[green]Saved benchmark results to {output_path}[/green]")

    return report_data


def main():
    parser = argparse.ArgumentParser(description="Linux Command Pilot Latency Benchmark.")
    parser.add_argument("--category", "-c", choices=["safe", "filesystem", "system", "troubleshooting", "blocked"])
    parser.add_argument("--limit", "-n", type=int, help="Limit number of tasks to evaluate.")
    parser.add_argument("--dataset", "-d", type=Path, default=Path(__file__).parent / "tasks.jsonl")
    parser.add_argument("--output", "-o", type=Path, default=Path(__file__).parent / "baseline_latency.json")
    parser.add_argument("--no-warmup", action="store_true", help="Skip warm-up request.")

    args = parser.parse_args()
    run_benchmark(
        dataset_path=args.dataset,
        category=args.category,
        limit=args.limit,
        output_path=args.output,
        warmup=not args.no_warmup,
    )


if __name__ == "__main__":
    main()
