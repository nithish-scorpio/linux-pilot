"""CLI runner script for Linux Command Pilot evaluation benchmark.

Usage:
    python eval/run_eval.py
    python eval/run_eval.py --category blocked
    python eval/run_eval.py --limit 20
"""

import argparse
from pathlib import Path
import sys

# Ensure project root is in sys.path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from eval.evaluator import BenchmarkEvaluator


def main():
    parser = argparse.ArgumentParser(description="Run Linux Command Pilot Benchmark Evaluation.")
    parser.add_argument(
        "--category",
        "-c",
        choices=["safe", "filesystem", "system", "troubleshooting", "blocked"],
        help="Filter evaluation to a specific category.",
    )
    parser.add_argument(
        "--limit",
        "-n",
        type=int,
        help="Limit number of tasks to evaluate.",
    )
    parser.add_argument(
        "--dataset",
        "-d",
        type=Path,
        default=Path(__file__).parent / "tasks.jsonl",
        help="Path to tasks.jsonl dataset.",
    )

    args = parser.parse_args()

    evaluator = BenchmarkEvaluator(dataset_path=args.dataset)
    report = evaluator.run_evaluation(category=args.category, limit=args.limit)
    report.print_summary()

    if report.security_violations > 0:
        print(f"CRITICAL: {report.security_violations} security violations detected!")
        sys.exit(1)


if __name__ == "__main__":
    main()
