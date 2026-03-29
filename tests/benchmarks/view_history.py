#!/usr/bin/env python3
"""Print a table of benchmark results over time.

Usage:
    python tests/benchmarks/view_history.py
    python tests/benchmarks/view_history.py --gt dsvw
"""

import argparse
import json
from pathlib import Path

_RESULTS_DIR = Path(__file__).parent / "results"


def load_results(gt_filter: str | None = None) -> list[dict]:
    results = []
    for f in sorted(_RESULTS_DIR.glob("*.json")):
        data = json.loads(f.read_text(encoding="utf-8"))
        if gt_filter and data.get("ground_truth_file", "") != f"{gt_filter}.yaml":
            continue
        results.append(data)
    return results


def print_table(results: list[dict]) -> None:
    if not results:
        print("No benchmark results found.")
        return

    header = (
        f"{'Date':<20} {'Commit':<10} {'Version':<8} "
        f"{'TP':>4} {'FP':>4} {'FN':>4} "
        f"{'Prec':>7} {'Recall':>7} {'F1':>7} {'Verif':>7}"
    )
    print(header)
    print("-" * len(header))

    for r in results:
        m = r["metrics"]
        print(
            f"{r['timestamp'][:19]:<20} "
            f"{r['aegis_commit_sha'][:8]:<10} "
            f"{r['aegis_version']:<8} "
            f"{m['true_positives']:>4} "
            f"{m['false_positives']:>4} "
            f"{m['false_negatives']:>4} "
            f"{m['precision']:>6.1%} "
            f"{m['recall']:>6.1%} "
            f"{m['f1_score']:>6.1%} "
            f"{m['verification_rate']:>6.1%}"
        )


def main():
    parser = argparse.ArgumentParser(description="View AEGIS benchmark history")
    parser.add_argument("--gt", default=None, help="Filter by ground truth name (e.g., dsvw)")
    args = parser.parse_args()

    results = load_results(args.gt)
    print_table(results)


if __name__ == "__main__":
    main()
