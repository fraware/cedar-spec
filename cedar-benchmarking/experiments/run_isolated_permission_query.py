#!/usr/bin/env python3
"""Measure Cedar permission-query workloads in separate OS processes.

Each resource-count workload gets a fresh process so Linux VmRSS values are not
confounded by *earlier* benchmark sizes in the same process. These are still
whole-process measurements, not an accounting of individual Rust allocations.
"""

import argparse
import json
import math
import os
import platform
import subprocess
from pathlib import Path


def measure(sizes: list[int], executable: Path, trials: int, warmups: int) -> dict:
    if not sizes or any(size <= 0 for size in sizes) or trials <= 0 or warmups < 0:
        raise ValueError("sizes and trials must be positive; warmups must be nonnegative")

    results = []
    for size in sizes:
        cmd = [
            str(executable.absolute()),
            "--sizes",
            str(size),
            "--trials",
            str(trials),
            "--warmups",
            str(warmups),
        ]
        result = subprocess.run(cmd, capture_output=True, text=True, check=True)
        data = json.loads(result.stdout)
        rows = data.get("rows", [])
        if len(rows) != 1 or rows[0].get("documents") != size:
            raise ValueError(f"missing or unexpected result for size {size}: {rows!r}")
        row = rows[0]
        if row.get("trials") != trials:
            raise ValueError(f"wrong trial count for {size}")
        for key in ("query_resource", "query_resource_prepared", "snapshot_preparation_us"):
            if key not in row:
                raise ValueError(f"missing field {key} for size {size}")

        original = row["query_resource"]["mean_us"]
        prepared = row["query_resource_prepared"]["mean_us"]
        preparation = row["snapshot_preparation_us"]
        if not all(isinstance(v, (int, float)) and 0 <= v < float("inf")
                   for v in (original, prepared, preparation)):
            raise ValueError(f"invalid timing result for {size}")
        speedup = original / prepared if prepared > 0 else None
        rss_start = row.get("rss_before_preparation_kib")
        rss_end = row.get("rss_after_preparation_kib")
        rss_change = (
            rss_end - rss_start
            if isinstance(rss_start, int) and isinstance(rss_end, int)
            else None
        )
        results.append({
            "size": size,
            "measurements": row,
            "derived": {
                "mean_speedup": speedup,
                "rss_change_kib": rss_change,
                "estimated_minimum_queries_to_amortize": (
                    math.floor(preparation / (original - prepared)) + 1
                    if original > prepared
                    else None
                ),
            },
            "cedar_version": data.get("cedar_version"),
        })
        print(
            f"documents={size} original={original:.3f}us "
            f"prepared={prepared:.3f}us speedup={speedup!r} "
            f"rss_delta={rss_change}KiB",
            flush=True,
        )

    return {
        "protocol": "isolated-one-process-per-workload-size",
        "host": {"os": platform.system(), "machine": platform.machine()},
        "ci": {"commit": os.environ.get("GITHUB_SHA"), "run_id": os.environ.get("GITHUB_RUN_ID")},
        "cedar_source_revision": os.environ.get("CEDAR_SOURCE_REVISION"),
        "trials": trials,
        "warmups": warmups,
        "results": results,
        "limitations": (
            "VmRSS is process-resident memory, not snapshot allocation. "
            "Each size is isolated from earlier sizes, but allocator caches, "
            "process startup and the preallocated test fixture still affect RSS. "
            "Observed speedups are synthetic workload measurements, not guarantees."
        ),
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--executable", type=Path, default=Path("target/release/permission_query_baseline"))
    parser.add_argument("--sizes", type=int, nargs="+", default=[100, 1000, 10000])
    parser.add_argument("--trials", type=int, default=30)
    parser.add_argument("--warmups", type=int, default=3)
    parser.add_argument("--output", type=Path, default=Path("permission_query_isolated_results.json"))
    args = parser.parse_args()
    report = measure(args.sizes, args.executable, args.trials, args.warmups)
    args.output.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    print(f"Wrote {args.output}", flush=True)


if __name__ == "__main__":
    main()
