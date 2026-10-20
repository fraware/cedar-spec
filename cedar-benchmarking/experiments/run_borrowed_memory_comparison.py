#!/usr/bin/env python3
"""Independent-process RSS comparison of owned and borrowed Cedar snapshots.

Each snapshot kind and document count gets a new OS process. This isolates
the alternatives from each other's retained allocations, but VmRSS is still
a whole-process metric rather than exact heap allocation.
"""

import argparse
import json
import statistics
import subprocess
from pathlib import Path


def compare(executable: Path, sizes: list[int], repetitions: int) -> dict:
    if not sizes or any(n <= 0 for n in sizes) or repetitions <= 0:
        raise ValueError("sizes and repetitions must be positive")
    cases = []
    for n in sizes:
        for trial in range(repetitions):
            observations = {}
            # Rotate process launch order to reduce systematic thermal/load bias.
            order = ("owned", "borrowed") if trial % 2 == 0 else ("borrowed", "owned")
            for mode in order:
                completed = subprocess.run(
                    [str(executable.absolute()), "--sizes", str(n),
                     "--snapshot-memory-mode", mode],
                    capture_output=True, text=True, check=True,
                )
                data = json.loads(completed.stdout)
                if data.get("snapshot_mode") != mode or data.get("documents") != n:
                    raise ValueError("snapshot variant or document count mismatch")
                rss_start, rss_end = data.get("rss_before_kib"), data.get("rss_after_kib")
                if not isinstance(rss_start, int) or not isinstance(rss_end, int):
                    raise ValueError("missing Linux VmRSS measurement")
                if not isinstance(data.get("authorized"), int):
                    raise ValueError("missing authorized-result accounting")
                observations[mode] = {
                    "rss_before_kib": rss_start,
                    "rss_after_kib": rss_end,
                    "observed_delta_kib": rss_end - rss_start,
                    "snapshot_preparation_us": data["snapshot_preparation_us"],
                    "authorized": data["authorized"],
                }
            if observations["owned"]["authorized"] != observations["borrowed"]["authorized"]:
                raise ValueError("authorized-resource mismatch")
            cases.append({"documents": n, "replicate": trial, "observations": observations})
        print(f"documents={n} separate-process replicates={repetitions}", flush=True)

    aggregates = []
    for n in sizes:
        group = [c["observations"] for c in cases if c["documents"] == n]
        aggregates.append({
            "documents": n,
            "replicates": repetitions,
            "owned_median_rss_delta_kib": statistics.median(
                r["owned"]["observed_delta_kib"] for r in group
            ),
            "borrowed_median_rss_delta_kib": statistics.median(
                r["borrowed"]["observed_delta_kib"] for r in group
            ),
            "owned_median_preparation_us": statistics.median(
                r["owned"]["snapshot_preparation_us"] for r in group
            ),
            "borrowed_median_preparation_us": statistics.median(
                r["borrowed"]["snapshot_preparation_us"] for r in group
            ),
        })

    return {
        "protocol": "fresh-process-per-size-per-variant-per-replicate",
        "raw_cases": cases,
        "aggregates": aggregates,
        "limitations": (
            "VmRSS is whole-process resident memory, not allocated bytes; "
            "measurement noise and allocator caching may affect results. "
            "This design isolates owned from borrowed alternatives but "
            "does not quantify live object allocations or simultaneous snapshots."
        ),
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--executable", type=Path, default=Path("target/release/permission_query_baseline"))
    parser.add_argument("--sizes", nargs="+", type=int, default=[100, 1000, 10000])
    parser.add_argument("--repetitions", type=int, default=4)
    parser.add_argument("--output", type=Path, default=Path("borrowed_vs_owned_memory.json"))
    args = parser.parse_args()
    report = compare(args.executable, args.sizes, args.repetitions)
    args.output.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    for row in report["aggregates"]:
        print(json.dumps(row, sort_keys=True), flush=True)
    print(f"Wrote {args.output}", flush=True)


if __name__ == "__main__":
    main()
