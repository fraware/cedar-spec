# Borrowed versus owned prepared entity snapshots

**Status:** Experimental comparison, stacked on the prepared-snapshot prototype
in fork PR #6. Not a production Cedar API or upstream merge proposal.

## Motivation

The owned prepared-query prototype retains a separate concrete `Entities`
collection plus a validated `PartialEntities` representation. A borrowed
alternative uses Rust shared references to the caller's `Entities` and
`Schema`, retaining the prepared partial representation without retaining an
additional concrete-store copy. Both paths delegate to the same resource-query
evaluation helper in the pinned Cedar SDK overlay.

Borrowing constrains lifetimes: the caller must keep the referenced immutable
entity store and schema alive for the full lifetime of the prepared snapshot.
Any authorization-relevant data change requires a new snapshot.

## Benchmarks

The main `permission_query_baseline` binary compares the ordinary query,
owned prepared query, borrowed prepared query, and exhaustive concrete
authorization. Complete allowed-resource UID sets must match before timing,
on every timed trial, and in the targeted differential unit tests. Each
prepared snapshot's construction time is reported separately.

**The main benchmark constructs both prepared variants in the same process.
Its `rss_after_preparation_kib` covers only the owned constructor and must
not be used to claim a memory difference between variants.**

The separate-process memory protocol measures exactly one snapshot
constructor per fresh process:

```bash
python3 experiments/run_borrowed_memory_comparison.py \
  --sizes 100 1000 10000 --repetitions 3
```

For each document count and replicate, the harness starts an independent
process for each representation, invokes
`permission_query_baseline --sizes N --snapshot-memory-mode owned|borrowed`,
confirms equal authorized-resource counts, and records the before/after
Linux `VmRSS` readings and construction durations. It preserves every
observation plus medians in `borrowed_vs_owned_memory.json`.

The GitHub Actions workflow uploads this raw evidence as
`cedar-borrowed-vs-owned-memory-raw`. It also checks formatting, Clippy with
warnings treated as errors, release compilation, Rust differential tests,
and the independent-process harness unit tests.

## Threats to validity and acceptance criteria

- Process RSS includes allocator caching, unrelated runtime allocations,
  and noise. Even fresh processes do not produce exact snapshot heap sizes.
- Creation order and host load may affect timings. Replicates provide a
  preliminary signal, not confidence intervals or robust production claims.
- This workload has flat synthetic document entities; hierarchy tests exist
  for correctness, whereas performance across realistic graphs remains open.
- The borrowed design holds references: applications requiring an independently
  owned snapshot, detached lifetime, or snapshot transfer across threads must
  evaluate lifetime and concurrency implications.
- Passing the current resource-set tests does not prove equivalence for all
  Cedar errors, diagnostics, partial data and extension-function semantics.

A useful result would show a reproducible reduction in additional process RSS
without a material query-latency regression, alongside successful authorization
equivalence checks. Neither result should be claimed until the exact final
commit's CI evidence exists.
