# Prepared entity snapshot: Cedar permission-query experiment

**Status:** Experimental SDK overlay for evaluation. Not a Cedar core PR, not a
production API, and not proof of formal equivalence.

## Question

Can repeated permission queries over an unchanged, validated entity store
avoid the repeated `Entities` -> `PartialEntities` construction cost observed
in [cedar issue #1811](https://github.com/cedar-policy/cedar/issues/1811)?

## Experiment

- Checkout `cedar-policy/cedar` at commit
  `10b7222f01489cc1546607d8d8981747b61310f3` into `cedar/` (current core pin for the expanded experiment).
- Apply `apply_prepared_resource_query.py`, which **fails closed** unless the
  TPE SDK source Git blob matches
  `0335586bc7d241cbd79f74f2f09c2bd7a9f7c6fd`.
- The overlay adds an immutable `PreparedResourceQueryEntities` owning the
  schema, concrete store and validated partial representation. The constructor
  performs the existing schema-completeness check and conversion.
- `PolicySet::query_resource_prepared` uses the exact same final query logic
  as the existing `query_resource` method, factoring that shared logic into
  a private helper. The existing public API remains available unchanged.
- The benchmark constructs one prepared snapshot per dataset, measures its
  one-time preparation cost, and measures repeatedly querying the same
  snapshot. Queries with and without preparation are compared against
  exhaustive concrete authorization for the **complete authorized UID set**,
  before timing and on every timed trial.

### Local reproduction (Rust toolchain required)

```bash
git clone https://github.com/cedar-policy/cedar.git cedar
git -C cedar checkout 10b7222f01489cc1546607d8d8981747b61310f3
python3 cedar-benchmarking/experiments/apply_prepared_resource_query.py cedar
cargo fmt --manifest-path cedar/Cargo.toml --all --check
cd cedar-benchmarking
cargo clippy --all-targets -- -D warnings
cargo test --release --bin permission_query_baseline
python3 experiments/run_isolated_permission_query.py --sizes 100 1000 10000 --warmups 3 --trials 30
```

The fork CI applies the same overlay without changing the upstream repository.
The revised harness uses a **fresh OS process per resource count**, writes
`permission_query_isolated_results.json`, and preserves it through an
`actions/upload-artifact@v4` CI artifact. Its Python regression tests check
process separation, malformed size results, and invalid arguments. The Rust
suite also tests that a replaced entity snapshot reflects updated authorization
data while the old immutable snapshot retains its original semantics.

The overlay still matches the current `cedar-policy/src/api/tpe.rs` source
blob because that file is unchanged across the intervening Cedar commits.
The newer pinned core revision has changes to deterministic validation errors,
which motivates rerunning differential tests.

## Historical measurements on the earlier Cedar revision

Three GitHub-hosted Linux CI runs of the in-memory workload completed
successfully against the **earlier Cedar commit**
`cf7e99c7d40867af5280164cb17f04743937f5e8`. The revised isolated-process
measurements against the newer pin must be interpreted separately. Units are **mean milliseconds per full query**;
snapshot preparation is a separate, one-time operation.

| Resources | Run | Original query | Prepared query | Speedup | One-time preparation |
| ---: | --- | ---: | ---: | ---: | ---: |
| 100 | [39178101010](https://github.com/fraware/cedar-spec/actions/runs/39178101010) | 0.577 | 0.319 | 1.81x | 0.296 |
| 1,000 | 39178101010 | 6.428 | 3.060 | 2.10x | 3.195 |
| 10,000 | 39178101010 | 73.223 | 34.104 | 2.15x | 46.635 |
| 100 | [39178514607](https://github.com/fraware/cedar-spec/actions/runs/39178514607) | 0.568 | 0.317 | 1.79x | 0.288 |
| 1,000 | 39178514607 | 6.782 | 3.209 | 2.11x | 3.436 |
| 10,000 | 39178514607 | 85.711 | 37.097 | 2.31x | 52.664 |
| 100 | [39209984432](https://github.com/fraware/cedar-spec/actions/runs/39209984432) | 0.452 | 0.261 | 1.74x | 0.222 |
| 1,000 | 39209984432 | 5.428 | 2.592 | 2.09x | 2.684 |
| 10,000 | 39209984432 | 74.105 | 32.745 | 2.26x | 36.588 |

Each reported query mean averages 30 timed trials after three warm-up trials.
The second run passed seven tests. The third run passed **10/10** tests,
adding hierarchical entity and resource relations, changing request context
against a reused snapshot, and a Linux RSS parser test.

### Observational Linux resident memory

The third run measured process VmRSS before and after preparing the snapshot:

| Entities | RSS before | RSS after | Difference |
| ---: | ---: | ---: | ---: |
| 100 | 9,724 KiB | 9,824 KiB | 100 KiB |
| 1,000 | 15,648 KiB | 17,400 KiB | 1,752 KiB |
| 10,000 | 73,848 KiB | 87,864 KiB | 14,016 KiB |

These **whole-process RSS differences are not per-object heap sizes**.
Allocator reuse, process activity, and the earlier benchmark sizes run
within the same process affect the readings. The isolated-process harness removes interference **from earlier benchmark
sizes** in the same process. Retained-heap and allocator profiling remain
necessary, since RSS remains process-wide.

For this benchmark, amortization over repeated queries looks promising:
the one-time preparation expense is comparable to roughly one to two query
latency savings. **This is an observed workload-specific break-even, not a
prediction for arbitrary Cedar policies or resource stores.**

## Limits

1. Prepared snapshots represent a **fixed owned copy** of both schema and
   entities. New data requires construction of a new prepared snapshot. The
   experiment does not expose mutation, aliases or cache invalidation.
2. The prepared snapshot consumes additional memory by holding concrete and
   partial representations. Process RSS changes have now been observed, but
   exact retained heap, allocator behavior, and concurrent-snapshot memory
   pressure remain unmeasured.
3. Query construction is excluded from the timed query loop. Snapshot
   preparation is reported separately, and its amortized cost depends on the
   number of queries per snapshot.
4. The existing benchmark uses flat, synthetic entities and a fixed
   permit/forbid policy set. Results are not universal across policies,
   hierarchies, extension functions, or workloads.
5. Matching result sets in tested cases do **not** prove equivalence of all
   diagnostic/error behavior or all Cedar semantics. A production
   implementation requires extensive differential and formal testing.
6. This only prototypes reuse of the partial entity representation. It does
   not implement the maintainer-suggested general entity-access trait.

## Decision gate

Advance towards a separate `cedar-policy/cedar` implementation only if
(a) patched SDK compilation/format/Clippy succeeds on the newer pinned core revision, (b) complete result-set
comparisons succeed, (c) repeated-query latency materially improves on
multiple workloads, (d) snapshot preparation/memory tradeoffs are reported,
and (e) maintainers consider the architectural tradeoff acceptable.
