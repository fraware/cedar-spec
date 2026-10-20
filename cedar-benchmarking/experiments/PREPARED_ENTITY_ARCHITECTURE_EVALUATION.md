# Evaluating entity representation strategies for repeated Cedar permission queries

**Status:** Experimental evaluation. This is not an upstream Cedar engine API proposal or a claim of general performance or behavioral equivalence.

## Decision to be made

Cedar's pinned `PolicySet::query_resource` implementation checks the schema and constructs `PartialEntities::from_concrete(entities.clone(), schema)` on every query. For repeated permission queries over an unchanged entity store, the repeated conversion has measurable cost. The question is which implementation removes that cost with acceptable additional memory, lifetime constraints, semantic risk and maintenance burden.

Three implementation strategies are considered. The first two are **implemented prototypes** in fork PRs [#6](https://github.com/fraware/cedar-spec/pull/6) and [#7](https://github.com/fraware/cedar-spec/pull/7). The third is a **proposal for evaluation**, not a measured alternative.

| Strategy | Query-time behavior | Additional retained state | Tradeoffs |
| --- | --- | --- | --- |
| Owned prepared snapshot | Reuses a previously validated `PartialEntities` representation | An owned concrete `Entities` copy, schema and partial representation | Independent ownership, increased retained memory and snapshot-rebuild responsibility |
| Borrowed prepared snapshot | Reuses the same kind of validated partial representation | A partial representation plus references to caller-owned `Entities` and `Schema` | Reduced concrete-store duplication; reference lifetimes must outlive the snapshot |
| Evaluator entity-access trait | **Proposed:** evaluate through a source abstraction without repeated conversion | Depends on backing store/adapter | Potentially better flexibility and memory characteristics; significantly larger semantic and interface review surface |

**Important:** the borrowed prototype still performs `PartialEntities::from_concrete(entities.clone(), schema)` *during preparation*. It is not zero-copy and does not eliminate the initial conversion; it prevents reconstructing that representation per repeated query and avoids retaining a second concrete entity store.

## Evidence from the exact validated experimental head

Source: Cedar core `10b7222f01489cc1546607d8d8981747b61310f3`, an exact-blob-guarded experimental overlay, and the benchmark job of [GitHub Actions run 39484106208](https://github.com/fraware/cedar-spec/actions/runs/39484106208), fork commit `f353773ff39554cadc5ca0bc30401cd69b20d4b4`.

Mean latency in milliseconds per complete candidate-set query, 30 trials after warmup on **one synthetic runner/workload**:

| Documents | Original | Owned prepared | Borrowed prepared |
| ---: | ---: | ---: | ---: |
| 100 | 0.567 | 0.326 | 0.323 |
| 1,000 | 6.431 | 3.135 | 3.080 |
| 10,000 | 74.618 | 36.161 | 35.828 |

Median *observed incremental process VmRSS*, in KiB, from four fresh-process replicates for each candidate representation at each size:

| Documents | Owned prepared | Borrowed prepared | Reduction in observed delta |
| ---: | ---: | ---: | ---: |
| 100 | 98 | 80 | 18 |
| 1,000 | 1,822 | 1,564 | 258 |
| 10,000 | 14,084 | 12,020 | 2,064 |

The 10,000-document run indicates comparable query times, with approximately 14.7% lower observed incremental process RSS for the borrowed representation relative to the owned representation. The RSS values are **not heap allocations attributable to snapshot objects**: they include allocator behavior, runtime allocations, and process measurement noise. Four replicates do not warrant confidence intervals or broad generalization.

The main timing benchmark and separate-process RSS benchmark use different protocols and must not be conflated. Initial snapshot preparation has a nonzero cost: for a deployment issuing `N` repeated queries on an immutable snapshot, an approximate total cost model is `C_prepare + N * T_prepared` against `N * T_original`. A production break-even claim needs preparation and query costs under the same application workload, incorporating rebuild frequency and external loading.

The [raw prepared-query artifact](https://github.com/fraware/cedar-spec/actions/runs/39484106208) and [raw owned-versus-borrowed memory artifact](https://github.com/fraware/cedar-spec/actions/runs/39484106208) were uploaded by the targeted benchmarking job. Artifact names are `cedar-prepared-query-isolated-raw` and `cedar-borrowed-vs-owned-memory-raw`, respectively.

## Correctness contract

For a fixed set of policies `P`, request `q`, concrete entities `E`, schema `S`, and a successfully prepared snapshot `B(E,S)`, the key obligation is equality of complete allowed-resource UID sets:

```text
Query(P, q, E, S) == QueryPrepared(P, q, B(E, S))
```

An API-level contract also needs to cover rejection/error behavior, diagnostic differences, partial evaluation semantics, and the consequences of incomplete and invalid input. Conversion and schema validation occur at snapshot construction instead of query time in the prototype, which changes the observable timing and location of some errors. Equating resource sets does not settle those error behaviors.

Existing tests compare resource sets against exhaustive concrete authorization, including permits and forbids, hierarchy membership, changing request contexts, and entity updates for the **owned** snapshot. The evaluation branch strengthens the borrowed snapshot with the same relevant correctness cases and a policy-set mutation test. These executable checks are regression evidence, not a universal proof.

A valid snapshot is a view of immutable input data. Callers must rebuild it after every authorization-relevant change to entities or schema; a borrowed Rust reference does not prove freshness relative to an external database. A production design must state ownership, invalidation/version publication, concurrent reading, and replacement/rollback behavior.

## Next experiments and acceptance gates

1. **Differential semantics:** test complete results and error/diagnostic outcomes for generated policies, type-directed queries, multi-level entity graphs, missing/incorrect attributes, schema changes, partial data and extensions. Fix random seeds; save minimal failures. Treat authorizer-vs-resource-query agreement as an empirical oracle on matching supported semantics, not a formal proof.
2. **Representative workloads:** sample flat and hierarchical stores, policy counts/structures, attribute sizes, 100–200,000+ entities where feasible, mixed action/principal/resource queries, high and low result cardinality, and repeated queries over mutable snapshots. Avoid claiming all cases represent real customer workloads.
3. **Memory accounting:** use a profiling allocator or heap profiler for live and peak allocations in addition to isolated process RSS. Record clone, conversion, prepare, evaluate and rebuild costs separately.
4. **Alternative architecture:** prototype one minimal trait/adapter for entity lookup and hierarchy membership as proposed in [cedar#1811](https://github.com/cedar-policy/cedar/issues/1811) and [cedar#1532](https://github.com/cedar-policy/cedar/issues/1532). Compare with owned, borrowed and an explicit shared-ownership alternative under matched workload conditions.
5. **Rebase and review:** revalidate the exact code and benchmark results on current Cedar main; request maintainer guidance before choosing a public API. Keep engine code in the Cedar core repository if adopted, not as a permanent overlay in cedar-spec.

Decision rule: select an implementation only after evidence establishes equivalence for the proposed API contract and a reproducible improvement in latency, retained memory, or both, under explicitly scoped workloads. Prefer the smallest implementation and trust surface that satisfies the demonstrated need.

## Upstream context and release boundary

- [cedar#1811](https://github.com/cedar-policy/cedar/issues/1811): avoid expensive `PartialEntities` and concrete `Entities` conversions in TPE.
- [cedar#1532](https://github.com/cedar-policy/cedar/issues/1532): alternative entity representation and trait-based authorizer access.
- [cedar#1273](https://github.com/cedar-policy/cedar/issues/1273): batch authorization.
- [cedar#2378](https://github.com/cedar-policy/cedar/issues/2378): large pre-fetched entity graph scalability.
- [fraware/cedar-spec#6](https://github.com/fraware/cedar-spec/pull/6): owned snapshot experiment.
- [fraware/cedar-spec#7](https://github.com/fraware/cedar-spec/pull/7): borrowed snapshot experiment.

The experimental overlay must not be merged into production Cedar without an explicit upstream API design, end-to-end validation, and a current-main test run. The broader workflow in this fork can fail at unrelated reusable checkout steps; use the **targeted job and exact commit SHA** when making test claims.
