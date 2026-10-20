/*
 * Copyright Cedar Contributors
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

//! Reproducible in-memory permission-query baseline, with correctness checked
//! against exhaustive concrete authorization before every timed experiment.
//!
//! The experiment intentionally excludes database I/O and input construction.
//! It measures two existing Cedar API paths against the same entity snapshot.

use cedar_policy::{
    Authorizer, BorrowedPreparedResourceQueryEntities, Context, Decision, Entities, EntityUid,
    PartialEntities, PolicySet, PreparedResourceQueryEntities, Request, ResourceQueryRequest,
    Schema, ValidationMode, Validator,
};
use clap::Parser;
use serde::Serialize;
use serde_json::json;
use std::collections::BTreeSet;
use std::error::Error;
use std::hint::black_box;
use std::io;
use std::time::Instant;

const SCHEMA: &str = r#"
entity User;
entity Document {
    owner: User,
    isPublic: Bool,
    blocked: Bool
};
action view appliesTo {
    principal: [User],
    resource: [Document]
};
"#;

const POLICIES: &str = r#"
permit(
    principal == User::"alice",
    action == Action::"view",
    resource
) when {
    resource.owner == principal || resource.isPublic
};
forbid(
    principal,
    action == Action::"view",
    resource
) when {
    resource.blocked
};
"#;

type ExperimentResult<T> = Result<T, Box<dyn Error>>;

fn parse_vm_rss_kib(status: &str) -> Option<u64> {
    status.lines().find_map(|line| {
        let value = line.strip_prefix("VmRSS:")?;
        let mut pieces = value.split_whitespace();
        let kib = pieces.next()?.parse::<u64>().ok()?;
        (pieces.next() == Some("kB")).then_some(kib)
    })
}

/// Linux-only process resident set snapshot. Not a per-object allocation size;
/// allocator reuse, other allocations, and previous experiments affect it.
fn process_rss_kib() -> Option<u64> {
    parse_vm_rss_kib(&std::fs::read_to_string("/proc/self/status").ok()?)
}

#[derive(Debug, Parser)]
#[command(about = "Compare Cedar query_resource with exhaustive in-memory authorization")]
struct Args {
    /// Comma-separated numbers of Document entities in each experiment.
    #[arg(long, value_delimiter = ',', default_value = "100,1000,10000")]
    sizes: Vec<usize>,

    /// Number of timed runs for each method at each size.
    #[arg(long, default_value_t = 30)]
    trials: usize,

    /// Untimed warm-up iterations for each method.
    #[arg(long, default_value_t = 3)]
    warmups: usize,

    /// Measure just one snapshot constructor in a fresh process: owned or borrowed.
    #[arg(long)]
    snapshot_memory_mode: Option<String>,
}

#[derive(Debug)]
struct Fixture {
    schema: Schema,
    policies: PolicySet,
    entities: Entities,
    principal: EntityUid,
    action: EntityUid,
    candidates: Vec<EntityUid>,
    prepared_requests: Vec<Request>,
    query: ResourceQueryRequest,
}

fn fixture(documents: usize) -> ExperimentResult<Fixture> {
    let schema = Schema::from_cedarschema_str(SCHEMA)?.0;
    let policies: PolicySet = POLICIES.parse()?;
    if !Validator::new(schema.clone())
        .validate(&policies, ValidationMode::Strict)
        .validation_passed()
    {
        return Err(io::Error::other("Synthetic benchmark policies did not validate").into());
    }

    let mut entities = vec![
        json!({
            "uid": {"__entity": {"type": "User", "id": "alice"}},
            "attrs": {}, "parents": []
        }),
        json!({
            "uid": {"__entity": {"type": "User", "id": "bob"}},
            "attrs": {}, "parents": []
        }),
    ];
    let mut candidates: Vec<EntityUid> = Vec::with_capacity(documents);
    for i in 0..documents {
        let id = format!("document-{i}");
        // The three fields create permits, forbids, and conflicting policies.
        let owner = if i % 2 == 0 { "alice" } else { "bob" };
        entities.push(json!({
            "uid": {"__entity": {"type": "Document", "id": id}},
            "attrs": {
                "owner": {"__entity": {"type": "User", "id": owner}},
                "isPublic": i % 7 == 0,
                "blocked": i % 13 == 0
            },
            "parents": []
        }));
        candidates.push(format!("Document::\"document-{i}\"").parse()?);
    }

    let entities = Entities::from_json_str(&serde_json::to_string(&entities)?, Some(&schema))?;
    let principal: EntityUid = r#"User::"alice""#.parse()?;
    let action: EntityUid = r#"Action::"view""#.parse()?;
    let example: EntityUid = r#"Document::"document-0""#.parse()?;
    let query = ResourceQueryRequest::new(
        principal.clone(),
        action.clone(),
        example.type_name().clone(),
        Context::empty(),
        &schema,
    )?;
    let prepared_requests = candidates
        .iter()
        .map(|resource| {
            Request::new(
                principal.clone(),
                action.clone(),
                resource.clone(),
                Context::empty(),
                None,
            )
        })
        .collect::<Result<Vec<_>, _>>()?;
    Ok(Fixture {
        schema,
        policies,
        entities,
        principal,
        action,
        candidates,
        prepared_requests,
        query,
    })
}

fn query_resources(f: &Fixture) -> ExperimentResult<BTreeSet<EntityUid>> {
    Ok(f.policies
        .query_resource(&f.query, &f.entities, &f.schema)?
        .collect())
}

fn query_resources_prepared(
    f: &Fixture,
    prepared: &PreparedResourceQueryEntities,
) -> ExperimentResult<BTreeSet<EntityUid>> {
    Ok(f.policies
        .query_resource_prepared(&f.query, prepared)?
        .collect())
}

fn query_resources_prepared_borrowed(
    f: &Fixture,
    prepared: &BorrowedPreparedResourceQueryEntities<'_>,
) -> ExperimentResult<BTreeSet<EntityUid>> {
    Ok(f.policies
        .query_resource_prepared_borrowed(&f.query, prepared)?
        .collect())
}

fn individually_authorize(f: &Fixture) -> ExperimentResult<BTreeSet<EntityUid>> {
    let authorizer = Authorizer::new();
    let mut allowed = BTreeSet::new();
    for candidate in &f.candidates {
        // Policy and schema validation have already occurred. We keep the
        // per-candidate Request construction in this baseline's timed work.
        let request = Request::new(
            f.principal.clone(),
            f.action.clone(),
            candidate.clone(),
            Context::empty(),
            None,
        )?;
        if authorizer
            .is_authorized(&request, &f.policies, &f.entities)
            .decision()
            == Decision::Allow
        {
            allowed.insert(candidate.clone());
        }
    }
    Ok(allowed)
}

/// Exhaustive baseline without per-candidate Request construction in the
/// timed loop. This isolates a different, realistic call path from the
/// request-constructing exhaustive baseline.
fn individually_authorize_prebuilt(f: &Fixture) -> BTreeSet<EntityUid> {
    let authorizer = Authorizer::new();
    f.prepared_requests
        .iter()
        .zip(&f.candidates)
        .filter(|(request, _)| {
            authorizer
                .is_authorized(request, &f.policies, &f.entities)
                .decision()
                == Decision::Allow
        })
        .map(|(_, resource)| resource.clone())
        .collect()
}

#[derive(Debug, Serialize)]
struct TimingSummary {
    mean_us: f64,
    median_us: f64,
    p95_us: f64,
}

fn summarize(mut samples: Vec<f64>) -> TimingSummary {
    samples.sort_by(f64::total_cmp);
    let p95_index = (samples.len() * 95).div_ceil(100).saturating_sub(1);
    let midpoint = samples.len() / 2;
    let median = if samples.len().is_multiple_of(2) {
        (samples[midpoint - 1] + samples[midpoint]) / 2.0
    } else {
        samples[midpoint]
    };
    TimingSummary {
        mean_us: samples.iter().sum::<f64>() / samples.len() as f64,
        median_us: median,
        p95_us: samples[p95_index],
    }
}

#[derive(Debug, Serialize)]
struct Row {
    documents: usize,
    candidates: usize,
    authorized: usize,
    trials: usize,
    query_resource: TimingSummary,
    query_resource_prepared: TimingSummary,
    query_resource_prepared_borrowed: TimingSummary,
    snapshot_preparation_us: f64,
    borrowed_snapshot_preparation_us: f64,
    rss_before_preparation_kib: Option<u64>,
    rss_after_preparation_kib: Option<u64>,
    exhaustive_authorization: TimingSummary,
    exhaustive_prebuilt_requests: TimingSummary,
    concrete_entities_clone: TimingSummary,
    partial_entities_from_concrete: TimingSummary,
}

#[derive(Debug, Serialize)]
struct Output {
    cedar_version: String,
    host_arch: &'static str,
    host_os: &'static str,
    notes: &'static str,
    rows: Vec<Row>,
}

fn experiment(documents: usize, trials: usize, warmups: usize) -> ExperimentResult<Row> {
    let f = fixture(documents)?;
    let rss_before_preparation_kib = process_rss_kib();
    let preparation_start = Instant::now();
    let prepared = PreparedResourceQueryEntities::new(f.entities.clone(), f.schema.clone())?;
    let snapshot_preparation_us = preparation_start.elapsed().as_secs_f64() * 1_000_000.0;
    let rss_after_preparation_kib = process_rss_kib();
    let borrowed_start = Instant::now();
    let prepared_borrowed = BorrowedPreparedResourceQueryEntities::new(&f.entities, &f.schema)?;
    let borrowed_snapshot_preparation_us = borrowed_start.elapsed().as_secs_f64() * 1_000_000.0;
    let reference = individually_authorize(&f)?;
    if individually_authorize_prebuilt(&f) != reference {
        return Err(io::Error::other("prepared and constructed requests disagree").into());
    }
    if query_resources_prepared_borrowed(&f, &prepared_borrowed)? != reference {
        return Err(
            io::Error::other("borrowed prepared query disagrees with authorization").into(),
        );
    }
    if query_resources_prepared(&f, &prepared)? != reference {
        return Err(
            io::Error::other("prepared query disagrees with exhaustive authorization").into(),
        );
    }
    if query_resources(&f)? != reference {
        return Err(
            io::Error::other("query_resource disagrees with exhaustive authorization").into(),
        );
    }

    for _ in 0..warmups {
        black_box(query_resources(&f)?);
        black_box(query_resources_prepared(&f, &prepared)?);
        black_box(query_resources_prepared_borrowed(&f, &prepared_borrowed)?);
        black_box(individually_authorize(&f)?);
        black_box(individually_authorize_prebuilt(&f));
        black_box(f.entities.clone());
        black_box(PartialEntities::from_concrete(
            f.entities.clone(),
            &f.schema,
        )?);
    }

    let mut query_samples = Vec::with_capacity(trials);
    let mut prepared_samples = Vec::with_capacity(trials);
    let mut borrowed_samples = Vec::with_capacity(trials);
    let mut exhaustive_samples = Vec::with_capacity(trials);
    let mut prebuilt_samples = Vec::with_capacity(trials);
    let mut clone_samples = Vec::with_capacity(trials);
    let mut conversion_samples = Vec::with_capacity(trials);
    for round in 0..trials {
        // Alternate ordering to avoid always benchmarking one implementation first.
        let mut timed_query = || -> ExperimentResult<()> {
            let start = Instant::now();
            let result = query_resources(&f)?;
            let elapsed = start.elapsed();
            if result != reference {
                return Err(io::Error::other("query result changed during experiment").into());
            }
            black_box(result);
            query_samples.push(elapsed.as_secs_f64() * 1_000_000.0);
            Ok(())
        };
        let mut timed_exhaustive = || -> ExperimentResult<()> {
            let start = Instant::now();
            let result = individually_authorize(&f)?;
            let elapsed = start.elapsed();
            if result != reference {
                return Err(io::Error::other("exhaustive result changed during experiment").into());
            }
            black_box(result);
            exhaustive_samples.push(elapsed.as_secs_f64() * 1_000_000.0);
            Ok(())
        };
        let mut timed_prebuilt = || -> ExperimentResult<()> {
            let start = Instant::now();
            let result = individually_authorize_prebuilt(&f);
            let elapsed = start.elapsed();
            if result != reference {
                return Err(io::Error::other("prepared request result changed").into());
            }
            black_box(result);
            prebuilt_samples.push(elapsed.as_secs_f64() * 1_000_000.0);
            Ok(())
        };
        let mut timed_clone = || {
            let start = Instant::now();
            let cloned = f.entities.clone();
            let elapsed = start.elapsed();
            black_box(cloned);
            clone_samples.push(elapsed.as_secs_f64() * 1_000_000.0);
        };
        let mut timed_conversion = || -> ExperimentResult<()> {
            let start = Instant::now();
            let converted = PartialEntities::from_concrete(f.entities.clone(), &f.schema)?;
            let elapsed = start.elapsed();
            black_box(converted);
            conversion_samples.push(elapsed.as_secs_f64() * 1_000_000.0);
            Ok(())
        };
        let mut timed_prepared = || -> ExperimentResult<()> {
            let start = Instant::now();
            let result = query_resources_prepared(&f, &prepared)?;
            let elapsed = start.elapsed();
            if result != reference {
                return Err(io::Error::other("prepared query result changed").into());
            }
            black_box(result);
            prepared_samples.push(elapsed.as_secs_f64() * 1_000_000.0);
            Ok(())
        };
        if round.is_multiple_of(2) {
            timed_prepared()?;
        }
        let mut timed_borrowed = || -> ExperimentResult<()> {
            let start = Instant::now();
            let result = query_resources_prepared_borrowed(&f, &prepared_borrowed)?;
            let elapsed = start.elapsed();
            if result != reference {
                return Err(
                    io::Error::other("borrowed query result changed during experiment").into(),
                );
            }
            black_box(result);
            borrowed_samples.push(elapsed.as_secs_f64() * 1_000_000.0);
            Ok(())
        };
        // Compare the owned and borrowed representations in alternating order.
        if round.is_multiple_of(2) {
            timed_borrowed()?;
        }
        // Rotate the original five measurements to reduce ordering effects.
        match round % 5 {
            0 => {
                timed_query()?;
                timed_exhaustive()?;
                timed_prebuilt()?;
                timed_clone();
                timed_conversion()?;
            }
            1 => {
                timed_exhaustive()?;
                timed_prebuilt()?;
                timed_clone();
                timed_conversion()?;
                timed_query()?;
            }
            2 => {
                timed_prebuilt()?;
                timed_clone();
                timed_conversion()?;
                timed_query()?;
                timed_exhaustive()?;
            }
            3 => {
                timed_clone();
                timed_conversion()?;
                timed_query()?;
                timed_exhaustive()?;
                timed_prebuilt()?;
            }
            _ => {
                timed_conversion()?;
                timed_query()?;
                timed_exhaustive()?;
                timed_prebuilt()?;
                timed_clone();
            }
        }
        if !round.is_multiple_of(2) {
            timed_prepared()?;
            timed_borrowed()?;
        }
    }

    Ok(Row {
        documents,
        candidates: f.candidates.len(),
        authorized: reference.len(),
        trials,
        query_resource: summarize(query_samples),
        query_resource_prepared: summarize(prepared_samples),
        query_resource_prepared_borrowed: summarize(borrowed_samples),
        snapshot_preparation_us,
        borrowed_snapshot_preparation_us,
        rss_before_preparation_kib,
        rss_after_preparation_kib,
        exhaustive_authorization: summarize(exhaustive_samples),
        exhaustive_prebuilt_requests: summarize(prebuilt_samples),
        concrete_entities_clone: summarize(clone_samples),
        partial_entities_from_concrete: summarize(conversion_samples),
    })
}

/// One constructor per invocation to avoid simultaneously retaining both
/// snapshot representations. Use a fresh OS process for each measurement.
fn snapshot_memory_experiment(documents: usize, mode: &str) -> ExperimentResult<serde_json::Value> {
    let f = fixture(documents)?;
    let expected = individually_authorize(&f)?;
    let before = process_rss_kib();
    let (elapsed_us, after, allowed) = match mode {
        "owned" => {
            let start = Instant::now();
            let snapshot =
                PreparedResourceQueryEntities::new(f.entities.clone(), f.schema.clone())?;
            let elapsed_us = start.elapsed().as_secs_f64() * 1_000_000.0;
            let after = process_rss_kib();
            let allowed = query_resources_prepared(&f, &snapshot)?;
            black_box(&snapshot);
            (elapsed_us, after, allowed)
        }
        "borrowed" => {
            let start = Instant::now();
            let snapshot = BorrowedPreparedResourceQueryEntities::new(&f.entities, &f.schema)?;
            let elapsed_us = start.elapsed().as_secs_f64() * 1_000_000.0;
            let after = process_rss_kib();
            let allowed = query_resources_prepared_borrowed(&f, &snapshot)?;
            black_box(&snapshot);
            (elapsed_us, after, allowed)
        }
        _ => return Err(io::Error::other("unknown snapshot memory mode").into()),
    };
    if allowed != expected {
        return Err(io::Error::other("snapshot-memory query disagrees with reference").into());
    }
    Ok(json!({
        "snapshot_mode": mode,
        "documents": documents,
        "authorized": expected.len(),
        "snapshot_preparation_us": elapsed_us,
        "rss_before_kib": before,
        "rss_after_kib": after,
        "note": "Whole-process VmRSS, not precise object allocation",
    }))
}

fn main() -> ExperimentResult<()> {
    let args = Args::parse();
    if let Some(mode) = args.snapshot_memory_mode.as_deref() {
        if args.sizes.len() != 1 || args.sizes[0] == 0 {
            return Err(io::Error::other("snapshot memory mode needs one positive size").into());
        }
        println!(
            "{}",
            serde_json::to_string_pretty(&snapshot_memory_experiment(args.sizes[0], mode)?)?
        );
        return Ok(());
    }
    if args.trials == 0 || args.sizes.is_empty() || args.sizes.contains(&0) {
        return Err(io::Error::other("trials and all entity sizes must be positive").into());
    }

    let rows = args
        .sizes
        .into_iter()
        .map(|size| experiment(size, args.trials, args.warmups))
        .collect::<ExperimentResult<Vec<_>>>()?;
    let output = Output {
        cedar_version: cedar_policy::get_sdk_version().to_string(),
        host_arch: std::env::consts::ARCH,
        host_os: std::env::consts::OS,
        notes: "Experimental Cedar source overlay. The snapshot owns concrete and partial entities. Timings exclude data generation and schema parsing; preparation is reported separately. Linux VmRSS before and after preparation is observational whole-process resident memory, not per-snapshot allocation: it is affected by allocator reuse and earlier workload sizes. Only a flat synthetic workload is timed; no production change or database I/O.",
        rows,
    };
    println!("{}", serde_json::to_string_pretty(&output)?);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn permission_query_agrees_with_concrete_authorization() {
        for count in [1, 2, 7, 13, 100] {
            let f = fixture(count).expect("fixture construction");
            assert_eq!(
                query_resources(&f).expect("resource query"),
                individually_authorize(&f).expect("concrete baseline")
            );
        }
    }

    #[test]
    fn prepared_snapshot_matches_unprepared_query_and_authorizer() {
        for count in [1, 2, 7, 13, 100] {
            let f = fixture(count).expect("fixture");
            let prepared = PreparedResourceQueryEntities::new(f.entities.clone(), f.schema.clone())
                .expect("validated snapshot");
            let expected = individually_authorize(&f).expect("concrete authorization");
            assert_eq!(
                query_resources_prepared(&f, &prepared).expect("prepared"),
                expected
            );
            assert_eq!(query_resources(&f).expect("unprepared"), expected);
        }
    }

    #[test]
    fn snapshot_memory_modes_return_matching_authorized_counts() {
        let owned = snapshot_memory_experiment(13, "owned").expect("owned");
        let borrowed = snapshot_memory_experiment(13, "borrowed").expect("borrowed");
        assert_eq!(owned["authorized"], borrowed["authorized"]);
        assert_eq!(owned["documents"], borrowed["documents"]);
        assert!(snapshot_memory_experiment(13, "invalid").is_err());
    }

    #[test]
    fn borrowed_snapshot_matches_original_owned_and_exhaustive() {
        for count in [1, 2, 7, 13, 100] {
            let f = fixture(count).expect("fixture");
            let borrowed = BorrowedPreparedResourceQueryEntities::new(&f.entities, &f.schema)
                .expect("borrowed snapshot");
            let owned = PreparedResourceQueryEntities::new(f.entities.clone(), f.schema.clone())
                .expect("owned snapshot");
            let expected = individually_authorize(&f).expect("concrete baseline");
            assert_eq!(
                query_resources_prepared_borrowed(&f, &borrowed).expect("borrowed query"),
                expected
            );
            assert_eq!(
                query_resources_prepared(&f, &owned).expect("owned query"),
                expected
            );
            assert_eq!(query_resources(&f).expect("original query"), expected);
        }
    }

    #[test]
    fn prepared_snapshot_preserves_all_allow_all_deny_and_scoped_permissions() {
        for policy in [
            r#"permit(principal, action, resource);"#,
            r#"forbid(principal, action, resource);"#,
            r#"permit(
                principal == User::"alice",
                action == Action::"view",
                resource
            );"#,
        ] {
            let mut f = fixture(100).expect("fixture");
            f.policies = policy.parse().expect("policy syntax");
            assert!(
                Validator::new(f.schema.clone())
                    .validate(&f.policies, ValidationMode::Strict)
                    .validation_passed(),
                "policy must validate: {policy}"
            );
            let prepared = PreparedResourceQueryEntities::new(f.entities.clone(), f.schema.clone())
                .expect("snapshot");
            let expected = individually_authorize(&f).expect("concrete authorization");
            assert_eq!(
                query_resources_prepared(&f, &prepared).expect("prepared resource query"),
                expected,
                "prepared query disagrees for policy: {policy}"
            );
            assert_eq!(
                query_resources(&f).expect("original resource query"),
                expected,
                "original query disagrees for policy: {policy}"
            );
        }
    }

    #[test]
    fn incompatible_schema_is_rejected_during_snapshot_construction() {
        let f = fixture(10).expect("fixture");
        let wrong_schema = Schema::from_cedarschema_str("entity User;")
            .expect("schema syntax")
            .0;
        assert!(PreparedResourceQueryEntities::new(f.entities, wrong_schema).is_err());
    }

    #[test]
    fn hierarchy_membership_preserves_permission_queries() {
        let mut f = fixture(21).expect("base fixture");
        let (schema, _) = Schema::from_cedarschema_str(
            r#"
                entity Group;
                entity Folder;
                entity User in [Group];
                entity Document in [Folder] {
                    owner: User,
                    isPublic: Bool,
                    blocked: Bool
                };
                action view appliesTo {
                    principal: [User],
                    resource: [Document]
                };
            "#,
        )
        .expect("hierarchy schema");
        let mut entities = vec![
            json!({"uid":{"__entity":{"type":"Group","id":"reviewers"}},"attrs":{},"parents":[]}),
            json!({"uid":{"__entity":{"type":"Folder","id":"shared"}},"attrs":{},"parents":[]}),
            json!({"uid":{"__entity":{"type":"User","id":"alice"}},"attrs":{},
                "parents":[{"__entity":{"type":"Group","id":"reviewers"}}]}),
            json!({"uid":{"__entity":{"type":"User","id":"bob"}},"attrs":{},"parents":[]}),
        ];
        for i in 0..21 {
            let parents = if i % 3 == 0 {
                vec![json!({"__entity":{"type":"Folder","id":"shared"}})]
            } else {
                vec![]
            };
            entities.push(json!({
                "uid":{"__entity":{"type":"Document","id":format!("document-{i}")}},
                "attrs":{
                    "owner":{"__entity":{"type":"User","id":"alice"}},
                    "isPublic":false,
                    "blocked":i % 7 == 0
                },
                "parents":parents
            }));
        }
        f.schema = schema;
        f.entities = Entities::from_json_str(
            &serde_json::to_string(&entities).expect("entity json"),
            Some(&f.schema),
        )
        .expect("hierarchical entities");
        f.policies = r#"
            permit(
                principal in Group::"reviewers",
                action == Action::"view",
                resource in Folder::"shared"
            );
            forbid(principal, action, resource)
                when { resource.blocked };
        "#
        .parse()
        .expect("hierarchy policies");
        assert!(Validator::new(f.schema.clone())
            .validate(&f.policies, ValidationMode::Strict)
            .validation_passed());
        let prepared = PreparedResourceQueryEntities::new(f.entities.clone(), f.schema.clone())
            .expect("snapshot");
        for principal in [r#"User::"alice""#, r#"User::"bob""#] {
            f.principal = principal.parse().expect("principal");
            f.query = ResourceQueryRequest::new(
                f.principal.clone(),
                f.action.clone(),
                f.candidates[0].type_name().clone(),
                Context::empty(),
                &f.schema,
            )
            .expect("query");
            let expected = individually_authorize(&f).expect("concrete");
            assert_eq!(query_resources(&f).expect("original"), expected);
            assert_eq!(
                query_resources_prepared(&f, &prepared).expect("prepared"),
                expected
            );
            if principal == r#"User::"alice""# {
                assert!(!expected.is_empty());
                assert!(expected.len() < f.candidates.len());
            } else {
                assert!(expected.is_empty());
            }
        }
    }

    #[test]
    fn changing_request_context_does_not_reuse_old_decisions() {
        let mut f = fixture(20).expect("fixture");
        let (schema, _) = Schema::from_cedarschema_str(
            r#"
                entity User;
                entity Document {
                    owner: User,
                    isPublic: Bool,
                    blocked: Bool
                };
                action view appliesTo {
                    principal: [User],
                    resource: [Document],
                    context: { emergency: Bool }
                };
            "#,
        )
        .expect("context schema");
        f.schema = schema;
        f.policies = r#"
            permit(principal, action == Action::"view", resource)
                when { context.emergency };
            forbid(principal, action == Action::"view", resource)
                when { resource.blocked };
        "#
        .parse()
        .expect("context policies");
        assert!(Validator::new(f.schema.clone())
            .validate(&f.policies, ValidationMode::Strict)
            .validation_passed());
        let prepared = PreparedResourceQueryEntities::new(f.entities.clone(), f.schema.clone())
            .expect("prepared context snapshot");
        let mut previous = None;
        for emergency in [false, true, false] {
            let context = Context::from_json_value(
                json!({"emergency": emergency}),
                Some((&f.schema, &f.action)),
            )
            .expect("request context");
            f.query = ResourceQueryRequest::new(
                f.principal.clone(),
                f.action.clone(),
                f.candidates[0].type_name().clone(),
                context.clone(),
                &f.schema,
            )
            .expect("typed query");
            let mut allowed = BTreeSet::new();
            for candidate in &f.candidates {
                let request = Request::new(
                    f.principal.clone(),
                    f.action.clone(),
                    candidate.clone(),
                    context.clone(),
                    Some(&f.schema),
                )
                .expect("typed request");
                if Authorizer::new()
                    .is_authorized(&request, &f.policies, &f.entities)
                    .decision()
                    == Decision::Allow
                {
                    allowed.insert(candidate.clone());
                }
            }
            assert_eq!(query_resources(&f).expect("original"), allowed);
            assert_eq!(
                query_resources_prepared(&f, &prepared).expect("prepared"),
                allowed
            );
            if let Some(last) = previous {
                assert_ne!(
                    allowed, last,
                    "changing context should change allowed resources"
                );
            }
            previous = Some(allowed);
        }
    }

    #[test]
    fn changed_entity_snapshot_must_be_rebuilt() {
        let mut f = fixture(21).expect("initial fixture");
        let original_snapshot =
            PreparedResourceQueryEntities::new(f.entities.clone(), f.schema.clone())
                .expect("initial snapshot");
        let first_result =
            query_resources_prepared(&f, &original_snapshot).expect("initial prepared result");
        assert!(!first_result.is_empty());

        let mut updated = vec![
            json!({"uid":{"__entity":{"type":"User","id":"alice"}},"attrs":{},"parents":[]}),
            json!({"uid":{"__entity":{"type":"User","id":"bob"}},"attrs":{},"parents":[]}),
        ];
        for i in 0..21 {
            updated.push(json!({
                "uid":{"__entity":{"type":"Document","id":format!("document-{i}")}},
                "attrs":{
                    "owner":{"__entity":{"type":"User","id":"alice"}},
                    "isPublic":true,
                    "blocked":true
                },
                "parents":[]
            }));
        }
        f.entities = Entities::from_json_str(
            &serde_json::to_string(&updated).expect("updated JSON"),
            Some(&f.schema),
        )
        .expect("updated entities");
        let replacement = PreparedResourceQueryEntities::new(f.entities.clone(), f.schema.clone())
            .expect("replacement snapshot");
        let expected = individually_authorize(&f).expect("updated concrete authorization");
        assert!(expected.is_empty());
        assert_eq!(query_resources(&f).expect("unprepared update"), expected);
        assert_eq!(
            query_resources_prepared(&f, &replacement).expect("updated prepared"),
            expected
        );
        // The original immutable snapshot still represents the old entity data;
        // it must be replaced to observe changed authorization attributes.
        assert_eq!(
            query_resources_prepared(&f, &original_snapshot).expect("old snapshot"),
            first_result
        );
        assert_ne!(first_result, expected);
    }

    #[test]
    fn process_rss_parser_rejects_unrelated_and_invalid_lines() {
        assert_eq!(
            parse_vm_rss_kib("VmSize: 2048 kB\nVmRSS: 4096 kB\n"),
            Some(4096)
        );
        assert_eq!(parse_vm_rss_kib("VmRSS: unknown kB"), None);
        assert_eq!(parse_vm_rss_kib("VmRSS: 45 MB"), None);
        assert_eq!(parse_vm_rss_kib("VmSize: 4096 kB"), None);
    }

    #[test]
    fn timing_summary_uses_conventional_even_median() {
        let result = summarize(vec![1.0, 5.0, 2.0, 4.0]);
        assert_eq!(result.median_us, 3.0);
    }

    #[test]
    fn prebuilt_requests_match_both_existing_apis() {
        for count in [1, 7, 13, 100] {
            let f = fixture(count).expect("fixture");
            assert_eq!(
                individually_authorize_prebuilt(&f),
                individually_authorize(&f).expect("exhaustive")
            );
            assert_eq!(
                query_resources(&f).expect("resource query"),
                individually_authorize_prebuilt(&f)
            );
        }
    }

    #[test]
    fn synthetic_policy_exercises_both_outcomes() {
        let f = fixture(100).expect("fixture construction");
        let allowed = individually_authorize(&f).expect("authorization");
        assert!(!allowed.is_empty());
        assert!(allowed.len() < f.candidates.len());
    }
}
