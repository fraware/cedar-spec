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
    Authorizer, Context, Decision, Entities, EntityUid, PartialEntities, PolicySet, Request,
    ResourceQueryRequest, Schema, ValidationMode, Validator,
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
    let reference = individually_authorize(&f)?;
    if individually_authorize_prebuilt(&f) != reference {
        return Err(io::Error::other("prepared and constructed requests disagree").into());
    }
    if query_resources(&f)? != reference {
        return Err(
            io::Error::other("query_resource disagrees with exhaustive authorization").into(),
        );
    }

    for _ in 0..warmups {
        black_box(query_resources(&f)?);
        black_box(individually_authorize(&f)?);
        black_box(individually_authorize_prebuilt(&f));
        black_box(f.entities.clone());
        black_box(PartialEntities::from_concrete(
            f.entities.clone(),
            &f.schema,
        )?);
    }

    let mut query_samples = Vec::with_capacity(trials);
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
        // Rotate all five measurements to reduce systematic ordering effects.
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
    }

    Ok(Row {
        documents,
        candidates: f.candidates.len(),
        authorized: reference.len(),
        trials,
        query_resource: summarize(query_samples),
        exhaustive_authorization: summarize(exhaustive_samples),
        exhaustive_prebuilt_requests: summarize(prebuilt_samples),
        concrete_entities_clone: summarize(clone_samples),
        partial_entities_from_concrete: summarize(conversion_samples),
    })
}

fn main() -> ExperimentResult<()> {
    let args = Args::parse();
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
        notes: "In-memory synthetic entities and fixed validated policies; no database I/O. Candidate IDs are precomputed. One exhaustive baseline constructs Requests during timing and another uses prepared Requests. The query path internally clones and converts the entity store. Conversion-only includes the concrete clone; standalone clone-only is reported separately. Timings are per complete candidate-set query or one whole-store transformation.",
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
