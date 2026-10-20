#!/usr/bin/env python3
"""Apply an experimental, snapshot-owned Cedar resource-query fast path.

This is intentionally an exact-revision overlay, NOT a replacement for an
upstream Cedar PR. It only modifies the checked-out Cedar SDK for experiments.
The source-blob check makes upstream changes fail closed instead of patching an
unknown implementation.
"""

import argparse
import subprocess
from pathlib import Path

EXPECTED_BLOB = "0335586bc7d241cbd79f74f2f09c2bd7a9f7c6fd"

STRUCT = """/// An immutable, schema-validated entity snapshot for repeated resource queries.
///
/// Construction performs the same completeness check and concrete-to-partial
/// conversion as \`PolicySet::query_resource\`, but only once for the snapshot.
/// Callers cannot modify the owned entities, schema or partial representation.
/// Building a new snapshot is required after any relevant data/schema change.
#[doc = include_str!("../../experimental_warning.md")]
#[derive(Debug)]
pub struct PreparedResourceQueryEntities {
    entities: Entities,
    schema: Schema,
    partial_entities: PartialEntities,
}

impl PreparedResourceQueryEntities {
    /// Convert and validate the entity store once for repeated queries.
    pub fn new(entities: Entities, schema: Schema) -> Result<Self, PermissionQueryError> {
        schema.0.check_complete().map_err(tpe_err::TpeError::from)?;
        let partial_entities = PartialEntities::from_concrete(entities.clone(), &schema)?;
        Ok(Self {
            entities,
            schema,
            partial_entities,
        })
    }
}

"""

ORIGINAL = """        let partial_entities = PartialEntities::from_concrete(entities.clone(), schema)?;
        let tpe_response = self.tpe(&request.0, &partial_entities, schema)?;
"""
REPLACEMENT = """        let partial_entities = PartialEntities::from_concrete(entities.clone(), schema)?;
        self.query_resource_impl(request, entities, schema, &partial_entities)
    }

    /// Perform a resource permission query on a previously validated snapshot.
    ///
    /// The snapshot's owned data and schema cannot be mutated; construct a new
    /// snapshot whenever authorization-relevant entities or schema change.
    #[doc = include_str!("../../experimental_warning.md")]
    pub fn query_resource_prepared(
        &self,
        request: &ResourceQueryRequest,
        prepared: &PreparedResourceQueryEntities,
    ) -> Result<impl Iterator<Item = EntityUid>, PermissionQueryError> {
        self.query_resource_impl(
            request,
            &prepared.entities,
            &prepared.schema,
            &prepared.partial_entities,
        )
    }

    fn query_resource_impl(
        &self,
        request: &ResourceQueryRequest,
        entities: &Entities,
        schema: &Schema,
        partial_entities: &PartialEntities,
    ) -> Result<impl Iterator<Item = EntityUid>, PermissionQueryError> {
        let tpe_response = self.tpe(&request.0, partial_entities, schema)?;
"""


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("cedar_checkout", type=Path)
    args = parser.parse_args()

    source_file = args.cedar_checkout / "cedar-policy" / "src" / "api" / "tpe.rs"
    actual_blob = subprocess.check_output(
        ["git", "hash-object", str(source_file)], text=True
    ).strip()
    if actual_blob != EXPECTED_BLOB:
        raise SystemExit(
            f"Wrong Cedar SDK TPE source blob: {actual_blob}, expected {EXPECTED_BLOB}. "
            "Review upstream changes before updating this experimental overlay."
        )

    source = source_file.read_text()
    marker = "impl PolicySet {\n"
    if source.count(marker) != 1:
        raise SystemExit("Could not locate unique PolicySet implementation")
    start = source.index("    /// Perform a permission query on the resource")
    end = source.index("    /// Perform a permission query on the principal", start)
    before = source[:start]
    target = source[start:end]
    after = source[end:]
    if target.count(ORIGINAL) != 1:
        raise SystemExit("Resource query implementation does not match expected revision")
    target = target.replace(ORIGINAL, REPLACEMENT)
    if target.count("fn query_resource_impl(") != 1:
        raise SystemExit("Missing query helper after insertion")
    modified = before.replace(marker, STRUCT + marker) + target + after
    source_file.write_text(modified)
    print(f"Prepared-snapshot Cedar SDK experiment applied to {source_file}")


if __name__ == "__main__":
    main()
