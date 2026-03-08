# Milestones

This document captures the project milestones that have been demonstrated so far, along with the technical boundaries that still remain.

## Milestone 1: Payload Rebuild Core Proven

Canonical statement:

> ban-grapple has demonstrated successful reconstruction of a real macOS Ventura 13.7.8 system tree from Apple payloadv2 shards via deterministic shard ordering, PBZX decode, and YAA replay.

What was demonstrated:

- Apple `payloadv2` shards were decoded in Apple-provided order using `payload_chunks.txt`
- each shard was decoded from `pbzx`
- the unified decoded stream was parsed as YAA
- the YAA stream was replayed into a concrete filesystem tree
- the result contained real macOS layout semantics and recognizable system content

Observed proof points from the completed real-data run on the external drive:

- reconstructed tree size: about `27G`
- materialized records: `356,866`
- resolved OS identity from `SystemVersion.plist`:
  - `ProductVersion`: `13.7.8`
  - `ProductBuildVersion`: `22H730`
- the tree contained real app bundles, system libraries, link structure, and macOS-shaped layout

What this milestone proves:

- shard ordering is operationally correct
- `pbzx` decode is operationally correct enough for full replay
- YAA parse and replay semantics are operationally correct enough to reconstruct the system tree
- the payload reconstruction model is causally real, not hypothetical

What this milestone does not prove:

- bootability
- exact fidelity for every metadata class
- BaseSystem integration or patch synthesis
- final image composition
- Apple boot-chain acceptance

## Milestone 2: First Metadata Fidelity Pass

After the payload rebuild proof, replay was extended to apply recorded metadata during materialization.

Implemented in this phase:

- file mode replay during extraction
- deferred directory mode replay after extraction completes
- best-effort ownership replay using `lchown(2)`
- rebuild audit command for comparing replay metadata against the realized tree

The directory-mode deferral mattered because applying restrictive directory permissions immediately during replay caused the builder to lock itself out of later children. That bug was reproduced, diagnosed, and fixed.

## Milestone 3: Audit on Metadata-Aware Rebuild

A fresh rebuild (`rebuilt-tree-v3`) was completed after the directory-mode fix and reached the same structural endpoint as the original proof run.

Observed results:

- rebuilt tree size: about `27G`
- replay records: `356,866`
- xattr sidecars accounted for: `653 / 653`
- path coverage remained structurally complete enough to compare against replay metadata
- mode mismatches dropped from `356,723` on the original replay to `10,047` on the metadata-aware replay

This proves the first fidelity pass materially improved the realized tree instead of merely changing instrumentation.

## Current Phase Boundary

The project state is now:

1. payload rebuild core: done
2. first metadata fidelity pass: done
3. replay-gap classification: in progress
4. BaseSystem integration: not done
5. image composition: not done
6. boot validation: not done

## Recommended Next Sequence

The next implementation order should remain:

1. metadata correctness
2. replay-gap classification
3. substrate integration
4. image artifact composition
5. boot validation

Inside metadata correctness, the recommended order is:

1. mode
2. uid / gid
3. timestamps
4. xattrs
5. link-edge handling

## Milestone 4: Exhaustive Broken-Symlink Causal Taxonomy

The broken-symlink audit surface was exhausted into native causal producer and substrate classes, with no unclassified remainder.

Implemented in this phase:

- native Rust classification of broken symlink causes in the rebuild audit
- conservative contract receipt output for bundle executable obligations
- native broken-symlink receipt output for causal-class inspection
- CLI reporting of causal class counts and taxonomy exhaustiveness

Observed results from the clean workstation rebuild audit:

- `replay_paths=356861`
- `actual_paths=356861`
- `missing_from_tree=0`
- `extra_in_tree=0`
- `mode_mismatches=0`
- `mode_host_artifacts=10048`
- `bundle_executable_contract_missing_producers=1939`
- broken-symlink causal taxonomy reported `exhaustive=true`

Native causal class breakdown:

- `bundle_executable_contract_missing_producer`: `1939`
- `firmware_alias_map_missing_producer`: `1131`
- `locale_alias_map_missing_producer`: `207`
- `host_root_absolute_expected_external`: `55`
- `cryptex_runtime_substrate_missing`: `48`
- `bundle_structural_alias_missing_producer`: `18`
- `cross_tree_parent_chain_missing`: `10`
- `framework_relative_alias_missing_producer`: `9`
- `bundle_contract_metadata_unavailable`: `9`
- `library_alias_missing_producer`: `8`
- `template_data_or_paired_volume_substrate_missing`: `6`
- `bundle_declared_name_mismatch`: `5`
- `private_root_substrate_missing`: `3`
- `appleinternal_expected_external`: `3`
- `data_volume_substrate_missing`: `1`
- `packaging_alias_missing_producer`: `1`
- `host_or_paired_root_substrate_missing`: `1`

This milestone proves:

- the broken-symlink audit surface is fully classified into causal producer and substrate classes
- the audit now distinguishes host artifacts, explicit producer gaps, substrate/runtime gaps, and bundle-contract obligations
- the Rust product surface reflects the causal model directly instead of relying on external one-off analysis

This milestone does not yet prove:

- final image reconstruction is complete
- bundle contract obligations have explicit materialized producers
- BaseSystem and cryptex patch composition are fully integrated into a final deployable image artifact

## Milestone 5: Acceptance-Tested Causal Audit Taxonomy

The native causal broken-symlink taxonomy is now protected by bucket-specific acceptance tests in the Rust test suite.

Implemented in this phase:

- bucket-specific acceptance coverage for representative causal classes in `src/audit.rs`
- regression coverage for conservative causal reporting and receipt generation
- native test enforcement that the audit keeps classifying representative broken symlink shapes into the intended producer and substrate buckets

Verification:

- `cargo test -- --nocapture`
- observed result: `67` tests passed, `0` failed

Representative coverage now includes:

- `bundle_executable_contract_missing_producer`
- `firmware_alias_map_missing_producer`
- `locale_alias_map_missing_producer`
- `host_root_absolute_expected_external`
- `cryptex_runtime_substrate_missing`
- `bundle_structural_alias_missing_producer`
- `cross_tree_parent_chain_missing`
- `framework_relative_alias_missing_producer`
- `bundle_contract_metadata_unavailable`
- `library_alias_missing_producer`
- `template_data_or_paired_volume_substrate_missing`
- `bundle_declared_name_mismatch`
- `private_root_substrate_missing`
- `appleinternal_expected_external`
- `data_volume_substrate_missing`
- `packaging_alias_missing_producer`
- `host_or_paired_root_substrate_missing`

This milestone proves:

- the causal audit taxonomy is now enforced behavior, not just an observed analysis result
- representative producer, substrate, and host-artifact classes are protected against regression in the Rust test suite
- the conservative audit/reporting path is acceptance-tested end to end at the classification layer

This milestone does not yet prove:

- final image reconstruction is complete
- unresolved contract classes have explicit materialized producers
- optional synthetic compatibility behavior has been designed or implemented

## Milestone 6: Deterministic Native Audit Receipts

The native rebuild audit now emits byte-for-byte deterministic JSON receipts for a fixed rebuilt tree.

Implemented in this phase:

- ordered path-set tracking for replay and actual tree coverage in `src/audit.rs`
- sorted filesystem traversal before classification
- sorted receipt and sample emission before writing audit outputs
- regression coverage for deterministic repeated audit emission

Verification:

- `cargo test -- --nocapture`
- observed result: `68` tests passed, `0` failed
- determinism regression test passed:
  - `audit_rebuild_emits_deterministic_receipts`
- live double-run hash check on the clean workstation rebuild matched exactly for:
  - `_ban_grapple_audit.json`
  - `_ban_grapple_contract_receipts.json`
  - `_ban_grapple_broken_symlink_receipts.json`

This milestone proves:

- repeated audit on the same rebuilt tree yields stable JSON bytes for the native audit and receipt outputs
- the causal audit surface is now suitable for reliable diffing, reproducible evidence capture, and future CI expectations
- receipt ordering and sample ordering are no longer dependent on filesystem iteration order or hash-set nondeterminism

This milestone does not yet prove:

- final image reconstruction is complete
- unresolved contract classes have explicit materialized producers
- optional synthetic compatibility behavior has been designed or implemented
