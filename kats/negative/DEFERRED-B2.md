# Negative coverage deferred to slice B2

These reason codes belong to validation steps 12 through 19 and are deliberately
outside the B1 fixture generator.

- Resource graph limits: `resource/dag-depth`, `resource/dag-width`.
- Referential closure and graph: `graph/dangling-parent`,
  `graph/parent-metadata-mismatch`, `graph/edge-illegal`, `graph/root-missing`,
  `graph/root-forbidden`, `graph/tenant-site-splice`,
  `graph/cross-epoch-forbidden`, `graph/cross-epoch-unanchored`,
  `graph/dominator-missing`, `graph/dominator-ambiguous`.
- Epoch state: `epoch/event-chain`, `epoch/id-nonmonotonic`,
  `epoch/predecessor-mismatch`, `epoch/open-close`, `epoch/duration-exceeded`,
  `epoch/span-count-mismatch`, `epoch/late-insertion`,
  `epoch/anchor-deadline`, `epoch/fork`.
- Manifest index: `manifest/index-order`, `manifest/index-gap`,
  `manifest/index-duplicate`, `manifest/index-receipt-mismatch`,
  `manifest/index-root-mismatch`.
- Merkle: `merkle/batch-binding`, `merkle/duplicate-leaf`,
  `merkle/path-length`, `merkle/root-mismatch`.
- Anchors: `anchor/target-unplanned`, `anchor/manifest-binding`,
  `anchor/inclusion-invalid`, `anchor/consistency-invalid`,
  `anchor/submission-late`, `anchor/head-missing`, `anchor/head-mismatch`,
  `anchor/head-stale`, `anchor/independence-invalid`.
- Ranges and coverage: `bundle/selector-interval`,
  `bundle/range-manifest-missing`, `bundle/range-selector-mismatch`,
  `bundle/range-noncontiguous`, `bundle/range-boundary`,
  `bundle/range-proof-invalid`, `bundle/selected-receipt-missing`,
  `bundle/coverage-overclaim`, `bundle/artifact-out-of-scope`.
- Evidence classes: `evidence/time-class-unsatisfied`,
  `evidence/provenance-class-unsatisfied`,
  `evidence/outcome-class-unsatisfied`, `evidence/observer-not-independent`.

`bundle/selector-commitment` and `bundle/dependency-missing` are not deferred;
both have B1 fixtures because steps 3 and 7 can reach them.
