# Shared EP / producer

The EP owns the fresh signed request, trust-policy evaluation, durable journal,
receipt signing, DAG/manifest/range construction, local-anchor submission, and
bundle emission. Adapters receive only a secret-free command manifest and own
translation, auth injection, dispatch, and effect observation.

`dispatch_intent_persisted` is fsynced before adapter dispatch. On resume, an
unclosed intent suppresses redispatch and produces an honest `unknown` outcome.
An adapter refusal before action transport closes that intent with
`pre_transport_refusal_observed`, so a rerun remains a refusal rather than being
misclassified as crash recovery. The
`afterDispatchCut` hook is the deterministic S5 cut point for an external kill;
this is demo fault evidence, not R-31 conformance.
