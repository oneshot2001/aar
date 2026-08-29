# Shared EP / producer

The EP owns the fresh signed request, trust-policy evaluation, durable journal,
receipt signing, DAG/manifest/range construction, local-anchor submission, and
bundle emission. Adapters receive only a secret-free command manifest and own
translation, auth injection, dispatch, and effect observation.

For AAR-3, the exact signed eligible `action_attempt` envelope, receipt ID, and
envelope digest are fsynced as `action_attempt_committed` before the adapter is called.
If that append fails, the EP emits `not_dispatched` / `journal/unavailable` and
never enters either adapter. Recording the refusal in the failed journal is
best-effort. The S7 assertion can require `refusal_persisted` because its fault
is scoped to the exact command digest's `action_attempt_committed` append, so the
subsequent refusal append remains available.
`dispatch_intent_persisted` is then fsynced before adapter dispatch. On resume, an
unclosed intent suppresses redispatch and produces an honest `unknown` outcome.
An adapter refusal before action transport closes that intent with
`pre_transport_refusal_observed`, so a rerun remains a refusal rather than being
misclassified as crash recovery. The
`afterDispatchCut` hook is the deterministic S5 cut point for an external kill;
this is demo fault evidence, not R-31 conformance.
