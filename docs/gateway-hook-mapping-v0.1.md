# Gateway hook → AAR record mapping, v0.1

Status: draft against `v0.2.0`, 2026-09-26. Companion to
`related-work-addendum-2026-09-26.md` §D. This document states what a recorder
sitting behind an agent-actions gateway's webhooks can and cannot truthfully
assert in AAR terms. It changes neither the v0.2 wire nor the verifier. It is
written against Arcade's published hook contract (`docs.arcade.dev` →
Governance → Contextual access → How hooks work; schema
`ArcadeAI/schemas/logic_extensions/http/1.0/schema.yaml`; retrieved
2026-09-26) because that contract is fully enumerated. The shape (access /
pre-execution / post-execution, allow-deny-modify, fail-open or fail-closed) is
shared by Kong AI Gateway plugins and agentgateway ExtProc; where the mapping
relies on something Arcade-specific it says so.

A first draft of this mapping, in `08-Agent-Output` on 2026-09-26, said
"deny at each stage = `not_dispatched`" and "post-hook output =
`device_acknowledged`". Both were wrong. This document exists to replace them.

## 0. What the recorder is

A recorder behind hooks is **L2-shaped at the gateway boundary**
(`attestation-threat-model.md` §2): a separate process with its own key that
attests what the host, here the gateway, reports. It is L3 only if the gateway
itself signs at dispatch. It is TOA's `observer` role (on-path) and never
`third_party`; in AAR terms its outcome evidence is at most
`device_acknowledged`, because the post-execution payload is the acting
system's own report. The same-operator caveat (F22) applies when the recorder
is hosted by the gateway operator.

Two facts about the hook contract drive everything below:

- **No hook payload carries a timestamp.** The recorder's clock is the only
  time source. Every time field the recorder emits means *recorded at*, never
  *occurred at*.
- **"Any denial stops the entire pipeline and the operation fails
  immediately."** So a post-execution deny happens after the tool has run.

## 1. Stage → record

| Gateway stage | Payload the recorder sees | AAR record it may emit | AAR record it must NOT emit |
|---|---|---|---|
| **Access hook** (which tools a user sees) | `user_id`, tool catalog | Nothing in the action DAG. At most a `NegotiationRecord`-style local note. | `action-attempt-body`. No action was attempted; a hidden tool is not a refused call. Cached access decisions may predate the listing that used them. |
| **Pre-execution, allow** (`code: OK`) | `execution_id`, `tool{name,toolkit,version}`, `inputs`, `user_id`, `context.authorization` (provider scopes) | An `authorization` node the recorder itself authors (role `authority_source`, with the required `delegation` envelope) whose `decision-record.evaluated_inputs` hold the gateway verdict and scope digests, then `action-attempt-body` with `disposition: "eligible_for_dispatch"`, `normalized-action.parameters_digest` over `inputs`, `authorization_id` and `decision_commitment` naming that node. `authorization_id` is required, so no attempt can be emitted without it (§4 gap 5). | `dispatch-body`. Allow at pre-exec does not mean the tool ran; a later hook or the runtime can still stop it, and later hooks see accumulated overrides. |
| **Pre-execution, deny** (`CHECK_FAILED` / `RATE_LIMIT_EXCEEDED`) | same | `action-attempt-body` with `disposition: "not_dispatched"` and `refusal_reason` carrying the code. This is the one honest `not_dispatched`. | Any claim that the gateway's execution log holds a matching record. UNVERIFIED whether Arcade records pre-denied calls. |
| **Pre-execution, modify** | same, plus overrides | `action-attempt-body` over the **modified** parameters, with the original `parameters_digest` carried in the recorder-authored authorization node's `evaluated_inputs`. | A single attempt record that silently commits to one of the two parameter sets. AAR's `decision` enum (`permit / deny / permit_with_approval`) has no `modify`; record it as `permit` over the modified action and name the gap (see §4). |
| **Post-execution, allow** | `success` bool, `execution_code`, `execution_error`, `output` | `dispatch-body` (`dispatched_at` = recorder time, `target_status` from `execution_code` when it is numeric; `target_status` is a required `uint`, so a non-numeric code means no `dispatch-body` can be emitted and the attempt stays at `eligible_for_dispatch`; `target_response_body_digest` over `output`) and `outcome-evidence.level` **graded from what was received** (§2). | `outcome-observation-body`. The recorder is not an observer in a distinct failure domain; `state: consistent` is not available to it. |
| **Post-execution, deny or modify** | same, plus the override | `dispatch-body` as above, **plus** a commitment to both the tool output and the agent-facing output, or an explicit statement of which one is committed. | `disposition: "not_dispatched"`. The action ran. Suppressing the output is not refusing the action. |
| **Hook not invoked** (`fail_open`, webhook unreachable) | nothing | A local "hook configured, not invoked" note under the recorder's own key. | Anything about the call. Silence is not allow. |
| **Dry-run mode** | full payloads, nothing enforced | Records flagged as non-governing. | Any `decision_commitment` presented as having governed the call. |

## 2. Grading the post-execution payload

`outcome-evidence-level` (`aar-core.cddl:76-82`) as seen from the hook:

| Received | Level | Why not higher |
|---|---|---|
| `success: true`, `output` present, `execution_code` a terminal success value | `device_acknowledged` | It is the acting system's report. Nobody outside it saw the effect. |
| `success: true`, `output` shows a cached, queued, or intermediary response (e.g. an HTTP 202, a broker ack) | `dispatched` | Acceptance by an intermediary is not acknowledgment by the target. |
| `success: false`, `execution_error` present | `dispatched` with the error digested into `target_response_body_digest` | The command left the gateway; the target rejected or failed it. This is not `contradicted`: no independent observer said the effect did not occur. |
| Timeout / no post-execution payload for an `execution_id` seen at pre-execution | No `dispatch-body`; the attempt stays `eligible_for_dispatch` and the recorder's epoch close note records the unmatched `execution_id`. No AAR node carries `unknown` here (`evidence/outcome-class-unsatisfied`, `CONF:544`, rejects outcome labels on the wrong kind). | The recorder cannot distinguish "never ran" from "ran, response lost". |
| Per-attempt payloads with mixed `success` | one `dispatch-body` per attempt the recorder saw; execution-level status is **not** derivable | UNVERIFIED whether the post hook fires per attempt or once for the final one. Assert only attempts seen. |

`contradicted` and `independently_sensed` are unreachable from the hook
layer by construction. They require `outcome-observation-body` from an
`outcome_observer` principal whose `observer: device-identity` is in a
different failure domain from the tool server. A gateway that wants those
grades wires a separate observer, not a bigger post-hook.

## 3. Coverage, time, authority, retention

- **Coverage.** Hooks see only calls routed through the gateway. The
  receipt set may assert "no refusal within this boundary"; it may not assert
  "no such call happened". The verifier's mandatory
  `ingress_completeness_not_established` (D-72) is the right frame.
- **Time.** All `dispatched_at` / `observed_at` values are recorder time. An
  RFC 6962 anchor on the epoch (`claim: "existence_and_order_by_time_only"`)
  bounds when the epoch existed; nothing fixes either clock.
- **Authority.** `context.authorization` carries provider OAuth scopes, not a
  signed grant. The recorder may commit to their digest in the
  `evaluated_inputs` of the authorization node it authors. It may not treat
  them as the grant: that node records what the gateway evaluated, not a
  principal's authorization, and the packet says so.
- **Retention.** Gateway execution records expire (Arcade: 7-day default, 1–90
  configurable, recording can be disabled). A receipt that outlives the record
  cannot be re-checked against the gateway, so every receipt is self-verifying
  (digest + signature) or asserts nothing after expiry. This is why the
  recorder signs at the hook rather than signing exported log rows later.
- **Admin-only fields.** `inputs` / `outputs` are admin-visible in Arcade.
  Digest them; do not copy them. Carry `system_error_message`, not
  `developer_message` or stack traces.

## 4. Gaps this exposes in AAR v0.2

Listed for the backlog, not fixed here.

1. **No `modify` / `defer` decision.** Gateways rewrite requests; CSA AARM
   R5 tests a deferral receipt. AAR's `decision` enum cannot say either.
   Candidate: extend `decision` or add a `modification_commitment` to
   `action-attempt-body`.
2. **Tool provenance.** The hook carries `tool{name,toolkit,version}`.
   `normalized-action` has `action_name` and `target_id`; there is no field
   for the tool artifact's identity or version. Carry the version string as
   an evaluated input for now; do not fabricate a binary digest from it.
3. **Two-action ontology.** `action_name` is `camera.stream.view` /
   `camera.ptz.preset`. A gateway recorder needs a profile that admits other
   action names or a registered extension point. Out of scope for a
   physical-security profile; in scope for any generic adapter.
4. **Obligation records.** Nothing in the hook layer or in AAR records an
   action that should have happened and did not. Separate design item.
5. **Attempts require an authorization node.** `authorization_id` is required
   on every attempt and `evaluated_inputs` live only in `decision-record`. A
   recorder with no upstream authorization must author one, which is honest
   only if the node is labelled as the gateway's evaluation.
6. **No rule bars a dispatch after a refusal.** The v0.2 verifier does not
   reject a `dispatch` that names a `not_dispatched` attempt (only
   `receipt/dispatch-attempt-mismatch`, `CONF:465`). Candidate negative KAT
   and verifier rule; until then the transport witness carries that proof.

## 5. What to build first

One adapter, not a framework: an HTTP webhook receiving Arcade pre- and
post-execution payloads, emitting the records in §1 under its own key, with
tests driven by recorded fixtures for: pre-allow → post-success; pre-deny;
post-deny after success; timeout (pre seen, no post); `success:false` with
retries. Coverage limits from §3 printed in the bundle's manifest. Live
traffic against Arcade's free tier only after the fixtures pass, and only to
confirm the two UNVERIFIED enum vocabularies (`execution_status`,
`execution_code`).

## Disposition

Replaces the 2026-09-26 draft mapping. Cite from `related-work-addendum-2026-09-26.md`
§D. Re-verify the hook contract before any external use; the docs are unversioned.
