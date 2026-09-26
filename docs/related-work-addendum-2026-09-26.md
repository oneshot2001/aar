# Related-work addendum — 2026-09-26: Arcade (agent actions runtime)

Status: addendum against `v0.2.0`, dual-read (Claude + Codex, 2026-09-26).
Claims are limited to Arcade's public site and documentation as retrieved on
2026-09-26. No account was created and nothing was executed. The docs are
unversioned, so re-verify each claim before quoting it externally. This
document changes neither the v0.2 wire nor the verifier.

**Pin.** `arcade.dev` and `docs.arcade.dev`, retrieved 2026-09-26. Commercial
product, free tier, usage-priced. Pages read: homepage; About Arcade;
Governance → Audit logs, Tool executions, Contextual access → How hooks work.
Also SEP-1036 in `github.com/modelcontextprotocol/modelcontextprotocol`.

---

## A. What it is

Arcade describes itself as "the actions runtime between your agents and every
system they reach." Its documentation describes an MCP gateway, hosted tool
execution (prebuilt integrations such as Google Workspace, Slack, Microsoft
and Salesforce, plus custom tools), an OAuth broker that holds per-user tokens
so a tool runs as the end user, and a governance console.

Three documented surfaces bear on AAR:

- **Hooks.** Access (which tools a user sees), pre-execution (allow, deny, or
  modify the request), and post-execution (allow, deny, or modify the output).
  Each can be set to fail closed or fail open. A post-execution hook runs
  after the tool has run. It can filter output; it cannot prevent the action.
- **Tool-execution records.** Per run: tool, toolkit version, end user,
  status, created / scheduled / started / finished times, one entry per
  attempt with its outcome and error, and (admin-only) inputs and outputs.
  Available through the dashboard and a REST API. On Arcade Cloud, recording
  is on by default with a 7-day retention window, and it can be turned off.
  Self-hosted deployments record nothing until execution logging is enabled.
- **Audit logs.** Administrative actions (projects, API keys, gateways,
  deployments): who, how, what changed, when. Separate from tool executions.
  A REST API is provided for SIEM export.

Arcade's MCP authorship claim is concrete. SEP-1036, *URL Mode Elicitation for
secure out-of-band interactions* (Nate Barbettini, Wils Dawson; labelled
`final`), standardizes sending the user to a browser for third-party OAuth
instead of passing credentials through the MCP client. It is an
authorization-flow specification. It does not define records of actions.

## B. Where it sits relative to AAR

Arcade occupies the vantage point `docs/attestation-threat-model.md` §2 calls
**L3, the tool boundary**: "an MCP server, gateway, or Enforcement Point signs
'I was called with X and returned Y' under its own key." Arcade is such a
gateway, and it records calls with their inputs and outputs. What its
documentation does not describe is the part that turns an L3 record into
evidence:

| Property | Arcade (per public docs, 2026-09-26) | AAR v0.2 |
|---|---|---|
| Per-call record | Yes: operational log, JSON over REST | Yes: COSE-signed CBOR artifacts |
| Signed or tamper-evident | Not described | Required |
| Checkable by a third party without the vendor | Not described | `pyref`, offline, stdlib-only |
| Authorization, attempt, dispatch, outcome as separate linked records | Not described | Typed-edge DAG |
| Refusal as a record | Deny hooks exist; no refusal record described | `disposition: "not_dispatched"` with `refusal_reason` |
| Outcome graded by who observed it | Not described; the record holds the tool's returned output | `outcome-evidence-level`; `independently_sensed` requires an observer in a distinct failure domain |
| Retention | Operator-set; 7-day Cloud default; recording can be disabled | Held by whoever holds the bundle |

"Not described" means absent from the public documentation, not shown to be
absent from the product.

## C. Boundaries (do not overstate)

1. **Different problem, mostly.** Arcade governs what an agent may do and
   runs it. AAR specifies what can be proven afterward. Arcade does not claim
   to be a receipt format, and nothing here faults it for not being one.
2. **No shared domain in the pages read.** The integrations those pages
   foreground are SaaS. The tools catalog was not surveyed for physical-device
   toolkits.
3. **Docs-bound absence.** Enterprise, on-prem, or air-gapped deployments may
   carry capabilities the public docs do not describe.

## D. The plug-in point

The threat model names L3 as the strongest vantage point, which makes a
runtime of this shape a candidate producer of receipts, not a competitor to
them. Two routes, neither built nor tested:

- **The runtime signs at dispatch.** This is true L3 and requires the vendor.
  Signing existing log rows would not be enough: conformance needs the record
  cut at dispatch, typed links to the authorization and the outcome,
  anchoring, and published trust material.
- **A recorder behind the hooks.** An external service on the pre- and
  post-execution webhooks signs under its own key. That is a recorder
  observing the gateway, not the gateway attesting. The post-execution hook
  sees the tool's returned output, which is the acting system's own
  acknowledgement, not an independent observation.

Positioning line: "Runtime governance controls execution; AAR lets an
independent recipient verify exported evidence of authorization, dispatch,
and graded outcomes without the runtime."

## Disposition

CITE as the named example of an L3 gateway that governs and logs but, per its
public docs, does not attest. No dependency and no integration work planned.
Re-check the docs before any public comparison: this is the slot a runtime
vendor could move into.
