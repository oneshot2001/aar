# Verifier trust provisioning: design proposal v0.1 (D-58 freeze blocker)

**Status:** PROPOSAL, 2026-10-08. Revised after two Codex passes: a
challenge pass (FIX-FIRST, 15 findings) and a re-grade (FIX-FIRST, three
new items plus clarifications). All of them are applied below. Not normative. Changes no
wire bytes, KATs, or verifier behavior. If ratified it becomes a DECISIONS
entry, a v0.3 wire change (verdict `v: 4`), and a build packet.
**Closes, if ratified:** BACKLOG freeze blocker "Verifier identity / trust
provisioning for an unrelated verifier (CONFORMANCE.md:322, D-58)" and the
first half of crosswalk gap G-C (`docs/admissibility-crosswalk-v0.1.md:371`).
**Depends on:** fixes X-1 to X-4 (section 0). They were defects in v0.2.1
as shipped and are fixed by D-77 (v0.2.2, 2026-10-08), together with the
same signer-binding gap in delegations and presentations.
**Design reference:** the Lean FRO Comparator and how the `openai/math`
release (2026-10-06) used it. See section 2.

## 0. Prerequisites: four defects in v0.2.1 found during review

The review found four defects in the current verifiers. A relying-party
ceiling is a rule about credential chains, so it would inherit all four.
They need their own decision and KATs, and they ship before this proposal.
**Status: fixed by D-77 (v0.2.2).**

| ID | Defect | Evidence | Severity |
|---|---|---|---|
| X-1 | A credential's issuance is not tied to its issuer's signature. Each credential envelope is verified with the key named in its own protected header. Nothing requires that key to equal the payload's `issuer_kid`. Path construction checks only that the declared `issuer_kid` and `subject_kid` values line up, so a credential can declare a path to an accepted root that never signed it. CONFORMANCE step 6.7 ("resolve ... through the accepted credential path") does not state the equality either. | `pyref/verifier.py:715`, `:948-956`; `harness/verifier.ts:707`, `:878-884`. Reproduced 2026-10-08 against `kats/positive/bundle-valid-subset`: both verifiers return `conformant` with credentials the root never signed. Controls reject as expected (self-declared root → `credential/root-not-accepted`; corrupted signature → `sig/verify-failed`). The forgery is now KAT `repair-d77-credential-issuer-forged`. | P1, spec + both verifiers |
| X-2 | Root `allowed_key_usages` is enforced differently. pyref checks it for credentials whose kid signs a top-level envelope or presentation; its `used_kids` omits embedded delegations (`:777`). The harness checks it only for mediator credentials. | `pyref/verifier.py:967-969`; `harness/verifier.ts:892-895`. Confirmed by code read; Codex reproduced the divergent verdicts. | P1, cross-implementation |
| X-3 | Validity of the credential that verifies each envelope is checked differently. pyref uses evaluation time with `valid_until` inclusive. The harness uses the receipt's `committed_at` for receipts (evaluation time otherwise) with `valid_until` exclusive. | `pyref/verifier.py:733`; `harness/verifier.ts:718-721` | P2, cross-implementation |
| X-4 | Duplicate producer `root_kid` records are handled differently at step-8 acceptance. pyref keeps the last record; the harness accepts any matching record. Both still check every record's scope at step 5. | `pyref/verifier.py:920`; `harness/verifier.ts:892` | P2, cross-implementation |

The X-1 fix: every credential envelope's protected kid MUST equal its
payload `issuer_kid`. A self-signed root MUST have issuer, subject, and
signing kid all equal. X-2 to X-4 each need one normative rule and both
verifiers aligned to it. **Comparator lesson P5 applies to AAR itself:** a
second implementation catches divergence only where a test exercises it.
The cross-implementation byte gate caught none of the four.

## 1. The problem

A stranger cannot check an AAR bundle under their own trust or sign the
result under their own name unless the producer cooperates. Two mechanisms
cause this.

**Trust roots are producer-declared.** Default trust (roots, anchor heads,
policy digest) arrives in `bundle.trust_inputs` (D-58 scope note). The
roots may belong to anyone, an agency for example, but the producer
chooses them. The only verifier-side control is pyref's `--trust-policy`
pin, which must match exactly (`pyref/cli.py` `_check_policy_pin`). When an
evaluation succeeds or gets past step 5, a mismatched pin is a CLI usage
error (exit 2) with no signed verdict (`pyref/cli.py:319`). For a
successful evaluation, pinned and unpinned verdicts are byte-identical.
The report prints "externally pinned" or "producer-declared only", but that
line is not in the signed bytes. Early failures do differ, because the pin
fills sentinel fields. Someone holding only a passing verdict cannot tell
whether the relying party chose the roots or accepted the producer's.

**A passing verdict requires the producer to have credentialed the
verifier.** Step 20 resolves the verifier's own kid from bundle credentials
(D-58, D-73 item 3). Step 8 requires every carried credential to chain to a
producer-declared root. So a `conformant` verdict exists only if the bundle
carries a verifier credential under a root the producer declared. Both
reference implementations sign with the published Gate 4 KAT key for
reproducibility (`pyref/README.md`). Neither has an input for any other
signing key.

In courtroom terms: a defense examiner, an AUSA's lab, or a court-appointed
expert who checks a bundle today checks it against roots the party under
examination chose, and can produce a passing signed result only with a
credential that party carried.

## 2. What the formal-math checker gets right, and where its first big user fell short

Comparator ([leanprover/comparator](https://github.com/leanprover/comparator))
accepts a machine-made Lean proof only if it proves exactly a separately
written claim ("challenge") and uses only the axioms in a fixed list
(`permitted_axioms`: `propext`, `Quot.sound`, `Classical.choice`). OpenAI's
`openai/math` release used it for its Lean-linked results. Vault review:
`06-Wiki/pages/2026-10-07-openai-math-722-manuscripts-three-model-review-summary.md`.

| # | Principle | In Comparator / `openai/math` | AAR v0.2.1 | This proposal |
|---|---|---|---|---|
| P1 | The checking side owns the trust list | Comparator treats the challenge and config as the checker's input. In `openai/math`, the lab that produced the proofs also wrote the challenges, and its catalogue marks them `review: unchecked`, `automation: agent` | Producer declares roots; verifier can only pin them | Relying party supplies its own root list |
| P2 | The list is a ceiling, not an exact match | The proof may use only listed axioms and need not use all of them | Pin is exact-match | The producer's checks run as today; the relying party's list adds a second check that must also pass |
| P3 | Small enough to audit by hand | Headline claim files run 169 B to 8.8 KB; the long tail reaches 1.43 MB and nobody will audit it | n/a | One root plus one verifier chain is the expected case; no new caps (section 3.5) |
| P4 | Frozen before the run, bound into the result | Challenge files are fixed inputs | Trust store digest is bound; who chose it is not | Policy digest bound into every verdict made under it |
| P5 | A second independent checker | `enable_nanoda: false`: no second kernel | Two verifiers plus a byte gate, which missed X-2 to X-4 | Both verifiers implement it; KATs exercise every new rule |

**Where the analogy stops.** Comparator prints pass or fail on the
operator's machine. It signs nothing and has no checker identity, so it is
no guide for the verifier-identity half (section 3.3). Established
precedent there is trust-anchor configuration owned by the relying party:
RFC 5914 (Trust Anchor Format) and Sigstore's `TrustedRoot`
(protobuf-specs). Both are cited for shape only. AAR imports neither format.

## 3. Proposal: one relying-party policy, two sections that never mix

A relying party (the operator of a verifier who is not the producer)
supplies one closed policy object out of band, plus a signing key that
never goes inside the policy. pyref keeps its convention: a JSON mirror at
the CLI, deterministic CBOR for hashing.

```cddl
; PROPOSED, v0.3 candidate. Not part of aar-core.cddl.
relying-party-policy = {
  v: 1,
  artifact_roots: [ 1*64 relying-party-root ],         ; strictly sorted, unique by root_kid
  verifier_root_kid: kid,
  verifier_credentials: [ 1*9 credential-envelope ],   ; leaf + path (credential-path 0*8);
                                                       ; strictly sorted, unique by credential_id
}

relying-party-root = {
  root_kid: kid,
  tenant_id: id16,
  allowed_sites: ids16,             ; strictly sorted, unique
  allowed_key_usages: key-usages,   ; strictly sorted, unique
}

; "Strictly sorted" means bytewise order of each element's deterministic
; CBOR encoding (or of the named key's encoding), the rule the bundle
; arrays already use.
; relying-party-policy digest = SHA-256(deterministic-CBOR([
;   "AAR-RP-POLICY-v1", relying-party-policy
; ])).
```

The relying party authorizes a key/tenant identity, not a particular
producer `root_id` record or credential issuance. That matches the current
rule, which defines no equality between `root_id` and `trust_anchor_id`
(`pyref/verifier.py:963`).

### 3.1 Configuration validation, before the bundle is read

All of these checks run before bundle decoding. Any failure is a usage
error (exit 2) with no verdict, the same class as a malformed
`--trust-policy` file today. Internal defects stay unsigned crashes under
D-61.

1. The policy decodes, matches the CDDL above, and obeys its sorting and
   uniqueness rules.
2. **Signer contract.** The operator supplies the verifier's private key,
   or a signing provider, separately from the policy. The verifier computes
   the kid of that key's public SPKI. Exactly one credential in
   `verifier_credentials` must have that `subject_kid`; that credential is
   the leaf.
3. The verifier chain passes the algorithm in section 3.3 at the `--at`
   evaluation time.

Configuration is fully known before any bundle byte is read, so every
verdict emitted under a policy, early failures included, binds the policy
digest and is signed by the policy's leaf key. That replaces only the
corresponding sentinel (CONFORMANCE §5).

### 3.2 Artifact roots (Comparator's `permitted_axioms`)

- **Producer validation is unchanged:** store digest, every producer root's
  tenant/site at step 5, and steps 6 and 8 exactly as today (after X-1 to
  X-4). The policy never removes a producer root before those checks, so
  artifact validation never loosens: a bundle that fails producer or
  artifact checks today fails them under a policy too. The one intended new
  pass is identity. A bundle with no verifier credential, which today ends
  in signed indeterminate `key/not-found` at step 20, can pass under a
  policy, because section 3.3 replaces that requirement.
- **The ceiling is a second run of the same acceptance rule against the
  relying party's list.** In step 8's per-credential root-acceptance loop,
  right after a credential passes the producer check, it must also pass:
  - **root:** its terminal root kid equals a relying-party `root_kid` whose
    `tenant_id` equals the credential's, and its `site_id` is in that
    record's `allowed_sites`. This applies to every carried credential, the
    same population as the producer check.
  - **usage:** for credentials in the signer set, `key_usage` is in that
    record's `allowed_key_usages`. The signer set is whatever the X-2 fix
    ratifies for producer roots, defined over every validated signed
    envelope, embedded delegations and presentations included.
- One relying-party record is checked against one credential. Sites and
  usages are never pooled across records.
- A failure is `credential/root-not-accepted`, or
  `countersign/credential-invalid` for a mediator credential (the existing
  mapping). No new reason code.
- A relying party can narrow trust but never widen it. That keeps D-58's
  "can pin but never add" rule.
- **Consequence, stated plainly:** narrowing the list rejects a bundle that
  carries any credential under an unlisted root, whether or not that
  credential signs anything. A relying party that wants to narrow asks the
  producer for a bundle built for its list. (The first draft tried to
  exempt unused credentials. The exemption could not deliver, because a
  self-signed root signs its own envelope, and it would have opened a gap
  around embedded delegations. It is dropped.)

### 3.3 Verifier identity (no Comparator analog)

**Chain algorithm.** It runs at configuration time, over
`verifier_credentials` only, with no fallback to the bundle:

1. Each envelope decodes as deterministic CBOR and matches the closed
   `credential-profile-object` schema, and its protected content type is
   exactly `application/aar-credential+cbor;v=0.2`.
2. Each `credential_id` recomputes (`AAR-CREDENTIAL-ID-v1`).
3. `SHA-256(public_key) == subject_kid` for each, and each key is P-256.
4. The leaf (section 3.1, item 2) has `key_usage = "verifier_signing"`,
   `principal_role = "verifier"`, and a non-empty path.
5. The leaf's path resolves, entry by entry, to exactly one credential each
   by `credential_id`. Each entry's `subject_kid` equals the previous
   `issuer_kid`, and the path has at most 8 entries. No `credential_id` and
   no `subject_kid` appears twice in the chain. Each issuer credential's own
   `path` equals the remaining suffix of the leaf's path, so the terminal
   root's path is empty.
6. Every member's envelope protected kid equals its `issuer_kid` (the X-1
   rule), and its signature verifies under that issuer's carried SPKI.
7. The terminal credential is self-signed: `subject_kid`, `issuer_kid`, and
   protected kid all equal `verifier_root_kid`.
8. Every member except the leaf has `key_usage = "credential_issuing"`.
9. Every member is valid at the evaluation time, under the boundary rule
   X-3 ratifies.
10. `verifier_credentials` is exactly the leaf plus the credentials its
    path names. No extras, so the object stays auditable.
11. Every member's `tenant_id` and `site_id` are all-zero. A verifier is
    not tenant-scoped, and a fixed visible value beats a field that
    implementations ignore and might later start checking.

**In the bundle evaluation:**

- Under a policy, step 20 does not consult bundle credentials; verifier
  identity was settled in section 3.1. A `verifier_signing` credential the
  bundle carries is an ordinary carried credential for steps 6 and 8, the
  ceiling included, and gets no special role. This supersedes D-73's
  find-first rule only when a policy is supplied.
- **Separation rule.** Two checks, using the verifier kids
  (`verifier_root_kid` plus every `subject_kid` in `verifier_credentials`):
  - Step 5, after the existing per-root tenant/site checks and before the
    evaluation-time checks: a producer root whose `root_kid` is a verifier
    kid fails with `credential/root-not-accepted`.
  - Step 8, first in the per-credential root-acceptance loop, before the
    producer check for that credential: a carried credential whose
    `subject_kid` is a verifier kid fails with
    `credential/root-not-accepted`, or `countersign/credential-invalid` for
    a mediator credential (the existing mapping). A carried
  credential cannot reach a key that does not appear as some carried
  `subject_kid`, so these two checks also block the verifier's keys from
  signing artifacts or acting as intermediates. Without this rule, a
  verifier operator could issue artifact credentials that its own verifier
  accepts. Same reasoning as `credential/role-key-reuse`.
- The verdict's protected `kid` is the leaf's `subject_kid`. An outside
  reader resolves it from the policy object, whose digest the verdict
  carries. The reader's package is bundle + policy + verdict.

### 3.4 Verdict binding (the D-76 rule applied)

Add `relying_party_policy_digest: bstr .size 32` to `verdict-trust-policy`,
set to 32 zero bytes when no policy is supplied (the D-51/D-76 absence
convention). Adding a required key to a closed map raises the verdict to
`v: 4`, as D-76 did for `v: 3`. Proposed values for the ratifying entry to
freeze: verdict content type `application/aar-verdict+cbor;v=0.3` (the
first verdict of the v0.3 line), and credential `v: 2` with content type
`application/aar-credential+cbor;v=0.2`, unchanged, because credentials do
not change.

It has to be bound because the policy can flip a result: a bundle that
passes under the producer's roots fails `credential/root-not-accepted`
under a narrower list. D-76: "A verdict that flips on an input it does not
commit to is not a complete signed statement of its own evaluation." A zero
digest means no relying-party policy object. It can coexist with the
retained exact pin.

For this mechanism, the field replaces D-58's clause that external keys
"MUST be reflected in the verdict's `config_digest`". Binding the policy
explicitly is stronger than folding it into an implementation-defined
preimage. `config_digest` keeps its current meaning.

### 3.5 What this proposal does not change

- `expected_anchor_heads`, `verifier_policy_digest`, and
  `life_safety_action_names` stay producer-declared, with the existing pin.
  Anchor heads are arguably the same P1 problem (a relying party should
  supply the heads it observed itself). That is a separate follow-up and is
  not solved here.
- The `--trust-policy` exact pin stays. It commits snapshot metadata,
  anchor heads, the policy digest, and life-safety names, which a root list
  cannot replace.
- `build_digest` and `config_digest` stay implementation-defined constants.
  The second half of G-C, proof of which code actually ran, stays open.
- No new caps. The 64-root and 8-hop limits are existing wire constants.
- D-58 policy clauses stand: a relying-party policy or verifier key is
  never sourced from, or installed into, an OS or browser trust store.
- Without a policy, evaluation outcomes and receipt and bundle bytes are
  unchanged. Verdict bytes change everywhere, because `v: 4` adds a field.

## 4. Lifting D-58's objection to a trust file format

D-58 rejected "defining a trust-bundle file format now" because a normative
surface with no corpus coverage gets improvised differently by two
clean-room implementations (the D-56/D-57 failure shape). X-2 to X-4 show
that this happens even on surfaces that already exist. This proposal lifts
the objection only if all of the following ship together:

1. CDDL in `spec/aar-core.cddl`, gated by the D-74 oracle.
2. Both verifiers implement sections 3.1 to 3.4.
3. Verdict KATs:
   - positive: relying-party list is a strict subset of producer roots, and
     the bundle passes;
   - positive: verifier credentialed only by the relying party, with no
     verifier credential in the bundle;
   - negative: a carried credential under a producer root missing from the
     list → `credential/root-not-accepted` (step 8);
   - negative: same, for a mediator credential →
     `countersign/credential-invalid`;
   - negative, one KAT per signer category: the usage is missing from the
     relying-party record for an ordinary EP signer, a rotation issuer, a
     status-snapshot issuer, and an embedded-delegation signer →
     `credential/root-not-accepted`;
   - negative: a producer root equals `verifier_root_kid` (step 5); a
     carried credential reuses a verifier kid (step 8); the same for a
     mediator credential → `countersign/credential-invalid`;
   - flip pair: same bundle, one relying-party site removed → the result
     flips and `relying_party_policy_digest` differs;
   - early failure under a policy: step-1, step-2, and step-3 failure
     verdicts carry the policy digest and the leaf kid, alone and combined
     with the retained pin and with supplied replay and prior state;
   - order pairs (D-54): ceiling rejection combined with a bad signature
     (step 6 wins), with an invalid path, with role-key reuse, and with a
     revoked status snapshot (step-8 internal order); separation rejection
     combined with a step-5 digest failure and a step-8 path failure.
4. CLI tests for section 3.1: malformed policy, unsorted policy arrays,
   signing key not matching any leaf, expired leaf, `valid_until`
   boundary, broken path, issuer path not matching the suffix, duplicate
   intermediate `subject_kid`, wrong protected content type, extra
   credential, non-self-signed terminal, non-zero tenant. Each exits 2 with
   no verdict.
5. The cross-implementation byte gate covers every verdict KAT above.
6. Verdict KATs regenerated for `v: 4`.

## 5. What a pass will and will not mean

**Will:** every carried credential chains, by issuer signatures (after
X-1), to a root the relying party listed, within the sites and usages it
allowed. A key the relying party credentialed signed the verdict. The
signed bytes bind both facts.

**Will not:**
- Show that the relying party listed the right roots. Confirming a root kid
  out of band (an agency confirming its root in writing) is a human step.
  Comparator has the same limit: a pass shows the proof matches the claim,
  not that the claim is the one that matters.
- Show which verifier code ran (G-C, second half).
- Show that the verifier operator is independent of the producer. Key
  separation keeps their roots apart; it says nothing about who runs them.
- Count as a FRE 902(13) certification. A person certifies; a verdict is
  an exhibit to that certification (crosswalk §2).
- Change any `limits` value. `custody_continuity` and `legal_admissibility`
  stay `not_established`.

## 6. Decisions this note makes

| Gap | Choice | Alternative | Consequence |
|---|---|---|---|
| How the relying party's list combines with producer roots | Second acceptance check after producer checks (ceiling) | Replace the producer store, or filter it before validation | A failing bundle can never pass under a policy. The relying party cannot trust a root the producer did not declare. |
| Which credentials the ceiling covers | Root check on every carried credential; usage check on the signer set | Exempt unused credentials | One rule, the same population as today. Narrowing can reject bundles over credentials nothing uses. |
| Where the verifier's identity is anchored | A separate self-signed root that signs only verifier chains | Reuse an artifact root with `verifier_signing` usage | Blocks self-dealing (section 3.3). Costs one field. |
| When the verifier chain is checked | At configuration time; failure is a usage error with no verdict | At step 20, as a signed `key/not-found` | A verifier that cannot vouch for its own key signs nothing, early failures included. Every policy-mode verdict binds the digest. |
| Bundle-carried verifier credentials under a policy | Ordinary carried credentials, never resolved for step 20 | Find-first across bundle and policy (D-73) | The producer cannot pre-empt the verifier's identity. Without a policy, D-73 holds. |
| Tenant and site on verifier credentials | MUST be all-zero | Present but ignored | Visible and checkable. A future tenant-scoped verifier needs a new decision. |
| Verdict field | Required digest, zero when absent, `v: 4`; replaces the `config_digest` reflection for this mechanism | Optional key; reflect via `config_digest` | Same shape as D-51/D-76. A reader sees the policy digest directly. |
| Reason codes | Reuse `credential/root-not-accepted`, `countersign/credential-invalid` | New codes such as `policy/root-not-listed` | No new code surface. The digest shows that a policy applied; it does not say which root check rejected. The report layer names it. |
| Q1 (from the first draft): result class when the policy rejects | `nonconformant` | `indeterminate` | An explicit rejection under a supplied policy is not missing input. CONFORMANCE §5 already makes `conformant` relative to the bound policy. |

## 7. Open questions for ratification

- **Q2.** Revocation of a relying-party verifier credential (for example, an
  examiner's key compromised) has no status mechanism here, only the
  validity window. Is that enough for v0.3, or does the policy carry a
  status snapshot?
- **Q5.** A relying party with one root serving two tenants needs two
  records with the same `root_kid`, which the uniqueness rule forbids. Keep
  one tenant per root for v0.3?

## 8. Build sequence if ratified

0. X-1 to X-4: one DECISIONS entry, CONFORMANCE text, both verifiers, KATs
   including the X-1 forgery. This ships first and on its own.
1. Claude: DECISIONS entry for this proposal, CONFORMANCE steps 5, 8 and 20
   plus §5, and CDDL. This is the spec pass. Freeze blockers never run in
   the night loop.
2. Codex: harness and pyref implementation, KATs, CLI tests, byte gate (one
   spec-complete packet).
3. Claude: reviewer gate, then a Codex finding pass on the diff.
4. pyref README: document the policy JSON and the signing-key input. The
   Gate 4 KAT key stays the corpus verifier, and a relying-party KAT key is
   added for section 4.
