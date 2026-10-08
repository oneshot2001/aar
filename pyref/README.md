# pyref offline verifier

`pyref` is the free, clean-room AAR v0.2 offline verifier. It accepts exact
deterministic-CBOR bundle bytes, runs the normative 20-step verifier, and emits
both a human-readable report and a deterministic signed W-12 verdict. It uses
Python 3.11+ standard-library code only. It opens local files, never imports a
network client, never contacts a service, and never reads the wall clock.

## Usage

```console
python -m pyref verify BUNDLE.cbor --at UNIX_SECONDS
python -m pyref verify BUNDLE.cbor --at UNIX_SECONDS \
  --trust-policy POLICY.json --prior-state PRIOR.json
```

`--at` is required and is an unsigned decimal Unix timestamp no greater than
`2^53-1`. It must equal the evaluation time committed in a well-formed bundle.
The process exits `0` only for `conformant`, `1` for `nonconformant`, `3` for
`indeterminate`, `2` for CLI/file-format errors, and `70` for an internal error.

Without `--trust-policy`, pyref validates against the trust inputs carried by
the producer in the bundle and labels them `producer-declared only`. Supplying
`--trust-policy` pins those inputs to an operator-controlled local JSON file;
the file must match the bundle values exactly, apart from evaluation time,
which always comes from `--at`.

## Trust-policy JSON

Byte strings are hexadecimal without a `0x` prefix. Arrays retain their
canonical order. The closed format is:

```json
{
  "trust_store": {
    "digest": "32-byte hex",
    "snapshot_id": "32-byte hex",
    "created_at": 7632752,
    "roots": [
      {
        "root_id": "32-byte hex",
        "root_kid": "32-byte hex",
        "tenant_id": "16-byte hex",
        "allowed_sites": ["16-byte hex"],
        "allowed_key_usages": ["credential_issuing", "ep_signing"]
      }
    ]
  },
  "expected_anchor_heads": [
    {
      "target_id": "16-byte hex",
      "observed_at": 7636534,
      "tree_size": 4,
      "root": "32-byte hex"
    }
  ],
  "verifier_policy_digest": "32-byte hex",
  "life_safety_action_names": ["camera.ptz.preset"]
}
```

`life_safety_action_names` is optional and contains at most 64 strings of 1 to
128 UTF-8 bytes. A `hazard_class="life_safety"` action marker is valid only when
its action name occurs in this bound list; if the field is absent, no marker is
accepted.

The verifier recomputes the carried trust-store digest and validates root
tenant/site/key-usage scopes, expected heads, policy digest shape, and the
explicit evaluation time. A policy file is a pin, not a way to rewrite the
bundle or its signed-verdict preimage.

## Prior-state JSON

The closed top-level keys are `prior_emissions` and `entries`; either may be
omitted and defaults to an empty array. All byte strings are hex. `entries`
must be strictly sorted and unique by deterministic CBOR of
`[replay_domain, invocation_id, content_digest]`. `prior_emissions` must also be
strictly sorted and unique by deterministic CBOR of `[issuer_kid, issuer_seq,
epoch_owner_kid, epoch_id, epoch_seq, receipt_id, envelope_digest]` with hex
strings decoded to byte strings. Unsorted or duplicate entries are usage errors.

```json
{
  "prior_emissions": [
    {
      "issuer_kid": "32-byte hex",
      "issuer_seq": 106,
      "epoch_owner_kid": "32-byte hex",
      "epoch_id": 42,
      "epoch_seq": 6,
      "receipt_id": "32-byte hex",
      "envelope_digest": "32-byte hex"
    }
  ],
  "entries": [
    {
      "replay_domain": "32-byte hex",
      "invocation_id": "16-byte hex",
      "content_digest": "32-byte hex"
    }
  ]
}
```

`prior_emissions` supplies cross-evaluation receipt identity and sequence
state, bound into the signed verdict by `prior_emissions_digest` (D-76):
`SHA-256(deterministic-CBOR(["AAR-VERDICT-PRIOR-v1", { entries: [...] }]))`,
with the seven entry fields above and hex strings decoded to byte strings.
`entries` supplies previously accepted one-time replay coordinates, bound by
`replay_state_digest`. If `--prior-state` is absent, both digests are 32 zero
bytes and the report includes `stateful_not_evaluated`: those cross-evaluation
properties were not evaluated and did not pass. Supplying even an empty file
binds the canonical empty entries map under each digest's separate domain;
omitted arrays also mean empty arrays. Verdicts use `v: 3`, with the protected
content type still `application/aar-verdict+cbor;v=0.2`.

## Schema oracle (release test, D-74)

`python3 -B -m pyref.schema_kat` validates every conformant fixture, the two
golden demo bundles, and their signed verdicts against `spec/aar-core.cddl` and
the verdict CDDL in `spec/CONFORMANCE.md`, plus the D1/D2/D4 schema probes. It
shells out to the Ruby `cddl` gem (Bormann reference implementation), pinned
at **0.12.14**; any other version, a missing engine, or a failed engine
self-test exits 1. The gem is a dev tool, not a pyref dependency:

```console
gem install --user-install json_pure -v 2.7.6   # only on system Ruby 2.6
gem install --user-install cddl -v 0.12.14
export PATH="$(ruby -e 'print Gem.user_dir')/bin:$PATH"   # optional; the runner also looks there
```

## Claim boundary

A conformant verdict proves that the carried artifacts in the signed scope
satisfied AAR v0.2's structural, cryptographic, graph, policy, freshness,
coverage, and declared evidence-class checks under the exact inputs and fixed
limits named by that verdict.

It does **not** prove sensor truth, inference correctness, lawfulness, custody,
legal admissibility, or complete discovery. In particular:

- `complete` is only producer-declared completeness relative to signed manifest
  indexes; ingress completeness remains `not_established` without an independent
  census or reconciliation artifact.
- A successful Merkle proof is membership-only. It proves neither that other
  leaves are absent nor that a set is complete.
- v0.2 commits required attestation bytes but does not deeply interpret every
  TPM, provider, or predicate format.
- `empty_scope` means a conformant evaluation matched zero receipts, so the
  verdict asserts nothing about any receipt.
- `stateful_not_evaluated` means no prior state was supplied, so sequence
  rollback and cross-evaluation one-time reuse were not evaluated.

The last two are REPORT-LAYER observations. They are shown in the report but
are intentionally absent from the signed verdict bytes; D-51 preimages, extended
by D-76, remain frozen. Other section 4 observations are signed when applicable.

The reference verdict is signed with the published Gate 4 KAT
`verifier_signing` key so its bytes remain independently reproducible. That
public test key is not an operational verifier identity and its signature must
not be treated as third-party assurance or used as a deployment credential.

The implementation-defined verifier identity preimages are stable constants:
`pyref-aar-v0.2.2-d77-signer-binding-build-v1` for `build_digest` and
`pyref-aar-v0.2-gate4-c2-fixed-conformance-config-v1` for `config_digest`.

Both verifiers report version `v0.2.2`. The harness build digest is SHA-256 of
UTF-8 `harness-aar-v0.2.2-d77-signer-binding-build-v1`; its config digest keeps
the preimage `AAR-KAT-OPAQUE-ID:verifier-config:aar-reference-verifier@0.2.0-default`.
