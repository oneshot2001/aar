"""Pages 00, 02 and 03 and the legal-map listing. Templates render verdict values and the frozen
facts verbatim; the glosses are fixed strings keyed by enum value."""

from __future__ import annotations

import platform
import sys
from pathlib import Path

from .core import file_sha256, git, media_digests, sha256_hex
from .text import visible

LIMITS_FIRST = ("custody_continuity", "legal_admissibility", "source_authenticity")

OPENING = ("This report checks specified artifact signatures, commitments and conformance rules under the supplied "
           "trust, history and evaluation-time inputs. It does not establish source truth, complete activity, camera "
           "capture time, custody or admissibility. Demo-generated narrative fields are identified below.")

LIMIT_GLOSS = {
    "custody_continuity": "receipt signatures, anchors and countersignatures do not establish custody continuity (CONFORMANCE.md:1106-1109)",
    "legal_admissibility": "the verifier establishes nothing about admissibility in any forum",
    "source_authenticity": "no sensor, device or capture truth is established",
    "technical_integrity": "structural, cryptographic, graph, policy, freshness and coverage checks under the exact inputs named",
    "discovery_completeness": "producer-declared completeness relative to signed manifest indexes, nothing more",
    "control_path_completeness": "an action dispatched around the enforcement point produces no receipt; nothing shows none occurred (D-84)",
    "input_origin_ancestry": "origin labels are relayed, not checked against prompt, retrieval or tool manifest bytes (D-78)",
    "retained_manifest_membership": "no retained epochs were supplied by a relying party for this run",
    "maximum_time_class": "receipt time evidence class; `asserted` is the producer host's own clock",
    "maximum_provenance_class": "inference provenance class; `self_asserted` is the producer's own declaration",
    "maximum_outcome_level": "`device_acknowledged` is the device's response as the producer recorded it, not an independent sensing",
    "requested_profile": "the profile the producer claimed",
    "evaluated_profile": "the profile the verifier evaluated the bundle against",
}


def page_00(facts, pick, run1, pinned, decoded, bundle, receipts, trust_policy, still_digest) -> str:
    verdict = decoded["verdict"] if decoded else None
    lines = ["# 00 — READ FIRST", "", OPENING, "", f"Specimen: `{pick['dir']}` — {facts['specimen_kind']}", ""]
    lines += ["## 1. Limits", ""]
    if verdict is None:
        lines.append(f"The verifier produced no verdict (exit {run1['exit']}); see 02-verify/run1.stderr.txt.")
    else:
        limits = verdict["limits"]
        order = [*LIMITS_FIRST, *(key for key in limits if key not in LIMITS_FIRST)]
        lines += [f"- `{key}` = `{limits[key]}` — {LIMIT_GLOSS.get(key, '')}" for key in order]
    selector = bundle["selector"]
    lines += ["", "## 2. Coverage and completeness", "",
              f"- Selector scope: tenant `{selector['tenant_id'].hex()}`, site `{selector['site_id'].hex()}`, "
              f"committed {selector['committed_from']}..{selector['committed_until']}, kinds {selector['receipt_kinds']}, "
              f"subject ids {[s.hex() for s in selector.get('subject_ids', [])]}, correlation ids "
              f"{[c.hex() for c in selector.get('correlation_ids', [])]}.",
              f"- Matching receipt count: {pinned['selector_matching_receipts']} (carried receipts: {len(receipts)}).",
              f"- Requested profile `{verdict['limits']['requested_profile'] if verdict else 'n/a'}`, evaluated profile "
              f"`{verdict['limits']['evaluated_profile'] if verdict else 'n/a'}`.",
              "- Observations emitted: " + (", ".join(f"`{o['name']}` ({'signed' if o['signed'] else 'report layer, not signed'})"
                                                   for o in pinned["observations"]) or "none") + ".",
              f"- Coverage `{bundle['coverage']}`: " + (f"{facts['coverage_sentence']}; `discovery_completeness = "
              f"{verdict['limits']['discovery_completeness']}`; ingress completeness and control-path completeness not "
              "established (CONFORMANCE.md:944)." if bundle["coverage"] == "complete" and verdict else
              "not `complete`; the coverage sentence for a complete specimen does not apply.")]
    hazard = any(r.get("body", {}).get("action", {}).get("hazard_class") == "life_safety" for r in receipts if isinstance(r.get("body", {}).get("action"), dict))
    lines += ["", "## 3. The D-66 exception", "", facts["d66_sentence"],
              f"This specimen carries `hazard_class: \"life_safety\"`: {'yes' if hazard else 'no'}. "
              f"The pinned trust policy carries a `life_safety_action_names` entry: "
              f"{'yes' if 'life_safety_action_names' in trust_policy else 'no'} (aar-core.cddl:493,1190).",
              "", "## 4. Specimen facts", ""]
    lines += [f"- **{fact['label']}** — {fact['text']} ({fact['ref']})" for fact in facts["facts"]]
    dispatch, observed = media_digests(bundle)
    lines += ["", "## 5. Media", "",
              f"Still `01-copy/{pick['still']}`, SHA-256 `{still_digest}`. Committed digests: dispatch "
              f"`target_response_body_digest` {sorted(d.hex() for d in dispatch)}; outcome-observation "
              f"`observation_commitment` {sorted(o.hex() for o in observed)}. "
              f"Equal to the still: {'yes' if dispatch | observed == {bytes.fromhex(still_digest)} else 'NO'}. "
              "Receipts carrying them: " + ", ".join(f"`{r['receipt_id'].hex()}` ({r['kind']})" for r in receipts
                                                      if r.get("kind") in ("dispatch", "outcome_observation")) + ".",
              "A recompressed derivative fails this identity test; no similarity threshold exists or will be added.",
              "", "## 6. Result", ""]
    if verdict is None:
        lines += [f"- Verifier exit `{run1['exit']}`; Result `{run1['result']}`; stderr: `{run1['stderr'].strip()}`"]
    else:
        lines += [f"- Result: `{run1['result']}` (verifier exit `{run1['exit']}`)",
                  f"- verdict_id: `{run1['verdict_id']}`",
                  f"- bundle_digest: `{run1['bundle_digest']}`",
                  f"- Evaluation time: `{pinned['evaluated_at']}`, from `01-copy/meta.json`, a producer file; the verifier "
                  "never reads a clock.",
                  "- Verifier identity for this run: the published corpus test key (`kid` "
                  f"`{pinned['verdict_kid']}`), not an operational identity. Run 3 in `02-verify/README.md` is the "
                  "examiner's own-key run."]
    lines += ["", "Prohibited claims: `appendix/prohibited-claims.md` (admissibility crosswalk section 5).",
              "", "Reading order: `01-copy/` → `02-verify/` → `03-source-and-run.md` → `04-operator-records/` → "
              "`05-text-fields.md` → `06-worksheet-902-14.md` → `07-questions.md` → `appendix/`.", ""]
    return "\n".join(lines)


def page_02(pinned, at) -> str:
    cmd = " ".join(pinned["command"])
    return f"""# 02 — verify

Producer-supplied pins and history remain producer-supplied when passed through CLI options:
`01-copy/trust-policy.json`, `01-copy/prior-state.json` and the `--at` value from `01-copy/meta.json`
are the producer's files. The verifier (pyref, Python 3.11+, standard library only) is run as a
subprocess by the packager; the packager is not part of the verifier.

## Run 1 — pinned

From the package root, with `PYTHONPATH` set to the aar checkout at the commit in
`03-source-and-run.md` (bootstrap: `git clone https://github.com/oneshot2001/aar && cd aar && git checkout <commit>`):

```
{cmd}
```

| pinned | value |
|---|---|
| exit code | `{pinned['exit']}` |
| Result | `{pinned['result']}` |
| verdict_id | `{pinned['verdict_id']}` |
| bundle_digest | `{pinned['bundle_digest']}` |
| verdict kid (corpus test key) | `{pinned.get('verdict_kid')}` |
| raw envelope | `run1.verdict.cbor` (SHA-256 `{pinned.get('verdict_cbor_sha256')}`) |
| stdout / stderr | `run1.stdout.txt` / `run1.stderr.txt` |

`run1.json` holds the same values as data.

## Run 3 — the examiner's own key

The examiner mints a chain and runs the same verifier under `--policy` and `--signing-key`.
A self-issued chain establishes key control, not the examiner's identity or the verifier's
correctness. Private keys never enter the package.

Mint (from the aar checkout; stdlib `secrets` for the scalars):

```
python3 -B -m pyref.examiner_package.mint_examiner_chain --out KEYS --at {at} \\
    --trust-policy 01-copy/trust-policy.json
```

What it does, in full: draws two P-256 scalars `1 <= d < n` with `secrets.randbelow`; writes
`KEYS/examiner-root.key` and `KEYS/examiner.key` (64 lowercase hex characters then LF, mode 0600,
created exclusively); derives each SPKI (DER, 91 bytes) and `kid = SHA-256(SPKI)`; builds a
self-signed root credential (`key_usage credential_issuing`, `principal_role authority_source`,
empty `path`) and a leaf (`key_usage verifier_signing`, `principal_role verifier`, `path =
[root credential_id]`), both `principal_type service`, `tenant_id` and `site_id` sixteen zero
bytes, `trust_anchor_id = SHA-256("AAR-EXAMINER-TRUST-ANCHOR-v1" || root kid)`,
`valid_from = {at} - 86400`, `valid_until = {at} + 30*86400` (chosen to cover the historical
`--at`; the examiner states this choice), `profile_limits` AAR-1 constants; `credential_id =
SHA-256(deterministic-CBOR(["AAR-CREDENTIAL-ID-v1", fields without credential_id]))`; signs each
with COSE_Sign1 (protected `{{1: -7, 3: "application/aar-credential+cbor;v=0.2", 4: issuer kid}}`,
detached payload, RFC 6979 ES256, low-S, P1363 r||s); orders `verifier_credentials` by
`credential_id` and `artifact_roots` by `root_kid`; writes `KEYS/examiner-policy.json` with
`v: 1`, `artifact_roots` copied from the producer's pinned `trust_store.roots` (a policy narrows
trust and never widens it: the carried credentials must still chain to a listed root),
`verifier_root_kid` and the two credential envelopes as hex; prints both kids and the policy digest
`SHA-256(deterministic-CBOR(["AAR-RP-POLICY-v1", policy]))`.

Run:

```
{cmd} --policy KEYS/examiner-policy.json --signing-key KEYS/examiner.key > run3.stdout.txt
python3 -B -m pyref.examiner_package.check_run3 --stdout run3.stdout.txt --policy KEYS/examiner-policy.json --run1 run1.json
```

The five acceptance checks (`check_run3` prints each as PASS or FAIL):

1. the verdict signature verifies under the examiner's leaf public key;
2. the leaf `kid` is the `kid` in the verdict's protected header;
3. `relying_party_policy_digest` equals the policy digest recomputed from `examiner-policy.json`;
4. `bundle_digest` equals run 1's;
5. `Result` equals run 1's.

The verdict id is not pinned: a fresh kid changes the preimage (`pyref/verdict.py:128-131`).
Independent signature check with a second tool: `check_run3` writes `run3.sig_structure.bin`,
`run3.leaf-spki.der` and `run3.signature.der` beside the stdout file; then
`openssl pkey -pubin -inform DER -in run3.leaf-spki.der -out leaf.pem && openssl dgst -sha256 -verify leaf.pem -signature run3.signature.der run3.sig_structure.bin`.

Known limit: the relying-party chain has no revocation (D-83 part 10); a compromised examiner key
can sign verdicts asserting any evaluation time inside its window.

## Run 2 — optional, harness

Stateless experiment, no history or pin inputs (`harness/verify.ts:14` accepts neither
`--prior-state` nor `--trust-policy`). It is a second implementation, never corroboration of run 1:

```
bun install --frozen-lockfile && bun run harness/verify.ts 01-copy/bundle.cbor --at {at}
```
"""


def page_03(run1, pinned, files, source_rows) -> str:
    head = git("rev-parse", "HEAD")
    tag_object = git("rev-parse", "v0.4.0")
    tag_target = git("rev-parse", "v0.4.0^{}")
    head_tree = git("rev-parse", "HEAD:pyref")
    tag_tree = git("rev-parse", "v0.4.0^{}:pyref")
    status = git("status", "--porcelain")
    executable = Path(sys.executable).resolve()
    lines = ["# 03 — source and run", "",
             "This section identifies the source that was supplied and records the claimed conditions under which it ran. "
             "It does not prove which code executed.", "",
             "## Source identifiers (labels from the build host's git)", "",
             f"- commit at package time (the declared bootstrap target): `{head}`",
             f"- tag `v0.4.0`: tag object `{tag_object}` → commit `{tag_target}`; Git object format `{git('rev-parse', '--show-object-format')}`",
             f"- `pyref/` tree at package time `{head_tree}`; at `v0.4.0` `{tag_tree}`; equal: {'yes' if head_tree == tag_tree else 'no'}"
             " (`git rev-parse COMMIT:pyref` names the stored tree, not working files; working files are hashed below).",
             f"- working tree status (`git status --porcelain`): " + (f"\n```\n{status}\n```" if status else "clean, no untracked files"),
             "- builder label: the collector named in `01-copy/acquisition.json`; verifier identity for run 1: the published "
             "corpus test key (unauthenticated labels, both).",
             "", "## Interpreter and platform", "",
             f"- `sys.executable`: `{sys.executable}` → `{executable}`, SHA-256 `{file_sha256(executable)}`",
             f"- Python `{platform.python_version()}` ({sys.version.split()[0]}, {platform.python_implementation()})",
             f"- platform: `{platform.platform()}`, machine `{platform.machine()}`",
             "", "## Exact command and inputs", "",
             f"- cwd: the package root; `PYTHONPATH`: the aar checkout at `{head}`",
             f"- `{' '.join(pinned['command'])}`",
             f"- inputs: " + "; ".join(f"`01-copy/{f['name']}` {f['byte_length']} bytes SHA-256 `{f['destination_sha256']}`" for f in files),
             f"- exit `{run1['exit']}`; stdout `02-verify/run1.stdout.txt` (SHA-256 `{sha256_hex(run1['stdout'].encode())}`); "
             f"stderr `02-verify/run1.stderr.txt` (SHA-256 `{sha256_hex(run1['stderr'].encode())}`); raw verdict envelope "
             f"`02-verify/run1.verdict.cbor` (SHA-256 `{pinned.get('verdict_cbor_sha256')}`)",
             "", "## Source inventory (working files, hashed at package time)", "",
             "| path | mode | bytes | sha256 | blob at package commit | vs v0.4.0 |", "|---|---|---|---|---|---|"]
    lines += [f"| `{r['path']}` | {r['mode']} | {r['bytes']} | `{r['sha256']}` | `{r['blob']}` | {r['vs_v0_4_0']} |" for r in source_rows]
    lines += ["", "## Offline tag check", "",
              "`git tag -v v0.4.0` needs the tag and its object closure, the tagger's SSH public key, an `allowed_signers` "
              "file naming it, and a fingerprint obtained independently of this package. It proves the tag's assertions "
              "(which commit the tagger signed) and nothing about CI execution.",
              "", "## Absent, in writing", "",
              "No release assets, no SBOM, no provenance attestation, no reproducible build (threat model R-37). "
              "Fuzz-run reports and CI history are not cited as evidence of which code ran.", ""]
    return "\n".join(lines)


def legal_maps(receipts) -> str:
    lines = ["# Receipt `legal` maps", "",
             "Each carried receipt's `legal` map, decoded. These are demo constants written by the producer; `legal_hold` "
             "is a boolean, not a hold identifier; no retention or hold record exists for this specimen.", "",
             "| receipt_id | kind | purpose_id | jurisdiction_id | data_classification_id | retention_class_id | legal_hold |",
             "|---|---|---|---|---|---|---|"]
    for r in receipts:
        legal = r.get("legal", {})
        lines.append(f"| `{r['receipt_id'].hex()}` | {r.get('kind')} | {visible(str(legal.get('purpose_id')))} | "
                     f"{visible(str(legal.get('jurisdiction_id')))} | {visible(str(legal.get('data_classification_id')))} | "
                     f"{visible(str(legal.get('retention_class_id')))} | {legal.get('legal_hold')} |")
    return "\n".join(lines) + "\n"
