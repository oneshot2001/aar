# Examiner package v0.1 — documentary spec

Status: documentary, not normative. Promoted to `spec/` only after one examiner has used a package built
by this tooling. Adds no wire object, key role or verifier rule. The builder is not part of the verifier
and the verifier never validates the package's narrative.

## What it is

One directory, also shipped as a reproducible tarball, that a stranger can take, verify on their own
machine under their own key, and read without being misled. It packages one onvif-mcp specimen bundle
with the unchanged verifier's raw outputs. Every sentence on page 00 is about **this specimen**; every
producer artifact, sidecar and narrative field is labelled as a producer assertion, a demo-generated
placeholder, or an operator record.

## Builder

```
python3 -B -m pyref.examiner_package --candidates DIR --stills DIR --logs DIR --inputs DIR --out DIR [--camera q6358]
```

Python 3.11+, standard library only. `--candidates` is the producer's `receipts/aar/` (one directory per
bundle: `bundle.cbor`, `meta.json`, `trust-policy.json`, `prior-state.json`); `--stills` holds
`snap-*.jpg`; `--logs` holds `chain.jsonl`, with `journal.jsonl` and `anchor.jsonl` there or under
`aar/`; `--inputs` holds the two frozen inputs below; `--out` must be absent or empty. The verifier is
invoked as a subprocess, `python3 -B -m pyref verify …`, with the package root as cwd and `PYTHONPATH`
set to the checkout, so the recorded command is path-neutral. Exit 0 on a conformant run 1, 1 when run 1
failed (the package is still written with the failure on page 00), 2 on a missing or malformed input
(nothing partial is written beyond what preceded the error).

Frozen inputs (`--inputs`):

- `specimen-facts.json` — `specimen_kind`, `coverage_sentence`, `d66_sentence`, and `facts: [{label, text, ref}]`,
  rendered verbatim on page 00. The builder generates no narrative; a fact that stops being true of a
  new specimen must be re-checked by a person.
- `acquisition.json` — the acquisition record. On the first build (`collection_time_utc` null) the builder
  fills `files`, `copy_method`, `tool_versions`, `collection_time_utc`, `platform` from the actual copy
  step and writes the filled record into the package; to reproduce byte-identically, copy the filled
  record back into `--inputs`. A filled record is checked against the copy (name, length, source and
  destination SHA-256) and kept verbatim; a mismatch fails the build.

## Specimen rule

Every directory holding `bundle.cbor` is run under its own unchanged sidecars (`--at` =
`meta.evaluated_at`, `--trust-policy`, `--prior-state`). Kept: exit 0, and both the dispatch
`target_response_body_digest` and the outcome-observation `observation_commitment` equal the SHA-256 of
exactly one still. Ordered by `evaluated_at` descending, then `bundle_digest`; the first entry whose
`meta.camera` equals `--camera` is the specimen. `appendix/candidates.json` lists every directory with
exit code, reason (`verifier exit N: <last stderr line or Result>`, `no-exact-still-match`,
`missing sidecar: …`), matched still and rank. Refused sidecars are never modified. The build fails if
any conformant `camera.ptz.preset` candidate exists, because the frozen facts say none does.

## Layout and file formats

```
00-READ-FIRST.md         limits first, coverage, D-66, specimen facts, media identity, then the result
01-copy/                 bundle.cbor, meta.json, trust-policy.json, prior-state.json, the still,
                         acquisition.json (input), inventory.json (every file but itself; unsigned)
02-verify/               README.md (runs 1, 3, 2), run1.json, run1.stdout.txt, run1.stderr.txt, run1.verdict.cbor
03-source-and-run.md     commit and tag ids, pyref tree ids, status, interpreter, platform, command, inventory
04-operator-records/     journal/anchor/chain lines kept byte for byte, one companion .md each, legal-maps.md
05-text-fields.md        decoded-bundle traversal, invisible code points counted and escaped
05-payloads/             extracted embedded payload bytes (for access; the escrow is 01-copy/bundle.cbor)
06-worksheet-902-14.md   DRAFT; software-filled vs sworn columns
07-questions.md          the nine questions: supplied / unavailable / not collected
appendix/                candidates.json, prohibited-claims.md, text-fields-zero.md
```

- `run1.json`: `command` (argv with `python3`), `exit`, `result`, `verdict_id`, `bundle_digest`,
  `selector_matching_receipts`, `observations [{name, signed}]`, `evaluated_at`, `evaluated_at_source`,
  `verdict_kid`, `verdict_cbor_sha256`. `run1.verdict.cbor` is the raw `[payload, COSE_Sign1]` envelope.
- `inventory.json`: `files: [{path, byte_length, sha256}]` over every distributed file except itself.
- `04-operator-records/<log>.jsonl`: the kept source lines, bytes unchanged, in source order. Rules
  (stated in each companion): journal by carried `invocation_id` or `receipt_id`; anchor by
  `appended_at` in the selector window; chain by `ts` (ISO 8601 UTC, whole seconds) in the window.
  A missing log yields the companion only; nothing is fabricated.
- `05-text-fields.md`: envelope payloads, COSE arrays and protected headers are decoded under the
  artifact categories and the embedded `delegation`/`presentation` slots; `parameters_cbor`,
  `canonical_command`, `canonical_cbor`, `canonical_bytes` are decoded where they decode. The counted
  set, the Unicode data version and the escape forms are printed in the page header. Rows with zero
  findings go to `appendix/text-fields-zero.md`; opaque payloads are listed as "not decoded".

## Run 3 and the examiner's key

`python3 -B -m pyref.examiner_package.mint_examiner_chain --out KEYS --at AT --trust-policy 01-copy/trust-policy.json`
writes two 0600 key files (64 lowercase hex + LF) and `examiner-policy.json` (`v`, `artifact_roots`
copied from the producer's pinned roots, `verifier_root_kid`, two credential envelopes as hex).
`python3 -B -m pyref.examiner_package.check_run3 --stdout run3.stdout.txt --policy … --run1 02-verify/run1.json`
prints the five checks (signature under the leaf, leaf kid in the protected header, policy digest
recomputed, `bundle_digest` and `Result` equal to run 1) and writes `run3.sig_structure.bin`,
`run3.leaf-spki.der`, `run3.signature.der` for an OpenSSL re-check. Private keys never enter the package.

## Reproducible set and tarball

Two builds from the same inputs are byte-identical over: 00, 01 (`acquisition.json` is an input),
02 run-1 outputs, 03 source inventory, 04, 05, 06, 07, appendix. The tarball `examiner-package-v0.1.tar.gz`
holds the package under `examiner-package-v0.1/`: entries sorted by path, uid/gid 0, empty user and
group names, mode 0644/0755, mtime = `meta.evaluated_at`, PAX format, gzip with no name and mtime 0.
The tarball's SHA-256 is written to `<out>/examiner-package-v0.1.tar.gz.sha256` for publication outside
the tarball. Bootstrap (declared, not shipped): `git clone https://github.com/oneshot2001/aar`, check out
the commit named in `03-source-and-run.md`, Python 3.11+.

## Failure behaviour

Missing input directory or file, malformed `specimen-facts.json`, non-empty `--out`, no eligible
specimen, a conformant PTZ candidate, or an acquisition record that does not match the copy: usage error,
exit 2. A run-1 failure on the chosen specimen: package written with the failure on page 00, exit 1.
Verifier stderr is preserved verbatim in `02-verify/run1.stderr.txt` and in `candidates.json` reasons.
