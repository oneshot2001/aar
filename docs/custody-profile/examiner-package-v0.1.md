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
`aar/`; `--inputs` holds the two frozen inputs below; `--out` must be an absent or empty directory. The three roots
are given absolute and must resolve to at least two path components (`/` and one-component roots are refused). The
verifier is invoked as a subprocess, `python3 -B -m pyref verify …`, with the package root as cwd and
`PYTHONPATH` set to the checkout, so the recorded command is path-neutral. Exit 0 on a conformant run 1,
1 when run 1 failed (the package is still written with the failure on page 00), 2 on a missing or
malformed input, a non-empty or file `--out`, no eligible specimen, or a facts-binding failure. Nothing
is written under `--out` until the specimen rule and the facts binding both hold.

Frozen inputs (`--inputs`):

- `specimen-facts.json` — `specimen_kind`, `coverage_sentence`, `d66_sentence`, `facts: [{label, text, ref,
  ?generated_prefix}]`, `asserts` (closed keys: `no_conformant_tool_action_other_than`, a list of strings; an
  unknown key or a wrong value type is a usage error) and `verified_against`. Facts are rendered verbatim; the builder generates
  no narrative. The one `generated_prefix: "artifact_inventory"` fact is preceded by a counted inventory of
  every `artifacts` category from the decoded bundle. `asserts.no_conformant_tool_action_other_than` is
  checked against the sweep; `verified_against.bundle_digest` must equal the selected specimen's digest.
  Either failing refuses the build and names the fact: a person re-checks the facts for the new specimen,
  then updates the file.
- `acquisition.json` — the full acquisition record (absolute source paths; it stays beside the package as
  `<out>/acquisition-full.json`, never inside it). On the first build (`collection_time_utc` null) the
  builder fills `files`, `copy_method`, `tool_versions`, `collection_time_utc`, `platform` from the actual
  copy step; to reproduce byte-identically, copy `acquisition-full.json` back into `--inputs`. A filled
  record is checked against the copy (name, length, source and destination SHA-256) and kept verbatim; a
  mismatch fails the build. The distributed `01-copy/acquisition.json` carries relative identifiers
  (`<candidates>/<dir>/<file>`, `<stills>/<file>`) under roots described by label only, plus the host and
  collector labels from the input.

## Specimen rule

Every directory holding `bundle.cbor` is run under its own unchanged sidecars (`--at` =
`meta.evaluated_at`, `--trust-policy`, `--prior-state`). Kept: exit 0, and the dispatch
`target_response_body_digest` and the outcome-observation `observation_commitment` are one digest equal
to the SHA-256 of exactly one still. Ordered by `evaluated_at` descending, then `bundle_digest`; the
first entry whose `meta.camera` equals `--camera` is the specimen. `appendix/candidates.json` lists every
directory with exit code, reason (`verifier exit N: <last stderr line or Result>`, `missing sidecar: …`,
`commitments-missing`, `commitments-differ`, `still-ambiguous`, `no-exact-still-match`), matched still and
rank. Refused sidecars are never modified.

## Layout and file formats

```
00-READ-FIRST.md         limits first, coverage, D-66, specimen facts (with the artifact inventory), media identity, result
01-copy/                 bundle.cbor, meta.json, trust-policy.json, prior-state.json, the still,
                         acquisition.json (relative identifiers), inventory.json (every file but itself; unsigned)
02-verify/               README.md (runs 1, 3, 2), run1.json, run1.stdout.txt, run1.stderr.txt, run1.verdict.cbor
03-source-and-run.md     commit and tag ids, pyref tree ids, status, interpreter, platform, command, inventory
04-operator-records/     journal/anchor/chain lines, one companion .md each, legal-maps.md
05-text-fields.md        decoded-bundle traversal, invisible code points counted and escaped, undecoded bytes
05-payloads/             extracted embedded payload bytes (for access; the escrow is 01-copy/bundle.cbor)
06-worksheet-902-14.md   DRAFT; software-filled vs sworn columns
07-questions.md          the nine questions: supplied / unavailable / not collected
appendix/                candidates.json, prohibited-claims.md, text-fields-zero.md (+ identifier-sized byte strings)
```

- `run1.json`: `command` (argv with the portable `python3`), `exit`, `result`, `verdict_id`, `bundle_digest`, `selector_matching_receipts`,
  `observations [{name, signed}]`, `evaluated_at`, `evaluated_at_source`, `verdict_kid`,
  `verdict_cbor_sha256`. `run1.verdict.cbor` is the raw `[payload, COSE_Sign1]` envelope.
- `inventory.json`: `files: [{path, byte_length, sha256}]` over every distributed file except itself.
- `04-operator-records/<log>.jsonl`: the kept source lines in source order, after one stated transformation:
  each of the builder's resolved absolute root paths, where it occupies whole path segments (followed by `/`,
  a double quote, whitespace or the end of the line), is replaced by `<local>`. A log whose kept lines
  contained none is byte for byte the original; otherwise the file is an identified derivative and the
  companion lists each changed line's original and derivative SHA-256 (the operator holds the originals).
  Rules (stated in each companion): journal by carried `invocation_id` or `receipt_id`; anchor by
  `appended_at` in the selector window; chain by `ts` (ISO 8601 with an explicit offset, whole seconds) in
  the window — an offset-free `ts` is never interpreted and is listed as undated with its SHA-256. A missing
  log yields the companion only; nothing is fabricated. The anchor companion carries the frozen anchor fact
  and the pinned expected head.
- `05-text-fields.md`: envelope payloads, COSE arrays and protected headers are decoded under the artifact
  categories and the embedded `delegation`/`presentation` slots; `parameters_cbor`, `canonical_command`,
  `canonical_cbor`, `canonical_bytes` are decoded where they decode. Every other byte string is inventoried:
  16- and 32-byte strings as identifier-sized (appendix), all others as not decoded (body) with path, length
  and SHA-256. Every rendered column, paths included, goes through the same escaper. The counted set, the
  Unicode data version and the escape forms are printed in the page header; C0/C1 controls, U+2028/2029 and
  format characters outside the counted set are escaped but not counted. Rows with zero findings go to
  `appendix/text-fields-zero.md`.

## Run 3 and the examiner's key

Every command on page 02 runs from the package root with `AAR` (the checkout at the recorded commit)
and `PYTHONPATH="$AAR"` declared once; keys and every run-3 output go to `../examiner-keys/`, outside
the package. `mint_examiner_chain --keys DIR --at AT --trust-policy 01-copy/trust-policy.json` writes two
0600 key files (64 lowercase hex + LF) and `examiner-policy.json` (`v`, `artifact_roots` copied from the
producer's pinned roots, `verifier_root_kid`, two credential envelopes as hex), then loads the result
through the verifier's own `load_configuration`.

`check_run3 --keys DIR --run1 02-verify/run1.json` is a controlled invocation: it runs
`python3 -B -m pyref verify 01-copy/bundle.cbor --at <01-copy/meta.json> --trust-policy 01-copy/trust-policy.json
--prior-state 01-copy/prior-state.json --policy DIR/examiner-policy.json --signing-key DIR/examiner.key`
itself from the package root, captures the complete stdout into `DIR/run3.stdout.txt`, and checks what it
captured. It prints twelve PASS/FAIL lines: (0) the invocation exited 0, with its argv; (1) policy and key
pass `pyref.relying_party.load_configuration`; (2) signature under the examiner's leaf public key; (3) leaf
kid in the protected header; (4) policy digest recomputed; (5) `evaluated_at`, (6) `bundle_digest`,
(7) `result`, (8) the signed trust values except `relying_party_policy_digest` (the use of the pin file is
established by the controlled invocation, not by this equality), (9) `limits`, (10) `observations` equal
run 1's verdict (`run1.verdict.cbor`); (11) no report-layer `stateful_not_evaluated` / `empty_scope` /
`producer-declared only` marker in the captured stdout. With `--stdout FILE` a pasted transcript is checked
instead and the output is headed "UNVERIFIED TRANSCRIPT: the inputs used for this run are not established
by this check". It writes `run3.verdict.cbor`, `run3.sig_structure.bin`, `run3.leaf-spki.der` and
`run3.signature.der` beside the keys, never inside the package, for the printed OpenSSL re-check.
Private keys never enter the package.

## Reproducible set and tarball

Reproducible set: every distributed file except `03-source-and-run.md` (the build host's interpreter
and platform) and `01-copy/inventory.json` (it lists 03, so it varies with it). Two builds from the
same inputs are byte-identical over that set for the same CPython minor version and Unicode data
version; the `acquisition.json` inside the package derives from the input. The tarball
`examiner-package-v0.1.tar.gz` holds the package under `examiner-package-v0.1/`: entries sorted by
path, uid/gid 0, empty user and group names, mode 0644/0755, mtime = `meta.evaluated_at`, PAX format;
gzip level 9, mtime 0, no name. Two digests are written beside it for publication outside the
tarball: `examiner-package-v0.1.tar.gz.sha256` and, for the uncompressed tar bytes,
`examiner-package-v0.1.tar.sha256`. The distributed tree carries no absolute path and no machine
identity beyond the acquisition record's deliberate host label and 03's interpreter record.
Bootstrap (declared, not shipped): `git clone https://github.com/oneshot2001/aar`, check out the commit
named in `02-verify/README.md` and `03-source-and-run.md`, Python 3.11+.

## Failure behaviour

Missing input directory or file, a relative or one-component root, malformed `specimen-facts.json` (unknown
or mistyped `asserts` included), non-empty or file `--out`, no eligible specimen, a failed assert or
`verified_against` mismatch, or an acquisition record that does not match
the copy: usage error, exit 2, nothing written under `--out`. A run-1 failure on the chosen specimen:
package written with the failure on page 00, exit 1. Verifier stderr is preserved verbatim in
`02-verify/run1.stderr.txt` and in `candidates.json` reasons.
