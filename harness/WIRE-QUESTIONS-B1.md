# Wire questions from gate-2 slice B1

No verifier behavior below is resolved by inventing a replacement reason code.

1. **Slice-A consumption edge versus §2 step 10.** The closed positive bundle's
   `receipt-inference-requested` resolves its `consumption_manifest_id` from its
   direct observation parent, but that edge is `requested_by`, not
   `derived_from`. Step 10 literally permits only a consumption manifest carried
   by a `derived_from` parent observation (or a bundle canonical payload). The B1
   verifier accepts the direct observation parent so the required closed
   slice-A positive bundle passes. The gate should decide whether the fixture or
   the sentence is authoritative before B2 freezes graph behavior.

2. **`cose/kid-mismatch` is not independently reachable.** Mechanics select the
   credential by the protected kid. An absent credential is `key/not-found`; a
   credential whose carried key does not hash to that kid is
   `credential/kid-key-mismatch`; a valid different key reaches
   `sig/verify-failed`. Determining that some other key made the signature would
   require trying unselected keys and has no specified ordering or trust rule.

3. **`credential/algorithm-mismatch` is shadowed by payload schema.** The
   credential CDDL fixes `cose_alg` to `-7` and `curve` to `"P-256"`. Any other
   correctly typed value fails the selected closed schema first as
   `schema/enum-unknown`, before lifecycle can emit
   `credential/algorithm-mismatch`.

4. **`identity/reuse` is shadowed by bundle-array uniqueness.** Artifact arrays
   are checked at step 3 for strict primary-ID order and duplicates. Two
   nonidentical receipt envelopes carrying the same `receipt_id` therefore fail
   first as `schema/duplicate-entry`, before step 9 can classify identity reuse.

5. **Rollback fixtures require external evaluated state.**
   `identity/issuer-sequence-rollback` and
   `identity/epoch-sequence-rollback` are implemented through
   `VerifyB1Options.priorEmissions`, but no bundle-only `.cbor` mutation can
   encode that prior state. Within one bundle, observations are normatively
   sorted by sequence; reusing a coordinate is the earlier
   `identity/coordinate-equivocation` trigger.

