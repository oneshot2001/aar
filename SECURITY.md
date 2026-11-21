# Security policy

## Report a vulnerability privately

Use GitHub's private report form:
<https://github.com/oneshot2001/aar/security/advisories/new>. Please don't open a public
issue, pull request, or discussion about a security problem.

If the form isn't available to you, open a public issue that says only that you need a
private contact, with no details about the problem, and the maintainer will reach out.

Include what you found, the steps to reproduce it, and the commit or release you tested.
Use the fixture keys and synthetic data in anything you attach. Leave out real signing
keys, credentials, and live camera images or data.

## Scope

The specification and everything in this repository that implements or tests it. We want
to hear about:

- a conforming verifier returning `conformant` when a required signature, digest, or
  trust-policy check fails, or when the specification requires it to reject (for example,
  changed content under the same one-time coordinate, or a wire-ordering violation)
- a case where the specification claims a guarantee that doesn't hold

Some behavior is by design and isn't a vulnerability on its own. A verdict doesn't prove
that a signer told the truth before signing, and some re-presented or out-of-order receipts
are reported as observations rather than rejected. The README section "What a conformant
verdict proves, and what it does not" and `spec/CONFORMANCE.md` define exactly which. If
you're not sure, report it anyway.

## Rules for testing

This invitation covers the repository code and its offline fixtures. It doesn't authorize
testing any live device, service, or network.

- The test suite (`bun run test`) and the known-answer fixtures in `kats/` run offline.
  Start there.
- The live adapter suites (`adapters/vapix/live/` and `adapters/vms/live/`) ship with the
  maintainer's lab addresses. Replace those targets with your own before enabling a live
  run, and point them only at devices and systems you own, or whose owner has authorized
  the specific tests.
- Don't test against the maintainer's lab, cameras, or network.
- Resource-exhaustion testing is fine in an isolated environment you control. No
  denial-of-service against shared or third-party systems, and no social engineering.

## What to expect

One person maintains this project, so there are no guaranteed response or fix times. Each
confirmed report is assessed on its own, and fixes, mitigations, and disclosure timing are
worked out privately with the reporter.

There's no bug bounty. If an advisory is published and you want credit, you'll be credited.
