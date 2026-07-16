# Independent transport witness

`proxy.ts` is a minimal HTTP forward proxy. It records one append-only JSONL
entry per completed request/response: request line, response line, body hashes,
timestamp, invocation ID, command digest, and whether the attempt was
action-bearing. It deliberately does not record headers, so Digest credentials
cannot enter the log. `CONNECT` is rejected; no TLS interception is provided.

Adapters set the secret-free `X-AAR-Invocation-ID`, `X-AAR-Command-Digest`, and
`X-AAR-Action-Bearing` instrumentation headers. A Digest challenge is logged as
non-action-bearing. Each application-bearing retry is a separate action-bearing
entry; consequential automatic retries are disabled by adapter policy.
