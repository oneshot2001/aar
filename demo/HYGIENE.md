# Secret hygiene v2 sweep

Run after the demo, including every emitted/captured location:

```sh
bun run demo/hygiene-sweep.ts \
  --canary "$CANARY" --username "$DIGEST_USER" --realm "$DIGEST_REALM" \
  --root . \
  --root ~/.aar-demo/artifacts \
  --root /path/to/argv-env-log-temp-pcap-har-captures
```

The sweep checks the literal canary, Base64, percent-encoded form, MD5 and
SHA-256 of the literal, and both MD5 and SHA-256 Digest HA1 forms
(`H(username:realm:canary)`). It recursively scans
binary and text artifacts. Private key directories should not be included;
credential capture locations must be included. A hit exits 1 and prints only
the transform name and file path, never the secret.
