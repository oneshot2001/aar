# Demo keys

Generate distinct P-256 demo keys with:

```sh
bun run demo/keys/generate.ts
```

Private keys default to `~/.aar-demo/keys/`, outside this repository, with
directory mode `0700` and file mode `0600`. The script refuses to overwrite an
existing key (`wx`). Only `public-keys.json` (SPKI and kid values) is written in
the repository and may be committed. The `outcome` key is an additional wire
role needed to sign outcome-observation receipts; `verifier-trust` is the demo
credential-issuing trust root and is not pyref's published verdict key.

Never point `--private-dir` into the repository. Defensive ignore entries exist,
but ignore rules are not a secret store.
