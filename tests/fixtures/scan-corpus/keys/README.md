# TEST-ONLY DKIM key (scan corpus)

`eg2026.clean.scan.test.private` / `.public` is an RSA-2048 key pair used **only** to sign the
scan-corpus fixtures for the reserved test domain `clean.scan.test` (selector `eg2026`) and to
ARC-seal the `arc/` fixtures for the test sealers `arc-trusted.scan.test` and
`arc-untrusted.scan.test`. The public key is published by the test DNS server `dns-sink`
(`infrastructure/dns-sink/scan.test.db`, `eg2026._domainkey.clean.scan.test`,
`eg2026._domainkey.arc-trusted.scan.test`, `eg2026._domainkey.arc-untrusted.scan.test`), which runs
only in the `smtp-test` Compose profile and in CI.

- It is not a credential: `scan.test` is a reserved name (RFC 2606/6761) that no real resolver
  serves, so a signature made with this key is never trusted outside the test stack.
- Never use it for any domain outside `scan.test`, never load it into `redis-dkim`, `rspamd-outbound` or any
  deployed environment, and never copy it into a secret store.
- The files deliberately do not use the `.pem`/`.key` extensions (git-ignored repository-wide for
  real credentials).
- Regenerating it requires re-signing the corpus (`node tests/fixtures/scan-corpus/tools/build-corpus.mjs`)
  and updating the three TXT records in `scan.test.db`.
