# ADR-0077: Provider credential custody and encryption

**Status:** Accepted (2026-11-19, after the step 8.2 local verification against the provider simulators: the stack suite `provider-integrations` 10/10, the worker, library, api and smtp-adapter integration suites, the regression stack suites, Playwright 112/112, the 3-node RabbitMQ cluster suite on topology v14; record [docs/plan/steps/25-m365-google-connectors.md](../../plan/steps/25-m365-google-connectors.md) §13 WP6, §14; live verification against real Microsoft 365 and Google Workspace tenants, CI and a cluster apply not done). Proposed by the step 8.2 architect on 2026-11-17. Design: 25-m365-google-connectors.md D5, D17.

**Context.** Customer-owned methods require storing a Microsoft client secret or a Google service-account key; platform methods require the operator's own app secrets or keys. Access tokens are short-lived bearer credentials. The repository already encrypts webhook secrets with a dedicated AES-256-GCM key and row-bound associated data, and MFA secrets with `DATA_ENCRYPTION_KEY`.

**Decision.**

1. Customer credentials are encrypted with AES-256-GCM under a dedicated key `PROVIDER_CREDENTIAL_ENCRYPTION_KEY` (64 hex; `_PREVIOUS` decrypt-only for rotation), stored as `v1.<kid>.<iv>.<tag>.<ciphertext>` with AAD `provider-credential:v1:<organizationId>:<connectionPublicId>:<grantPublicId>:<credentialVersion>`, so a ciphertext copied to another row does not decrypt.
2. The plaintext is a strict per-method JSON document; unknown fields of uploaded service-account keys are dropped; the key's `token_uri` must equal the configured token endpoint.
3. **Custody:** the api encrypts and never decrypts; the integration-worker decrypts; any further decrypting holder is added by a later ADR (step 8.5 adds its response worker). Platform app secrets, certificates and service-account keys are held only by the workers that use them; the api holds only platform client ids.
4. Access tokens live only in process memory (bounded LRU, until 5 minutes before expiry); never in MySQL, Redis, logs, audit details, events or responses.
5. No credential is ever returned after upload; responses show a fingerprint, the set date and the declared expiry. Upload routes follow ADR-0057 (idempotent, redacted replay). Request bodies of credential routes are excluded from request logs.
6. Key rotation: the maintenance role re-encrypts grants under the previous key id in batches and reports counts; the operator then clears `_PREVIOUS`. Revocation and disconnection wipe the ciphertext.

**Consequences.** One more key to provision and rotate per deployment; credential exposure requires both the database and the worker's key. A KMS-backed key provider can replace the environment key later behind the same `kid` format.

**Alternatives considered.** Reusing `DATA_ENCRYPTION_KEY` (coupled rotation and blast radius); the 8.1 per-tenant envelope hierarchy (overkill for a handful of credentials); storing refresh tokens (no flow in 8.2 needs them).
