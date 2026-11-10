# @email-gateway/sandbox

Shared pieces of the step 4.6 sandbox engine ([design](../../docs/plan/steps/14-sandbox.md) §4,
X11–X14, [ADR-0040](../../docs/architecture/adr/0040-sandbox-engine-dispatch-results-artifacts.md),
[threat model](../../docs/security/sandbox-threat-model.md)), used by the email-worker (seal
samples, verify results, map verdicts) and the sandbox-controller (open samples, seal artifacts,
compute the result MAC). Pure: `node:crypto` only, no I/O (except the ops script). Vocabularies come
from `@email-gateway/security-contracts` (`sandbox.ts`).

| Module                     | Design | Exports                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                              |
| -------------------------- | ------ | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `src/envelope/sample.ts`   | X12    | `sealSample`, `openSample`, `sampleAad`: **`sandbox-sample/1`** = `EGSBXS1` ‖ u16be header length ‖ header JSON `{ v: 1, kid, wrappedKey }` ‖ IV(12) ‖ tag(16) ‖ AES-256-GCM ciphertext; AAD `eg-sandbox-sample/v1\0<taskId>\0<sha256>`; data key wrapped under `SANDBOX_SAMPLE_KEY` (kid `k1`, SecretBox `v1.<kid>.<iv>.<tag>.<ct>`, AAD + `\0dek`); `SANDBOX_SAMPLE_KEY_PREVIOUS` opens during a rotation; sealing and opening check the plaintext SHA-256                                                                                         |
| `src/envelope/artifact.ts` | X12    | `sealArtifact` (recipient **public** key only), `openArtifact` (PKCS#8 private key), `artifactAad`: **`sandbox-artifact/1`** = `EGSBXA1` ‖ IV ‖ tag ‖ ciphertext, AAD `eg-sandbox-artifact/v1\0<taskId>\0<seq>\0<kind>`; data key wrapped with an ephemeral X25519 ECDH ↔ `SANDBOX_ARTIFACT_PUBLIC_KEY`, KEK = HKDF-SHA256(shared, salt = raw ephemeral pub ‖ raw recipient pub, info `eg-sandbox-artifact-kek/v1`), AES-256-GCM; `wrappedKey = x1.<kid>.<ephemeralPub>.<iv>.<tag>.<ct>` (≤ 256), kid = first 8 hex of SHA-256 of the recipient SPKI |
| `src/envelope/errors.ts`   |        | `SandboxEnvelopeError` (`malformed` \| `unauthentic` \| `integrity`; no detail)                                                                                                                                                                                                                                                                                                                                                                                                                                                                      |
| `src/keys.ts`              | §5     | `parseSymmetricKey`, `parseOptionalSymmetricKey`, `parseArtifactPublicKey` (X25519 SPKI DER base64url), `parseArtifactPrivateKey` (PKCS#8 DER base64url), `artifactKeyId`, `generateArtifactKeyPair`, `SandboxKeyError` (names the key, never the value)                                                                                                                                                                                                                                                                                             |
| `src/result-mac.ts`        | X11    | `sealResultToken` / `openResultToken` (one-time 32-byte token per task, `t1.<iv>.<tag>.<ct>` under `HKDF(SANDBOX_RESULT_KEY, "eg-sandbox-result/v2 seal")`, AAD `eg-sandbox-result-token/v1\0<taskId>`; only its SHA-256 is stored), `canonicalJson`, `resultMac` = hex HMAC-SHA256(`HKDF(…, "… mac")`, `"eg-sandbox-result/v2\0" ‖ tokenSha256 ‖ "\0" ‖ organizationId ‖ "\0" ‖ canonicalJson(payload without resultMac)`), `verifyResultMac` (timing-safe)                                                                                         |
| `src/analysis-key.ts`      | X13    | `analysisKey` (first 16 hex of SHA-256 over canonical `{ profile, limits, epoch, map }`), `dedupeKey` (`<sha256>:<analysisKey>`, 81 characters)                                                                                                                                                                                                                                                                                                                                                                                                      |
| `src/object-keys.ts`       | X12    | `sampleObjectKey`, `artifactKeyPrefix`, `artifactObjectKey` (`artifacts/<yyyy>/<mm>/<taskId>/<runId>/<seq>-<kind>.bin`), `newArtifactRunId` (16 hex per run), `taskIdOfSampleKey`, `parseArtifactKey`                                                                                                                                                                                                                                                                                                                                                |
| `src/verdict/map.ts`       | X14    | `SANDBOX_MAP_VERSION` (`sandbox-map/1`), `mapAnalysis` (rules F1, F2, N1, M1, S1, U1, U2, U3, C1; codes = union of the fired rules, analysis-level codes first, then severity, then name, ≤ 16; `clean` only from C1 with isolation `vm`), `aggregateSubmissions` (the round final; all skipped → `skipped`), `submissionSkipCodes`, `orderReasonCodes`                                                                                                                                                                                              |

## Ops script: `artifact:open`

No service holds the artifact private key in 4.6. To read one artifact (runbook
`docs/runbooks/sandbox-controller.md`), with the private key from the secret store in the
environment:

```bash
pnpm --filter @email-gateway/sandbox build
SANDBOX_ARTIFACT_PRIVATE_KEY=… pnpm --filter @email-gateway/sandbox artifact:open -- \
  --object ./0-static_report.bin --wrapped-key 'x1.…' --task-id <uuid> --seq 0 \
  --kind static_report --out ./static_report.json
```

The plaintext goes to `--out` (mode 0600, never overwritten, never to the terminal: artifacts are
hostile content); stdout prints only its size and SHA-256. Exit codes: 0 opened, 1 cannot open
(wrong key, ids or tampered), 2 usage or key error. The script reads `../../.env` when present
(local tests only; `.env` carries a generated test key pair).

## Tests

`pnpm --filter @email-gateway/sandbox test`: envelope round trips (empty and large), tampering of
every region, wrong ids/AAD/keys, previous-key rotation, asymmetric artifact sealing (the
public-key side cannot open), key parsing errors without values, the result MAC (status binding,
malformed MACs), analysis-key determinism, object keys, every `sandbox-map/1` rule and boundary
(exhaustive: never `clean` outside C1 with `vm`), the round aggregation in every order, the
code-set contract (every emitted code ∈ `SANDBOX_REASON_CODES` and every code reachable), the
event-contracts mirrors, and the ops script.
