# @email-gateway/webhooks

Shared, pure TypeScript logic of the public webhooks and security alert notifications (step 6.2,
[design note](../../docs/plan/steps/19-webhooks-notifications.md) §W2; ADR-0054–0057). It is used
by the api (registration, secrets, replays, settings), the webhook-worker (projection, delivery,
retries) and the notification-worker (alert recipients and preferences). Apps never import each
other; everything they share about webhooks lives here. No I/O: `zod` and `node:crypto` only (the
content guard comes from `@email-gateway/common`, the verdict list from
`@email-gateway/security-contracts`, policy vocabularies from `@email-gateway/event-contracts`).

| Module             | What it holds                                                                                                                                                                                                                                                        |
| ------------------ | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `catalogue.ts`     | The ten subscribable event types and `webhook.ping`, a strict `data` schema per type (`dataSchemas`), the severity rules (`eventSeverity`, `severityRank`), the catalogue served by `GET /webhooks/event-types` (`WEBHOOK_EVENT_CATALOGUE`) and one example per type |
| `envelope.ts`      | `buildEnvelope` (validates, guards, serializes once, hashes), the strict envelope schema and the deterministic `webhookEventId`                                                                                                                                      |
| `filters.ts`       | `subscriptionFiltersSchema` (directions, domainIds, minSeverity, verdicts) and `matchesSubscription`                                                                                                                                                                 |
| `signing.ts`       | `generateWebhookSecret`, `signPayload`, `signatureHeader`, `parseSignatureHeader`, `verifyWebhookSignature`                                                                                                                                                          |
| `secret-cipher.ts` | `WebhookSecretCipher` (AES-256-GCM, `v1.<kid>.<iv>.<tag>.<ct>`, previous key for rotation) and `secretAad`                                                                                                                                                           |
| `retry.ts`         | `retryDelayMs`, `parseRetryAfter`, `nextAttempt` (backoff with jitter, `Retry-After` cap, dead letter after max attempts or max age)                                                                                                                                 |
| `payload-guard.ts` | `assertWebhookPayloadSafe` (the never-content rule, below)                                                                                                                                                                                                           |
| `snippet.ts`       | `responseSnippet`: the sanitized, redacted ≤ 512-character response excerpt stored per attempt                                                                                                                                                                       |
| `notifications.ts` | Alert and preference kinds, `ALERT_RECIPIENT_PERMISSION`, the tenant settings schema with defaults and bounds (`resolveNotificationSettings`), the per-user preference schema and `alertWindowStart`                                                                 |

## Envelope

```json
{
  "id": "5f0c…-8…",
  "type": "email.quarantined",
  "version": 1,
  "occurredAt": "2026-11-13T09:14:03.120Z",
  "organizationId": "0192f0c4-7d1e-7b6a-9c55-6f3e2a1d4b10",
  "data": { "message": { … }, "quarantine": { … } }
}
```

`id` is deterministic: the first 16 bytes of SHA-256 over
`eg-webhook-event/v1\0<sourceEventId>\0<type>\0<subKey>` with the UUID version nibble set to `8`
and the RFC 9562 variant bits. A redelivered internal event therefore produces the same public id
and the same bytes; receivers deduplicate on it (it is also sent as `EG-Event-Id` and
`Idempotency-Key`). The envelope is serialized once (`JSON.stringify` of the validated object, keys
in schema order), stored, and sent byte-identically on every attempt and replay.

## Signing algorithm

- Secret: `whsec_` + base64url (no padding) of 32 CSPRNG bytes (49 characters). Shown once at
  creation or rotation; stored only encrypted (`WebhookSecretCipher`, key
  `WEBHOOK_SECRET_ENCRYPTION_KEY`: the api encrypts, the webhook-worker decrypts, nobody else holds
  it).
- Signature: lower-case hex `HMAC-SHA256(key, "<t>.<raw body>")`, where the key is the UTF-8 bytes
  of the **whole** secret string (prefix included) and `t` the Unix time in seconds.
- Header: `EG-Signature: t=<t>,v1=<hex>[,v1=<hex>]`. During a rotation overlap every request
  carries two `v1` values (current secret first); either verifies.
- Receivers: verify **before** parsing, reject `|now − t| > 300 s` (both directions), compare in
  constant time against every `v1`, accept any match (`verifyWebhookSignature` returns
  `malformed`, `stale` or `mismatch` otherwise).

```js
// Node.js receiver, node:crypto only
const { createHmac, timingSafeEqual } = require('node:crypto');
function verify(header, rawBody, secret, now = Date.now()) {
  const parts = header.split(',').map((p) => p.trim());
  const t = Number(parts.find((p) => p.startsWith('t='))?.slice(2));
  if (!Number.isInteger(t) || Math.abs(Math.floor(now / 1000) - t) > 300) return false;
  const expected = createHmac('sha256', secret).update(`${t}.`).update(rawBody).digest();
  return parts
    .filter((p) => p.startsWith('v1='))
    .map((p) => Buffer.from(p.slice(3), 'hex'))
    .some((sig) => sig.length === expected.length && timingSafeEqual(sig, expected));
}
```

## Never content

A webhook payload, stored event, attempt row, alert e-mail, log line or metric never carries a
message body, attachment content, subject, address local part, raw header (other than the
documented `internetMessageId`), S3 key, URL found in mail, secret or token (design §2.0
invariant 1). Two layers enforce it:

1. Every `data` schema is strict and models public ids, the tenant's own domain names, codes,
   counts and times only (`message.senderDomain`, `recipientDomains`: domains, never addresses).
2. `buildEnvelope` runs `assertWebhookPayloadSafe`, which refuses (with a path, never a value):
   anything the broker content guard `assertMetadataOnly` refuses (strings > 1024 characters,
   binary, MIME content, base64 blobs, too deep); the keys `subject`, `body`, `html`, `text`,
   `content`, `headers`, `rawHeaders`, `eml`, `emlS3Key`, `s3Key`, `objectKey`, `key`, `url`,
   `urls`, `address`, `addresses`, `envelopeFrom`, `headerFrom`, `recipients` (as strings),
   `filename`, `secret`, `token`, `password` at any depth; any string that looks like an address
   (except `internetMessageId`), an `org/<id>/` object key or an absolute URL; and envelopes over
   16 KiB.

Response snippets are untrusted text: sanitized and redacted by `responseSnippet`, stored and
returned as JSON strings, never rendered as HTML.

## Tests

`pnpm --filter @email-gateway/webhooks test` (unit only; no infrastructure suites).
