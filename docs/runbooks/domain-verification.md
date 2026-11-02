# Runbook: domain verification and DNS checks

For platform operators. How the api verifies customer domains and keeps checking them, how to read the evidence, and what to do when domains look stuck, DNS is failing, ownership is contested or DKIM key material needs attention. Design: [docs/plan/steps/03-domain-onboarding.md](../plan/steps/03-domain-onboarding.md); decisions: [ADR-0017](../architecture/adr/0017-dns-resolution-strategy.md) (DNS resolution) and [ADR-0018](../architecture/adr/0018-dkim-key-custody.md) (DKIM key custody). Customer guide: [docs/domains/onboarding.md](../domains/onboarding.md). Endpoints: [docs/api/README.md](../api/README.md#domains-domains-tag-step-21).

## What runs where

Everything runs inside the **api** process; there is no separate worker.

- **Manual check:** `POST /api/v1/domains/{id}/verify` runs a fresh check (DNS cache bypassed) synchronously and returns the status view.
- **Background job:** `DomainCheckScheduler` ticks every `DOMAIN_JOBS_INTERVAL_SECONDS` (default 30) when `DOMAIN_BACKGROUND_JOBS_ENABLED=true`. Each tick:
  1. takes the tick lock `eg:jobs:domain-checks` in Redis (`SET NX`, TTL = interval − 1 s, at least 5 s); if another replica holds it, the tick is skipped. Redis down → the tick is skipped with a `warn` log;
  2. reads up to `DOMAIN_CHECK_BATCH_SIZE` (default 50) domains with `next_check_at <= now` (writer, oldest first);
  3. **claims** each one with a conditional update (`next_check_at` moves 5 minutes ahead only if nobody changed it), so two replicas never check the same domain; a domain whose check crashes is retried after the claim expires;
  4. domains of organizations that are not `active` are not checked; they are postponed by `DOMAIN_RECHECK_INTERVAL_SECONDS`;
  5. checks claimed domains with at most `DOMAIN_CHECK_CONCURRENCY` (default 4) in flight, each under the per-domain lock `eg:domains:check:<domain id>` (120 s; shared with manual checks, so a domain is never checked twice at once);
  6. retires DKIM keys whose overlap ended (up to 100 per tick);
  7. logs one line `Domain checks completed` with `due`, `claimed`, `checked`, `verified`, `failed`, `indeterminate`, `skipped`, `errors`, `retired`. Per-domain errors are logged as `Domain check failed` with `domainId`.

Several api replicas are safe: the tick lock, the conditional claim and the per-domain lock each prevent double work, and every write is state-based (audit rows and events are only written for transitions).

### Redis keys (all under the `eg:` prefix)

| Key                                           | Purpose                                        | Lifetime                      |
| --------------------------------------------- | ---------------------------------------------- | ----------------------------- |
| `jobs:domain-checks`                          | Tick lock (value = replica instance id)        | interval − 1 s                |
| `domains:check:<domain id>`                   | Per-domain check lock                          | 120 s                         |
| `domains:verify:<domain id>`                  | Manual verification counter (6 per minute)     | 60 s                          |
| `domains:rotate:<domain id>`                  | DKIM rotation counter (10 per 24 hours)        | 24 h                          |
| `rl:domains-create:<user\|api_key>:<id>`      | `POST /domains` per-caller limit (60/min)      | 60 s                          |
| `rl:domains-dkim-rotate:<user\|api_key>:<id>` | `POST /dkim/rotate` per-caller limit (30/min)  | 60 s                          |
| `dns:v1:<upstream hash>:<TXT\|MX>:<name>`     | Cached definitive DNS answers (never failures) | ≤ `DNS_CACHE_MAX_TTL_SECONDS` |

Flushing these keys is harmless: locks and counters reset, and cached answers are fetched again.

### Domains that existed before step 2.1

Migration `20261102110046_domain_check_backfill` makes every `pending_verification`, `verified`, `active` and `suspended` domain that was never scheduled (`next_check_at` NULL, e.g. the demo domain seeded before 2.1) due at once; `pnpm db:seed` also creates or re-seeds the demo domain as due. The next tick creates the missing configuration (ownership record, an RSA DKIM key, the DNS record rows) and schedules the domain like any other. Check with `SELECT name, status, next_check_at FROM domains WHERE status IN ('pending_verification','verified','active','suspended') AND next_check_at IS NULL` (expected: no rows).

### Schedule

| Domain state                                        | Next check                                                                                                                 |
| --------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------- |
| `pending_verification`                              | 1, 2, 4 … minutes (`DOMAIN_RETRY_BASE_SECONDS` × 2ⁿ) up to `DOMAIN_RETRY_MAX_SECONDS`, never after the verification expiry |
| last check indeterminate (`check_failures = k`)     | base × 2^(k−1), capped at the maximum                                                                                      |
| `verified`/`active`/`suspended`, a record not valid | `DOMAIN_RECHECK_INCOMPLETE_SECONDS` (default 30 min)                                                                       |
| `verified`/`active`/`suspended`, all records valid  | `DOMAIN_RECHECK_INTERVAL_SECONDS` (default daily)                                                                          |
| `failed`, `deleted`                                 | never (`next_check_at` NULL)                                                                                               |

Every delay gets ±10 % jitter.

## DNS resolver modes

Set in the api environment (see `.env.example`, section "Domain onboarding and DNS (step 2.1)"):

- **`DNS_RESOLVER_MODE=system`** (default): `node:dns` (c-ares) against `DNS_SERVERS` (comma list of `ip`, `ip:port`, `[ipv6]:port`), or the host's resolvers when empty. Point it at a resolver you trust: a local caching resolver (Unbound) or the VPC resolver. It cannot see TTLs of TXT/MX answers, so cached answers live at most `DNS_CACHE_NEGATIVE_TTL_SECONDS`.
- **`DNS_RESOLVER_MODE=doh`**: DNS-over-HTTPS (RFC 8484) against `DNS_DOH_URL` (`https` required outside `APP_ENV=local|ci`; URLs with credentials are refused). Independent of the platform resolver and reports TTLs, but sends customer domain names to that provider.
- **`DNS_PROPAGATION_UPSTREAMS`**: extra resolvers of the same kind (IPs in system mode, URLs in doh mode) used only to check that MX changes have propagated. Leave empty if unsure.
- **Timing:** `DNS_TIMEOUT_MS` per try, `DNS_TRIES` tries, `DOMAIN_CHECK_DEADLINE_MS` for the whole check of one domain (must be ≥ timeout × tries; queries still running at the deadline count as timeouts).

**Switching modes:** change the variables and roll the api (the configuration is validated at start-up; an invalid value stops the process with a message naming the key). Nothing in the database depends on the mode. Cache keys include the upstream, so answers of the old upstream are not reused; optionally delete `eg:dns:v1:*`. After switching, run `POST /verify` on one known-good domain and check the evidence `upstream` field (`system:<servers>` or `doh:<url>`).

DNSSEC is not validated by the gateway; it relies on the upstream (the DoH `AD` flag is recorded in evidence as `dnssecAuthenticated`).

## Reading the evidence

Each check stores what it saw, so you can explain any status without repeating the lookup:

- `domain_dns_records` (one row per record key: `verification`, `mx:<host>`, `spf`, `dkim:<selector>`, `dmarc`): `status` (last definitive result), `last_outcome` (including `indeterminate`), `last_checked_at`, `last_error` (`<reason>: <detail>` of an indeterminate result), `observed_value`, `expected_value` (for SPF and DMARC: the current recommendation), `evidence` JSON (≤ 8 KiB: `query { upstream, queriedName, outcome, reason, detail, answers, durationMs, fromCache, ttlSeconds }`, MX `propagation[]`/`propagationOutcomes`, SPF `lookupCount`/`lookupCountExact`/`records`, DMARC `stage`/`nextStep`, `warnings`).
- `domain_verifications` (current = newest row): `status`, `attempts`, `last_outcome`, `last_error`, `evidence`, `expires_at`.
- `domains`: `status`, `status_reason`, `last_checked_at`, `next_check_at`, `check_failures` (consecutive indeterminate checks).
- `domain_mx_records`: the MX hosts last seen in a definitive answer, with `points_to_gateway`.
- `audit_logs` (`resource_type = 'domain'`, `resource_id` = domain public id): every transition (`domain.verified`, `domain.claim_superseded`, `domain.verification_expired`, `domain.status_changed`, `domain.deleted`, DKIM rotation/activation/retirement, `domain.ownership_record_missing`); background actions have `actor_type = system`.
- `message_outbox` (`aggregate_type = 'domain'`, `aggregate_id` = decimal domain id, `event_type = domain.status.changed.v1`): one row per status transition. No relay publishes them yet (step 3.2).

Customers see the same information through `GET /domains/{id}/status` and `/dns-records` (support can read it under an override with `platform_admin`).

Example (writer, read-only account):

```sql
SELECT d.name, d.status, d.status_reason, d.check_failures, d.next_check_at,
       r.record_key, r.status, r.last_outcome, r.last_error, r.last_checked_at
FROM domains d JOIN domain_dns_records r ON r.domain_id = d.id
WHERE d.public_id = '<domain public id>';
```

## Stuck or indeterminate domains

- **`check_failures` keeps growing, `last_error` = `timeout: …` / `servfail: …` / `refused: …`**: the customer's DNS (or our upstream) does not answer. Nothing changes state while this lasts. Compare with an independent lookup (`dig TXT _emailgateway-verify.<domain> @<another resolver>`). If only our upstream fails, see "DNS outage" below; if the customer's authoritative servers fail, tell the customer.
- **Pending domain never verifies but `dig` shows the record**: check `observed_value` and `evidence.query.answers` of the `verification` row. Typical causes: the record was published at `_emailgateway-verify.<domain>.<domain>`, the value has extra characters, or the system resolver still caches an old negative answer (wait `DNS_CACHE_NEGATIVE_TTL_SECONDS`, or ask the customer to press verify, which bypasses the cache).
- **`next_check_at` in the past and not moving**: background jobs are off (`DOMAIN_BACKGROUND_JOBS_ENABLED`), the tick lock is held by a replica that died (it expires within the interval), or ticks fail (look for `Domain checks failed` / `Domain check failed` logs). Organizations that are not active are postponed by design.
- **`failed` with `verification_expired`**: the customer calls `POST /verify` to restart (same token). Do not change the status in the database.

## DNS outage behaviour

An upstream outage (our resolver, the DoH provider, or the network) makes lookups indeterminate. By design (ADR-0017):

- no domain changes status, no record changes status, no DKIM key changes state, no ownership is granted or revoked;
- `check_failures` increases and retries back off up to `DOMAIN_RETRY_MAX_SECONDS`;
- pending verifications still expire on time (expiry is time-based); a customer affected by a long outage simply restarts verification afterwards.

Mitigation: switch the resolver mode or `DNS_SERVERS` (see above) and roll the api. Recovery is automatic once lookups succeed.

## Contested ownership

The first organization to prove ownership owns the name (`domains.verified_name` is globally unique across `verified`, `active`, `suspended`). Other organizations' pending claims fail with `claimed_by_another_organization`, and nobody else can add the name while it is owned. Ownership is **not** revoked automatically when the TXT record disappears (the owner gets `domain.ownership_record_missing` in the audit log and a missing ownership record in the status view).

When a customer proves that a name owned by another organization belongs to them (a sold domain, a stale test account):

1. Confirm the claim out of band (ticket, proof of control of the domain — for example a TXT value you choose, published at a name you choose).
2. Start an audited platform override into the **current owner's** organization as `super_admin`, with the ticket in the reason (`POST /api/v1/platform/overrides`, MFA session).
3. If the domain is `active`, suspend it first: `PATCH /api/v1/domains/{id}/status {"status": "suspended", "reason": "Ownership dispute, ticket …"}`. Then `DELETE /api/v1/domains/{id}`. Both are audited with `metadata.override`, the name is freed and the domain's DKIM keys are revoked.
4. End the override (`DELETE /api/v1/platform/overrides/{id}`) and tell the claimant to add (or re-verify) the domain.

Never edit `domains.status` or `verified_name` by hand: `verified_name` is a generated column and the audit trail would be lost. A dedicated ownership-transfer workflow is out of scope for step 2.1.

## DKIM key custody

- Private keys are generated in the api (`node:crypto`), stored only as `domain_dkim_keys.private_key_ciphertext` (AES-256-GCM via `SecretBox` with `DATA_ENCRYPTION_KEY`, bound to `dkim:<domain public id>:<selector>`), and never logged, audited or returned. The logger redacts `privateKey`, `privateKeyPem` and `privateKeyCiphertext` fields.
- Retired and revoked keys have their ciphertext set to NULL (crypto-shredding); the public key and selector stay for history.
- In step 2.1 nothing decrypts DKIM keys yet (signing arrives with step 2.2); only the api holds `DATA_ENCRYPTION_KEY`.
- **`DATA_ENCRYPTION_KEY` rotation limits:** `SecretBox` decrypts with `DATA_ENCRYPTION_KEY_PREVIOUS` as a fallback and re-encrypts values it uses, but DKIM keys are not used (decrypted) by anything in this step and there is **no bulk re-encryption job** (deferred). After rotating the key, keep the old key in `DATA_ENCRYPTION_KEY_PREVIOUS` until every pending/active/rotating DKIM key has been re-encrypted or replaced. Removing the previous key earlier makes those keys undecryptable; the remedy is a DKIM rotation per affected domain (new keys are encrypted with the current key; the customer must publish the new selector). Count affected keys with `SELECT COUNT(*) FROM domain_dkim_keys WHERE private_key_ciphertext IS NOT NULL`.
- A suspected leak of `DATA_ENCRYPTION_KEY` means every stored DKIM key (and MFA secret) must be considered exposed: rotate the key and rotate DKIM keys of every domain.

## Deleted domains

`DELETE` is a soft delete: the row stays with `status = deleted` (name freed, checks stopped, keys revoked) for the audit trail and is purged with the organization purge (not implemented yet, see [organization deletion](organization-deletion.md)).
