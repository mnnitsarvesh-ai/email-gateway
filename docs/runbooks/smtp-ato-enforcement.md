# Runbook: SMTP account takeover enforcement and telemetry (smtp-adapter)

For platform operators. Step 8.4 ([design](../plan/steps/24-account-takeover-core.md) D4, D14, D19; [ADR-0073](../architecture/adr/0073-ato-enforcement-smtp-and-policy-facts.md)). The smtp-adapter enforces two kinds of temporary ATO restriction that the ATO store (ato-worker automation or an approved analyst action) writes into `ato_smtp_restrictions`, and it records SASL and submission telemetry for ATO detection. Code and configuration: [apps/smtp-adapter/README.md](../../apps/smtp-adapter/README.md#account-takeover-telemetry-and-enforcement-step-84).

| Restriction  | Scopes                                   | Where it is checked                                                                    | What the client sees                                                                                                                                                                                                                                        |
| ------------ | ---------------------------------------- | -------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `send_block` | `mailbox` (envelope sender), `connector` | Policy service, contexts `submission` (587) and `relay` (25 with a connector), at RCPT | mode `reject`: `554 5.7.1 … Sending temporarily restricted by security policy` (Postfix's default `access_map_reject_code`); mode `defer`: `450 4.7.1 … Sending temporarily restricted by security policy, try again later` (the tenant MTA keeps the mail) |
| `auth_block` | `connector`, `connector_ip` (CIDR)       | SASL server, after the connector lookup and before the secret is verified              | `535 5.7.8 Error: authentication failed` (the same as a wrong password, after `SMTP_AUTH_FAILURE_DELAY_MS`); the client IP is **not** counted towards the per-IP failure throttle                                                                           |

Inbound mail (port 25 to tenant domains), reinjection (10026/10027) and bounce notices are never affected. Mail accepted **before** a restriction is not held by it; tenants who want that use an `ato.*` policy rule (held or quarantined at the delivery gate, [policy-dsl.md](../architecture/policy-dsl.md)).

## Detection

- `smtp_ato_restrictions_enforced_total{kind,mode}` rising: restrictions are refusing submissions or authentications (expected while an incident is contained).
- `smtp_ato_restriction_lookups_total{result="error"}` rising (alert `AtoRestrictionLookupErrors`, pages): the per-organization lookup fails. **Enforcement fails closed**: every `submission`/`relay` recipient of the affected organizations is tempfailed (`450 4.3.5 … Policy service unavailable` via `smtp_policy_decisions_total{action="tempfail"}`) and SASL authentications get `454 4.7.0 Temporary authentication failure`. Cause is Redis or the MySQL writer behind the adapter: follow [smtp-policy-service-down.md](smtp-policy-service-down.md) step 3.
- `smtp_ato_telemetry_total{result=~"dropped|expired|error"}` rising (alert `AtoSmtpTelemetryDropped`): telemetry is being lost (buffer full, or the writer refuses the outbox insert for longer than `SMTP_ATO_TELEMETRY_MAX_AGE_MS`). Mail is never affected; ATO detection sees fewer SMTP signals. `smtp_ato_telemetry_buffer_entries` shows the backlog. `dropped` with `kind="auth"` and no database error also happens when the database has no platform organization (`organizations.kind = 'platform'`): unknown-username entries have nowhere to go (run `pnpm db:seed`).
- Tenant reports "my server cannot send / authenticate" with the replies above.

## Diagnosis

1. Which restrictions are active for the organization (writer; no addresses are stored, only SHA-256 of the lower-cased sender):

   ```sql
   SELECT id, kind, scope, connector_id, ip_cidr, mode, status, reason_code, starts_at, expires_at
   FROM ato_smtp_restrictions
   WHERE organization_id = ? AND status = 'active' AND expires_at > UTC_TIMESTAMP(3)
   ORDER BY id;
   ```

   For a mailbox scope compare `mailbox_sha256` with `SHA2(LOWER('<sender>'), 256)`.

2. The adapter's cached view: `redis-cli GET sa:ato:r:<organizationId>` (JSON of the active rows; TTL `SMTP_ATO_RESTRICTION_CACHE_SECONDS`, default 15 s). Rows past `expiresAt` are ignored at read time even before the expiry sweeper flips them to `expired`.
3. The incident and the action that created the restriction: the ATO incident page of the organization in the admin portal (or `GET /api/v1/ato/...` once the ATO api is deployed); every restriction has an action and an audit trail.

## Recovery

- **Lift one restriction (normal path):** roll back the response action in the incident (admin portal or ATO api; approvals and MFA as for applying it). The ATO store sets the row `lifted` and writes `ato.restriction.changed.v1`; every adapter's outbox tail deletes `sa:ato:r:<organizationId>` within `SMTP_CACHE_INVALIDATION_POLL_MS`, at the latest after the cache TTL.
- **Do not edit `ato_smtp_restrictions` by hand.** A manual `UPDATE` bypasses the audit trail and the outbox event (the cache still clears after at most the TTL). If it is unavoidable during an outage, record it in the incident afterwards.
- **Kill switch (emergency only, e.g. a false-positive storm restricting many legitimate senders):** set `SMTP_ATO_ENFORCEMENT_ENABLED=false` and restart the smtp-adapter (Compose: change `.env`, `docker compose --profile apps up -d smtp-adapter`; Kubernetes: change the value in `infrastructure/kubernetes/base/smtp-adapter.yaml` or the overlay and roll out). Every `send_block` and `auth_block` stops being enforced without any lookup; restriction rows, incidents and telemetry are unchanged, and `smtp_ato_restrictions_enforced_total` stops rising. The change is audited by the deployment history only: open an incident ticket, find the cause (ATO settings, a detection rule, automation) and set the switch back to `true` as soon as the cause is fixed. While it is off, a compromised account the ATO module restricted can send and authenticate again; prefer lifting the individual false positives.
- **Username hash key.** `SMTP_ATO_USERNAME_HASH_KEY` (≥ 32 characters) is required while telemetry is enabled; the adapter refuses to start without it. Compose reads it from `.env`; Kubernetes mounts it from its own Secret `email-gateway-smtp-ato-key` (key `username-hash-key`, mounted only by the smtp-adapter at `/var/run/secrets/smtp-ato`, read through `SMTP_ATO_USERNAME_HASH_KEY_FILE`). Generate it like the other keys (`openssl rand -hex 32`); rotating it only breaks correlation of hashes recorded before the rotation.
- **Telemetry only (never needed for mail flow):** `SMTP_ATO_TELEMETRY_ENABLED=false` stops recording (no buffer, no outbox rows). Use it only if the outbox inserts themselves harm the writer; ATO detection then sees no SMTP AUTH or submission signals.

## Verification

- A restricted sender gets the reply in the table above, another mailbox of the same organization and every other organization still get `250` at RCPT.
- After a lift: the next RCPT (or AUTH) succeeds within the poll interval; `redis-cli EXISTS sa:ato:r:<organizationId>` is `0` or holds only the remaining rows.
- With the kill switch off: `smtp_ato_restrictions_enforced_total` stops increasing and `smtp_ato_restriction_lookups_total` stops counting new lookups.
- Telemetry: `smtp_ato_telemetry_total{result="flushed"}` rises and `smtp_ato_telemetry_buffer_entries` returns to near zero.

## Never

- Leave `SMTP_ATO_ENFORCEMENT_ENABLED=false` in place after the emergency.
- Flush Redis to "clear" a restriction: the next lookup reloads it from MySQL (and the other caches are lost).
- Copy SASL usernames or passwords into tickets: telemetry stores unknown usernames only as a keyed hash (`SMTP_ATO_USERNAME_HASH_KEY`, smtp-adapter only); rotating that key only breaks correlation of older hashes.
