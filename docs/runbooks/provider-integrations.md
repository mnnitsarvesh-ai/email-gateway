# Runbook: Microsoft 365 and Google Workspace connectors (integration-worker, provider relay)

Step 8.2 ([design](../plan/steps/25-m365-google-connectors.md), ADR-0076..0081). Deployment, secrets and app registration: [deployment/provider-integrations.md](../deployment/provider-integrations.md). Worker internals: [apps/integration-worker/README.md](../../apps/integration-worker/README.md).

All SQL below runs on the **writer**. The provider tables are written only by the api, the smtp-adapter and the integration-worker: never edit a grant's credential columns or a connection's binding by hand. Never paste credentials, consent states, probe addresses, route tokens or provider error texts into tickets: ids, codes and counts only. Nothing here ever needs a call to a customer's Microsoft or Google tenant beyond what the worker does with its read-only grants (I3).

**Invariant to keep in mind (I1):** connection health never changes mail flow. A critical connection still relays and delivers; suspending outbound relay is an explicit administrator action in the wizard (`suspend` change), never an automatic one.

```sql
-- Connections of an organization, with health and the latest validation
SELECT c.id, c.public_id, c.provider, c.status, c.outbound_mode, c.health_status,
       c.health_changed_at, c.next_health_check_at, c.last_relay_accepted_at
FROM provider_connections c WHERE c.organization_id = ?;
-- Failing checks of a connection (latest result per check and subject)
SELECT check_code, subject, status, severity, first_failed_at, checked_at
FROM provider_health_checks WHERE connection_id = ? AND status IN ('fail','warn','error');
-- Grants and their last error code
SELECT public_id, profile, auth_method, status, last_error_code, consecutive_failures,
       verify_requested_at, verified_at, credential_key_id, credential_expires_at
FROM provider_connection_grants WHERE connection_id = ?;
```

## IntegrationWorkerDown

A replica has not been scraped for 5 minutes. Check the pods (`kubectl -n email-gateway get pods -l app.kubernetes.io/name=integration-worker`), readiness (`/health/ready`: mysql) and logs (codes only; a configuration error names the key, never the value). A start-up refusal usually means: a Secret item is missing (`PROVIDER_M365_MAILFLOW_APP_CERT_PATH does not hold a readable private key`, `PROVIDER_GOOGLE_MAILFLOW_SA_KEY_PATH is not readable`), the thumbprint is not 40 hex characters, `PROVIDER_CREDENTIAL_ENCRYPTION_KEY_PREVIOUS` equals the current key, or a local-only switch is set outside local/ci. Nothing is lost while the worker is down: verifications and validation runs wait in their tables (`IntegrationTaskBacklog` follows), claims of a dead replica expire after their lease and are taken over. Compose: `docker compose logs integration-worker`.

## IntegrationTaskBacklog

The oldest grant in `verifying` or validation run in `queued` has waited more than 300 s for 15 minutes.

1. Is any replica running the `tasks` role (`INTEGRATION_WORKER_ROLES`) and ready? See IntegrationWorkerDown.
2. Are provider calls timing out? `provider_api_requests_total{result=~"timeout|unavailable|throttled"}` and `provider_api_duration_seconds`. Provider outages keep grants in `verifying` with back-off (`last_error_code = provider_unavailable`); they resume by themselves.
3. Saturation: `INTEGRATION_TASK_CONCURRENCY` (4 per replica); scale the Deployment (claims are disjoint, `FOR UPDATE SKIP LOCKED`).

```sql
SELECT status, last_error_code, COUNT(*), MIN(verify_requested_at)
FROM provider_connection_grants WHERE status = 'verifying' GROUP BY 1, 2;
SELECT kind, status, COUNT(*), MIN(created_at), MAX(attempts)
FROM provider_validation_runs WHERE status IN ('queued','running') GROUP BY 1, 2;
```

## Stuck validation runs

- `running` with `claimed_until` in the past: the replica died; another replica takes it over on its next poll (the run restarts its checks; results are written once). Nothing to do unless `attempts` keeps growing: then look for a check that crashes the worker (logs `integration task failed; retried` with `errName`/`errCode`).
- `awaiting_probe`: waiting for the customer's probe message (Exchange admin center **Connectors → outbound connector → Validate** with the probe address, or any message from a Google user of a linked domain). The run completes as soon as the smtp-adapter has recorded an observation for its token; after `PROVIDER_PROBE_TTL_SECONDS` (24 h) the maintenance leader ends it `expired`. If the customer says the probe was sent:
  1. `smtp_provider_relay_total{result="probe"}` and `smtp_provider_probe_observations_total{result}` on the smtp-adapter: `fail` = the proof failed (tenant header or aligned DKIM: see ProviderRelayProofFailuresHigh), `temperror` = DNS trouble (Postfix retries).
  2. The probe did not reach the provider relay at all (no `probe` decision): the customer's outbound connector / routing rule does not route through `GATEWAY_RELAY_HOSTS`, or the sending address is not in the active egress ranges (the relay denies it like any unknown client; see ProviderEgressRangesStale). With a null MX on the probe domain the customer's provider bounces such a probe.
  3. The run's connection must have outbound mode `probe_only` or `active`; otherwise the probe is refused (`not_active`).
- A run is never edited by hand; the administrator starts a new one (`POST /provider-connections/{id}/validations`, rate-limited).

```sql
SELECT public_id, kind, status, attempts, claimed_until, probe_expires_at, created_at, completed_at
FROM provider_validation_runs WHERE connection_id = ? ORDER BY id DESC LIMIT 10;
SELECT proof_result, failure_code, tenant_header, received_at FROM provider_probe_observations
WHERE connection_id = ? ORDER BY id DESC LIMIT 10;
```

## ProviderConnectionsCritical

At least one connection has been `critical` for 30 minutes (a ticket, not a page: the organization's administrators already received `integration_unhealthy` and the `integration.health_changed` webhook). Find the failing checks (SQL above) and act by code:

| Check                       | Typical cause                                                                                                                   | Who fixes it                                                                                                                          |
| --------------------------- | ------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------- |
| `credentials.token`         | consent revoked, app removed from the tenant, delegation removed, customer secret expired (`consent_missing`, `invalid_client`) | customer administrator (re-consent / new credential in the wizard); platform app problem if many tenants fail (ProviderTokenFailures) |
| `permissions.granted`       | a required permission was removed                                                                                               | customer administrator (re-consent with exactly the profile's permissions)                                                            |
| `tenant.identity`           | the credential now authenticates against another tenant                                                                         | customer administrator; the binding never moves automatically                                                                         |
| `domains.provider_verified` | a linked domain is no longer listed/verified in the tenant (outbound or internal routing active = critical)                     | customer administrator; relay keeps accepting (I1); the administrator may suspend outbound in the wizard (§15 Q7)                     |
| `routing.loops`             | `loop_detected` deliveries to linked domains in 24 h (internal routing rules out of order, route token mismatch)                | customer administrator: transport rules A/B of the guide; the route token version                                                     |
| `credential.expiry`         | a customer secret expires within 7 days                                                                                         | customer administrator: upload a new secret                                                                                           |
| `egress.ranges_fresh`       | the provider's egress set is stale (operator)                                                                                   | operator: import ranges                                                                                                               |

Disabled (disconnected) connections are excluded from this alert: the health role no longer evaluates them, so their last health status stays as it was at the disconnect.

Provider-API `error`s (`throttled`, `unavailable`, `timeout`) never turn a connection critical within `INTEGRATION_HEALTH_ERROR_GRACE_MINUTES` (60); provider checks back off ×2 up to 1 h per connection.

## ProviderTokenFailures

More than half of a provider's token requests failed over 30 minutes. One tenant failing is that tenant's problem (critical health, see above); **many tenants at once** points at the platform side:

- Microsoft `invalid_client` for `platform_app` grants: the platform app's certificate expired or was removed from the app, the Secret item changed, the thumbprint does not match, or the app registration was deleted. Check the app in the operator tenant, then the Secret items `m365-mailflow-cert.pem` / `m365-mailflow-cert-thumbprint` (restart the worker after a change).
- Google `invalid_client` for `platform_service_account` grants: the service-account key was deleted or disabled. Rotate the key (deployment doc).
- `unavailable`/`timeout`/`throttled` everywhere: provider outage or egress blocked (NetworkPolicy, NAT). Health stays within the grace window; nothing changes mail flow.

`provider_token_requests_total{provider,method,result}` shows the method (`platform_app`, `customer_app_secret`, `platform_service_account`, `customer_service_account`).

## ProviderEgressRangesStale

The active egress set of a provider was published more than 45 days ago (`PROVIDER_EGRESS_MAX_AGE_DAYS`). It keeps working, but mail from new provider addresses is relay-denied. Import the current list (below). The seeded snapshot (2026-06-01) is stale by design: import once at deployment.

## Egress import

1. Convert the provider's published list into `{ "schema": "provider-egress-import/1", "provider": "<microsoft_365|google_workspace>", "cidrs": [ … ] }` (details: [deployment doc](../deployment/provider-integrations.md#egress-ranges)).
2. Dry run, then import (Kubernetes: copy the file to `/tmp` of a worker pod; Compose: `docker compose cp` into the container's `/tmp` or run on the host with `DATABASE_URL` of the writer):

   ```bash
   kubectl -n email-gateway exec deploy/integration-worker -- node dist/cli/egress-import.js \
     --provider google_workspace --file /tmp/ranges-google.json --source "<where you took it from>" \
     --published-at <YYYY-MM-DD> --operator <your-name> --dry-run
   ```

   The JSON result shows `added`, `removed`, `removedFraction`, `rangeCount`, `sha256`. `refused: … (entry N)` names the invalid entry (private or special-purpose range, host bits set, prefix too short, more than 5 000 entries).

3. A set that removes more than 50 % of the active ranges is refused unless `--force`; check the source before forcing (a truncated download looks like this).
4. Re-running with identical data is a no-op (`unchanged`). The previous set is kept as `superseded` (the newest 5 per provider). Audit: `integration.egress_ranges_imported` (platform row, actor system, `--operator`).
5. Within 60 s every smtp-adapter loads the new set: `smtp_provider_egress_ranges{provider}` equals the new `rangeCount`.

Rollback: import the previous set's CIDRs again (`SELECT cidr FROM provider_egress_ranges WHERE set_id = ?` of the superseded version) with `--force` if needed.

## ProviderEgressRangesEmpty

Critical. Organizations have outbound relay `active` for a provider, but an smtp-adapter replica has 0 ranges loaded for it: their relayed mail is **deferred** (fail closed, `4.3.5`), queued at the provider (Exchange Online ≈ 24–48 h, Gmail up to 5 days). Check `smtp_provider_egress_load_errors_total` and the adapter logs (MySQL reachable?), then the active set (`SELECT provider, version, range_count FROM provider_egress_range_sets WHERE status = 'active'`). An active set with 0 ranges cannot be created by the CLI; a missing set means the seed or an import never ran: import the ranges.

## ProviderRelayProofFailuresHigh

More than 20 % of at least 50 messages relayed from a provider failed the tenant proof in 30 minutes and were refused (`550 5.7.26`). The ratio comes from the per-rule counter and can over-count a message that fails two rules.

1. Which rule? `sum by (provider, rule, result) (increase(smtp_provider_proof_total[30m]))`.
2. Which organization? Proof failures are counted per connection and hour in `provider_relay_counters` (`proof_failed`), and the adapter logs the failure code (`tenant_header_absent`, `tenant_header_mismatch`, `dkim_none`, `dkim_failed`, `dkim_weak`, `dkim_unaligned`, `dkim_stale`, `dkim_replayed`, `dkim_temperror`, …) with the connection id.
3. One organization: its DKIM signing broke (Microsoft: `New-DkimSigningConfig` per linked domain; Google: "Authenticate email") or its tenant id changed — tell the administrator; validation run `outbound` shows the probe failing the same way.
4. Many organizations of one provider: DNS trouble resolving `_domainkey` records (temperror is not a failure, but check `PROVIDER_RELAY_DNS_SERVERS`), a provider-side signing change, or abuse of the shared provider infrastructure (messages claiming linked domains from foreign tenants: the proof is doing its job; keep the refusals, inform security).

## SmtpConnectorOnSharedProviderRange

Active `source_ip` SMTP connectors accept mail from networks that overlap a provider's egress ranges: **any** tenant of that provider could relay as the connector's organization. The api refuses new such connectors (`network_shared_provider`); this alert finds old ones (and ones that became shared after an egress import).

```sql
SELECT c.id, c.organization_id, c.name, n.cidr
FROM smtp_connectors c JOIN smtp_connector_networks n ON n.connector_id = c.id
WHERE c.auth_type = 'source_ip' AND c.status = 'active';
-- compare with the active provider_egress_ranges (the maintenance leader computes the gauge)
```

Contact the organization: move it to a provider connection (relay with tenant proof) and disable the `source_ip` connector. Do not disable it without the organization: their outbound mail would stop. Until then the connector serves only senders of its own organization from the provider ranges; every other organization's provider traffic goes to the provider relay (the same holds for a client-certificate connector carrying a provider's shared certificate).

## A connection stays `configuring` with an active grant and no tenant

The tenant a grant names is only a claim until a linked domain that is TXT-verified at the gateway is verified in that tenant (D4). Check the linked domains' `providerVerification` (`GET /provider-connections/{id}/domains`): `absent`/`unverified` means the domain is not (or not yet) verified in the tenant the administrator consented with, or a different tenant was claimed. Grant `error` `tenant_bound_elsewhere`: another non-disabled connection holds that tenant (`SELECT organization_id, public_id FROM provider_connections WHERE active_tenant_key = '<provider>:<tenant id>'`); `tenant_mismatch`: the tenant identity changed between verification and binding. Audit actions `integration.grant_verified` (metadata `tenantBinding: pending_domain_proof`) and `integration.tenant_bound` show the two stages.

## Credential key rotation

`PROVIDER_CREDENTIAL_ENCRYPTION_KEY` encrypts customer credentials (api: encrypt, integration-worker: decrypt). Rotation never leaves a credential unreadable:

1. Generate a new key (`openssl rand -hex 32`). In the Secret `email-gateway-provider-credential-key` set `previous-key` = the current `key`, then `key` = the new key.
2. Roll out the **integration-worker first**, then the api (the worker can decrypt both; the api starts encrypting with the new key id).
3. The maintenance leader re-encrypts every grant whose `credential_key_id` is the previous key's id, in batches of 100 (audit `integration.credentials_reencrypted` with counts; `provider_credentials_reencrypted_total{result}`). Wait until none is left:

   ```sql
   SELECT credential_key_id, COUNT(*) FROM provider_connection_grants
   WHERE credential_ciphertext IS NOT NULL GROUP BY credential_key_id;
   ```

   (key ids are `k` + the first 7 hex characters of SHA-256 of the key; only the new id may remain). `failed` counts mean a ciphertext that decrypts with neither key (tampering or a lost earlier key): those grants need a new credential from the customer.

4. Remove `previous-key` from the Secret and roll out both Deployments again.

Platform certificate / service-account key rotation: [deployment doc](../deployment/provider-integrations.md#registering-the-platform-microsoft-app-profile-m365mail_flow).

## Disconnect and data

A disconnect (`DELETE /provider-connections/{id}`, wizard) revokes grants and wipes credentials, disables the relay connector and keeps destinations. Retention (maintenance leader, §3.3): consent states 24 h after expiry, validation runs 180 days (newest 50 per connection), probe observations 30 days, health events 365 days, relay counters 35 days, superseded egress sets beyond 5 per provider (`integration_maintenance_deleted_total{table}`). Organization deletion purges the provider tables in the order of [organization-deletion.md](organization-deletion.md).
