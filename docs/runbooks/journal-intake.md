# Runbook: journal intake

Journal-only intake (step 8.6, [design](../plan/steps/27-journal-intake-and-archive-split.md) D1–D3, D9; [ADR-0087](../architecture/adr/0087-journal-intake-path.md)). Customers send Microsoft 365 / on-premises Exchange journal reports, Google Workspace "Also deliver to" copies or `always_bcc` copies to a per-source address `journal-<token>@<JOURNAL_INTAKE_DOMAIN>`. The inbound Postfix asks the smtp-adapter policy at RCPT, routes the intake domain to the journal LMTP (`:10053`), which unwraps, proves, stores the original in S3 and commits it as an `ingest_source = journal_intake` message that the archive engine captures. Deployment: [smtp-gateway.md](../deployment/smtp-gateway.md#journal-intake-step-86), [archive.md](../deployment/archive.md#journal-intake-and-cross-source-dedupe-step-86). Code: [apps/smtp-adapter/README.md](../../apps/smtp-adapter/README.md#journal-only-intake-step-86).

**Ground rules.** Intake never delivers, forwards or bounces mail itself (I1, I2). Refusals at RCPT are answered in-session to the customer's provider or server, which reports to the customer's own alternate journaling mailbox; content-proof failures are accepted and dropped (no backscatter). Logs carry the source public id, codes and sizes only: never search logs for addresses or tokens, use the source id. Never paste an intake address or header token into a ticket (they are credentials; the api shows them masked unless the caller holds `journal:manage`).

## Where to look

| Question                  | Look at                                                                                                                                                                                      |
| ------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Is a source receiving?    | `journal_intake_sources.last_accepted_at`, `health_status`; `journal_intake_counters` of today (`accepted`, `refused_*`, `dropped_proof`, `unwrap_failed`), flushed every 30 s               |
| Why was it refused last?  | `journal_intake_sources.last_refused_at`, `last_refusal_code` (table below)                                                                                                                  |
| Platform-wide             | `journal_intake_messages_total{kind,outcome}`, `journal_intake_refusals_total{stage,code}`, `journal_intake_unwrap_total{format,result}`, `journal_intake_lmtp_seconds` (job `smtp-adapter`) |
| One message               | smtp-adapter log `component=lmtp-journal` / `journal-intake-policy` with the Postfix queue id (`queueId`) and `sourceId` (public id)                                                         |
| Is the adapter listening? | `GET :3010/health/ready` check `lmtp-journal` (present only while `JOURNAL_INTAKE_DOMAIN` is set)                                                                                            |

```sql
-- One source (by public id): state and today's counters.
SELECT s.status, s.health_status, s.verified_at, s.last_accepted_at, s.last_refused_at,
       s.last_refusal_code, c.accepted, c.duplicates, c.refused_address, c.refused_network,
       c.refused_tls, c.refused_size, c.refused_rate, c.refused_unavailable, c.dropped_proof,
       c.unwrap_failed
FROM journal_intake_sources s
LEFT JOIN journal_intake_counters c ON c.source_id = s.id AND c.day = UTC_DATE()
WHERE s.public_id = '<source public id>';
```

## Refusal codes

What the sender sees, what is counted, and what to do. RCPT answers come from the policy (`policy_context=inbound`, contracts §34); the journal LMTP answers only `250` or `451`.

| Stage / answer                                          | `last_refusal_code` (counter)                                                                                | Meaning                                                                                                                                                                                                                 | Action                                                                                                                                       |
| ------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------ | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------- |
| RCPT `550 5.1.1 … User unknown`                         | none (metrics `unknown_address` only)                                                                        | Not `journal-<26 base32>`, or no source has this address hash                                                                                                                                                           | Customer uses a wrong or old address (rotation past the overlap); address guessing if it spikes                                              |
| RCPT `550 5.1.1`                                        | `refused_disabled` / `refused_address_expired` (`refused_address`)                                           | Source disabled (terminal), or the previous address after `previous_valid_until`                                                                                                                                        | Customer must use the current address (guide); a disabled source stays refused                                                               |
| RCPT `450 4.7.1 Journal intake temporarily unavailable` | `refused_unavailable` / `refused_paused` (`refused_unavailable`)                                             | Organization not active, `archiving` or `journal_intake` not entitled, archiving disabled, or the source is paused                                                                                                      | Temporary on purpose: Microsoft 365 / Exchange retry for up to two days. Fix entitlement or archive settings, or resume the source           |
| RCPT `550 5.7.1 Journal intake sender not authorized`   | `refused_network`, `refused_connection`, `refused_provider_range`, `refused_client_cert` (`refused_network`) | Provider kinds: client not in the bound provider's egress set, or the connection disabled/unbound. On-premises: client outside the source's networks, or inside a provider range. Certificate fingerprint not presented | Check the source's networks and the customer's egress IPs, the 8.2 connection binding, the provider egress set (`ProviderEgressRangesStale`) |
| RCPT `550 5.7.1 Must issue a STARTTLS command first`    | `refused_tls` (`refused_tls`)                                                                                | `require_tls` and a plaintext session                                                                                                                                                                                   | Customer enables TLS on the send connector / journal rule path (or the source drops `requireTls`)                                            |
| RCPT `452 4.5.3 Error: too many recipients`             | none (metrics `one_destination`)                                                                             | The transaction already carries another source or tenant recipients (intake-only rule, D2.2.5)                                                                                                                          | None: the client retries the rest in a new transaction. Persistent: a customer BCCs the intake address alongside normal recipients           |
| RCPT `DEFER_IF_PERMIT 4.7.1 Rate limit exceeded`        | `refused_rate` (`refused_rate`)                                                                              | `JOURNAL_INTAKE_RATE_PER_SOURCE_PER_MINUTE` or the plan's `journal_intake_messages_per_minute`                                                                                                                          | Raise the organization limit (`organization_limits`) if legitimate                                                                           |
| RCPT / END-OF-MESSAGE `550 5.3.4 Message too big`       | `refused_size` (`refused_size`)                                                                              | Above min(source `max_message_bytes`, plan `journal_intake_max_message_bytes`, `JOURNAL_INTAKE_MAX_MESSAGE_BYTES`)                                                                                                      | Raise the source or plan limit; Exchange then reports to the alternate mailbox                                                               |
| RCPT `DEFER_IF_PERMIT 4.3.5 Policy service …`           | none                                                                                                         | Adapter, Redis or writer down, egress ranges not loaded yet                                                                                                                                                             | [smtp-policy-service-down.md](smtp-policy-service-down.md)                                                                                   |
| LMTP `250 2.0.0 Ok: dropped`                            | `proof_tenant_header`, `proof_header_token`, `proof_header_block` (`dropped_proof`)                          | Content proof failed: Microsoft 365 tenant header missing or another tenant; Google token missing, repeated or wrong; header block cut                                                                                  | [JournalIntakeProofDropsHigh](#journalintakeproofdropshigh)                                                                                  |
| LMTP `451 4.3.0`                                        | the RCPT codes above at `stage="lmtp"`                                                                       | Writer re-check refused (state changed since RCPT), no END-OF-MESSAGE marker, S3/DB/Redis failure, proof `temperror` (binding gone)                                                                                     | [JournalIntakeTempfails](#journalintaketempfails)                                                                                            |

## JournalIntakeSilentSources

A verified source accepted nothing for longer than its `silence_alert_minutes` (default 240; the archive-worker health loop sets `health_status = silent` and sends the `journal_intake_silent` alert to the organization).

1. Today's counters of the source (query above). Refusals without acceptances → follow the refusal code. Nothing at all → the customer side stopped sending.
2. Customer side: Microsoft 365 Purview journal rule still enabled and pointing at the **current** address (after a rotation the old one works only during the overlap); the "Send undeliverable journal reports to" mailbox holds the reports Exchange could not deliver (it says why); Google routing rule still active with the header; on-premises send connector up.
3. Small or quiet tenants: raise `silence_alert_minutes` or set it to NULL (no alert) through the api.

## JournalIntakeProofDropsHigh

Messages passed the RCPT checks (address, network, TLS) but the content proof failed, so they were accepted and dropped: nothing is archived.

- `proof_tenant_header` (Microsoft 365): the report's `X-MS-Exchange-CrossTenant-Id` is absent or another tenant. The address is known to someone sending from Microsoft's shared ranges for another tenant (spoofing or a misconfigured second tenant), or the customer's tenant changed — compare with the connection's `external_tenant_id`. If Exchange Online journal reports genuinely lack the header (design R1, PO Q1), the documented follow-up is a per-source relaxation; until then, open an incident (journaling is lost while it lasts). Rotate the address when spoofing is suspected (below).
- `proof_header_token` (Google): the routing rule's custom header is missing, repeated or wrong — typically the customer did not update `X-EG-Journal-Token` after a rotation (the previous token works only during the overlap). Give the customer the current guide.
- `proof_header_block`: the outer header block exceeded `INGEST_HEADER_MAX_BYTES`; evidence beyond it is unseen. Raise the limit only with care.

## JournalIntakeUnwrapFailures

Reports were not recognized as Exchange journal reports (`journal_report_unparsed`: no `X-MS-Journal-Report`, not `multipart/mixed`, no envelope or embedded part, an envelope above `JOURNAL_INTAKE_ENVELOPE_MAX_BYTES`, an unsupported encoding such as TNEF). They were stored **as received** (compliance kept), counted in `unwrap_failed`, but the original was not extracted and the envelope recipients come from the report's headers only. Check `journal_intake_unwrap_total{result}` for the reason. A source of kind `microsoft_365_journal` / `exchange_onprem_journal` that receives copies instead of reports was set up with the wrong kind (create a `smtp_bcc` source instead). Envelope too large (huge distribution lists): raise `JOURNAL_INTAKE_ENVELOPE_MAX_BYTES`.

## JournalIntakeRefusalsSpike

Many RCPT refusals of one code. `unknown_address`: address guessing against the intake domain (nothing is accepted; consider postscreen/DNSBL limits on the inbound tier) or a customer still using a rotated address. `network`: a customer's egress changed (on-premises networks need updating) or the provider egress ranges are stale. `unavailable`: an organization lost the entitlement or disabled archiving while its journal rule keeps sending (Exchange retries for two days, then reports to the alternate mailbox). `rate` / `size`: limits.

## JournalIntakeTempfails

The journal LMTP keeps answering `451`; Postfix retries with backoff and, after `POSTFIX_MAXIMAL_QUEUE_LIFETIME` (5 days), bounces the report to its envelope sender (the customer's own system, which passed RCPT; design R6).

1. smtp-adapter log `component=lmtp-journal` at `warn`/`error`: `without a matching source or END-OF-MESSAGE marker` (Redis lost the marker `sa:jintake:q:<queueId>`; Redis runs `noeviction`, so look for a flush or failover), `re-check refused` (the source changed between RCPT and delivery: paused, disabled, network), `upload to S3 failed`, `transaction failed`, `proof could not be checked` (connection unbound or Google token not configured).
2. Infrastructure: [smtp-persistence-failure.md](smtp-persistence-failure.md) (S3, writer).
3. Queue inspection below.

## ArchiveDedupeVariantLimit

Copies matched an archive record (same Message-ID and header fingerprint within `ARCHIVE_DEDUPE_WINDOW_HOURS`) but the record already holds `ARCHIVE_MAX_CONTENT_VARIANTS` differing bodies; they were archived as separate records (nothing lost, storage not saved). Expected occasionally for gateway-modified inbound mail; frequent hits point at a relay that rewrites bodies on every hop or at Message-ID reuse. Raise `ARCHIVE_MAX_CONTENT_VARIANTS` only with the archive-worker owner (archive record size).

## Address rotation

`POST /journaling/intake-sources/{id}/rotate-address` (MFA, `journal:manage`) derives a new address (and Google token); the old hashes stay valid until `previous_valid_until` (`JOURNAL_INTAKE_ROTATION_OVERLAP_DAYS`, default 7). Use it when an address or token leaked or spoofing drops appear. The customer must update the journal rule (and Google's custom header) within the overlap; after it, the old address is `550 5.1.1` (`refused_address_expired`). The adapter sees a rotation within `JOURNAL_INTAKE_SOURCE_CACHE_SECONDS` at RCPT and immediately at LMTP.

## Paused and disabled sources

- **Paused** (`PATCH … status=paused`): RCPT `450 4.7.1`; Microsoft 365 and Exchange retry for up to two days, so a short pause loses nothing. Resume within that window; longer pauses send reports to the customer's alternate journaling mailbox.
- **Disabled** (`DELETE …`, terminal): RCPT `550 5.1.1`. Create a new source to resume; the customer gets a new address.
- A disabled 8.2 connection makes its provider sources refuse `550 5.7.1` (`refused_connection`) and the health `failing`.
- Kill switch of the whole path: `JOURNAL_INTAKE_ENABLED=false` on the smtp-adapter (restart). The intake domain then resolves to nothing (`RELAY_DENIED` at RCPT; Postfix still routes the domain to `:10053`, which no longer listens). To take intake fully out, empty `JOURNAL_INTAKE_DOMAIN` on postfix, rspamd, api and smtp-adapter.

## Postfix queue inspection for intake

Intake mail sits in the **inbound** Postfix queue (`postfix`, not `postfix-outbound`), with the intake address as recipient and transport `lmtp:inet:<adapter>:10053`:

```bash
docker compose exec postfix postqueue -j | grep -c 'journal-'               # queued intake messages
docker compose exec postfix sh -c "postqueue -j | grep journal-" | head      # delay reasons (reason field)
docker compose exec postfix postcat -hq <queue id> | grep -i '^X-MS-Journal-Report\|^Subject'
docker compose exec postfix postqueue -i <queue id>                          # retry one now
```

Never delete intake queue files to "clear" a backlog: they are the customer's compliance copies. A queue file that will never be accepted (a disabled source) expires after 5 days and bounces to its sender; to speed that up deliberately, `postsuper -d <queue id>` only after the customer confirmed the reports are no longer needed. Production: the same commands on the inbound ASG instance (see [smtp-queue-backlog.md](smtp-queue-backlog.md)).
