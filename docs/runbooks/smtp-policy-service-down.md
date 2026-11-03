# Runbook: smtp-adapter (policy, socketmap, SASL, LMTP) unavailable

For platform operators. Both Postfix instances depend on smtp-adapter for every decision: policy (`:10040`), lookup tables (`:10041`), SASL (`:10042`) and ingestion (`:10050`-`:10052`). Design: [step 2.2 D2, D4, D9-D11](../plan/steps/04-smtp-gateway.md), [ADR-0019](../architecture/adr/0019-smtp-gateway-topology.md).

## Detection

- smtp-adapter `/health/ready` failing or the process/pod down; metrics scrape (`job="smtp-adapter"`) down.
- Postfix logs:
  - `warning: connect to <host>:10041: Connection refused` / `table socketmap:inet:…:relay_domain lookup error` (inbound and outbound lookups),
  - `warning: problem talking to server <host>:10040` (policy),
  - `warning: SASL: Connect to Dovecot auth socket 'inet:<host>:10042' failed` followed by `fatal: no SASL authentication mechanisms` (submission),
  - `status=deferred … connect to <host>[…]:10050: Connection refused` (ingestion).
- Clients see (all temporary):

  | Listener                    | Reply                                                                                                                                                    |
  | --------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------- |
  | inbound 25                  | `451 4.3.0 <rcpt>: Temporary lookup failure`                                                                                                             |
  | outbound 587 after STARTTLS | connection closed after `STARTTLS` (no AUTH possible), or `454 4.7.0 Temporary authentication failure` when the adapter is up but its Redis/MySQL is not |
  | outbound 25 (relay)         | `451 4.3.5 … Client host rejected: Server configuration error`                                                                                           |
  | 10026 / 10027               | `450 4.3.5 <rcpt>: Recipient address rejected: Policy service unavailable`                                                                               |

- Policy answering but erroring: `smtp_policy_decisions_total{action="tempfail"}` and `smtp_socketmap_lookups_total{result="temp"}` rising (Redis or MySQL behind the adapter).

## Impact

Fail closed by design: no mail is accepted unchecked, nothing is bounced. Senders keep mail in their own queues and retry; mail already in a Postfix spool waits there. Long outages delay mail; senders give up after their own queue lifetime (typically 5 days).

## Recovery

1. Is the adapter process up? Locally: `pnpm --filter @email-gateway/smtp-adapter dev` (host mode, `SMTP_ADAPTER_HOST=host.docker.internal`) or `docker compose --profile apps up -d smtp-adapter`. Production: pod/instance status, recent deploys (roll back if the outage started with a release).
2. Can Postfix reach it? `docker compose exec smtp-tools nc -zv <SMTP_ADAPTER_HOST> 10040` (and 10041, 10042, 10050). Check `SMTP_ADAPTER_HOST` of the Postfix containers (`docker compose exec postfix postconf smtp_adapter_host`), `extra_hosts` for `host.docker.internal`, security groups (`sg-smtp-adapter` ports per listener), and `SMTP_INTERNAL_CLIENT_NETWORKS` on the adapter (a peer outside it is refused).
3. Adapter up but deciding `tempfail`: `/health/ready` names the dependency. Redis down → policy tempfails (rate limits are fail closed); MySQL writer down → lookups `TEMP`; fix the dependency.
4. After recovery nothing needs restarting: Postfix reconnects per request for policy and socketmap, and the submission listener runs one session per `smtpd` process (`max_use=1`), so the next session opens a fresh SASL connection. (Postfix's Dovecot SASL client never reconnects inside a process: without `max_use=1` every AUTH in a process that held a connection across an adapter restart answered `454 4.7.0 … Connection lost to authentication server` until the process exited. If you see that message persisting, check `postconf -P submission/inet/max_use` on `postfix-outbound`.) Retry queued mail now with `postqueue -f` on both instances.

## Verification

- `docker compose exec smtp-tools swaks --server postfix --to user@<active tenant domain> --quit-after RCPT` → `250`; to an unknown domain → `554 5.7.1 … Relay access denied`.
- Submission with valid connector credentials authenticates (`235 2.7.0`).
- No new `Connection refused` warnings; `smtp_policy_decisions_total{action="dunno"}` rising.

## Never

- Remove `check_policy_service`, set `default_action=DUNNO`/`OK`, or replace the socketmap `relay_domains` with a static list to "keep mail flowing": that opens relay paths and skips tenant checks (invariants 3 and 4).
- Add `permit_mynetworks` with wide networks or `permit` to any restriction list.
- Point `SMTP_ADAPTER_HOST` at an address outside the internal network.
