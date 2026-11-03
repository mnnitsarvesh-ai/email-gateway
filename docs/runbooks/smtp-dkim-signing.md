# Runbook: DKIM signing (rspamd-outbound, redis-dkim)

For platform operators. Outbound mail leaves only through `postfix-outbound` 10027, whose milter `rspamd-outbound` signs with the active key of the From domain, read from `redis-dkim`. The api's `DkimSigningPublisher` fills redis-dkim every `DKIM_SIGNING_SYNC_INTERVAL_SECONDS` (default 30). Design: [step 2.2 D12](../plan/steps/04-smtp-gateway.md#d12-dkim-signing-adr-0020), [ADR-0020](../architecture/adr/0020-dkim-signing.md); deployment: [DKIM signer and redis-dkim](../deployment/smtp-gateway.md#dkim-signer-and-redis-dkim-isolation-d12-adr-0020).

## Detection

- Reinjection on 10027 deferred with `4.7.0 Signing key not available` (policy: no selector in `dkim_selectors` for the sender domain) or with the milter's `Signing key not available, try again later` (unsigned at end of DATA).
- rspamd-outbound log: `FORCE_ACTION_GATEWAY_DKIM_UNSIGNED`, `cannot make request to load DKIM selector/key`, `NOPERM`, `WRONGPASS`.
- redis-dkim health: `docker compose ps redis-dkim`; count of signable domains (selectors only, safe to show): `docker compose exec redis-dkim sh -c 'REDISCLI_AUTH="$REDIS_DKIM_PROBE_PASSWORD" redis-cli --no-auth-warning --user dkim-probe HEXISTS dkim_selectors <domain>'`.
- api logs of the publisher (sync outcome, counts; never PEMs).
- Recipients report `dkim=fail`: compare the `s=` selector of the signature with the DNS record of that selector (`dig TXT <selector>._domainkey.<domain>`).

## Impact

Fail closed: mail is never sent unsigned. It waits in the delivery-worker/postfix-outbound path and is retried. A domain with no `active` key, not `outbound_enabled`, or an organization that is not `active` is intentionally not signable.

## Recovery

1. **redis-dkim down or restarted** (it has no persistence by design): `docker compose up -d --wait redis-dkim`, then refill immediately with `pnpm --filter @email-gateway/api dkim:sync` (or wait one interval). rspamd-outbound reconnects on its own.
2. **Domain missing from `dkim_selectors`**: check in the api/DB that the domain is `active`, `outbound_enabled = true`, its organization `active`, and it has an `active` `rsa_2048` key with ciphertext; run the sync; check publisher logs for a decrypt error (wrong `DATA_ENCRYPTION_KEY`/`_PREVIOUS` after a key rotation).
3. **Authentication errors** (`WRONGPASS`/`NOPERM` in rspamd-outbound or api logs): the passwords in `.env`/secrets differ from what redis-dkim rendered at start. Fix the secret and recreate both sides: `docker compose up -d --force-recreate redis-dkim rspamd-outbound` (then sync). ACL grants are in `infrastructure/redis-dkim/entrypoint.sh`.
4. **Signature fails at receivers**: the DNS record of the selector does not match the key (rotation published the new selector before DNS propagated, or the record was edited). Rotate per [domain-verification.md](domain-verification.md); the publisher switches the selector only when the new key is `active`.
5. **Retry deferred mail** after the fix: `docker compose exec postfix-outbound postqueue -f` (and the delivery-worker retries its own).

### Manual signing check (no customer data)

```bash
# 1. throwaway key for a .test domain (as dkim-writer), 2. sign a sample, 3. remove the key
docker compose exec -T smtp-tools openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 2>/dev/null \
  | docker compose exec -T redis-dkim sh -c 'REDISCLI_AUTH="$REDIS_DKIM_WRITER_PASSWORD" redis-cli --no-auth-warning --user dkim-writer -x HSET dkim_keys check.dkim-check.test'
docker compose exec -T redis-dkim sh -c 'REDISCLI_AUTH="$REDIS_DKIM_WRITER_PASSWORD" redis-cli --no-auth-warning --user dkim-writer HSET dkim_selectors dkim-check.test check'
printf 'From: a@dkim-check.test\r\nTo: b@x.sink.test\r\nSubject: check\r\n\r\nbody\r\n' \
  | docker compose exec -T rspamd-outbound rspamc -h 127.0.0.1:11333 -i 10.0.0.1 -F a@dkim-check.test | grep -E 'Action|DKIM_SIGNED'
docker compose exec -T redis-dkim sh -c 'REDISCLI_AUTH="$REDIS_DKIM_WRITER_PASSWORD" redis-cli --no-auth-warning --user dkim-writer HDEL dkim_selectors dkim-check.test; REDISCLI_AUTH="$REDIS_DKIM_WRITER_PASSWORD" redis-cli --no-auth-warning --user dkim-writer HDEL dkim_keys check.dkim-check.test'
```

Expected: `Action: no action` and `Symbol: DKIM_SIGNED (0.00)[dkim-check.test:s=check]`. A domain without a key gives `Action: soft reject`. Never use a real customer domain or key for this.

## Verification

- 10027 accepts and the message reaches the destination with `DKIM-Signature: … d=<domain>; s=<selector>` that verifies (`mailauth` or the receiver's `Authentication-Results`).
- No new `FORCE_ACTION_GATEWAY_DKIM_UNSIGNED` lines.

## Never

- `FLUSHALL`/`DEL dkim_keys` on redis-dkim (no user has the right to flush; do not add it), or restart redis-dkim **without** a resync: until the next sync every outbound message is deferred.
- Add persistence (`--save`, `--appendonly yes`) or a volume to redis-dkim, or copy keys out of it: plaintext keys must never reach a disk (ADR-0020).
- Disable `force_actions.conf` or set `try_fallback`/static `domain {}` keys to "make mail flow": that sends unsigned mail or signs with the wrong key.
- Give `dkim-probe` or any other service read access to `dkim_keys`.
- Print or log PEMs (redis-cli `HGET dkim_keys …` in a shared terminal, CI logs).
