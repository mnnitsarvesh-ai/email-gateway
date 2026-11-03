# ADR-0020: DKIM signing by a dedicated Rspamd fed by the api through an isolated, non-persistent Redis

**Status:** Accepted. Amends decision 1 of [ADR-0018](0018-dkim-key-custody.md) ("private keys never leave the process unencrypted"): active signing keys now leave the api, decrypted, to the signing path described here. Storage at rest (SecretBox ciphertext in MySQL, crypto-shredding) is unchanged. Design: [step 2.2 D12](../../plan/steps/04-smtp-gateway.md#d12-dkim-signing-adr-0020).

**Context.** ADR-0018 left the signer to step 2.2. Outbound mail leaves through `postfix-outbound` (reinjection listener 10027) and must carry a DKIM signature of the sender's domain with its active selector. Only the api holds `DATA_ENCRYPTION_KEY`. A signer needs the plaintext key at signing time.

**Decision.**

1. **Signer**: a dedicated `rspamd-outbound` instance, used as milter only by the 10027 reinject-outbound listener, with `dkim_signing` reading keys from Redis (sign by the `From` header domain, no mismatch allowed, no fallback). It never scans or rejects; it only signs. The inbound Rspamd never sees signing keys.
2. **Key distribution**: the api's `DkimSigningPublisher` reconciles every 30 s (and on demand through a CLI) the set of signable keys — the `active` RSA-2048 key of every `active`, outbound-enabled domain of an `active` organization — into **redis-dkim**: hash `dkim_selectors` (domain → selector) and hash `dkim_keys` (`selector.domain` → PEM), applied atomically, removed when a domain stops being signable or the key rotates.
3. **redis-dkim** is a separate Redis instance with **no persistence** (`save ''`, `appendonly no`) and ACL users per role, default user disabled: `dkim-writer` (api; write both hashes), `dkim-reader` (rspamd-outbound; `HGET` on both hashes), `dkim-probe` (smtp-adapter; read-only on `dkim_selectors`, never keys). It is reachable only from those three components (security groups / network policy in production).
4. **Fail closed**: the reinject-outbound policy defers (`4.7.0`) when the sender domain has no selector in redis-dkim, so mail is never sent unsigned for lack of a key (for example right after a redis-dkim restart). Submission refuses senders whose domain has no active DKIM key at all (configurable).

**Alternatives considered.**

- _OpenDKIM with a KeyTable synced from MySQL_: plaintext keys in files on disk and `DATA_ENCRYPTION_KEY` in a sync sidecar on the MTA host; OpenDKIM is barely maintained.
- _Keys in the shared Redis_: every service using that Redis could read them (Redis ACL key patterns cannot exclude a prefix from the default user).
- _Signing in the inbound Rspamd_: exposes keys to the component that parses untrusted mail and risks signing spoofed inbound mail delivered to tenants.
- _Signing in Node (after-queue filter)_: adds an SMTP hop implemented in Node and buffers messages.
- _KMS-based signing (sign via KMS `Sign`)_: strongest custody but per-message AWS calls and no local equivalent; possible later behind the same publisher contract.

**Consequences.** Plaintext keys exist in memory of the api (transiently), redis-dkim and rspamd-outbound, never on disk outside MySQL ciphertext. Compromise of redis-dkim or rspamd-outbound exposes the active keys of all outbound-enabled domains; mitigations are isolation, ACLs, no persistence and rotation (step 2.1). Only RSA keys are signed with; Ed25519 dual signing is future work.
