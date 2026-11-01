# ADR-0006: Postfix at the edge; pre-queue vs post-queue split; Postfix owns delivery retries

**Status:** Accepted

**Context.** A gateway can reject mail during the SMTP session (cheap, no backscatter, but adds latency while the client waits) or after accepting it (thorough, but any rejection becomes an NDR, which is backscatter to forged senders). Delivery needs MX lookup, TLS policy, retries and DSNs, all of which Postfix already does well.

**Decision.**

- **Postfix** is the MTA for inbound and outbound mail. Production runs it on EC2 Auto Scaling Groups with an EBS spool, because the spool must survive pod rescheduling.
- **In-session** checks are only `smtp-adapter` (policy delegation: recipient validation, tenant resolution, rate limits) and **Rspamd as a milter**. These are the only components that may reject or defer, and both **fail closed to 4xx** (`smtpd_policy_service_default_action = DEFER_IF_PERMIT`, `milter_default_action = tempfail`).
- Relay control is a permanent `554` (`smtpd_relay_restrictions = permit_mynetworks, reject_unauth_destination`).
- **Handoff** to ingestion is over LMTP. `250` is returned only after the EML is in S3 and the DB transaction has committed.
- **Post-queue** outcomes are `deliver | tag | quarantine | discard`. The pipeline **never bounces**.
- `delivery-worker` reinjects into an **outbound Postfix**, which then owns retries, backoff, queue lifetime and DSNs. No retry scheduler is written in Node.

**Consequences.** Malicious mail that passes in-session checks is silently quarantined or discarded, which is intended. `discard` must always be audited. The outbound Postfix needs a durable spool and sizing for tenant-server outages.
