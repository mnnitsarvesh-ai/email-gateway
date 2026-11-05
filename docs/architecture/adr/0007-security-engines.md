# ADR-0007: Rspamd, ClamAV and YARA behind one engine contract

**Status:** Superseded by [ADR-0026](0026-security-scan-pipeline.md) (step 4.1): the engine contract and outcome set are replaced by standardized verdicts and per-engine scan queues; the SMTP-time milter behaviour is now [ADR-0027](0027-rspamd-milter-policy.md). Rspamd, ClamAV and YARA remain the chosen engines.

**Decision.**

- **Rspamd 3.x**: spam scoring, SPF/DKIM/DMARC/ARC, phishing heuristics. Runs as a milter in-session (only obvious spam above score 15 is rejected) and over HTTP `/checkv2` post-queue. Uses Redis for its own state.
- **ClamAV 1.4**: antivirus over the clamd `INSTREAM` TCP protocol. Signatures are updated by freshclam inside the container. We use the `clamav/clamav-debian` image because it is multi-arch (the Alpine image has no arm64 build).
- **YARA**: custom rules for attachments and content, run in-process by `email-worker` (rules versioned in the repo, loaded at startup). Added with the engine-adapter phase.
- URL protection, BEC and DLP are first-party engines that implement the same contract.
- **Contract** (`packages/security-contracts`): `SecurityEngine.scan(input, AbortSignal) → EngineVerdict`, where the outcome is `clean | suspicious | malicious | error | timeout` and the score is normalised to 0–100. Engines never choose the final action; the policy engine does.

**Consequences.** Adding or swapping an engine is local to `email-worker`. Explicit `error` and `timeout` outcomes force policy to make a deliberate fail-safe choice. Production needs its own recursive DNS resolver for Rspamd, because public DNSBLs refuse queries arriving through shared resolvers.
