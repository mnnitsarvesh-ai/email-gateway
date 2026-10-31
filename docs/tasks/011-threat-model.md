# 011: Initial STRIDE threat model (docs/threat-model.md)

Owner agent: security-reviewer
Depends on: none. It reads the designs in 002–010 and is updated as they land.
Status: draft
Branch: feat/011-threat-model
Phase: 0

**Why security-reviewer owns this.** Its role definition makes it the only writer of `docs/threat-model.md`. This is a docs-only task. Review is by architect (design consistency) and Sarvesh. code-reviewer isn't needed because there is no code.

## User story

Story: _to be written by product-owner_

As Sarvesh, I want a STRIDE threat model of the gateway before pipeline code is written so that every later task can name the threats it touches and reviewers can check mitigations against a known list.

## Acceptance criteria

AC-1 Given the repo, when `docs/threat-model.md` is checked, then the file exists and contains the six sections: scope and overview, assets, trust boundaries, STRIDE table, open and accepted risks, review triggers.
AC-2 Given the assets section, when read, then it lists all ten asset classes named in the task design notes (EML, verdicts and quarantine, archive, tenant config, identities, DKIM and TLS keys, credentials, outbound IP reputation, audit logs, ClickHouse events).
AC-3 Given the trust boundaries, when counted, then each has an id `TB-n` and the eleven boundaries in the task are present, with Phase 3/4 ones marked as such.
AC-4 Given the STRIDE table, when parsed (a script checks the header row), then every threat row has a unique id, a STRIDE category of S, T, R, I, D or E, a scenario, impact, mitigation, location (rule number, task id or file), status in {`planned`,`implemented`,`verified`} and residual risk, with no empty cell.
AC-5 Given each boundary TB-n, when the table is grouped, then every boundary has at least one threat row and every STRIDE letter appears at least once overall.
AC-6 Given hard rules 1 to 12 in CLAUDE.md, when threat rows are searched for each rule number, then every rule maps to at least one threat entry.
AC-7 Given the list of minimum threats in the task (open relay and connector impersonation, header tenant spoofing, domain verification abuse, cross-tenant access, fail-open paths, message loss and duplication, backscatter and DSN leaks, hostile-input DoS/RCE, SSRF, portal XSS/CSRF/authZ, secrets exposure, outbound abuse, supply chain, operator access, local dev exposure), when searched, then each has at least one row.
AC-8 Given mitigations that cite a task or hard rule, when links are checked, then every referenced task file and rule exists, and the open-relay row cites 004 and the Docker NAT trap row cites 004 and 003.
AC-9 Given the open and accepted risks section, when read, then each entry has an owner and a decision date; NEEDS SARVESH items 1 to 3 appear as open risks (assumes defaults: TLS `encrypt` to tenant servers, tiered plus dedicated IPs, no standing operator access).
AC-10 Given the review-trigger section, when read, then it states an update is required on a new trust boundary, external dependency, data store, input parser or queue.
AC-11 Given the git diff of the task branch, when listed, then only `docs/threat-model.md` (and the task file) changed; no code, config or test file differs.
AC-12 Given the document, when scanned (gitleaks and grep for real malware names, hashes or sample links), then it contains no secret or real sample reference; EICAR is mentioned only by name if at all.

## Out of scope

- Reviewing code. There is none yet.
- A penetration test (Phase 6, external vendor, human task).
- Compliance mapping (DPDP, CERT-In, ISO 27001). Legal and compliance are tracked in `docs/human-tasks.md`.

## Design notes

### Structure of `docs/threat-model.md`

1. **Scope and system overview.** Reference the mail-path diagram in CLAUDE.md, the deployment modes and the regions.
2. **Assets.**
   - EML bodies and attachments (S3).
   - Verdicts and quarantine.
   - Archive copies.
   - Tenant config: domains, mail servers, policy.
   - User identities and sessions.
   - DKIM private keys and TLS keys.
   - DB, broker and S3 credentials.
   - Outbound IP reputation.
   - Audit logs.
   - ClickHouse events, which hold metadata.
3. **Trust boundaries.** Each one gets an id (TB-1 …):
   - internet → inbound Postfix (MX);
   - tenant connector → outbound Postfix (Phase 3);
   - Postfix → `ingest-service` (LMTP);
   - services ↔ MySQL, RabbitMQ, S3 and Redis;
   - scan workers ↔ hostile content (parsers, ClamAV, YARA);
   - URL fetcher → internet (Phase 4);
   - browser → portal → `api`;
   - `delivery-service` → outbound Postfix → tenant servers or the internet;
   - operators → AWS (IAM, Terraform);
   - CI and supply chain → repo and images;
   - SaaS tenant ↔ tenant (logical isolation).
4. **STRIDE table per boundary.** Columns: threat id, STRIDE category, scenario, impact, mitigation, where it's implemented (hard rule number, task id or file), status (`planned` / `implemented` / `verified`), and residual risk.
5. **Open risks and accepted risks**, each with an owner and a decision date.
6. **Review triggers.** Update the model when a change adds a trust boundary, external dependency, data store, input parser or queue.

### Threats to cover at minimum

- **Open relay** and connector impersonation (tenant A sending as tenant B). See 004 and Phase 3.
- **Tenant spoofing through headers.** Planted `X-ESG-*` or spam verdict headers. Direction or tenant taken from `From`/`To` (hard rule 4).
- **Domain verification abuse.** Claiming another organization's domain, or a stale verification after the domain lapses. Mitigated by unique `verified_name` (005); periodic re-verification is needed.
- **Cross-tenant data access.** A forged S3 key in a queue payload (009 `assertKeyBelongsTo`), queries missing `organization_id`, IDOR in the API, and Redis key namespace collisions.
- **Fail-open paths.** A milter outage that accepts mail, an engine crash reported as `clean`, a missing stage treated as passed (hard rule 5, 004 `milter_default_action=tempfail`).
- **Message loss and duplication.** `250` before persist, ack before durable, replica-lag decisions (hard rules 1, 2 and 6).
- **Backscatter and DSN information leaks** (ADR-020, ADR-022).
- **Hostile-input DoS and RCE.** Zip bombs, deep MIME, huge headers, parser exploits in ClamAV, YARA or MIME libraries. Mitigated by sandboxing workers (non-root, read-only filesystem, no egress, memory and CPU limits).
- **SSRF** from URL analysis and webhooks: metadata endpoints, private ranges, DNS rebinding.
- **Portal XSS** through HTML email. Covered by the sandboxed iframe and CSP. CSRF and session theft. AuthZ on quarantine release and attachment download.
- **Secrets exposure.** Logs, images, Terraform state, CI, `.env` files (hard rule 9).
- **Outbound abuse.** A compromised tenant connector spamming, which ruins the shared IP reputation for everyone.
- **Supply chain.** npm dependencies, base images, YARA and rule feeds, ClamAV signature mirror integrity.
- **Operator and insider access** to tenant mail (break-glass, audit).
- **Local dev exposure.** Ports bound to localhost only, and the Docker NAT trust trap on outbound 10025 (see 004).

## Hard rules at risk

This task changes no code. It documents threats against every hard rule, and must map each hard rule (1–12) to at least one threat entry.

## NEEDS SARVESH

1. **Default TLS posture for delivery to tenant mail servers** (security posture). Options: `may` (opportunistic), `encrypt` (STARTTLS required, no cert check) or `verify`. *Recommendation:* default to `encrypt` for tenant downstream servers, because they're our customers and we can require it, with a per-server override recorded in the audit log. For internet outbound (Phase 3), use `may` plus MTA-STS and DANE where published.
2. **Outbound IP strategy** (cost and reputation). Options: (a) one shared IP pool for all SaaS tenants; (b) shared pools tiered by tenant reputation; (c) dedicated IPs per tenant as an add-on. *Recommendation:* (b) plus (c), with per-tenant outbound rate limits from Phase 3.
3. **Operator access to tenant mail content** (break-glass policy). *Recommendation:* no standing access. Time-boxed break-glass with tenant-visible audit entries, documented before dogfood in Phase 3.
