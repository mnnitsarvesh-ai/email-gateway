# Human tasks: only Sarvesh can do these

Owner: Sarvesh. Maintained by architect. Agents never do these. CLAUDE.md hard rule 10 forbids agents from running `terraform apply`/`destroy`, the `aws` CLI, cloud `kubectl` and `git push`, and some items are legal, commercial or account-level decisions.

Items are grouped by the **phase that first needs them** (see [roadmap](phases/roadmap.md)). Several have long lead times, such as the AWS port-25 unblock, legal review and IP warm-up. Start them earlier than the phase they're listed under.

Tick a box only when the item is done. Where an agent needs the result (an ARN, a hostname, a decision), record it in the linked task or ADR.

---

## Ongoing (every phase)

- [ ] **Approve each story and task before work starts.** Confirm product-owner's acceptance criteria, then mark the task `ready`.
- [ ] **Resolve every NEEDS SARVESH item** in task files and ADRs. A task with open items can't go `ready`.
- [ ] **Decide Proposed ADRs.** Accept, reject or amend them. Only you change ADR status.
- [ ] **Review and merge every branch.** Agents commit locally in worktrees. You approve, merge to `main` and push.
- [ ] **Run every `terraform apply`** (and any `destroy`), after reading the plan yourself. Also run any `plan` against a real backend.
- [ ] **Create, rotate and revoke secrets** in AWS Secrets Manager or SSM (DB, RabbitMQ, S3, DKIM keys, TLS keys, OAuth and SAML secrets, webhook signing keys, log-hash HMAC key). Agents only ever see placeholders and ARNs.
- [ ] **Budget watch.** Review AWS Budgets and Cost Anomaly Detection alerts.

## Phase 0: Foundations (weeks 1–3)

- [ ] **Create the git remote and push `main`.** Choose the CI platform (task 001, NEEDS SARVESH). Set branch protection on `main` (required CI checks, no direct pushes, your review required).
- [ ] **Agent permissions in `.claude/settings.json`.**
  - Allow reading `**/.env.example`. It's currently blocked by the `Read(**/.env.*)` deny rule (task 001).
  - Decide whether `terraform init -backend=false`, `terraform test` and `tflint` should be allowed without a prompt for devops-engineer (task 010).
- [ ] **Decide Phase 0 NEEDS SARVESH items.** Package names, table name, cross-tenant system queries, ADR-026 and ADR-027, MinIO image, max message size, log address policy, KMS granularity, corpus sources, ClickHouse hosting, Valkey vs Redis, dedicated account topology, TLS posture, outbound IP strategy, operator break-glass policy. The full list is in each task.
- [ ] **Install local tooling** on your machine: Docker Desktop (or OrbStack), Node 24, pnpm, swaks, Terraform ≥ 1.7.
- [ ] **AWS Organization and accounts.** Start in Phase 0, because Phase 3 needs them.
  - Management account, plus accounts for `security`/`log-archive`, `shared-services` (ECR, CI OIDC), `staging` (dogfood), `prod-saas`, and a pattern for `dedicated-<name>` accounts.
  - IAM Identity Center for human access, with MFA everywhere and no long-lived IAM user keys.
  - SCPs: deny regions other than ap-south-1, ap-south-2 and the global services; deny disabling CloudTrail and GuardDuty.
  - Organization CloudTrail, GuardDuty, Security Hub and AWS Config in both regions.
- [ ] **Budgets.** Per-account AWS Budgets with alerts at 50%, 80% and 100%, plus Cost Anomaly Detection. Set the monthly ceiling for staging and prod.
- [ ] **Terraform remote state bootstrap.** A state S3 bucket (versioned, encrypted, Block Public Access) with locking, in a dedicated account, and the `backend.hcl` values for each env root (task 010). Kept out of git.

## Phase 1: Inbound core (weeks 4–7)

- [ ] **Request removal of the AWS port 25 / email-sending limitation** for the accounts and regions that will send mail (staging and prod, ap-south-1 and ap-south-2). This needs Elastic IPs allocated first. **Start in week 4.** Approval can take days and may require a description of the use case.
- [ ] **Allocate Elastic IPs** for outbound Postfix (both regions). Request **reverse DNS (PTR)** for each, using the same AWS form or support case, for example `out1.<gateway-domain>`. Forward DNS must match the PTR (FCrDNS).
- [ ] **Choose the gateway's own domain and hostnames.** Examples: `mx1.<gateway-domain>` for the tenant MX target, `out1.…` for outbound HELO/PTR, `portal.…`, `api.…`, `mta-sts.…`. Register or allocate them in Route 53.
- [ ] **Set up `postmaster@` and `abuse@`** for the gateway domain (RFC 5321/2142). Blocklist operators and receivers expect them to work.
- [ ] **Decide the default tenant policy for failure states** (roadmap NEEDS SARVESH 3). Needed before the Phase 2 policy engine, but it shapes Phase 1 contracts.

## Phase 2: Security core (weeks 8–12)

- [ ] **Decide ADR-024 (Amazon MQ vs self-managed RabbitMQ) and ADR-025 (Aurora vs RDS MySQL) by the end of week 10.** They block the Phase 3 infrastructure.
- [ ] **ClamAV.**
  - Accept the GPL-2.0 licence terms for running clamd as a separate process. We don't link to it, so our code isn't affected.
  - Decide whether to run a **private signature mirror** (cvdupdate) for production. Cisco Talos rate-limits and blocks heavy freshclam use from cloud IPs.
  - Decide on any **third-party signature feeds** (for example SaneSecurity or commercial feeds) and buy their commercial licences.
- [ ] **YARA rule feeds.** Review the licence of every rule set before it's used. Many public sets are GPL, Detection Rule License or **CC BY-NC (non-commercial, which we can't use)**. Approve each feed and record its licence in `test/corpus` or the rules directory.
- [ ] **Rspamd reputation data.**
  - **Spamhaus**: commercial use needs a paid **Data Query Service (DQS)** subscription. The free public mirrors aren't allowed at our volume or for commercial use.
  - Decide the same for SURBL and URIBL, and for **MaxMind GeoIP** (licence key, EULA).
  - Rspamd's own licence (Apache-2.0) is fine.
- [ ] **TLS certificates for SMTP** (Postfix on EC2 needs certificate files; ACM certs can't be used directly unless they're exported). Options:
  - ACM exportable public certificates (paid);
  - Let's Encrypt using DNS-01 against Route 53, automated on instances;
  - a commercial CA.

  Decide, then create the certs or automation credentials. For the portal and API behind ALB or ingress, use ACM (free).
- [ ] **Apply staging Terraform** in ap-south-1 (week 12), after reviewing the plan. Grant the CI OIDC role ECR push in `shared-services` only.
- [ ] **Create staging secrets** in Secrets Manager: DB writer and reader users, RabbitMQ users, S3 access via IRSA roles (no keys), Redis auth, log-hash HMAC key.

## Phase 3: Portal + outbound; dogfood on Threatcop's domain (weeks 13–16)

- [ ] **Generate DKIM keys** (2048-bit RSA; Ed25519 optional as a second signature) for the Threatcop domain. Store the private keys **only** in Secrets Manager. Publish the selector TXT records.
- [ ] **Threatcop domain DNS for dogfood.**
  - **Lower the MX TTL** (for example to 300 s) at least 48 hours before cutover.
  - Write down the current MX and mail provider as the **rollback target**.
  - Cut the MX over to `mx1.<gateway-domain>`.
  - **SPF**: add the gateway's outbound IPs (`ip4:` or an `include:`), and keep under 10 DNS lookups.
  - **DKIM**: selector records.
  - **DMARC**: start at `p=none` with an `rua=` mailbox you watch, then move to `quarantine` after the dogfood is stable.
  - **MTA-STS** (`_mta-sts` TXT plus the `mta-sts.` HTTPS policy host) and **TLS-RPT** (`_smtp._tls` TXT).
- [ ] **Configure Threatcop's mailbox provider** (Google Workspace or Microsoft 365) so that:
  - inbound is accepted only from the gateway's IPs (inbound connector or allow-list, so attackers can't bypass the MX);
  - outbound smart-hosts through the gateway connector.
- [ ] **IP warm-up plan** for the new outbound IPs. Ramp volume gradually, and register with Microsoft SNDS/JMRP and Google Postmaster Tools.
- [ ] **Blocklist monitoring.** Subscribe to a DNSBL monitoring service, or approve a scheduled check.
- [ ] **Portal identity for staff.** Who in Threatcop gets `org_admin` during dogfood?
- [ ] **Decide the operator break-glass policy** for access to tenant mail (task 011) before real mail flows.
- [ ] **Approve the dogfood go/no-go and the rollback runbook.** Do the cutover yourself.

## Phase 4: Internal mail + advanced detection (weeks 17–20)

- [ ] **URL reputation sources.**
  - **Google Safe Browsing's free API is non-commercial only.** Use Google **Web Risk** (paid) or another commercial feed (for example PhishTank or OpenPhish commercial, or a vendor feed).
  - Approve the vendor and create the API keys in Secrets Manager.
- [ ] **Decide URL rewriting and time-of-click** (roadmap NEEDS SARVESH 5).
- [ ] **Set detection quality targets** (roadmap NEEDS SARVESH 6).
- [ ] **DLP rule policy.** Which identifiers to ship by default (Aadhaar, PAN, card numbers, IFSC and bank accounts), and the default actions.
- [ ] **Egress path for the URL fetcher.** Approve a dedicated egress (NAT or proxy with fixed IPs) that is separate from the mail IPs.

## Phase 5: Enterprise (weeks 21–23)

- [ ] **Archiving product decisions.**
  - Default retention options.
  - Whether to offer **S3 Object Lock** (compliance or governance mode) for archives; it is irreversible in compliance mode.
  - Export formats and pricing.
- [ ] **SSO/SCIM.** Test IdP tenants (for example Okta developer, Entra ID, Google Workspace) to validate against. Approve the SAML signing certificate lifecycle.
- [ ] **Webhook policy.** Allowed destinations (public HTTPS only), signing-key rotation and the retry window.

## Phase 6: Scale, DR, dedicated profile, go-live (weeks 24–26)

- [ ] **Set the latency SLOs and the RPO/RTO** (roadmap NEEDS SARVESH 7).
- [ ] **Apply prod-saas Terraform** in ap-south-1 and the **DR stack in ap-south-2**. Approve the load-test environment's cost and window.
- [ ] **Run or authorise the DR drill.** Declare the primary region lost, switch DNS and MX, and sign the drill report.
- [ ] **External penetration test.** Choose a vendor (CERT-In empanelled auditors are preferred for Indian enterprise buyers), agree the scope, and fix every critical and high finding before go-live.
- [ ] **First dedicated deployment.** Create the customer's account (per the decision in task 010), apply its tfvars, and run its DNS cutover with the customer.
- [ ] **Onboard real customers.** Contracts, the onboarding runbook, domain verification help, MX cutover scheduling, and a support contact.
- [ ] **On-call and incident process.** Paging tool, rota, escalation, and a status page.
- [ ] **Sign the go-live checklist.**

## Legal, compliance and commercial (start in Phase 0; needed before Phase 3 dogfood with real mail, and before any external customer)

- [ ] **DPDP Act 2023 and the DPDP Rules 2025.**
  - Confirm with counsel which obligations apply on which commencement dates.
  - The gateway acts as a **Data Processor** for customers, who are Data Fiduciaries, and as a Fiduciary for its own portal users.
  - Breach notification flow, purpose limitation, and erasure on contract end.
- [ ] **Data residency.** Commit contractually that mail data stays in India (ap-south-1 and ap-south-2). Make sure every sub-processor complies (AWS, ClickHouse Cloud if chosen, URL-reputation vendors that receive URLs, and any error tracking or log SaaS). Publish the **sub-processor list**.
- [ ] **CERT-In Directions (April 2022).** Report cyber incidents within **6 hours**. Keep ICT system logs for **180 days within India**, which affects log and ClickHouse retention. Sync clocks to NTP. Nominate a point of contact.
- [ ] **DPA template** for customers (processing instructions, security measures, sub-processors, deletion, audit rights) and **terms of service**.
- [ ] **Retention policy.** Message metadata, EML, quarantine, archive, audit logs and backups, reconciled with DPDP minimisation and CERT-In's 180 days (task 005, NEEDS SARVESH 3).
- [ ] **Sector requirements** for target customers: RBI or SEBI data localisation and outsourcing guidelines for BFSI customers, and government requirements such as MeitY empanelment if you target them.
- [ ] **Licences of third-party components and feeds** (consolidated). ClamAV and feeds, YARA feeds, Spamhaus DQS, SURBL/URIBL, MaxMind, the URL-reputation vendor, MinIO (AGPL, local dev only), Terraform (BSL; fine for internal use).
- [ ] **Abuse handling policy.** What happens when a tenant sends spam through outbound: suspension terms in the ToS.
