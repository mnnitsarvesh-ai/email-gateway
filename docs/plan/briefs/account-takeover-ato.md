# Account takeover (ATO) detection and prevention: brief

**Status:** requested by the product owner on 2026-11-16 as an extension of the gateway (not a separate application). Planned in two steps:

- **8.4 ATO detection core:** gateway-observed signals (outbound mail behaviour per sending account, SMTP submission authentication on `postfix-outbound` port 587, portal and API logins, IP reputation, BEC and phishing findings on outbound mail), the detection engine (rules, baselines, anomaly and correlation), explainable account risk scores, incidents, the responses the gateway can enforce itself (alerts, notifications, webhooks, SMTP sending restriction, blocking suspicious SMTP authentication, escalation with approvals and rollback), the API and the admin portal pages.
- **8.5 ATO identity-provider adapters:** Microsoft Entra ID / Microsoft 365 and Google Workspace telemetry and provider-confirmed actions, built on the provider-integration framework of step 8.2.

The order relative to 8.1–8.3 is set in the execution plan. The design and gap analysis of 8.4 come first and need approval before implementation. The requirements as given follow unchanged.

---

# TASK: Implement Account Takeover (ATO) Detection and Prevention in the Existing Email Security Gateway

Act as a Principal Email Security Architect, Threat Intelligence Engineer and Multi-Agent Development Lead.

We are already developing an enterprise Email Security Gateway targeting 1 million+ emails per day.

Extend the existing platform by implementing a complete **Account Takeover (ATO) Detection and Prevention module**.

IMPORTANT:

- This is an extension of the existing Email Security Gateway.
- Do not create a separate application or independent security platform.
- Reuse existing authentication, tenant management, MySQL, Redis, RabbitMQ, email processing, security scanning and notification services.
- Do not break existing email gateway functionality.
- Use MySQL 8.4 as the primary transactional database.

## 1. Understand the Existing Repository

Before implementation:

1. Inspect the complete repository.
2. Identify existing authentication and login mechanisms.
3. Identify existing user, tenant, domain and mailbox models.
4. Identify existing SMTP authentication mechanisms.
5. Identify existing email ingestion and delivery pipelines.
6. Identify existing security scanning and risk scoring engines.
7. Identify existing audit logs and notification services.
8. Identify existing API and frontend architecture.
9. Identify existing MySQL tables and migrations.
10. Identify available integration points for external identity providers.

Prepare a gap analysis and implementation plan.

Do not duplicate existing functionality.

## 2. Multi-Agent Responsibilities

Assign work to the existing agents:

**Agent 1 – Principal Architect**

- Design ATO architecture.
- Define event contracts and detection workflows.
- Coordinate integrations.
- Review security and architectural decisions.

**Agent 2 – Backend Developer**

- Develop ATO APIs.
- Implement account security management.
- Implement incident management.
- Implement response and remediation workflows.

**Agent 3 – Database Engineer**

- Design MySQL schema.
- Implement migrations and indexes.
- Optimize security event queries.
- Implement retention and audit metadata.

**Agent 4 – SMTP Engineer**

- Integrate SMTP authentication telemetry.
- Detect suspicious sending activity.
- Identify abnormal SMTP sessions and authentication patterns.

**Agent 5 – Processing Engineer**

- Build asynchronous ATO event processing.
- Integrate RabbitMQ and Redis.
- Implement detection workers and correlation.
- Implement event deduplication and recovery.

**Agent 6 – Security Engineer**

- Develop ATO detection rules.
- Implement anomaly detection and risk scoring.
- Detect suspicious mailbox and email behavior.
- Implement automated response recommendations.

**Agent 7 – Frontend Developer**

- Develop ATO dashboard.
- Develop account risk views.
- Develop incident investigation screens.
- Develop response and remediation UI.

**Agent 8 – DevOps Engineer**

- Configure monitoring and alerting.
- Integrate supported identity-provider telemetry.
- Configure deployment and scaling.

**Agent 9 – QA Engineer**

- Test ATO detection scenarios.
- Test false-positive handling.
- Test automated response workflows.
- Test tenant isolation and performance.

Agents must coordinate through the existing architecture and shared contracts.

## 3. ATO Detection Capabilities

Implement detection for the following scenarios.

### A. Suspicious Login Detection

- Multiple failed login attempts.
- Successful login after repeated failures.
- Login from a new IP address.
- Login from an unusual geographical location.
- Unusual device or browser.
- Unusual login time.
- Impossible or highly improbable travel patterns.
- Multiple geographically inconsistent sessions.
- Suspicious VPN, proxy or anonymizing network indicators, where reliable intelligence is available.
- Login from known malicious IP addresses.
- Unexpected changes in authentication patterns.

Do not treat a VPN or new location alone as proof of compromise.

### B. Credential Compromise Detection

- Credentials appearing in known breach intelligence sources.
- Suspicious authentication attempts using exposed credentials.
- Password spraying patterns.
- Brute-force attempts.
- Credential stuffing.
- Repeated authentication from suspicious IP ranges.
- Unusual authentication success rates.

Never store plaintext passwords or authentication secrets.

### C. Suspicious Mailbox Activity

- Unexpected mailbox access.
- Unusual email sending volume.
- Sudden increase in outbound messages.
- Sending emails to unusual recipient groups.
- Unusual external recipient activity.
- Unusual attachment distribution.
- Abnormal sending frequency.
- Suspicious SMTP authentication.
- Unexpected mailbox forwarding configuration.
- New inbox rules or auto-forwarding rules.
- Unexpected delegate or mailbox permission changes.
- Suspicious OAuth application consent or token usage, where provider telemetry is available.

### D. Suspicious Email Behavior

- Unusual sender behavior.
- Abnormal email subject patterns.
- Unexpected bulk sending.
- Unusual reply-chain behavior.
- Unusual use of financial or payment-related language.
- Sudden change in communication patterns.
- Unusual external communication.
- Suspicious use of an authenticated account to distribute phishing emails.

Integrate with the existing BEC and phishing engines to avoid duplicate detection implementations.

## 4. ATO Detection Engine

Build a modular detection engine.

It should evaluate:

- Authentication events.
- IP reputation.
- Geographic signals.
- Device and session information.
- SMTP authentication events.
- Email sending behavior.
- Recipient patterns.
- Mailbox configuration changes.
- OAuth and identity-provider events.
- Historical account behavior.

Implement:

1. Rule-based detection.
2. Behavioral baseline detection.
3. Anomaly detection.
4. Threat intelligence correlation.
5. Cross-event correlation.
6. Account-level risk scoring.

Start with explainable rule-based detection and statistical baselines. Make advanced machine learning optional and evidence-driven.

Do not use an LLM as the sole ATO detection authority.

## 5. Account Risk Scoring

Implement an account-level risk score from 0 to 100.

Suggested severity:

- 0–29: LOW
- 30–49: MEDIUM
- 50–74: HIGH
- 75–100: CRITICAL

Consider the following signals:

- Login anomaly.
- IP reputation.
- Geographic inconsistency.
- Device change.
- Authentication failure patterns.
- Abnormal outbound email volume.
- Suspicious forwarding rules.
- Unusual recipient activity.
- Credential compromise intelligence.
- OAuth or session anomalies.

Requirements:

- Store individual risk signals.
- Record the reason behind every score.
- Support configurable weights.
- Apply time decay to old signals.
- Prevent duplicate events from artificially increasing scores.
- Maintain account-specific historical baselines.
- Provide explainable detection results.
- Allow authorized analysts to override a verdict with an audit reason.

These score bands are initial defaults, not universal security thresholds. Make them configurable per tenant.

## 6. ATO Incident Management

Create an incident whenever an account crosses the configured risk threshold.

Each incident should include:

- Tenant ID.
- Account ID.
- Email address.
- Risk score.
- Severity.
- Detection timestamp.
- Detection reason.
- Related IP addresses.
- Geographic information, where available.
- Device information, where available.
- Related login events.
- Related outbound emails.
- Related security scan findings.
- Recommended actions.
- Incident status.
- Assigned analyst.
- Investigation notes.
- Resolution details.

Support incident states:

- OPEN
- INVESTIGATING
- CONFIRMED
- FALSE_POSITIVE
- MITIGATED
- RESOLVED

Maintain a complete incident audit trail.

## 7. ATO Prevention and Automated Response

Implement configurable response actions:

- Generate security alert.
- Notify tenant administrator.
- Notify security operations team.
- Require additional authentication through a supported identity provider.
- Revoke supported sessions or tokens.
- Temporarily restrict SMTP sending.
- Block suspicious SMTP authentication.
- Suspend an account through a supported identity-provider integration.
- Require password reset through the identity provider.
- Remove malicious forwarding rules through supported APIs.
- Escalate to manual investigation.

Important safeguards:

- Do not automatically disable legitimate accounts based only on a single weak signal.
- Use configurable response thresholds.
- Require approval for high-impact actions unless an explicit tenant policy authorizes automation.
- Support rollback and account recovery.
- Record every automated action.
- Make response actions idempotent.
- Never claim an action succeeded unless the external provider confirms it.

## 8. Integrations

Design integrations with:

- Microsoft 365 / Microsoft Entra ID.
- Google Workspace.
- Existing SMTP authentication services.
- Existing email gateway.
- Existing identity-provider integrations.

Use supported provider APIs and event sources for:

- Sign-in logs.
- Risk events.
- OAuth application activity.
- Mailbox audit events.
- Forwarding rule changes.
- Delegation changes.
- Session and token events, where supported.

Implement provider-specific adapters rather than hardcoding provider behavior into the core ATO engine.

Do not assume that every identity provider exposes the same events or permissions.

## 9. MySQL 8.4 Database

Inspect existing tables before introducing new ones.

Create migrations for the missing entities, potentially including:

- ato_detection_configurations
- ato_detection_rules
- ato_account_profiles
- ato_account_baselines
- ato_security_events
- ato_risk_signals
- ato_risk_scores
- ato_incidents
- ato_incident_events
- ato_response_actions
- ato_response_action_logs
- ato_ip_reputation_cache
- ato_device_profiles
- ato_provider_integrations
- ato_audit_logs

Requirements:

- Use existing tenant, user, domain and account relationships.
- Add tenant-aware indexes.
- Support high-volume event ingestion.
- Implement event deduplication.
- Implement appropriate retention policies.
- Store risk score history.
- Avoid storing sensitive authentication secrets.
- Use version-controlled migrations.
- Consider high-volume table growth before choosing partitioning strategies.

Do not create duplicate user or tenant tables.

## 10. RabbitMQ and Redis Integration

Reuse existing RabbitMQ infrastructure.

Suggested event types:

- ato.login.detected
- ato.login.failed
- ato.login.success
- ato.authentication.anomaly
- ato.mailbox.activity.detected
- ato.outbound.anomaly.detected
- ato.account.risk.updated
- ato.incident.created
- ato.response.requested
- ato.response.completed

Use Redis for:

- Short-term event correlation.
- Rate limiting.
- Temporary account activity windows.
- IP reputation caching.
- Recent login tracking.
- Detection deduplication.

MySQL remains the durable source of truth.

Implement durable queues, retries, dead-letter handling and idempotent consumers.

## 11. Frontend Integration

Extend the existing Email Gateway admin portal.

Create:

### ATO Dashboard

- Total monitored accounts.
- High-risk accounts.
- Critical incidents.
- Suspicious login activity.
- Suspicious outbound email activity.
- Geographic anomaly overview.
- Incident trends.

### Account Risk Explorer

- Account email.
- Current risk score.
- Risk severity.
- Recent login history.
- Device history.
- IP history.
- Outbound activity.
- Suspicious mailbox changes.
- Detection reasons.

### ATO Incident Management

- Incident list.
- Incident details.
- Risk signals.
- Investigation timeline.
- Analyst assignment.
- Investigation notes.
- Recommended remediation.
- Resolution workflow.

### ATO Policy Configuration

- Risk thresholds.
- Detection rules.
- IP reputation settings.
- Behavioral baseline configuration.
- Notification settings.
- Automated response settings.
- Provider integration configuration.

Use the existing frontend design system and RBAC.

## 12. Notifications and Reporting

Integrate with existing notification services.

Support:

- Email alerts.
- Admin dashboard notifications.
- Webhooks.
- Security incident reports.
- Daily and weekly ATO summaries.
- Critical account compromise alerts.

Do not expose sensitive login credentials, tokens or unnecessary personal information in notifications.

## 13. Monitoring and Performance

Monitor:

- Authentication event ingestion rate.
- Detection processing latency.
- Number of suspicious logins.
- ATO incidents by severity.
- False-positive rate.
- Automated response success rate.
- RabbitMQ queue depth.
- Redis performance.
- MySQL query performance.
- Provider integration failures.

Ensure ATO detection does not block the SMTP gateway's critical email processing path.

Use asynchronous event processing for behavioral detection.

## 14. QA and Security Testing

Test:

1. Brute-force login attempts.
2. Credential stuffing patterns.
3. Suspicious geographic logins.
4. New device login.
5. Impossible travel signals.
6. Suspicious IP reputation.
7. Abnormal outbound email volume.
8. Unusual recipient patterns.
9. Suspicious forwarding rules.
10. OAuth anomalies.
11. Account risk escalation.
12. False-positive handling.
13. Session revocation.
14. SMTP restriction and restoration.
15. Identity-provider integration failures.
16. Tenant isolation.
17. Duplicate event processing.
18. High-volume event ingestion.
19. Recovery after worker failure.
20. Existing Email Gateway regression tests.

Create synthetic test accounts and events. Never use real credentials or unauthorized accounts for testing.

## 15. Final Acceptance Criteria

ATO is complete only when:

- ATO events are collected from supported sources.
- Suspicious account behavior is detected.
- Account risk scores are explainable.
- Incidents are created and managed.
- Automated and manual response workflows work.
- Identity-provider integrations are functional where configured.
- Suspicious SMTP sending can be restricted safely.
- All actions are auditable.
- MySQL migrations and APIs are complete.
- Frontend dashboard and incident management are integrated.
- Unit, integration and end-to-end tests pass.
- Existing Email Gateway functionality remains stable.

## 16. Final Execution Instructions

This is an extension of the existing Email Security Gateway.

Inspect the repository first, identify reusable components, prepare the gap analysis and obtain Principal Architect approval.

Use multiple agents for parallel development where dependencies permit.

Do not duplicate BEC, phishing, threat intelligence, authentication, email scanning or incident management functionality.

Implement actual working functionality rather than placeholder APIs.

At completion, provide:

- Agent-wise implementation report.
- Files created and modified.
- MySQL migrations.
- API documentation.
- Detection rules.
- Integration details.
- Test results.
- Known limitations.
- Production deployment instructions.
