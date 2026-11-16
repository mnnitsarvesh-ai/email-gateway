# Advanced Threat Protection (ATP): brief

**Status:** requested by the product owner on 2026-11-16 as an extension of the gateway (not a separate application). Much of it builds on steps 4.1–4.6 (rspamd, ClamAV and YARA attachments, URL protection with time-of-click, phishing and BEC, DLP, sandbox orchestration) and 5.1–5.3 (risk scoring, policy engine, quarantine). Its gap analysis classifies every capability as IMPLEMENTED, PARTIALLY_IMPLEMENTED, MISSING or REQUIRES_ENHANCEMENT; only missing or incomplete work is built. The analysis is in [advanced-threat-protection-gap-analysis.md](advanced-threat-protection-gap-analysis.md), and the implementation steps and their place in the execution plan follow from it after approval. The requirements as given follow unchanged.

---

# TASK: Integrate Advanced Threat Protection (ATP) into the Existing Email Security Gateway

Act as a Principal Email Security Architect and Multi-Agent Engineering Lead.

We are already developing an enterprise Email Security Gateway targeting 1 million+ emails per day.

Extend the existing Email Security Gateway by implementing a comprehensive **Advanced Threat Protection (ATP)** module.

IMPORTANT:

- This is an extension of the existing Email Security Gateway.
- Do not create a separate application or independent security platform.
- Reuse existing SMTP, MIME parsing, MySQL 8.4, RabbitMQ, Redis, object storage, security scanning, policy engine and notification services.
- Reuse existing phishing, BEC, malware, URL and DLP engines wherever available.
- Do not duplicate functionality that has already been implemented.
- Maintain compatibility with existing ATO, Email Journaling and Email Archiving modules.

## 1. Repository Analysis

Before implementation, inspect:

1. Existing project architecture.
2. Existing email ingestion and SMTP pipeline.
3. Existing security scanning engines.
4. Existing phishing and BEC detection.
5. Existing URL scanning.
6. Existing malware and attachment scanning.
7. Existing YARA and ClamAV integrations.
8. Existing risk scoring and policy engine.
9. Existing RabbitMQ infrastructure.
10. Existing MySQL database schema.
11. Existing ATO and journaling modules.
12. Existing frontend dashboard.

Prepare an ATP gap analysis.

Classify each capability as:

- IMPLEMENTED
- PARTIALLY_IMPLEMENTED
- MISSING
- REQUIRES_ENHANCEMENT

Only implement missing or incomplete functionality.

## 2. Multi-Agent Development Ownership

Use the existing multi-agent team.

**Agent 1 – Principal Architect**

- Own ATP architecture.
- Define module boundaries and integration contracts.
- Approve database and API changes.
- Coordinate security engine integration.

**Agent 2 – Backend Developer**

- Develop ATP APIs.
- Implement threat investigation and incident management.
- Implement ATP configuration and reporting.

**Agent 3 – Database Engineer**

- Extend MySQL schema.
- Implement migrations and indexes.
- Optimize threat intelligence and detection queries.

**Agent 4 – SMTP Engineer**

- Integrate ATP into inbound and outbound email processing.
- Ensure SMTP routing and delivery behavior remain stable.

**Agent 5 – Processing Engineer**

- Implement asynchronous ATP processing.
- Integrate RabbitMQ and Redis.
- Implement event correlation and retry handling.

**Agent 6 – Security Engineer**

- Implement advanced threat detection.
- Develop sandbox integration.
- Implement threat intelligence, campaign detection and behavioral analysis.
- Integrate phishing, BEC, malware, URL and impersonation detection.

**Agent 7 – Frontend Developer**

- Build ATP dashboard.
- Build threat investigation screens.
- Build threat intelligence management.
- Build sandbox analysis results and reporting.

**Agent 8 – DevOps Engineer**

- Deploy isolated sandbox infrastructure.
- Configure threat intelligence feeds.
- Configure monitoring and scaling.

**Agent 9 – QA Engineer**

- Create attack simulations and security test cases.
- Test malware, phishing, malicious URLs and sandbox workflows.
- Test false positives and system performance.

Agents must work in parallel only where interfaces and file ownership are defined.

## 3. Advanced Phishing Detection

Enhance the existing phishing engine to detect:

- Credential harvesting emails.
- Fake login pages.
- Brand impersonation.
- Executive impersonation.
- Vendor impersonation.
- Financial fraud emails.
- Fake invoice emails.
- Password reset scams.
- Multi-stage phishing campaigns.
- HTML-based phishing.
- Image-based phishing.
- QR-code phishing.
- Suspicious email reply-chain manipulation.
- Lookalike sender domains.
- Display-name spoofing.
- Suspicious authentication patterns.

Analyze:

- Sender identity.
- Reply-To mismatch.
- Return-Path.
- Header anomalies.
- SPF, DKIM and DMARC results.
- Domain age and reputation where reliable data is available.
- URL reputation.
- HTML structure.
- Email language and intent.
- Historical sender behavior.

Provide explainable detection results.

## 4. Advanced BEC Protection

Enhance existing BEC detection.

Detect:

- CEO fraud.
- CFO impersonation.
- Executive impersonation.
- Vendor payment diversion.
- Invoice fraud.
- Bank account change requests.
- Payroll diversion.
- Gift card scams.
- Urgent financial requests.
- Fake supplier communication.
- Conversation hijacking.
- Compromised business email accounts.

Implement:

- Sender relationship analysis.
- Communication pattern analysis.
- Financial request detection.
- Recipient risk analysis.
- Domain similarity analysis.
- Historical communication comparison.

Integrate with ATO signals when account compromise is suspected.

Do not duplicate the existing BEC engine. Extend it.

## 5. Advanced URL Protection

Implement a complete URL security engine.

Capabilities:

- URL extraction from email bodies and attachments.
- URL normalization.
- Domain reputation checking.
- IP reputation checking.
- Redirect-chain analysis.
- Shortened URL expansion.
- Homograph and typosquatting detection.
- Punycode analysis.
- Suspicious TLD detection.
- URL path and query analysis.
- Credential-harvesting detection.
- Phishing landing-page detection.
- Malicious download detection.
- Reputation caching.
- Threat intelligence correlation.

### Time-of-Click Protection

Implement time-of-click URL protection.

When users click a protected URL:

1. Route through the gateway's secure URL inspection service.
2. Validate the destination.
3. Re-evaluate current URL reputation.
4. Check redirect chains.
5. Identify malicious or suspicious destinations.
6. Block or warn according to tenant policy.
7. Log the inspection event.
8. Redirect to the destination only when policy permits.

Implement secure redirect validation, SSRF protections, DNS rebinding protections and safe browsing controls.

Do not expose internal network services through URL scanning.

## 6. Advanced Attachment Protection

Implement advanced attachment security.

Detect:

- Executable files.
- Macro-enabled documents.
- Malicious PDFs.
- Suspicious Office documents.
- Script files.
- Archive-based malware.
- Password-protected archives.
- Double extensions.
- File type mismatches.
- Embedded scripts.
- Suspicious document behavior.
- Malicious embedded URLs.

Integrate:

- ClamAV.
- YARA.
- File signature validation.
- Static file analysis.
- Archive extraction with resource limits.
- Optional external threat intelligence.

Preserve original attachments separately from sanitized or reconstructed files.

## 7. Malware Sandbox Integration

Implement an isolated malware analysis sandbox.

The sandbox must support:

- Windows executable analysis.
- PDF analysis.
- Microsoft Office document analysis.
- Script analysis.
- Archive analysis.
- Suspicious attachment execution.
- Behavioral monitoring.
- Process monitoring.
- File system monitoring.
- Network activity monitoring.
- Registry monitoring where applicable.
- IOC extraction.
- Malware family identification where supported.

### Sandbox Security Requirements

- Run samples in disposable isolated virtual machines.
- Do not execute untrusted samples in normal application containers.
- Prevent access to production networks.
- Restrict outbound connectivity.
- Prevent access to cloud metadata endpoints.
- Use resource limits.
- Implement execution timeouts.
- Destroy or reset analysis environments after execution.
- Securely handle sample storage.
- Record sandbox execution metadata.

Use an existing supported sandbox solution if available. Do not build a malware execution environment from scratch without a separate security architecture review.

## 8. Zero-Day and Unknown Threat Detection

Implement capabilities to identify previously unseen threats using:

- Static analysis.
- Behavioral analysis.
- File entropy.
- Suspicious code patterns.
- Macro behavior.
- Script analysis.
- Sandbox execution.
- Threat intelligence correlation.
- Heuristic detection.
- Anomaly detection.

Store:

- File hash.
- File type.
- Detection engine.
- Detection timestamp.
- Analysis result.
- Behavioral indicators.
- Extracted IOCs.
- Sandbox report.
- Confidence score.

Do not claim zero-day detection guarantees.

## 9. QR-Code Phishing Protection

Implement QR-code security scanning.

Requirements:

- Detect QR codes in email bodies.
- Extract QR codes from image attachments.
- Decode embedded URLs.
- Normalize decoded URLs.
- Send URLs through the existing URL security engine.
- Detect credential harvesting destinations.
- Detect malicious redirect chains.
- Associate QR findings with the email security verdict.
- Provide detailed findings in the admin portal.

## 10. Brand and Domain Impersonation Protection

Implement:

- Lookalike domain detection.
- Typosquatting detection.
- Unicode homograph detection.
- Display-name impersonation.
- Executive impersonation.
- Vendor impersonation.
- Similar domain detection.
- Suspicious sender-domain changes.
- Brand-specific detection policies.

Allow tenants to configure:

- Protected brands.
- Executive identities.
- Trusted vendors.
- Approved sender domains.
- Trusted communication relationships.

## 11. Threat Intelligence Platform

Integrate a modular threat intelligence service.

Support:

- Malicious IP intelligence.
- Malicious domain intelligence.
- URL reputation.
- File hash reputation.
- Malware indicators.
- Phishing indicators.
- Known attacker infrastructure.
- Threat campaign indicators.

Implement provider adapters rather than hardcoding a single threat intelligence provider.

Support:

- Commercial threat feeds.
- Open-source intelligence feeds.
- Internal threat intelligence.
- Manually submitted indicators.
- Tenant-specific indicators.

Implement:

- Feed ingestion.
- Indicator normalization.
- Indicator expiration.
- Reputation scoring.
- Source attribution.
- Confidence levels.
- Redis caching.
- MySQL persistence.
- Scheduled feed updates.

Do not treat unverified threat intelligence as definitive proof of malicious activity.

## 12. Cross-Email Threat Campaign Detection

Implement correlation across multiple emails.

Identify:

- Repeated phishing campaigns.
- Similar malicious URLs.
- Repeated attachment hashes.
- Similar email templates.
- Common sender infrastructure.
- Coordinated impersonation attacks.
- Repeated malicious recipients.
- Related threat indicators.

Support:

- Tenant-level campaign correlation.
- Global campaign correlation where privacy and contractual policies permit.
- Campaign severity.
- Related message identification.
- Campaign timeline.
- Campaign investigation.

Ensure tenant boundaries are preserved.

## 13. AI-Assisted Threat Analysis

Integrate AI as an optional supporting analysis engine.

Use AI to:

- Explain suspicious email behavior.
- Analyze suspicious email language.
- Identify social engineering indicators.
- Summarize sandbox reports.
- Correlate threat findings.
- Generate analyst investigation summaries.
- Recommend remediation actions.

Requirements:

- Treat email bodies and attachments as untrusted input.
- Defend against prompt injection in emails and documents.
- Do not send sensitive email content to external AI providers without explicit tenant authorization and appropriate data controls.
- Do not allow AI to execute actions directly.
- Do not use AI as the sole security verdict authority.
- Maintain explainability and evidence references.

## 14. Unified ATP Risk Scoring

Extend the existing risk scoring engine.

Create a unified ATP risk score from 0 to 100.

Consider:

- Phishing score.
- BEC score.
- URL reputation.
- Malware verdict.
- Sandbox verdict.
- QR-code findings.
- Domain impersonation.
- Threat intelligence matches.
- Campaign correlation.
- Sender reputation.

Suggested initial severity:

- 0–29: LOW
- 30–49: MEDIUM
- 50–74: HIGH
- 75–100: CRITICAL

Make weights and thresholds configurable per tenant.

Store:

- Individual signals.
- Detection evidence.
- Engine versions.
- Confidence.
- Final risk score.
- Policy decision.
- Scan timestamps.

Prevent duplicate findings from artificially increasing risk scores.

## 15. Unified Policy and Response Engine

Integrate ATP with the existing policy engine.

Support:

- Deliver.
- Deliver with warning.
- Quarantine.
- Reject.
- Block malicious URLs.
- Block dangerous attachments.
- Request additional review.
- Notify administrators.
- Escalate to security operations.

Implement:

- Tenant-specific policies.
- Domain-specific policies.
- User-specific policies.
- Severity-based policies.
- Exception management.
- Allowlisting with audit.
- Policy simulation where feasible.

Ensure security decisions remain explainable.

## 16. MySQL 8.4 Database Integration

Inspect existing database tables first.

Extend the existing schema through version-controlled migrations.

Potential additional entities:

- atp_detection_configurations
- atp_detection_rules
- atp_threat_indicators
- atp_threat_intelligence_sources
- atp_threat_feed_sync_logs
- atp_url_scan_results
- atp_attachment_scan_results
- atp_sandbox_jobs
- atp_sandbox_reports
- atp_extracted_iocs
- atp_qr_scan_results
- atp_impersonation_findings
- atp_threat_campaigns
- atp_campaign_messages
- atp_risk_signals
- atp_incidents
- atp_audit_logs

These are proposed entities only. Reuse existing security and incident tables where possible.

Requirements:

- MySQL 8.4.
- Tenant isolation.
- Appropriate foreign keys.
- Index optimization.
- Event deduplication.
- Retention management.
- Version-controlled migrations.
- No raw email or attachment BLOB storage in MySQL.

## 17. RabbitMQ and Redis Integration

Reuse existing infrastructure.

Suggested events:

- atp.email.analysis.requested
- atp.email.analysis.completed
- atp.url.scan.requested
- atp.url.scan.completed
- atp.attachment.scan.requested
- atp.attachment.scan.completed
- atp.sandbox.analysis.requested
- atp.sandbox.analysis.completed
- atp.threat.detected
- atp.campaign.detected
- atp.incident.created
- atp.policy.action.requested

Requirements:

- Durable queues.
- Publisher confirms.
- Manual acknowledgments.
- Retry queues.
- Dead-letter handling.
- Idempotent workers.
- Event versioning.

Redis should be used for reputation caching, rate limiting and short-lived correlation data.

Do not place raw email bodies or attachments in RabbitMQ.

## 18. Frontend Integration

Extend the existing admin portal.

Implement:

### ATP Dashboard

- Total emails analyzed.
- Threats detected.
- Phishing attempts.
- BEC attempts.
- Malicious URLs.
- Malware detections.
- Sandbox detections.
- QR phishing detections.
- Threat campaigns.
- Critical incidents.

### Threat Explorer

- Search by email.
- Search by sender.
- Search by recipient.
- Search by URL.
- Search by file hash.
- Filter by threat type.
- Filter by severity.
- View detailed evidence.

### Sandbox Analysis

- Sandbox job status.
- File analysis details.
- Behavioral indicators.
- Extracted IOCs.
- Malware verdict.
- Sandbox reports.

### Threat Intelligence

- Threat feed management.
- Indicator search.
- Indicator reputation.
- Feed synchronization status.
- Manual IOC submission.

### Campaign Investigation

- Campaign overview.
- Related emails.
- Related domains.
- Related URLs.
- Related file hashes.
- Campaign timeline.

### ATP Policy Configuration

- Threat detection rules.
- Risk thresholds.
- Quarantine policies.
- URL protection settings.
- Attachment protection settings.
- Tenant-specific exceptions.

Follow the existing UI design system.

## 19. Monitoring and Performance

Monitor:

- Email analysis throughput.
- URL scanning latency.
- Attachment scanning latency.
- Sandbox queue depth.
- Sandbox execution duration.
- Threat intelligence feed health.
- Detection failure rate.
- RabbitMQ queue depth.
- Redis cache performance.
- MySQL query performance.
- False-positive rate.

ATP processing must not cause SMTP gateway instability.

Use asynchronous processing for expensive threat analysis, with explicit policy-based handling of pending scans.

## 20. QA and Security Testing

Test:

1. Phishing emails.
2. BEC scenarios.
3. Lookalike domains.
4. Malicious URLs.
5. Redirect-chain attacks.
6. QR-code phishing.
7. Malicious attachments.
8. Macro-enabled documents.
9. Archive-based malware.
10. Password-protected archives.
11. Sandbox execution.
12. Suspicious behavioral indicators.
13. Threat intelligence matches.
14. Campaign correlation.
15. False-positive scenarios.
16. Prompt injection attempts in email content.
17. SSRF and DNS rebinding protections.
18. Tenant isolation.
19. High-volume processing.
20. Existing email gateway regression tests.

Use safe test samples and controlled security test environments.

## 21. Final Acceptance Criteria

ATP is complete only when:

- ATP is integrated into the existing email gateway.
- Existing security engines are reused.
- Advanced phishing and BEC detection work.
- URL protection works.
- Attachment security works.
- Sandbox integration works.
- QR-code phishing detection works.
- Domain impersonation detection works.
- Threat intelligence integration works.
- Campaign correlation works.
- Unified risk scoring works.
- Policy-based response works.
- ATP findings are visible in the existing admin portal.
- MySQL migrations and APIs are complete.
- Automated and integration tests pass.
- Existing email gateway functionality remains stable.

## 22. Final Execution Instructions

Inspect the repository before implementing anything.

Prepare an ATP gap analysis and implementation plan.

Assign tasks to the existing multi-agent team.

Reuse existing services, scanning engines, database tables, APIs and frontend components.

Do not duplicate BEC, phishing, URL, malware, ATO or DLP functionality.

Implement real working integrations, not placeholder functionality.

At completion, provide:

- Agent-wise implementation report.
- Gap analysis.
- Files created and modified.
- Database migrations.
- API documentation.
- Security engine integration details.
- Sandbox architecture.
- Test results.
- Performance results.
- Known limitations.
- Deployment instructions.

This is a production-grade extension of the existing Email Security Gateway. Architecture consistency, security isolation, tenant protection, performance and reliability are mandatory.
