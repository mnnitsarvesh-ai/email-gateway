# Entity-relationship diagrams

One overview and one diagram per module. Columns are limited to keys and the columns that define relationships; the full column lists are in [schema-reference.md](schema-reference.md).

Legend:

- **Solid line** (`--`): a real foreign key.
- **Dashed line** (`..`): a **logical** reference with no foreign key. Every reference to or from a partitioned table is logical, because MySQL does not allow foreign keys on partitioned tables. Integrity comes from writing parent and children in one transaction.
- Partitioned tables carry `PARTITIONED` in their attribute list, with the partition column marked `PK` as part of the composite primary key.
- `organizations` appears in most module diagrams; every tenant-owned table references it (`organization_id`).

## Overview

```mermaid
flowchart LR
  subgraph tenant[Tenant management]
    organizations
    organization_plans
  end
  subgraph iam[Identity and access]
    users
    roles
    permissions
  end
  subgraph domain[Domains and SMTP connectors]
    domains
    smtp_connectors
  end
  subgraph mail[Email metadata - partitioned]
    message_identities
    email_messages[(email_messages P)]
    email_message_parses[(email_message_parses P)]
  end
  subgraph security[Security]
    email_scans[(email_scans P)]
    email_auth_results[(email_auth_results P)]
    attachment_scan_results[(attachment_scan_results P)]
    sandbox_submissions[(sandbox_submissions P)]
    sandbox_analyses
    sandbox_artifacts
    message_urls[(message_urls P)]
    url_scan_results[(url_scan_results P)]
    url_rewrites[(url_rewrites P)]
    url_dynamic_inspections[(url_dynamic_inspections P)]
    url_click_events[(url_click_events P)]
    bec_scan_results[(bec_scan_results P)]
    scan_engine_settings
    attachment_rescan_jobs
    bec_profiles[bec_executive_profiles, bec_vendor_profiles, bec_trusted_senders]
    bec_feedback
    bec_suppression_rules
    bec_contact_history
    dlp_scan_results[(dlp_scan_results P)]
    dlp_evidence[(dlp_evidence P)]
    dlp_policies[dlp_policies, dlp_policy_rules]
    dlp_exceptions
    dlp_config[dlp_custom_patterns, dlp_keyword_dictionaries, dlp_compliance_settings]
    message_risk_scores[(message_risk_scores P)]
    risk_scoring_profiles
    risk_scoring_profile_versions
  end
  subgraph policy[Policy]
    email_policies
    policy_settings
    tenant_departments[tenant_departments, tenant_department_members]
    policy_execution_logs[(policy_execution_logs P)]
  end
  subgraph delivery[Delivery]
    email_deliveries[(email_deliveries P)]
    delivery_reinjections[(delivery_reinjections P)]
    delivery_status_events[(delivery_status_events P)]
  end
  subgraph quarantine[Quarantine]
    quarantine_messages
    quarantine_approval_requests
    quarantine_object_purges
  end
  subgraph archive[Archiving and eDiscovery]
    email_archives[(email_archives P)]
    archive_capture_intents[(archive_capture_intents P)]
    archive_disposals[(archive_disposals P)]
    archive_encryption_keys
    ediscovery_cases[ediscovery_cases, custodians, searches, hits, exports]
    archive_record_sources[(archive_record_sources P)]
    archive_dedupe_keys
  end
  subgraph intake[Journal intake]
    journal_intake_sources
    journal_intake_counters
    journal_intake_messages[(journal_intake_messages P)]
  end
  subgraph integrations[Provider integrations]
    provider_connections
    provider_connection_grants[provider_connection_grants, provider_consent_states, provider_connection_domains]
    provider_health[provider_validation_runs, provider_probe_observations, provider_health_checks, provider_health_events, provider_relay_counters]
    provider_egress[provider_egress_range_sets, provider_egress_ranges]
  end
  subgraph apimode[API-mode protection]
    api_mode_connections
    api_mailboxes[api_mailboxes, api_mailbox_addresses]
    api_message_copies[(api_message_copies P)]
    api_mode_counters[api_mode_counters, api_copy_dedupe_keys]
  end
  subgraph assistant[AI assistant]
    ai_chat_settings
    ai_chat_conversations[ai_chat_conversations, ai_chat_turns, ai_chat_messages, ai_chat_tool_executions, ai_chat_action_confirmations]
    ai_chat_usage_daily
  end
  subgraph ops[Platform operations]
    message_outbox[(message_outbox P)]
    audit_logs[(audit_logs P)]
    api_idempotency_keys
    webhook_subscriptions
    webhook_events[(webhook_events P)]
    webhook_deliveries[(webhook_deliveries P)]
    notification_settings[notification_settings, notification_user_preferences, notification_alert_windows]
  end
  organization_plans --> organizations
  organizations --> users
  organizations --> roles
  organizations --> domains
  organizations --> smtp_connectors
  organizations --> provider_connections
  provider_connections --> smtp_connectors
  organizations --> email_policies
  organizations --> message_identities
  message_identities -.-> email_messages
  domains -.-> email_messages
  email_messages -.-> email_message_parses
  email_messages -.-> email_scans
  email_scans -.-> email_auth_results
  email_scans -.-> attachment_scan_results
  email_scans -.-> sandbox_submissions
  sandbox_submissions -.-> sandbox_analyses
  sandbox_analyses --> sandbox_artifacts
  email_messages -.-> message_urls
  email_scans -.-> url_scan_results
  email_scans -.-> url_rewrites
  email_scans -.-> url_dynamic_inspections
  message_urls -.-> url_click_events
  organizations --> scan_engine_settings
  organizations --> attachment_rescan_jobs
  email_scans -.-> bec_scan_results
  organizations --> bec_profiles
  organizations --> bec_feedback
  organizations --> bec_suppression_rules
  organizations --> bec_contact_history
  bec_scan_results -.-> bec_feedback
  email_scans -.-> dlp_scan_results
  email_scans -.-> dlp_evidence
  organizations --> dlp_policies
  organizations --> dlp_exceptions
  organizations --> dlp_config
  dlp_policies --> dlp_exceptions
  email_scans -.-> message_risk_scores
  organizations --> risk_scoring_profiles
  risk_scoring_profiles --> risk_scoring_profile_versions
  risk_scoring_profile_versions -.-> email_scans
  email_messages -.-> email_deliveries
  delivery_reinjections -.-> email_deliveries
  email_deliveries -.-> delivery_status_events
  email_messages -.-> quarantine_messages
  email_messages -.-> email_archives
  email_messages -.-> archive_capture_intents
  email_archives -.-> archive_disposals
  email_archives -.-> archive_record_sources
  email_archives -.-> archive_dedupe_keys
  organizations --> journal_intake_sources
  provider_connections --> journal_intake_sources
  journal_intake_sources --> journal_intake_counters
  email_messages -.-> journal_intake_messages
  journal_intake_sources -.-> journal_intake_messages
  organizations --> api_mode_connections
  provider_connections --> api_mode_connections
  api_mode_connections --> api_mailboxes
  api_mode_connections --> api_mode_counters
  email_messages -.-> api_message_copies
  api_mailboxes -.-> api_message_copies
  organizations --> archive_encryption_keys
  organizations --> ediscovery_cases
  email_messages -.-> message_outbox
  email_policies -.-> email_messages
  organizations --> policy_settings
  organizations --> tenant_departments
  email_messages -.-> policy_execution_logs
  organizations -.-> audit_logs
  organizations -.-> api_idempotency_keys
  organizations --> webhook_subscriptions
  webhook_subscriptions -.-> webhook_deliveries
  webhook_events -.-> webhook_deliveries
  organizations --> notification_settings
  organizations --> ai_chat_settings
  organizations --> ai_chat_conversations
  users --> ai_chat_conversations
  organizations --> ai_chat_usage_daily
  ai_chat_conversations -.-> audit_logs
```

Solid arrows are foreign keys, dotted arrows are logical references. Cylinders (`P`) are partitioned tables.

## Tenant management

```mermaid
erDiagram
  organization_plans ||--o{ organizations : "plan_id"
  organizations ||--o| organization_settings : "1:1"
  organizations ||--o{ organization_limits : ""
  organizations ||--o{ organization_features : ""
  organizations ||--o{ organization_deployments : ""
  organization_plans {
    bigint id PK
    varchar code UK
    json default_limits
    json default_features
  }
  organizations {
    bigint id PK
    char public_id UK
    varchar slug UK
    enum kind "customer or platform"
    enum status
    bigint plan_id FK
    enum deployment_mode
    bigint deletion_requested_by_user_id "no FK"
    bigint deletion_confirmed_by_user_id "no FK"
    datetime purge_after "IDX with status"
  }
  organization_settings {
    bigint id PK
    bigint organization_id FK,UK
    bool mfa_required
  }
  organization_limits {
    bigint id PK
    bigint organization_id FK
    varchar limit_key "UQ with organization_id"
  }
  organization_features {
    bigint id PK
    bigint organization_id FK
    varchar feature_key "UQ with organization_id"
  }
  organization_deployments {
    bigint id PK
    bigint organization_id FK
    enum status
  }
```

## Identity and access management

```mermaid
erDiagram
  organizations ||--o{ users : ""
  organizations |o--o{ roles : "NULL = system role"
  roles ||--o{ role_permissions : "CASCADE"
  permissions ||--o{ role_permissions : ""
  users ||--o{ user_roles : "CASCADE"
  roles ||--o{ user_roles : ""
  users |o--o{ user_roles : "granted_by"
  users ||--o{ user_sessions : "CASCADE"
  users ||--o{ user_tokens : "CASCADE"
  users |o--o{ user_tokens : "created_by, SET NULL"
  organizations ||--o{ user_tokens : ""
  users ||--o{ user_mfa_recovery_codes : "CASCADE"
  organizations ||--o{ user_mfa_recovery_codes : ""
  organizations ||--o{ api_keys : ""
  users |o--o{ api_keys : "created_by"
  organizations |o--o{ login_audit_logs : "nullable"
  users |o..o{ login_audit_logs : "no FK, survives deletion"
  users {
    bigint id PK
    char public_id UK
    bigint organization_id FK
    varchar email "UQ with organization_id"
    enum status
    bigint mfa_last_used_step "TOTP replay protection"
  }
  roles {
    bigint id PK
    bigint organization_id FK "nullable"
    varchar key "UQ with organization_id"
    bool is_system
  }
  permissions {
    bigint id PK
    varchar key UK "resource:action"
  }
  role_permissions {
    bigint role_id PK,FK
    bigint permission_id PK,FK
  }
  user_roles {
    bigint user_id PK,FK
    bigint role_id PK,FK
    bigint organization_id FK
  }
  user_sessions {
    bigint id PK
    bigint user_id FK
    char refresh_token_hash UK
    char family_id "IDX with revoked_at"
    datetime absolute_expires_at
    bool mfa_authenticated
  }
  user_tokens {
    bigint id PK
    bigint organization_id FK
    bigint user_id FK
    enum purpose "invitation, password_reset, email_verification"
    char token_hash UK "SHA-256"
    datetime consumed_at
    bigint created_by_user_id FK "nullable"
  }
  user_mfa_recovery_codes {
    bigint id PK
    bigint organization_id FK
    bigint user_id FK
    char code_hash "UQ with user_id"
    datetime used_at
  }
  api_keys {
    bigint id PK
    char public_id UK
    varchar key_prefix UK
    char key_hash
  }
  login_audit_logs {
    bigint id PK
    bigint organization_id "nullable"
    bigint user_id "nullable, no FK"
    enum outcome
  }
```

## Domain management and SMTP connectors

Step 2.2 added the recipient allow-list (`domain_recipient_addresses`, D3) and the organization-level outbound connectors (`smtp_connectors` and `smtp_connector_networks`, D10). `created_by_user_id` on both (FK to `users`, `SET NULL`) is omitted from the diagram. Step 2.3 added `public_id`, `provider` and `tls_verify_names` to `domain_mail_servers` and the platform table `mail_destination_presets` (R2). A server's `provider` names a preset by value only: presets are configuration data, so there is no foreign key.

```mermaid
erDiagram
  organizations ||--o{ domains : ""
  domains ||--o{ domain_recipient_addresses : "CASCADE"
  organizations ||--o{ domain_recipient_addresses : ""
  organizations ||--o{ smtp_connectors : ""
  smtp_connectors ||--o{ smtp_connector_networks : "CASCADE"
  organizations ||--o{ smtp_connector_networks : ""
  domains ||--o{ domain_verifications : "CASCADE"
  domains ||--o{ domain_dns_records : "CASCADE"
  domains ||--o{ domain_dkim_keys : "CASCADE"
  domains ||--o{ domain_mx_records : "CASCADE"
  domains ||--o{ domain_mail_servers : "CASCADE"
  domains ||--o| domain_settings : "1:1, CASCADE"
  domain_dkim_keys |o--o{ domain_dns_records : "dkim_key_id, SET NULL"
  domains {
    bigint id PK
    char public_id UK
    bigint organization_id FK
    varchar name "lower-case punycode"
    enum status "pending_verification, verified, failed, active, suspended, deleted"
    datetime next_check_at "background DNS checks"
    varchar verified_name UK "generated: name when verified, active or suspended"
    varchar live_name "generated: name unless deleted; UK with organization_id"
  }
  domain_verifications {
    bigint id PK
    bigint domain_id FK
    enum status
    enum last_outcome "DnsCheckOutcome"
  }
  domain_dns_records {
    bigint id PK
    bigint domain_id FK
    varchar record_key "UQ with domain_id"
    enum purpose
    bigint dkim_key_id FK "nullable"
    enum status "last definitive outcome"
    enum last_outcome "DnsCheckOutcome"
  }
  domain_dkim_keys {
    bigint id PK
    bigint domain_id FK
    varchar selector "UQ with domain_id"
    text private_key_ciphertext "SecretBox-encrypted, NULL once retired (ADR-0018)"
    varchar private_key_ref "external store reference, nullable"
    datetime retire_after "rotation overlap"
  }
  domain_mx_records {
    bigint id PK
    bigint domain_id FK
    varchar host "UQ with domain_id"
  }
  domain_mail_servers {
    bigint id PK
    char public_id UK "step 2.3, API id"
    bigint domain_id FK
    enum role "inbound_destination; outbound_source deprecated (2.2 D10)"
    varchar host "index with port (tls_policy)"
    enum provider "custom, microsoft_365, google_workspace"
    varchar tls_verify_names "Postfix match= list, NULL = nexthop"
  }
  mail_destination_presets {
    enum provider PK "microsoft_365, google_workspace"
    json host_patterns "anchored regexes"
    json default_servers "NULL = customer supplies the host"
    enum tls_mode "verify"
    tinyint max_servers
  }
  domain_settings {
    bigint id PK
    bigint domain_id FK,UK
    enum recipient_validation "none, list, smtp_callout, ldap"
  }
  domain_recipient_addresses {
    bigint id PK
    bigint organization_id FK
    bigint domain_id FK
    varchar local_part "UQ with domain_id"
  }
  smtp_connectors {
    bigint id PK
    char public_id UK
    bigint organization_id FK
    varchar name "UQ with organization_id"
    enum auth_type "sasl, source_ip, client_certificate"
    enum status "active, disabled"
    varchar sasl_username UK "sasl only"
    varchar secret_hash "Argon2id, never returned"
    char cert_fingerprint_sha256 UK "client_certificate only"
  }
  smtp_connector_networks {
    bigint id PK
    bigint organization_id FK
    bigint connector_id FK
    varchar cidr "UQ with connector_id"
    tinyint ip_version "index with range_start"
    varbinary range_start "4 or 16 bytes"
    varbinary range_end "ranges never overlap"
  }
```

## Email metadata

```mermaid
erDiagram
  organizations ||--o{ message_identities : ""
  message_identities ||..|| email_messages : "id = registry id, no FK"
  domains |o..o{ email_messages : "domain_id, no FK"
  email_messages ||..|{ email_recipients : "message_id + received_at"
  email_messages ||..o{ email_headers : "message_id + received_at"
  email_messages ||..o{ email_attachments : "message_id + received_at"
  email_messages ||..o{ email_events : "message_id + received_at"
  email_messages ||..|{ email_message_status_history : "message_id + received_at"
  email_messages ||..o| email_message_parses : "message_id + received_at, one per message"
  message_identities {
    bigint id PK "allocates the message id"
    char public_id UK
    bigint organization_id FK
    varchar ingest_key "UQ with organization_id; v2 + SHA-256 of mta, queue id, direction, content, recipient set"
    datetime received_at
  }
  email_messages {
    bigint id PK "registry id"
    datetime received_at PK "PARTITIONED month"
    bigint organization_id
    enum status "lifecycle state, 16 values (ADR-0025; journaled since 8.6)"
    enum ingest_source "gateway, journal_intake (8.6)"
    int version "+1 per applied transition"
    smallint lifecycle_round "+1 on rescan and release (step 3.3)"
    varchar status_reason "reason code of the last transition"
    varchar mta_queue_id "utf8mb4_bin, case-sensitive"
    varchar eml_object_key "S3 key org/ORG/eml/YYYY/MM/DD/REF.eml, no content"
  }
  email_recipients {
    bigint id PK
    datetime received_at PK "PARTITIONED month"
    bigint message_id
    smallint rcpt_seq
    enum direction "routed direction (step 2.3), NULL before"
  }
  email_headers {
    bigint id PK
    datetime received_at PK "PARTITIONED month"
    bigint message_id
  }
  email_attachments {
    bigint id PK
    datetime received_at PK "PARTITIONED month"
    bigint message_id
    smallint part_index "UQ with message_id, received_at; node index in the parse structure"
    char sha256
    varchar object_key "S3 key org/ORG/part/YYYY/MM/DD/MSG/IDX.att, NULL when not stored"
    json flags "ATTACHMENT_FLAGS codes (step 3.1)"
  }
  email_events {
    bigint id PK
    datetime received_at PK "PARTITIONED month"
    bigint message_id
  }
  email_message_status_history {
    bigint id PK
    datetime received_at PK "PARTITIONED month"
    bigint message_id
    int version "UQ with message_id, received_at; 0 = NULL to received"
    enum from_status
    enum to_status
    varchar actor_role "legacy before step 3.3"
    char transition_key "UQ with message_id, received_at; hex SHA-256"
    char state_event_id "mail.message.state_changed.v1 event id"
  }
  email_message_parses {
    bigint id PK
    datetime received_at PK "PARTITIONED month"
    bigint message_id "UQ with received_at"
    bigint organization_id
    enum status "parsing, parsed, parsed_with_defects, parse_limit_exceeded, parse_failed"
    varchar text_body_object_key "S3 key org/ORG/part/YYYY/MM/DD/MSG/IDX.text, no content"
    varchar html_body_object_key "S3 key .../IDX.html"
  }
```

Every write of the lifecycle columns of `email_messages` (`status`, `status_changed_at`, `version`, `lifecycle_round`, `status_reason`) and every `email_message_status_history` row goes through `@email-gateway/message-lifecycle` (step 3.3 L5, one door). A message's history starts with version 0 (`NULL → received`) and its highest version equals `email_messages.version`; the migration `20261104130000_message_lifecycle` backfilled both for older rows.

`email_message_parses` (step 3.1) is the parse stage record written by email-worker: at most one row per message, in the message's partition. Headers and attachment rows of the same message are written in the transaction that finalizes it.

## Security

```mermaid
erDiagram
  email_messages ||..o{ email_scans : "message_id + received_at, one per lifecycle_round"
  email_scans ||..o{ scan_engine_results : "scan_id + received_at, attempts + one final per engine"
  email_scans ||..o{ email_auth_results : "scan_id + received_at, one per engine"
  organizations ||--o{ scan_engine_settings : "RESTRICT, one per engine"
  users |o--o{ scan_engine_settings : "updated_by, SET NULL"
  email_scans ||..o{ attachment_scan_results : "scan_id + received_at, one per attachment"
  email_attachments ||..o{ attachment_scan_results : "attachment_id, one per round"
  email_scans ||..o{ sandbox_submissions : "scan_id + received_at, one per submitted attachment"
  sandbox_analyses |o..o{ sandbox_submissions : "analysis_id (logical), many submissions per analysis"
  sandbox_analyses ||--o{ sandbox_artifacts : "RESTRICT, unique (analysis_id, seq)"
  organizations |o--o{ attachment_rescan_jobs : "RESTRICT, NULL = every organization"
  users |o--o{ attachment_rescan_jobs : "requested_by, SET NULL"
  users |o--o{ malware_signatures : "added_by, SET NULL"
  organizations |o--o{ threat_indicators : "NULL = platform feed"
  users |o--o{ threat_indicators : "added_by, SET NULL"
  email_messages ||..o{ message_urls : "message_id + received_at, one per unique URL"
  email_scans ||..o{ url_scan_results : "scan_id + received_at, one per URL"
  message_urls ||..o{ url_scan_results : "url_seq, one per round"
  email_scans ||..o| url_rewrites : "scan_id + received_at, one per round"
  email_scans ||..o{ url_dynamic_inspections : "scan_id + received_at, one per inspected URL"
  message_urls ||..o{ url_click_events : "message_id + message_received_at + url_seq"
  email_scans ||..o| bec_scan_results : "scan_id + received_at, one per round"
  organizations ||--o{ bec_executive_profiles : "RESTRICT"
  organizations ||--o{ bec_vendor_profiles : "RESTRICT"
  organizations ||--o{ bec_trusted_senders : "RESTRICT"
  organizations ||--o{ bec_feedback : "RESTRICT"
  organizations ||--o{ bec_suppression_rules : "RESTRICT"
  organizations ||--o{ bec_contact_history : "RESTRICT"
  users |o--o{ bec_executive_profiles : "created_by, updated_by, SET NULL"
  users |o--o{ bec_vendor_profiles : "created_by, updated_by, SET NULL"
  users |o--o{ bec_trusted_senders : "created_by, SET NULL"
  users |o--o{ bec_feedback : "created_by, SET NULL"
  users |o--o{ bec_suppression_rules : "created_by, SET NULL"
  bec_scan_results ||..o{ bec_feedback : "bec_result_id + message_received_at"
  bec_feedback ||..o{ bec_suppression_rules : "feedback_id (logical)"
  email_scans ||..o| dlp_scan_results : "scan_id + received_at, one per round"
  email_scans ||..o| dlp_evidence : "scan_id + received_at, at most one per round"
  dlp_policies |o..o{ dlp_scan_results : "matched_policy_id (logical)"
  dlp_policy_rules |o..o{ dlp_scan_results : "matched_rule_id (logical)"
  organizations ||--o{ dlp_policies : "RESTRICT"
  organizations ||--o{ dlp_policy_rules : "RESTRICT"
  organizations ||--o{ dlp_exceptions : "RESTRICT"
  organizations ||--o{ dlp_custom_patterns : "RESTRICT"
  organizations ||--o{ dlp_keyword_dictionaries : "RESTRICT"
  organizations ||--o| dlp_compliance_settings : "RESTRICT, one per organization"
  dlp_policies ||--o{ dlp_policy_rules : "RESTRICT"
  dlp_policies |o--o{ dlp_exceptions : "policy target, RESTRICT"
  dlp_policy_rules |o--o{ dlp_exceptions : "rule target, RESTRICT"
  users |o--o{ dlp_policies : "created_by, updated_by, SET NULL"
  users |o--o{ dlp_policy_rules : "created_by, updated_by, SET NULL"
  users |o--o{ dlp_exceptions : "created_by, updated_by, SET NULL"
  users |o--o{ dlp_custom_patterns : "created_by, updated_by, SET NULL"
  users |o--o{ dlp_keyword_dictionaries : "created_by, updated_by, SET NULL"
  users |o--o{ dlp_compliance_settings : "aadhaar_recorded_by, SET NULL"
  email_scans ||..o{ message_risk_scores : "scan_id + received_at, one per revision (0, 1)"
  organizations ||--o| risk_scoring_profiles : "RESTRICT, one per organization"
  organizations ||--o{ risk_scoring_profile_versions : "RESTRICT"
  risk_scoring_profiles ||--o{ risk_scoring_profile_versions : "RESTRICT, unique (profile_id, version_no)"
  risk_scoring_profiles |o..o| risk_scoring_profile_versions : "active_version_id, no FK (cycle)"
  risk_scoring_profile_versions |o..o{ email_scans : "risk_profile_version_id snapshot (logical)"
  risk_scoring_profile_versions |o..o{ message_risk_scores : "profile_version_id (logical)"
  users |o--o{ risk_scoring_profiles : "updated_by, SET NULL"
  users |o--o{ risk_scoring_profile_versions : "created_by, updated_by, published_by, SET NULL"
  organizations |o--o{ yara_rules : "NULL = platform rule"
  users |o--o{ yara_rules : "updated_by"
  email_scans {
    bigint id PK
    datetime received_at PK "PARTITIONED month"
    bigint message_id
    smallint lifecycle_round "UK with message_id, received_at"
    enum scan_kind
    enum status
    enum scan_verdict
    json required_engines
    json reason_codes
    datetime deadline_at
    bigint risk_profile_version_id "nullable, no FK, snapshot at open"
  }
  scan_engine_results {
    bigint id PK
    datetime received_at PK "PARTITIONED month"
    bigint scan_id
    varchar engine
    smallint attempt
    tinyint is_final
    varchar final_engine "generated: IF(is_final = 1, engine, NULL); in a UK"
    enum outcome
    json reason_codes
    json evidence
  }
  email_auth_results {
    bigint id PK
    datetime received_at PK "PARTITIONED month"
    bigint scan_id
    varchar engine
    enum spf
    enum dkim
    enum dmarc
    enum arc
  }
  scan_engine_settings {
    bigint id PK
    bigint organization_id FK
    varchar engine
    json settings
    int version
  }
  threat_indicators {
    bigint id PK
    bigint organization_id "nullable"
    char value_sha256
    bigint org_scope "generated: IFNULL(organization_id, 0); in the UK"
    enum category "nullable, step 4.3"
    bigint added_by_user_id FK "nullable, step 4.3"
  }
  message_urls {
    bigint id PK
    datetime received_at PK "PARTITIONED month"
    bigint message_id "UK with url_seq / url_sha256, received_at"
    smallint url_seq
    varchar url "normalized redirect form, the only redirect target"
    char url_sha256 "identity form"
    varchar host
    enum host_kind
  }
  url_scan_results {
    bigint id PK
    datetime received_at PK "PARTITIONED month"
    bigint scan_id "UK with url_seq, received_at"
    smallint url_seq
    enum verdict "UrlVerdict"
    json reason_codes
    json reputation
    json redirect_chain "hosts only"
  }
  url_rewrites {
    bigint id PK
    datetime received_at PK "PARTITIONED month"
    bigint scan_id "UK with received_at"
    enum status "rewritten, skipped"
    varchar object_key "S3 org/ORG/rewrite/..., nullable"
    varchar skip_reason "nullable"
  }
  url_dynamic_inspections {
    bigint id PK
    datetime received_at PK "PARTITIONED month"
    bigint scan_id "UK with url_seq, received_at"
    smallint url_seq
    enum status "pending, completed, failed, expired"
    json signals "counts, hosts, brand ids"
  }
  url_click_events {
    bigint id PK
    datetime clicked_at PK "PARTITIONED month by clicked_at"
    char public_id "reference id"
    bigint message_id
    datetime message_received_at
    enum decision
    varchar client_network "truncated, nullable"
  }
  bec_scan_results {
    bigint id PK
    datetime received_at PK "PARTITIONED month"
    bigint scan_id "UK with received_at"
    smallint lifecycle_round
    tinyint deterministic_score
    tinyint score
    enum deterministic_verdict
    enum verdict
    json inputs "auth, url, text, history states"
    json rules "codes, weights, offsets, no text"
    json ai "assessments, no text"
  }
  bec_executive_profiles {
    bigint id PK
    char public_id UK
    bigint organization_id FK "UK with normalized_name"
    varchar normalized_name
    json known_addresses
  }
  bec_vendor_profiles {
    bigint id PK
    char public_id UK
    bigint organization_id FK "UK with normalized_name"
    varchar normalized_name
    json domains
  }
  bec_trusted_senders {
    bigint id PK
    char public_id UK
    bigint organization_id FK "UK with kind, value"
    enum kind "address, domain"
    varchar value
    datetime expires_at "nullable"
  }
  bec_feedback {
    bigint id PK
    char public_id UK
    bigint organization_id FK
    bigint scan_id "UK with created_by_user_id, kind"
    bigint bec_result_id
    enum kind "false_positive, false_negative"
  }
  bec_suppression_rules {
    bigint id PK
    char public_id UK
    bigint organization_id FK "UK with reason_code, sender_scope, sender_value"
    varchar reason_code
    datetime expires_at "at most 90 days"
  }
  bec_contact_history {
    bigint id PK
    bigint organization_id FK "UK with scope, key_hash"
    enum scope "sender, pair"
    char key_hash "HMAC-SHA256, no plaintext"
    int message_count
    datetime last_seen_at
  }
  dlp_scan_results {
    bigint id PK
    datetime received_at PK "PARTITIONED month"
    bigint scan_id "UK with received_at"
    smallint lifecycle_round
    enum verdict
    enum action "allow .. block"
    enum action_source
    bigint matched_policy_id "nullable, no FK"
    bigint matched_rule_id "nullable, no FK"
    enum coverage
    json findings "masked samples only"
  }
  dlp_evidence {
    bigint id PK
    datetime received_at PK "PARTITIONED month"
    bigint scan_id "UK with received_at"
    varchar object_key "S3 ciphertext, NULL after delete"
    varchar wrapped_key "NULL = crypto-shredded"
    datetime expires_at
    datetime purged_at "nullable"
  }
  dlp_policies {
    bigint id PK
    char public_id UK
    bigint organization_id FK "UK with name"
    enum mode "enforce, monitor"
    smallint priority
  }
  dlp_policy_rules {
    bigint id PK
    char public_id UK
    bigint organization_id FK
    bigint policy_id FK "UK with name"
    json conditions
    enum action
  }
  dlp_exceptions {
    bigint id PK
    char public_id UK
    bigint organization_id FK "UK with scope, value, target_key"
    enum scope
    varchar value
    bigint policy_id FK "nullable"
    bigint rule_id FK "nullable"
    varchar target_key "all, policy:id, rule:id"
    datetime expires_at
  }
  dlp_custom_patterns {
    bigint id PK
    char public_id UK
    bigint organization_id FK "UK with name"
    varchar pattern "RE2"
    enum validator
  }
  dlp_keyword_dictionaries {
    bigint id PK
    char public_id UK
    bigint organization_id FK "UK with name"
    enum category
    json terms
  }
  dlp_compliance_settings {
    bigint id PK
    bigint organization_id FK "UK"
    boolean aadhaar_enabled
    enum aadhaar_basis "nullable"
    bigint aadhaar_recorded_by_user_id FK "nullable"
    datetime aadhaar_review_due_at "nullable"
  }
  message_risk_scores {
    bigint id PK
    datetime received_at PK "PARTITIONED month"
    bigint scan_id "UK with revision, received_at"
    tinyint revision "0 round, 1 with sandbox"
    bigint message_id
    enum level "none .. critical"
    enum recommended_action "deliver .. block"
    bigint profile_version_id "nullable, no FK"
  }
  risk_scoring_profiles {
    bigint id PK
    char public_id UK
    bigint organization_id FK "UK"
    bigint active_version_id "nullable, no FK"
    int version "CAS"
  }
  risk_scoring_profile_versions {
    bigint id PK
    char public_id UK
    bigint organization_id FK
    bigint profile_id FK "UK with version_no"
    int version_no
    enum status "draft, published"
    json overrides
  }
  ip_reputation {
    bigint id PK
    varchar ip_address UK
  }
  domain_reputation {
    bigint id PK
    varchar domain UK
  }
  url_reputation {
    bigint id PK
    char url_sha256 UK
  }
  malware_signatures {
    bigint id PK
    char sha256 UK
    enum severity
    varchar source "analyst, feed:<name>, sandbox"
    bigint added_by_user_id FK "nullable"
    datetime expires_at "nullable"
  }
  attachment_scan_results {
    bigint id PK
    datetime received_at PK "PARTITIONED month"
    bigint scan_id "UK with attachment_id, received_at"
    bigint attachment_id
    char sha256
    varchar detected_type
    enum verdict
    json reason_codes
    json archive "index paths, no entry names"
  }
  sandbox_submissions {
    bigint id PK
    datetime received_at PK "PARTITIONED month"
    bigint scan_id "UK with attachment_id, received_at"
    bigint attachment_id
    varchar object_key "S3 part key"
    enum status "4.6 appends skipped"
    bigint analysis_id "logical, indexed (4.6)"
    varchar skip_reason "4.6"
  }
  sandbox_analyses {
    bigint id PK
    char public_id UK "task id"
    char sha256
    varchar dedupe_key UK "sha256:analysis_key, nullable"
    enum status
    bigint organization_id "dispatching org, routing only"
    varchar sample_object_key "sandbox bucket"
    enum verdict "nullable"
    json report "bounded view, no content"
  }
  sandbox_artifacts {
    bigint id PK
    bigint analysis_id FK "UK with seq"
    enum kind
    varchar object_key "sandbox bucket"
    varchar wrapped_key "nullable = crypto-shredded"
  }
  attachment_rescan_jobs {
    bigint id PK
    char public_id UK
    varchar dedupe_key UK "nullable"
    bigint organization_id FK "nullable"
    enum trigger
    enum status
  }
  scan_signature_versions {
    bigint id PK
    varchar engine "UK with component, version"
    varchar component
    varchar version
  }
  yara_rules {
    bigint id PK
    varchar rule_key UK
  }
```

The four reputation catalogs and `malware_signatures` are platform-wide; `malware_signatures` references only the analyst who added a hash (step 4.2 A17), and `scan_signature_versions` stands alone.

Step 4.1 ([§3](../plan/steps/09-rspamd.md#3-data-model-one-forward-migration-scan_pipeline-wp1)): a scan round is `(message_id, received_at, lifecycle_round)`, one `email_scans` row; each engine writes its failed attempts as non-final `scan_engine_results` rows and exactly one final row (the unique key on the generated `final_engine`); the Rspamd engine also writes one `email_auth_results` row per round. All three are partitioned and copy the message's `received_at`, so a message's scan graph lives in one partition. `scan_engine_settings` (not partitioned) holds a tenant's override of an engine's platform thresholds, validated by `@email-gateway/security-contracts`.

Step 4.2 ([§3](../plan/steps/10-attachment-scanning.md#3-data-model-one-forward-migration-attachment_scanning-wp1)): the attachment engine writes, in the finalize transaction of its final `scan_engine_results` row, one `attachment_scan_results` row per attachment (logical reference to `email_attachments.id`) and one `sandbox_submissions` row per attachment submitted to the sandbox; both are partitioned and copy the message's `received_at`. Archive entries are findings inside their attachment's row (index paths), not rows. `attachment_rescan_jobs` and `scan_signature_versions` are not partitioned.

Step 4.3 ([§3](../plan/steps/11-url-protection.md#3-data-model-one-forward-migration-url_protection-wp1)): the URL engine writes, in the finalize transaction of its final `scan_engine_results` row, the message's new `message_urls` rows (one per unique URL; a rescan keeps the seqs already stored), one `url_scan_results` row per URL, one `url_rewrites` row and one `url_dynamic_inspections` row per URL sent to the browser worker; all four copy the message's `received_at`. The click-service writes one `url_click_events` row per decided click, partitioned by `clicked_at` and pointing to its URL by `(message_id, message_received_at, url_seq)`. No foreign keys (all five are partitioned); `threat_indicators` gains the analyst who added a platform indicator (`SET NULL`).

Step 4.4 ([§3](../plan/steps/12-phishing-bec.md#3-data-model-one-forward-migration-bec_detection-wp1)): the BEC engine (a stage-2 engine that runs after `rspamd` and `url` finalized) writes, in the finalize transaction of its final `scan_engine_results` row, one `bec_scan_results` row per round (partitioned, copies the message's `received_at`, no foreign keys) and, in round 0 only and when the tenant opted in, its `bec_contact_history` upserts. The six tenant tables are not partitioned and reference `organizations` (`RESTRICT`, deleted explicitly by organization deletion) and `users` (`SET NULL`); `bec_feedback` points to its result by `(bec_result_id, message_received_at)` and `bec_suppression_rules` to its feedback by `feedback_id`, both logical references without a foreign key.

Step 4.6 ([§3](../plan/steps/14-sandbox.md#3-data-model-one-forward-migration-sandbox_engine-wp1)): the sandbox engine of the email-worker links each `sandbox_submissions` row (partitioned) to one content-addressed `sandbox_analyses` row by `analysis_id` (a logical reference: no foreign key from a partitioned table); several submissions of different tenants and rounds can share one analysis (`dedupe_key`). `sandbox_analyses` and `sandbox_artifacts` are not partitioned and platform-level (no foreign key to `organizations`); `sandbox_artifacts` references its analysis (`RESTRICT`: the sweeper deletes artifacts first). Sample and artifact bytes live only in the sandbox bucket, sealed.

Step 4.5 ([§3](../plan/steps/13-dlp.md#3-data-model-one-forward-migration-dlp_engine-wp1)): the DLP engine (a stage-1 engine on `scan.dlp`) writes, in the finalize transaction of its final `scan_engine_results` row, one `dlp_scan_results` row per round and, when a reportable finding was sealed into an encrypted S3 evidence object, one `dlp_evidence` row (both partitioned, copy the message's `received_at`, no foreign keys; `matched_policy_id` / `matched_rule_id` are logical references). The six tenant tables are not partitioned and reference `organizations` (`RESTRICT`, deleted explicitly by organization deletion) and `users` (`SET NULL`); rules reference their policy and exceptions their target policy or rule (`RESTRICT`).

Step 5.1 ([§3](../plan/steps/15-risk-scoring.md#3-data-model-one-forward-migration-risk_scoring-wp1)): the email-worker writes one `message_risk_scores` row per scan round and revision (partitioned, copies the message's `received_at`, no foreign keys): revision 0 in the transaction that completes the round, revision 1 (the round's inputs plus the late sandbox final) once, both under the `email_scans` row lock. Each organization has at most one `risk_scoring_profiles` row (`RESTRICT` to `organizations`), whose versions are `risk_scoring_profile_versions` rows (`RESTRICT` to the profile and the organization, `SET NULL` to the three user columns). The active version is the profile's `active_version_id` (a logical reference, no foreign key: it would form a cycle with `profile_id`). When a round opens, the email-worker copies that pointer into `email_scans.risk_profile_version_id` (n rounds to one version, logical), and `message_risk_scores.profile_version_id` records the version actually used (NULL = the platform default).

Step 5.2 ([§3](../plan/steps/16-policy-engine.md#3-data-model-one-forward-migration-policy_engine-wp1)): a policy's versions hold `policy-dsl/1` documents (`dsl_version`; legacy rows without it are `superseded` and their relational `policy_conditions` / `policy_actions` / `policy_exceptions` rows are retired: no reader or writer). Each organization has at most one `policy_settings` row (`RESTRICT`), whose `generation` every effective policy change increments. The tenant directory is `tenant_departments` (`RESTRICT` to `organizations`) with `tenant_department_members` (`RESTRICT` to the department and the organization; `user_id` `CASCADE` to `users`; exactly one of address / user, api-enforced); versions name the departments and users they reference in `references` (public ids, logical). The policy-engine writes one `policy_execution_logs` row per message and lifecycle round (partitioned, copies the message's `received_at`, no foreign keys; `scan_id` and `decisive_policy_version_id` are logical references, `decisive_policy_public_id` the decisive policy's public id).

```mermaid
erDiagram
  organizations ||--o{ email_policies : "RESTRICT"
  email_policies ||--o{ policy_versions : "CASCADE"
  email_policies |o..o| policy_versions : "active_version_id, no FK (cycle)"
  policy_versions ||--o{ policy_conditions : "CASCADE (retired)"
  policy_versions ||--o{ policy_actions : "CASCADE (retired)"
  email_policies |o--o{ policy_exceptions : "NULL = organization-wide (retired)"
  users |o--o{ email_policies : "created_by, updated_by, SET NULL"
  users |o--o{ policy_versions : "created_by, updated_by, published_by, SET NULL"
  organizations ||--o| policy_settings : "RESTRICT, one per organization"
  users |o--o{ policy_settings : "updated_by, SET NULL"
  organizations ||--o{ tenant_departments : "RESTRICT, unique (organization_id, name)"
  tenant_departments ||--o{ tenant_department_members : "RESTRICT"
  users |o--o{ tenant_department_members : "user_id CASCADE"
  policy_versions |o..o{ tenant_departments : "references.departmentIds (logical)"
  email_messages ||..o{ policy_execution_logs : "message_id + received_at, one per round"
  email_scans |o..o{ policy_execution_logs : "scan_id (logical; NULL for parse failures)"
  policy_versions |o..o{ policy_execution_logs : "decisive_policy_version_id (logical)"
  email_policies {
    bigint id PK
    char public_id UK
    bigint organization_id FK
    bigint active_version_id "no FK"
    int row_version "CAS"
  }
  policy_versions {
    bigint id PK
    bigint policy_id FK
    int version "UQ with policy_id"
    json definition "policy-dsl/1"
    varchar dsl_version "NULL = legacy, superseded"
    json references "departmentIds, userIds"
  }
  policy_settings {
    bigint id PK
    bigint organization_id FK "UK"
    bigint generation "incremented per effective change"
    json settings
  }
  tenant_departments {
    bigint id PK
    char public_id UK
    bigint organization_id FK
    varchar name "UK with organization_id"
  }
  tenant_department_members {
    bigint id PK
    bigint department_id FK
    varchar address "nullable, xor user_id"
    bigint user_id FK "nullable, CASCADE"
  }
  policy_conditions {
    bigint id PK
    bigint policy_version_id FK
    smallint seq
  }
  policy_actions {
    bigint id PK
    bigint policy_version_id FK
    smallint seq
  }
  policy_exceptions {
    bigint id PK
    bigint policy_id FK "nullable"
  }
  policy_execution_logs {
    bigint id PK
    datetime received_at PK "PARTITIONED month"
    bigint message_id
    smallint evaluation_seq "lifecycle round, UQ with message_id"
    enum disposition
    enum decision_source
    bigint policy_generation
  }
```

## Delivery

Step 2.3 added per-recipient delivery tracking: `delivery_reinjections` (one SMTP transaction into postfix-outbound per group of recipients) and the append-only audit `delivery_status_events`, both partitioned like the message (same `received_at`). `delivery_routes` stays unused (reserved for rule-based routing, 5.x).

```mermaid
erDiagram
  organizations ||--o{ delivery_routes : ""
  domains |o--o{ delivery_routes : "CASCADE"
  domain_mail_servers |o--o{ delivery_routes : "SET NULL"
  email_recipients ||..o{ email_deliveries : "recipient_id + received_at"
  email_deliveries ||..o{ delivery_attempts : "delivery_id + received_at"
  delivery_routes |o..o{ email_deliveries : "route_id"
  email_messages ||..o{ delivery_reinjections : "message_id + received_at"
  delivery_reinjections |o..o{ email_deliveries : "reinjection_id + received_at"
  email_deliveries ||..o{ delivery_status_events : "delivery_id + received_at"
  organizations ||--o{ delivery_suppressions : ""
  email_messages |o..o{ bounce_events : "message_id + message_received_at"
  delivery_routes {
    bigint id PK
    bigint organization_id FK
    enum match_type
    int priority
  }
  email_deliveries {
    bigint id PK
    datetime received_at PK "PARTITIONED month"
    bigint message_id
    bigint recipient_id
    smallint delivery_seq
    bigint reinjection_id "step 2.3"
    enum status "pending ... queued, expired, unknown"
    varchar outbound_queue_id "indexed: log and DSN matching; utf8mb4_bin"
    varchar dsn_queue_id "utf8mb4_bin"
  }
  delivery_reinjections {
    bigint id PK
    datetime received_at PK "PARTITIONED month"
    char public_id "token dw1-HEX"
    bigint message_id
    char idempotency_key "UQ with message_id, received_at"
    enum status "pending, in_progress, queued, failed"
    varchar queue_id "utf8mb4_bin"
  }
  delivery_status_events {
    bigint id PK
    datetime received_at PK "PARTITIONED month"
    bigint delivery_id
    char signal_key "UQ with delivery_id, received_at"
    enum source "planner, reinjection, postfix_log, bounce_notice, reconciler"
    boolean applied
    varchar queue_id "utf8mb4_bin"
  }
  delivery_attempts {
    bigint id PK
    datetime received_at PK "PARTITIONED month"
    bigint delivery_id
    smallint attempt_no
  }
  delivery_suppressions {
    bigint id PK
    bigint organization_id FK
    varchar address "UQ with organization_id"
  }
  bounce_events {
    bigint id PK
    datetime occurred_at PK "PARTITIONED month"
    char dedupe_key
  }
```

## Quarantine

Step 5.3 ([§3](../plan/steps/17-quarantine.md#3-data-model-one-forward-migration-quarantine-wp1)): an entry per (message, lifecycle round, recipient), the one approval model, single-use download grants, tenant settings, end-user preferences, object purges and digests. None is partitioned; every table references `organizations` ON DELETE RESTRICT (tenant purge order: grants, approval requests, release logs, actions, purges, digests, preferences, entries, settings). The message, recipient, scan and approval-request references of an entry are logical (no FK).

```mermaid
erDiagram
  organizations ||--o{ quarantine_messages : ""
  email_recipients ||..o{ quarantine_messages : "message_id, rcpt_seq, no FK"
  users |o--o{ quarantine_messages : "user_id, decided_by: SET NULL"
  quarantine_messages ||--o{ quarantine_actions : "CASCADE"
  quarantine_messages ||--o{ quarantine_release_logs : "CASCADE"
  quarantine_actions ||--o| quarantine_release_logs : "action_id"
  quarantine_messages ||--o{ quarantine_approval_requests : "CASCADE"
  quarantine_messages ||..o| quarantine_approval_requests : "approval_request_id, no FK"
  users |o--o{ quarantine_approval_requests : "requester, decider: SET NULL"
  quarantine_messages ||--o{ quarantine_download_grants : "CASCADE"
  users ||--o{ quarantine_download_grants : "CASCADE"
  organizations ||--o| quarantine_settings : "one row"
  users ||--o| quarantine_user_preferences : "CASCADE"
  email_messages ||..o| quarantine_object_purges : "message_id, received_at, no FK"
  organizations ||--o{ quarantine_digest_runs : ""
  quarantine_digest_runs ||--o{ quarantine_digests : "CASCADE"
  users ||--o{ quarantine_digests : "CASCADE"
  quarantine_messages {
    bigint id PK
    char public_id UK
    bigint message_id "logical, UK with round and rcpt_seq"
    datetime message_received_at "for pruning"
    smallint lifecycle_round
    smallint rcpt_seq
    enum status "entry state"
    enum kind
    enum origin
    enum reason
    datetime quarantined_at
    datetime expires_at
    int row_version "CAS"
  }
  quarantine_actions {
    bigint id PK
    bigint quarantine_message_id FK
    enum action
    varchar idempotency_key
  }
  quarantine_release_logs {
    bigint id PK
    bigint quarantine_message_id FK
    bigint action_id FK,UK
    char release_public_id "UK with entry"
    enum mode
    enum status
  }
  quarantine_approval_requests {
    bigint id PK
    char public_id UK
    bigint quarantine_message_id FK
    enum kind
    enum status
    json approval_reasons
    datetime expires_at
  }
  quarantine_download_grants {
    bigint id PK
    char jti UK
    bigint user_id FK
    bigint quarantine_message_id FK
    datetime expires_at
    datetime consumed_at
  }
  quarantine_settings {
    bigint id PK
    bigint organization_id FK,UK
    json settings
  }
  quarantine_user_preferences {
    bigint id PK
    bigint user_id FK,UK
    boolean digest_opt_out
  }
  quarantine_object_purges {
    bigint id PK
    bigint message_id "logical, UK with received_at"
    enum status
    datetime purge_after
  }
  quarantine_digest_runs {
    bigint id PK
    enum kind "UK with org and scheduled_for"
    datetime scheduled_for
  }
  quarantine_digests {
    bigint id PK
    char public_id UK
    bigint run_id FK
    bigint user_id FK "UK with run"
  }
```

## Archiving

Step 8.1 ([design §3](../plan/steps/23-journaling-archiving.md#3-data-model-one-forward-migration-journaling_archiving-wp1)). Solid lines are foreign keys; dotted lines are logical references (partitioned tables have no foreign keys). Metadata only: message content lives in the encrypted objects of the archive bucket.

```mermaid
erDiagram
  organizations ||--o| archive_settings : "1:1, RESTRICT"
  organizations ||--o{ archive_retention_policies : "RESTRICT"
  archive_retention_policies |o--o{ archive_settings : "default policy, SET NULL"
  users |o--o{ archive_settings : "updated_by SET NULL"
  email_messages ||..o| archive_capture_intents : "message_id + received_at (UQ)"
  email_messages ||..o| email_archives : "message_id + received_at (UQ)"
  archive_capture_intents |o..o| email_archives : "archive_id"
  archive_retention_policies |o..o{ email_archives : "retention_policy_id"
  archive_encryption_keys ||..o{ email_archives : "organization_id + key_version"
  organizations ||--o{ archive_encryption_keys : "RESTRICT"
  email_archives ||..o{ archive_index_queue : "message_id + received_at"
  organizations ||--o{ archive_index_checks : "RESTRICT"
  email_archives ||..o| archive_disposals : "archive_record_id, message_id"
  organizations ||--o{ archive_legal_holds : "RESTRICT"
  ediscovery_cases |o--o{ archive_legal_holds : "case_id RESTRICT"
  organizations ||--o{ ediscovery_cases : "RESTRICT"
  ediscovery_cases ||--o{ ediscovery_custodians : "RESTRICT"
  users |o--o{ ediscovery_custodians : "user_id SET NULL"
  ediscovery_cases ||--o{ ediscovery_searches : "RESTRICT"
  ediscovery_searches ||--o{ ediscovery_search_hits : "RESTRICT"
  email_archives ||..o{ ediscovery_search_hits : "message_id + received_at"
  ediscovery_cases ||--o{ ediscovery_exports : "RESTRICT"
  ediscovery_searches ||--o{ ediscovery_exports : "RESTRICT"
  ediscovery_exports |o--o{ archive_download_grants : "export_id CASCADE"
  email_archives |o..o{ archive_download_grants : "message_id + received_at"
  users ||--o{ archive_download_grants : "user_id CASCADE"
  organizations ||--o{ archive_download_grants : "RESTRICT"
  email_archives ||..o{ archive_record_sources : "archive_id + archive_received_at (8.6)"
  email_messages ||..o{ archive_record_sources : "merged copy: message_id + message_received_at"
  email_archives ||..o{ archive_dedupe_keys : "archive_id + archive_received_at (8.6)"
  archive_capture_intents |o..o| email_archives : "merged: archive_id + archive_received_at (8.6)"
  archive_settings {
    bigint id PK
    bigint organization_id FK,UK
    json settings "archive-settings/1, NULL = defaults"
    bigint generation
    int row_version
    enum scope "RETIRED"
    varchar encryption_key_ref "RETIRED"
  }
  archive_retention_policies {
    bigint id PK
    char public_id UK
    bigint organization_id FK
    varchar name "UQ with organization_id"
    json criteria "archive-retention/1"
    datetime deleted_at "soft delete"
    bool is_default "RETIRED"
  }
  archive_capture_intents {
    bigint id PK
    datetime received_at PK "PARTITIONED month, 4 months"
    bigint message_id "UQ with received_at"
    enum status
    datetime next_check_at
    datetime archive_received_at "8.6: NULL = received_at"
    bool merged "8.6"
  }
  email_archives {
    bigint id PK
    datetime received_at PK "PARTITIONED month, never dropped"
    bigint message_id "UQ with received_at"
    char message_public_id
    enum status "active, expiry_review, disposing"
    json parties "archive-parties/1"
    json objects "keys and version ids"
    varchar wrapped_dek "NULL = crypto-shredded"
    datetime retain_until
    bool legal_hold "informational"
    bool source_gateway "8.6"
    bool source_journal_intake "8.6"
    bigint intake_source_id "8.6, no FK"
    smallint merged_count "8.6"
  }
  archive_record_sources {
    bigint id PK
    datetime archive_received_at PK "PARTITIONED month, never dropped (8.6)"
    bigint archive_id
    bigint message_id "UQ with message_received_at, archive_received_at"
    enum source "gateway, journal_intake"
    bool content_variant
  }
  archive_dedupe_keys {
    bigint id PK
    bigint organization_id "no FK"
    char message_id_hash "index with org, header_fingerprint"
    char header_fingerprint "archive-fingerprint/1"
    char body_sha256
    bigint archive_id
  }
  archive_encryption_keys {
    bigint id PK
    char public_id UK
    bigint organization_id FK "UQ with version"
    int version
    varchar wrapped_key "under the root key"
  }
  archive_index_queue {
    bigint id PK
    bigint organization_id "no FK"
    enum op "upsert, delete, purge_org"
  }
  archive_index_checks {
    bigint id PK
    bigint organization_id FK "UQ with day"
    date day
  }
  archive_disposals {
    bigint id PK
    datetime requested_at PK "PARTITIONED month, never dropped"
    bigint archive_record_id
    enum state
  }
  archive_legal_holds {
    bigint id PK
    char public_id UK
    bigint organization_id FK
    bigint case_id FK
    enum status
  }
  ediscovery_cases {
    bigint id PK
    char public_id UK
    bigint organization_id FK "UQ with name"
    enum status "open, closed"
  }
  ediscovery_custodians {
    bigint id PK
    bigint case_id FK "UQ with address"
    varchar address
  }
  ediscovery_searches {
    bigint id PK
    char public_id UK
    bigint case_id FK
    json criteria "archive-search/1"
    bool index_complete
  }
  ediscovery_search_hits {
    bigint id PK
    bigint search_id FK "UQ with message_id, received_at"
    enum review_tag
  }
  ediscovery_exports {
    bigint id PK
    char public_id UK
    bigint search_id FK
    char package_sha256
    varchar wrapped_dek
  }
  archive_download_grants {
    bigint id PK
    char jti UK
    bigint user_id FK
    enum kind "message, export"
  }
```

## Journal intake

Step 8.6 ([design §3](../plan/steps/27-journal-intake-and-archive-split.md#3-data-model-one-forward-migration-utc-timestamp_journal_intake-wp1), ADR-0087). Intake messages are ordinary registry messages (`email_messages.ingest_source = journal_intake`); `journal_intake_messages` holds their envelope and proof. Solid lines are foreign keys; dotted lines are logical references. Only hashes of the intake credentials are stored.

```mermaid
erDiagram
  organizations ||--o{ journal_intake_sources : "RESTRICT"
  provider_connections |o--o{ journal_intake_sources : "provider kinds, RESTRICT"
  journal_intake_sources ||--o{ journal_intake_counters : "CASCADE"
  journal_intake_sources ||..o{ journal_intake_messages : "source_id, no FK"
  email_messages ||..o| journal_intake_messages : "message_id + received_at"
  journal_intake_sources {
    bigint id PK
    char public_id UK
    bigint organization_id FK "UQ with display_name"
    enum kind "microsoft_365_journal, google_workspace_copy, exchange_onprem_journal, smtp_bcc"
    enum status "pending_verification, active, paused, disabled"
    bigint provider_connection_id FK
    char address_hash UK "SHA-256 of the local part"
    char previous_address_hash UK "rotation overlap"
    char header_token_hash "Google only"
    enum health_status
    int row_version
  }
  journal_intake_counters {
    bigint id PK
    bigint source_id FK "UQ with day"
    bigint organization_id "no FK"
    date day
  }
  journal_intake_messages {
    bigint message_id PK
    datetime received_at PK "PARTITIONED month, 6 months"
    bigint organization_id
    bigint source_id
    enum format "journal_report, copy, journal_report_unparsed"
    json envelope "journal-envelope/1"
    json proof "journal-intake-proof/1"
  }
  email_messages {
    bigint id PK
    datetime received_at PK "PARTITIONED"
    enum ingest_source "gateway, journal_intake"
    enum status "... journaled"
  }
```

## API-mode protection

Step API-1 ([design §3](../plan/steps/35-api-mode-protection.md#3-data-model-one-forward-migration-utc-timestamp_api_mode_protection-wp1), ADR-0098, ADR-0100). Copies are ordinary registry messages (`email_messages.ingest_source` `journal_intake` or `mailbox_api`); `api_message_copies` holds one row per scanned copy and mailbox. The protection mode lives on `organizations.protection_mode` (default) and `domains.protection_mode` (NULL = inherit). Solid lines are foreign keys; dotted lines are logical references. No message content and no provider credential is stored here (credentials are step 8.2 grants).

```mermaid
erDiagram
  organizations ||--o{ api_mode_connections : "RESTRICT"
  provider_connections ||--o| api_mode_connections : "UQ, RESTRICT"
  api_mode_connections ||--o{ api_mailboxes : "RESTRICT"
  api_mailboxes ||--o{ api_mailbox_addresses : "CASCADE"
  api_mode_connections ||--o{ api_mode_counters : "CASCADE"
  api_mailboxes ||..o{ api_message_copies : "mailbox_id, no FK"
  email_messages ||..o{ api_message_copies : "message_id + received_at"
  api_mailboxes ||..o{ api_copy_dedupe_keys : "mailbox_id, no FK"
  api_message_copies ||..o| api_copy_dedupe_keys : "copy_id + copy_received_at"
  domains ||..o{ api_mailboxes : "domain_id, no FK"
  api_mode_connections {
    bigint id PK
    char public_id UK
    bigint organization_id FK
    bigint provider_connection_id FK "UQ"
    enum provider "microsoft_365, google_workspace"
    bool feeds_enabled
    enum feed_mode "poll, notify"
    enum inventory_status "never, ok, failed, unavailable"
    enum health_status "unknown, healthy, degraded, failing"
    int row_version
  }
  api_mailboxes {
    bigint id PK
    char public_id UK
    bigint organization_id
    bigint api_connection_id FK "UQ with provider_user_id"
    varchar provider_user_id "NULL = discovered"
    varchar primary_address
    bigint domain_id
    enum status "active, discovered, disabled, deleted"
    enum coverage_state "covered, gap, out_of_scope"
    enum feed_status "off, pending, active, error, throttled, revoked"
    varchar subscription_id UK
    char client_state_hash
  }
  api_mailbox_addresses {
    bigint id PK
    bigint organization_id "UQ with address"
    bigint mailbox_id FK
    varchar address
    enum kind "primary, alias"
  }
  api_message_copies {
    bigint id PK
    datetime received_at PK "PARTITIONED month"
    char public_id
    bigint organization_id
    bigint api_connection_id
    bigint mailbox_id "UQ with message_id, received_at"
    bigint message_id
    enum source "journal, graph, gmail"
    enum status "pending, scanned, scan_failed, parse_failed, too_large"
    enum verdict "MessageVerdict"
    enum verdict_authority "copy, inline"
  }
  api_copy_dedupe_keys {
    bigint id PK
    bigint organization_id
    bigint mailbox_id "UQ with message_id_hash"
    char message_id_hash
    enum claimed_by "journal, graph, gmail"
    bigint copy_id
  }
  api_mode_counters {
    bigint id PK
    bigint organization_id
    bigint api_connection_id FK "UQ with hour"
    datetime hour
  }
```

## Security incidents and account takeover

Step 8.4 ([design §3](../plan/steps/24-account-takeover-core.md#3-data-model-two-forward-migrations-wp1), ADR-0070, ADR-0075). Solid lines are foreign keys; dotted lines are logical references (partitioned tables have no foreign keys, and `ato_accounts` keeps no foreign key to the subject it monitors, so the trail survives a deleted user or connector).

```mermaid
erDiagram
  organizations ||--o{ security_incidents : "RESTRICT"
  users |o--o{ security_incidents : "assigned_user SET NULL"
  security_incidents ||--o{ security_incident_events : "CASCADE"
  security_incidents ||--o{ security_incident_links : "CASCADE"
  security_incident_links }o..o| email_messages : "message: ref_id + ref_time"
  security_incident_links }o..o| ato_risk_signals : "ato_signal: ref_id + ref_time"
  security_incident_links }o..o| ato_auth_events : "ato_auth_event: ref_id + ref_time"
  security_incidents ||--o| ato_incident_details : "1:1, CASCADE"
  security_incidents |o..o| ato_accounts : "subject_ref_id (ato_account); active_incident_id"
  organizations ||--o| ato_settings : "1:1, RESTRICT"
  users |o--o{ ato_settings : "updated_by SET NULL"
  organizations ||--o{ ato_settings_versions : "RESTRICT"
  organizations ||--o{ ato_accounts : "RESTRICT"
  users |o..o{ ato_accounts : "user_id (gateway_user)"
  smtp_connectors |o..o{ ato_accounts : "connector_id (smtp_connector)"
  ato_accounts ||--o| ato_account_baselines : "1:1, CASCADE"
  ato_accounts ||..o{ ato_account_activity_daily : "account_id + day_start (UQ)"
  ato_accounts |o..o{ ato_auth_events : "account_id"
  ato_accounts ||..o{ ato_risk_signals : "account_id"
  ato_accounts ||..o{ ato_risk_scores : "account_id"
  ato_accounts ||--o{ ato_risk_overrides : "CASCADE"
  ato_accounts ||--o{ ato_trusted_contexts : "CASCADE"
  ato_accounts ||--o{ ato_account_identities : "CASCADE"
  ato_accounts ||--o{ ato_incident_details : "RESTRICT"
  ato_accounts ||--o{ ato_response_actions : "RESTRICT"
  security_incidents |o--o{ ato_response_actions : "RESTRICT"
  ato_response_actions ||--o{ ato_response_action_logs : "CASCADE"
  ato_response_actions |o..o| ato_smtp_restrictions : "restriction_id / response_action_id"
  organizations ||--o{ ato_smtp_restrictions : "RESTRICT"
  organizations ||--o{ ato_provider_integrations : "RESTRICT"
  organizations ||--o{ ato_provider_streams : "RESTRICT (8.5)"
  ato_provider_integrations ||--o{ ato_provider_streams : "CASCADE (8.5)"
  organizations ||--o{ ato_provider_mailbox_items : "RESTRICT (8.5)"
  ato_provider_integrations ||--o{ ato_provider_mailbox_items : "CASCADE (8.5)"
  ato_accounts |o--o{ ato_provider_mailbox_items : "SET NULL (8.5)"
  ato_provider_integrations |o--o{ ato_account_identities : "SET NULL (8.5)"
  ato_provider_integrations |o..o{ ato_response_actions : "integration_id, no FK (8.5)"
  security_incidents {
    bigint id PK
    char public_id UK
    bigint organization_id FK
    enum category "account_takeover (append-only)"
    enum subject_type "ato_account (append-only)"
    bigint subject_ref_id "UQ with org, category, subject_type, active_marker"
    enum status "six states"
    tinyint active_marker "GENERATED STORED"
  }
  ato_accounts {
    bigint id PK
    char public_id UK
    bigint organization_id FK
    enum kind "mailbox, gateway_user, smtp_connector"
    char subject_hash "UQ with organization_id, kind"
    tinyint risk_score
    bigint active_incident_id "logical"
  }
  ato_auth_events {
    bigint id PK
    datetime occurred_at PK "PARTITIONED month, 3 months"
    char dedupe_key "UQ with organization_id, occurred_at"
  }
  ato_account_activity_daily {
    bigint id PK
    datetime day_start PK "PARTITIONED month, 6 months"
  }
  ato_risk_signals {
    bigint id PK
    datetime detected_at PK "PARTITIONED month, 13 months"
  }
  ato_risk_scores {
    bigint id PK
    datetime computed_at PK "PARTITIONED month, 13 months"
  }
  ato_response_actions {
    bigint id PK
    char dedupe_hash "UQ with organization_id, active_marker"
    tinyint active_marker "GENERATED STORED"
  }
  ato_smtp_restrictions {
    bigint id PK
    char subject_hash "UQ with organization_id, active_marker"
    tinyint active_marker "GENERATED STORED"
  }
```

## Provider integrations

Step 8.2 ([design §3](../plan/steps/25-m365-google-connectors.md#3-data-model-one-forward-migration-provider_integrations-wp1), ADR-0076–0081). None of these tables is partitioned, so every reference is a real foreign key. Tenant children of a connection carry `organization_id` without a foreign key (always the parent connection's); the two egress tables are platform data (no `organization_id`). Credentials are stored only as AES-256-GCM ciphertext (ADR-0077); probe evidence holds no message content.

```mermaid
erDiagram
  organizations ||--o{ provider_connections : "RESTRICT"
  users |o--o{ provider_connections : "created_by SET NULL"
  provider_connections ||--o{ provider_connection_grants : "CASCADE"
  provider_connections ||--o{ provider_consent_states : "CASCADE"
  provider_connection_grants ||--o{ provider_consent_states : "CASCADE"
  users ||--o{ provider_consent_states : "CASCADE"
  provider_connections ||--o{ provider_connection_domains : "CASCADE"
  domains ||--o| provider_connection_domains : "UQ domain_id, CASCADE"
  provider_connections ||--o{ provider_validation_runs : "CASCADE"
  provider_connections ||--o{ provider_probe_observations : "CASCADE"
  provider_validation_runs |o--o{ provider_probe_observations : "SET NULL"
  provider_connections ||--o{ provider_health_checks : "CASCADE"
  provider_connections ||--o{ provider_health_events : "CASCADE"
  provider_connections ||--o{ provider_relay_counters : "CASCADE"
  provider_connections |o--o| smtp_connectors : "provider_relay connector, UQ, RESTRICT"
  provider_egress_range_sets ||--o{ provider_egress_ranges : "CASCADE"
  provider_connections {
    bigint id PK
    char public_id UK
    bigint organization_id FK
    enum provider "microsoft_365, google_workspace"
    enum status "draft ... disabled"
    varchar external_tenant_id
    varchar active_tenant_key UK "provider:tenant while not disabled"
    enum outbound_mode "off, probe_only, active, suspended"
    enum health_status
  }
  provider_connection_grants {
    bigint id PK
    char public_id UK
    bigint connection_id FK "UQ with profile"
    varchar profile
    enum auth_method
    enum status
    text credential_ciphertext "AES-256-GCM, never returned"
  }
  provider_consent_states {
    bigint id PK
    bigint grant_id FK
    bigint user_id FK
    char state_sha256 UK
    datetime expires_at
  }
  provider_connection_domains {
    bigint id PK
    bigint connection_id FK
    bigint domain_id FK,UK
    enum provider_verification
  }
  provider_validation_runs {
    bigint id PK
    char public_id UK
    bigint connection_id FK
    enum kind
    enum status
    char probe_token_sha256 UK
  }
  provider_probe_observations {
    bigint id PK
    bigint connection_id FK
    bigint validation_run_id FK
    char token_sha256 "UQ with queue_id"
    enum proof_result
  }
  provider_health_checks {
    bigint id PK
    bigint connection_id FK "UQ with check_code, subject"
    enum status
    enum severity
  }
  provider_health_events {
    bigint id PK
    bigint connection_id FK
    enum from_status
    enum to_status
  }
  provider_relay_counters {
    bigint id PK
    bigint connection_id FK "UQ with hour_start"
    datetime hour_start
  }
  provider_egress_range_sets {
    bigint id PK
    enum provider "UQ with version"
    int version
    enum status "active, superseded"
  }
  provider_egress_ranges {
    bigint id PK
    bigint set_id FK "UQ with cidr"
    tinyint ip_version
    varbinary range_start
    varbinary range_end
  }
  smtp_connectors {
    bigint id PK
    enum auth_type "+ provider_relay (8.2)"
    bigint provider_connection_id FK,UK
  }
```

## AI assistant

Step AI-1 ([design §3](../plan/steps/28-ai-chat-management.md#3-data-model-migration-ai_assistant-ai-1-wp1), ADR-0094). Not partitioned. Every table references `organizations` (RESTRICT; the organization purge deletes them explicitly); a conversation belongs to one user (CASCADE, private data) and its turns, messages and tool executions cascade from it. Step AI-2 ([design §3](../plan/steps/29-ai-chat-confirmations-mail-writes.md#3-data-model-migration-ai_assistant_confirmations-wp1)) added `ai_chat_action_confirmations`: one per write proposal execution, cascading from its execution, turn and conversation. Dotted lines are logical references (no FK). No email body or attachment is stored.

```mermaid
erDiagram
  organizations ||--o| ai_chat_settings : "RESTRICT"
  organizations ||--o{ ai_chat_conversations : "RESTRICT"
  users ||--o{ ai_chat_conversations : "CASCADE"
  ai_chat_conversations ||--o{ ai_chat_turns : "CASCADE"
  ai_chat_conversations ||--o{ ai_chat_messages : "CASCADE"
  ai_chat_turns ||--o{ ai_chat_messages : "CASCADE"
  ai_chat_conversations ||--o{ ai_chat_tool_executions : "CASCADE"
  ai_chat_turns |o--o{ ai_chat_tool_executions : "CASCADE (NULL for more)"
  ai_chat_tool_executions |o..o{ ai_chat_tool_executions : "parent_execution_id, no FK"
  ai_chat_tool_executions ||..o{ audit_logs : "correlation_id, resource id"
  organizations ||--o{ ai_chat_usage_daily : "RESTRICT"
  organizations ||--o{ ai_chat_action_confirmations : "RESTRICT"
  organizations ||--o{ ai_chat_reports : "RESTRICT"
  ai_chat_conversations ||--o{ ai_chat_reports : "CASCADE"
  ai_chat_reports |o..o| ai_chat_tool_executions : "execution_id, no FK"
  organizations ||--o{ ai_chat_report_deliveries : "RESTRICT"
  ai_chat_reports ||--o{ ai_chat_report_deliveries : "CASCADE"
  ai_chat_report_deliveries |o..o| ai_chat_action_confirmations : "confirmation_id UK, no FK"
  ai_chat_conversations ||--o{ ai_chat_action_confirmations : "CASCADE"
  ai_chat_turns |o--o{ ai_chat_action_confirmations : "CASCADE"
  ai_chat_tool_executions ||--o| ai_chat_action_confirmations : "CASCADE (the proposal)"
  ai_chat_action_confirmations |o..o| ai_chat_tool_executions : "result_execution_id, no FK"
  ai_chat_settings {
    bigint organization_id PK
    bool enabled
    datetime external_processing_ack_at
    int daily_token_budget "NULL = platform default"
    smallint retention_days "1-365"
    enum data_sharing "metadata"
    int row_version
  }
  ai_chat_conversations {
    bigint id PK
    char public_id UK
    bigint organization_id FK
    bigint user_id FK
    char platform_override_id "no FK"
    varchar title "content, purged"
    enum status "active, archived, deleted"
    datetime last_turn_at
    datetime purge_after
  }
  ai_chat_turns {
    bigint id PK
    char public_id UK
    bigint conversation_id FK "UQ with seq, UQ with client_turn_id"
    bigint organization_id FK
    bigint user_id "no FK"
    enum status "running, completed, failed, cancelled"
    mediumtext provider_transcript "content, purged"
  }
  ai_chat_messages {
    bigint id PK
    char public_id UK
    bigint conversation_id FK "UQ with seq"
    bigint turn_id FK
    bigint organization_id FK
    enum role "user, assistant"
    text content "content, purged"
  }
  ai_chat_tool_executions {
    bigint id PK
    char public_id UK
    bigint conversation_id FK "UQ with seq (refs r<seq>)"
    bigint turn_id FK "NULL for more"
    bigint organization_id FK
    bigint parent_execution_id "no FK"
    enum decision "allowed, denied_*"
    enum status "succeeded, failed, refused, timeout, pending_confirmation"
    varchar correlation_id
    json result_card "content, purged"
  }
  ai_chat_usage_daily {
    bigint organization_id PK
    date day PK
    varchar provider PK
    varchar model PK
  }
  ai_chat_action_confirmations {
    bigint id PK
    char public_id UK "Idempotency-Key of the confirmed write"
    bigint organization_id FK
    bigint user_id "no FK"
    char session_family_id
    bigint conversation_id FK
    bigint turn_id FK
    bigint execution_id FK,UK "the proposal"
    bigint result_execution_id "no FK"
    enum risk "low, medium, high"
    json request "content, purged"
    json summary "content, purged"
    char action_digest
    char token_hash "SHA-256; token never stored"
    enum status "pending, executing, executed, failed, expired, cancelled"
    datetime expires_at
  }
  ai_chat_reports {
    bigint id PK
    char public_id UK
    bigint organization_id FK
    bigint user_id "no FK"
    bigint conversation_id FK
    bigint execution_id UK "report_generate, no FK"
    enum status "pending, available, failed, purged"
    datetime period_from
    datetime period_to
    json sections
    json figures
    varchar object_key "mail bucket; HTML never in MySQL"
    char sha256
    datetime object_deleted_at
  }
  ai_chat_report_deliveries {
    bigint id PK
    char public_id UK "outbox eventId"
    bigint organization_id FK
    bigint report_id FK
    bigint confirmation_id UK "no FK"
    varchar recipient_address "content, purged"
    char recipient_sha256
    enum recipient_kind "self, member, domain"
    enum status "queued, sent, failed"
    datetime requested_at
  }
```

Step AI-R ([design §3](../plan/steps/31-ai-chat-reports.md#3-data-model-migration-ai_assistant_reports-wp1), ADR-0095) added `ai_chat_reports` (report metadata; the HTML is an object in the mail bucket) and `ai_chat_report_deliveries` (confirmed report emails, one per confirmation).

## Platform operations

```mermaid
erDiagram
  organizations ||..o{ message_outbox : "no FK"
  organizations |o..o{ audit_logs : "NULL = platform action"
  organizations ||--o{ webhook_subscriptions : ""
  webhook_subscriptions ||..o{ webhook_deliveries : "subscription_id"
  webhook_events ||..o{ webhook_deliveries : "event_id + occurred_at"
  webhook_deliveries ||..o{ webhook_delivery_attempts : "delivery_id + event_occurred_at"
  webhook_subscriptions ||--o{ webhook_replays : "RESTRICT"
  organizations ||--o{ webhook_replays : "RESTRICT"
  webhook_replays |o..o{ webhook_deliveries : "replay_id"
  organizations ||--o| notification_settings : "RESTRICT"
  users |o--o{ notification_settings : "updated_by SET NULL"
  users ||--o| notification_user_preferences : "CASCADE"
  organizations ||--o{ notification_alert_windows : "RESTRICT"
  users |o--o{ system_settings : "updated_by"
  message_outbox {
    bigint id PK
    datetime created_at PK "PARTITIONED day"
    char event_id
    datetime published_at "set by event-relay after the confirm"
    int attempts
    smallint redrive_count "reconciler, step 3.2"
    datetime last_redriven_at
  }
  message_idempotency {
    varchar consumer PK
    char event_id PK
    datetime processed_at
  }
  message_consumer_progress {
    varchar consumer PK
    char event_id PK
    enum state "retrying, dead_lettered"
    datetime updated_at
  }
  organizations ||..o{ api_idempotency_keys : "no FK"
  api_idempotency_keys {
    bigint id PK
    bigint organization_id "UQ with idempotency_key"
    varchar idempotency_key "utf8mb4_bin, case-sensitive"
    char request_sha256
    datetime expires_at "indexed; purged 1 day after"
  }
  audit_logs {
    bigint id PK
    datetime created_at PK "PARTITIONED month"
    bigint organization_id "nullable"
  }
  webhook_subscriptions {
    bigint id PK
    char public_id UK
    bigint organization_id FK
    enum status "active, paused, disabled, deleted"
    smallint secret_version
    int row_version
  }
  webhook_events {
    bigint id PK
    datetime occurred_at PK "PARTITIONED month"
    char event_id "UQ with occurred_at (deterministic)"
    bigint organization_id
    text payload_json "guarded envelope"
  }
  webhook_deliveries {
    bigint id PK
    datetime event_occurred_at PK "PARTITIONED month"
    char public_id
    bigint subscription_id
    char event_id
    smallint delivery_seq "UQ (subscription_id, event_id, event_occurred_at, delivery_seq)"
    enum status "pending, succeeded, failed, dead, cancelled"
  }
  webhook_delivery_attempts {
    bigint id PK
    datetime attempted_at PK "PARTITIONED month"
    bigint delivery_id
    smallint attempt_no
    enum outcome
  }
  webhook_replays {
    bigint id PK
    char public_id UK
    bigint organization_id FK
    bigint subscription_id FK
    enum status "queued, running, completed, failed, cancelled"
  }
  notification_settings {
    bigint id PK
    bigint organization_id FK "UQ"
    json settings
    int row_version
  }
  notification_user_preferences {
    bigint id PK
    bigint organization_id FK
    bigint user_id FK "UQ"
    json preferences "optOut kinds"
  }
  notification_alert_windows {
    bigint id PK
    bigint organization_id FK
    varchar kind "UQ with scope_key, window_start"
    varchar scope_key
    datetime window_start
    int event_count
  }
  system_settings {
    bigint id PK
    varchar key UK
  }
  maintenance_watermarks {
    varchar name PK
    bigint value
  }
  stream_cursors {
    varchar name PK "outbox:CONSUMER, postfix-log:SOURCE"
    bigint position_id
    varchar file_id
    bigint file_offset
  }
```

`message_idempotency` stands alone: its key is the consumer name and the event id. So does `message_consumer_progress` (step 3.2 review round 1), with the same key. `stream_cursors` (step 2.3) holds the durable positions of the delivery-worker's outbox pollers and Postfix log tailers; it references nothing. `maintenance_watermarks` belongs to the partition-maintenance job (the registry purge watermark, see [retention.md](retention.md)). `api_idempotency_keys` (step 3.3 L11) is the api's Idempotency-Key store: unpartitioned and without a foreign key (the row outlives nothing it references and is purged one day after it expires), one row per organization and key. Step 6.2: `webhook_events` and `webhook_delivery_attempts` are partitioned (logical references only); `webhook_replays` and the three notification tables are unpartitioned with real foreign keys.
