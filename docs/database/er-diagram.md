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
    scan_engine_settings
  end
  subgraph policy[Policy]
    email_policies
  end
  subgraph delivery[Delivery]
    email_deliveries[(email_deliveries P)]
    delivery_reinjections[(delivery_reinjections P)]
    delivery_status_events[(delivery_status_events P)]
  end
  subgraph quarantine[Quarantine]
    quarantine_messages
  end
  subgraph archive[Archiving]
    email_archives[(email_archives P)]
  end
  subgraph ops[Platform operations]
    message_outbox[(message_outbox P)]
    audit_logs[(audit_logs P)]
    api_idempotency_keys
  end
  organization_plans --> organizations
  organizations --> users
  organizations --> roles
  organizations --> domains
  organizations --> smtp_connectors
  organizations --> email_policies
  organizations --> message_identities
  message_identities -.-> email_messages
  domains -.-> email_messages
  email_messages -.-> email_message_parses
  email_messages -.-> email_scans
  email_scans -.-> email_auth_results
  organizations --> scan_engine_settings
  email_messages -.-> email_deliveries
  delivery_reinjections -.-> email_deliveries
  email_deliveries -.-> delivery_status_events
  email_messages -.-> quarantine_messages
  email_messages -.-> email_archives
  email_messages -.-> message_outbox
  email_policies -.-> email_messages
  organizations -.-> audit_logs
  organizations -.-> api_idempotency_keys
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
    enum status "lifecycle state, 15 values (ADR-0025)"
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
  organizations |o--o{ threat_indicators : "NULL = platform feed"
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
  }
  yara_rules {
    bigint id PK
    varchar rule_key UK
  }
```

The four reputation catalogs and `malware_signatures` are platform-wide and stand alone.

Step 4.1 ([§3](../plan/steps/09-rspamd.md#3-data-model-one-forward-migration-scan_pipeline-wp1)): a scan round is `(message_id, received_at, lifecycle_round)`, one `email_scans` row; each engine writes its failed attempts as non-final `scan_engine_results` rows and exactly one final row (the unique key on the generated `final_engine`); the Rspamd engine also writes one `email_auth_results` row per round. All three are partitioned and copy the message's `received_at`, so a message's scan graph lives in one partition. `scan_engine_settings` (not partitioned) holds a tenant's override of an engine's platform thresholds, validated by `@email-gateway/security-contracts`.

## Policy

```mermaid
erDiagram
  organizations ||--o{ email_policies : ""
  email_policies ||--o{ policy_versions : "CASCADE"
  email_policies |o..o| policy_versions : "active_version_id, no FK (cycle)"
  policy_versions ||--o{ policy_conditions : "CASCADE"
  policy_versions ||--o{ policy_actions : "CASCADE"
  email_policies |o--o{ policy_exceptions : "NULL = organization-wide"
  email_messages ||..o{ policy_execution_logs : "message_id + received_at"
  policy_versions |o..o{ policy_execution_logs : "decisive_policy_version_id"
  email_policies {
    bigint id PK
    char public_id UK
    bigint organization_id FK
    bigint active_version_id "no FK"
  }
  policy_versions {
    bigint id PK
    bigint policy_id FK
    int version "UQ with policy_id"
    json definition
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
    smallint evaluation_seq
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

```mermaid
erDiagram
  organizations ||--o{ quarantine_messages : ""
  email_recipients ||..o| quarantine_messages : "message_id, recipient_id, no FK"
  users |o--o{ quarantine_messages : "SET NULL"
  quarantine_messages ||--o{ quarantine_actions : "CASCADE"
  quarantine_messages ||--o{ quarantine_release_logs : "CASCADE"
  quarantine_actions ||--o| quarantine_release_logs : "action_id"
  quarantine_messages {
    bigint id PK
    char public_id UK
    bigint message_id "logical"
    datetime message_received_at "for pruning"
    bigint recipient_id "logical"
    enum status
    datetime expires_at
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
  }
```

## Archiving

```mermaid
erDiagram
  organizations ||--o| archive_settings : "1:1"
  organizations ||--o{ archive_retention_policies : ""
  archive_retention_policies |o--o{ archive_settings : "default policy, SET NULL"
  email_messages ||..o| email_archives : "message_id + received_at"
  archive_retention_policies |o..o{ email_archives : "retention_policy_id"
  organizations ||--o{ archive_legal_holds : ""
  archive_settings {
    bigint id PK
    bigint organization_id FK,UK
  }
  archive_retention_policies {
    bigint id PK
    bigint organization_id FK
    varchar name "UQ with organization_id"
  }
  email_archives {
    bigint id PK
    datetime received_at PK "PARTITIONED month, never dropped"
    bigint message_id
    datetime retain_until
    bool legal_hold
  }
  archive_legal_holds {
    bigint id PK
    bigint organization_id FK
    enum status
  }
```

## Platform operations

```mermaid
erDiagram
  organizations ||..o{ message_outbox : "no FK"
  organizations |o..o{ audit_logs : "NULL = platform action"
  organizations ||--o{ webhook_subscriptions : ""
  webhook_subscriptions ||..o{ webhook_deliveries : "subscription_id"
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
  }
  webhook_deliveries {
    bigint id PK
    datetime event_occurred_at PK "PARTITIONED month"
    bigint subscription_id
    char event_id
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

`message_idempotency` stands alone: its key is the consumer name and the event id. So does `message_consumer_progress` (step 3.2 review round 1), with the same key. `stream_cursors` (step 2.3) holds the durable positions of the delivery-worker's outbox pollers and Postfix log tailers; it references nothing. `maintenance_watermarks` belongs to the partition-maintenance job (the registry purge watermark, see [retention.md](retention.md)). `api_idempotency_keys` (step 3.3 L11) is the api's Idempotency-Key store: unpartitioned and without a foreign key (the row outlives nothing it references and is purged one day after it expires), one row per organization and key.
