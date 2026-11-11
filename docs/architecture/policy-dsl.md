# Policy DSL reference (`policy-dsl/1`)

The reference for tenants and implementers of the email policy language of step 5.2. Design: [step 5.2](../plan/steps/16-policy-engine.md) P1–P12, P18, P19, P23; decisions: [ADR-0043](adr/0043-policy-dsl-and-deterministic-evaluator.md) (DSL, evaluator, conflict resolution, floor), [ADR-0045](adr/0045-policy-action-semantics.md) (what each action does in 5.2). Library: `packages/policy-dsl` (`@email-gateway/policy-dsl`).

A policy is **data, never code**: a JSON document validated by a strict schema over a closed catalog of fields, operators and actions. No script, template, SQL or JavaScript is ever compiled or run. Regular expressions run only through RE2 (`re2js`, linear time). Anything outside the schema is refused with violations by JSON path. The evaluator is a pure function of the message facts and the published policies: the same input and snapshot always give the byte-identical decision.

The field table and every JSON example in this document are checked by unit tests (`packages/policy-dsl/src/docs.test.ts`): the table must equal the library catalog (`POLICY_FIELDS`), every policy example must validate, and every worked example must produce the stated result.

## 1. Document shape

```text
PolicyDefinition = {
  dslVersion: "policy-dsl/1",
  direction: "inbound" | "outbound" | "internal" | "any",
  priority: 0..10000,                       // policy order, ascending
  rules: Rule[] (1..100),
  exceptions?: ExceptionNode[] (≤ 8)        // exempt every rule of this policy
}
Rule = {
  id: [a-z0-9][a-z0-9_-]{0,47}  (unique in the policy),
  priority: 0..10000             (unique in the policy; rule order, ascending),
  description?: string ≤ 256     (printable; never rendered into mail),
  enabled?: boolean = true,
  directions?: ["inbound" | "outbound" | "internal", …]  (each allowed by the policy direction),
  when: Node,
  unless?: ExceptionNode[] (≤ 8),
  actions: Action[] (1..8; at most one disposition; each other type at most once),
  stop?: boolean                 (default: true when the rule has a disposition),
  override?: boolean = false     (only with a disposition; see §8)
}
Node = { "all": Node[1..16] } | { "any": Node[1..16] } | { "not": Node } | Leaf
Leaf = { "field", "op", "value"?, "quantifier"?: "any" | "all" }
```

Objects are strict: an unknown key anywhere is refused (`unknown_key`). Validation returns **all** violations, sorted by path, each `{ path, code, message }` with a stable code:

| Code                                                                                                                       | Meaning                                                             |
| -------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------- |
| `unknown_key`, `unknown_field`, `unknown_operator`, `unknown_action`                                                       | Not in the schema or catalog                                        |
| `operator_not_allowed`, `quantifier_not_allowed`                                                                           | The field does not support it                                       |
| `value_required`, `value_invalid`                                                                                          | Missing or malformed value (type, vocabulary, format)               |
| `limit_exceeded`                                                                                                           | A bound of §10 was exceeded                                         |
| `dsl_version_unsupported`                                                                                                  | `dslVersion` is not `policy-dsl/1`                                  |
| `duplicate_rule_id`, `duplicate_rule_priority`, `duplicate_action`, `multiple_dispositions`                                | Rule structure                                                      |
| `override_without_disposition`, `direction_not_in_policy`                                                                  | Rule structure                                                      |
| `exception_negation`, `exception_quantifier`, `identity_unauthenticated`, `ai_field_in_exception`, `ai_field_in_hold_rule` | Safety restrictions (§5, §7)                                        |
| `regex_invalid`, `glob_invalid`, `cidr_invalid`, `time_zone_invalid`                                                       | Pattern and value checks                                            |
| `definition_hash_mismatch`                                                                                                 | A stored definition whose SHA-256 no longer matches (snapshot only) |

## 2. Field catalog

Types: `address` and `domain` compare after Unicode NFC and lower-casing, domains as ASCII (punycode); `string` compares case-insensitively; `enum` uses the listed vocabulary; `int` is an integer; `bool`; `ip` (IPv4/IPv6; IPv4-mapped IPv6 is treated as IPv4); `codes` is a set of reason codes or vocabulary members; `id` is the public id (UUID) of a tenant department or user; `time` is the evaluation time of the round. Scope `message` = one fact per message; `recipients`, `attachments`, `urls` = one fact per list element (quantified, §4).

<!-- field-table:start -->

| Field                          | Type    | Scope       | Operators                                                        | Sender identity       | AI-derived | Notes                                                                                                                                                                                                                                                |
| ------------------------------ | ------- | ----------- | ---------------------------------------------------------------- | --------------------- | ---------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `direction`                    | enum    | message     | `equals`, `in`                                                   |                       |            | Values: `inbound`, `outbound`, `internal`. Message direction (prefer the rule `directions`).                                                                                                                                                         |
| `sender.envelope.address`      | address | message     | `equals`, `in`, `not_in`, `glob`, `regex`, `exists`              | raw (unauthenticated) |            | MAIL FROM address; raw, unauthenticated.                                                                                                                                                                                                             |
| `sender.envelope.domain`       | domain  | message     | `equals`, `in`, `not_in`, `domain_in`, `glob`, `regex`, `exists` | raw (unauthenticated) |            | MAIL FROM domain; raw, unauthenticated.                                                                                                                                                                                                              |
| `sender.envelope.local_part`   | string  | message     | `equals`, `in`, `not_in`, `glob`, `regex`, `exists`              | raw (unauthenticated) |            | MAIL FROM local part; raw, unauthenticated.                                                                                                                                                                                                          |
| `sender.header_from.address`   | address | message     | `equals`, `in`, `not_in`, `glob`, `regex`, `exists`              | raw (unauthenticated) |            | Header From address; raw, unauthenticated.                                                                                                                                                                                                           |
| `sender.header_from.domain`    | domain  | message     | `equals`, `in`, `not_in`, `domain_in`, `glob`, `regex`, `exists` | raw (unauthenticated) |            | Header From domain; raw, unauthenticated.                                                                                                                                                                                                            |
| `sender.authenticated.address` | address | message     | `equals`, `in`, `glob`, `exists`                                 | authenticated         |            | Inbound: header From when DMARC passes and no authentication failure; outbound/internal: the organization-authenticated envelope sender; else unknown.                                                                                               |
| `sender.authenticated.domain`  | domain  | message     | `equals`, `in`, `domain_in`, `glob`, `exists`                    | authenticated         |            | Domain of `sender.authenticated.address`.                                                                                                                                                                                                            |
| `sender.trusted`               | bool    | message     | `is`                                                             | authenticated         |            | inbound only. Inbound only: BEC trusted sender authenticated as From, DMARC pass, no authentication failure; false otherwise; unknown without bec or auth facts.                                                                                     |
| `sender.department`            | id      | message     | `in`, `not_in`                                                   | authenticated         |            | outbound/internal only. Departments of the authenticated sender (outbound/internal only).                                                                                                                                                            |
| `sender.user`                  | id      | message     | `in`, `not_in`                                                   | authenticated         |            | outbound/internal only. Users matching the authenticated sender (outbound/internal only).                                                                                                                                                            |
| `recipient.address`            | address | recipients  | `equals`, `in`, `not_in`, `glob`, `regex`                        |                       |            | Envelope recipient (trusted).                                                                                                                                                                                                                        |
| `recipient.domain`             | domain  | recipients  | `equals`, `in`, `not_in`, `domain_in`, `glob`, `regex`           |                       |            | Envelope recipient domain.                                                                                                                                                                                                                           |
| `recipient.local_part`         | string  | recipients  | `equals`, `in`, `not_in`, `glob`, `regex`                        |                       |            | Envelope recipient local part.                                                                                                                                                                                                                       |
| `recipient.department`         | id      | recipients  | `in`, `not_in`                                                   |                       |            | Departments of the envelope recipient.                                                                                                                                                                                                               |
| `recipient.user`               | id      | recipients  | `in`, `not_in`                                                   |                       |            | Users matching the envelope recipient.                                                                                                                                                                                                               |
| `recipients.count`             | int     | message     | `eq`, `gt`, `gte`, `lt`, `lte`, `between`                        |                       |            | Number of envelope recipients.                                                                                                                                                                                                                       |
| `client.ip`                    | ip      | message     | `equals`, `in_cidr`                                              |                       |            | Connecting client IP (XFORWARD ADDR); unknown when absent.                                                                                                                                                                                           |
| `client.hostname`              | domain  | message     | `equals`, `domain_in`, `glob`                                    |                       |            | Verified client host name (XFORWARD NAME); unknown when absent.                                                                                                                                                                                      |
| `auth.spf`                     | enum    | message     | `equals`, `in`                                                   |                       |            | Values: `pass`, `fail`, `softfail`, `neutral`, `none`, `temperror`, `permerror`. SPF result.                                                                                                                                                         |
| `auth.dkim`                    | enum    | message     | `equals`, `in`                                                   |                       |            | Values: `pass`, `fail`, `softfail`, `neutral`, `none`, `temperror`, `permerror`. DKIM result.                                                                                                                                                        |
| `auth.dmarc`                   | enum    | message     | `equals`, `in`                                                   |                       |            | Values: `pass`, `fail`, `softfail`, `neutral`, `none`, `temperror`, `permerror`. DMARC result.                                                                                                                                                       |
| `auth.arc`                     | enum    | message     | `equals`, `in`                                                   |                       |            | Values: `pass`, `fail`, `softfail`, `neutral`, `none`, `temperror`, `permerror`. ARC result.                                                                                                                                                         |
| `auth.dmarc_policy`            | enum    | message     | `equals`, `in`                                                   |                       |            | Values: `none`, `quarantine`, `reject`. Published DMARC policy.                                                                                                                                                                                      |
| `message.size_bytes`           | int     | message     | `eq`, `gt`, `gte`, `lt`, `lte`, `between`                        |                       |            | Message size.                                                                                                                                                                                                                                        |
| `attachments.count`            | int     | message     | `eq`, `gt`, `gte`, `lt`, `lte`, `between`                        |                       |            | Number of attachments.                                                                                                                                                                                                                               |
| `attachments.total_bytes`      | int     | message     | `eq`, `gt`, `gte`, `lt`, `lte`, `between`                        |                       |            | Total decoded attachment bytes.                                                                                                                                                                                                                      |
| `attachments.truncated`        | bool    | message     | `is`                                                             |                       |            | True when attachment facts were capped.                                                                                                                                                                                                              |
| `attachment.extension`         | string  | attachments | `equals`, `in`, `not_in`                                         |                       |            | Lower-case extension of the sanitized filename, without the dot.                                                                                                                                                                                     |
| `attachment.filename`          | string  | attachments | `glob`, `regex`                                                  |                       |            | Sanitized filename (never stored or echoed).                                                                                                                                                                                                         |
| `attachment.declared_type`     | string  | attachments | `equals`, `in`, `not_in`, `glob`                                 |                       |            | Declared MIME type.                                                                                                                                                                                                                                  |
| `attachment.detected_type`     | string  | attachments | `equals`, `in`, `not_in`, `glob`                                 |                       |            | Detected type (FILE_TYPES id) of the round.                                                                                                                                                                                                          |
| `attachment.type_family`       | enum    | attachments | `equals`, `in`, `not_in`                                         |                       |            | Values: `document`, `archive`, `executable`, `script`, `disk_image`, `image`, `markup`, `text`, `other`. Detected type family of the round.                                                                                                          |
| `attachment.size_bytes`        | int     | attachments | `eq`, `gt`, `gte`, `lt`, `lte`, `between`                        |                       |            | Decoded attachment size.                                                                                                                                                                                                                             |
| `attachment.sha256`            | string  | attachments | `equals`, `in`                                                   |                       |            | Lower-case hex SHA-256 of the decoded bytes.                                                                                                                                                                                                         |
| `attachment.verdict`           | enum    | attachments | `equals`, `in`                                                   |                       |            | Values: `clean`, `suspicious`, `malicious`, `unknown`. Attachment verdict of the round; unknown without a result.                                                                                                                                    |
| `attachment.reason_codes`      | codes   | attachments | `contains_any`, `contains_all`                                   |                       |            | Attachment reason codes of the round.                                                                                                                                                                                                                |
| `attachment.is_archive`        | bool    | attachments | `is`                                                             |                       |            | True for archives.                                                                                                                                                                                                                                   |
| `attachment.encrypted`         | bool    | attachments | `is`                                                             |                       |            | True for encrypted archives.                                                                                                                                                                                                                         |
| `attachment.type_mismatch`     | bool    | attachments | `is`                                                             |                       |            | Declared and detected types disagree; unknown without a result.                                                                                                                                                                                      |
| `urls.count`                   | int     | message     | `eq`, `gt`, `gte`, `lt`, `lte`, `between`                        |                       |            | Number of URLs.                                                                                                                                                                                                                                      |
| `urls.truncated`               | bool    | message     | `is`                                                             |                       |            | True when URL facts were capped.                                                                                                                                                                                                                     |
| `urls.rewrite_status`          | enum    | message     | `equals`, `in`                                                   |                       |            | Values: `rewritten`, `skipped`, `none`. URL rewriting of the round (`none` = no rewrite record).                                                                                                                                                     |
| `url.host`                     | domain  | urls        | `equals`, `in`, `not_in`, `domain_in`, `glob`                    |                       |            | URL host (ASCII).                                                                                                                                                                                                                                    |
| `url.domain`                   | domain  | urls        | `equals`, `in`, `not_in`, `domain_in`, `glob`                    |                       |            | Registrable domain of the URL host; unknown for IP hosts.                                                                                                                                                                                            |
| `url.scheme`                   | enum    | urls        | `equals`, `in`                                                   |                       |            | Values: `http`, `https`. URL scheme.                                                                                                                                                                                                                 |
| `url.host_kind`                | enum    | urls        | `equals`, `in`                                                   |                       |            | Values: `domain`, `ipv4`, `ipv6`. Host kind.                                                                                                                                                                                                         |
| `url.verdict`                  | enum    | urls        | `equals`, `in`                                                   |                       |            | Values: `clean`, `suspicious`, `malicious`, `unknown`. URL verdict of the round; unknown without a result.                                                                                                                                           |
| `url.reason_codes`             | codes   | urls        | `contains_any`, `contains_all`                                   |                       |            | URL reason codes of the round.                                                                                                                                                                                                                       |
| `risk.present`                 | bool    | message     | `is`                                                             |                       |            | A revision-0 risk row exists.                                                                                                                                                                                                                        |
| `risk.score`                   | int     | message     | `eq`, `gt`, `gte`, `lt`, `lte`, `between`                        |                       |            | Risk score (maximum over revisions).                                                                                                                                                                                                                 |
| `risk.level`                   | enum    | message     | `equals`, `in`, `gte`, `lte`                                     |                       |            | Ordered: `none` < `low` < `medium` < `high` < `critical`. Risk level (maximum over revisions).                                                                                                                                                       |
| `risk.verdict`                 | enum    | message     | `equals`, `in`                                                   |                       |            | Values: `clean`, `spam`, `bulk`, `phishing`, `malware`, `bec`, `dlp_violation`, `suspicious`, `unknown`. Verdict of the decisive revision.                                                                                                           |
| `risk.recommended_action`      | enum    | message     | `equals`, `in`, `gte`, `lte`                                     |                       |            | Ordered: `deliver` < `tag` < `require_approval` < `quarantine` < `block`. Recommended action (maximum over revisions).                                                                                                                               |
| `risk.hard_blocks`             | codes   | message     | `contains_any`, `contains_all`, `exists`                         |                       |            | Values: `hb.malware_attachment`, `hb.malware_url`, `hb.malware_sandbox`, `hb.dlp_block`, `hb.known_phishing`, `hb.tenant_domain_spoof`, `hb.url_tenant_blocked`, `hb.bec_malicious`, `hb.dmarc_reject`. Fired hard-block ids (union over revisions). |
| `risk.reason_codes`            | codes   | message     | `contains_any`, `contains_all`                                   |                       |            | Risk reason codes (union over revisions).                                                                                                                                                                                                            |
| `risk.status`                  | enum    | message     | `equals`                                                         |                       |            | Values: `scored`, `error`. Risk status (worst over revisions).                                                                                                                                                                                       |
| `risk.sandbox_outcome`         | enum    | message     | `equals`, `in`                                                   |                       |            | Values: `clean`, `suspicious`, `malicious`, `unknown`, `timeout`, `error`. Sandbox outcome of revision 1; unknown without it.                                                                                                                        |
| `dlp.present`                  | bool    | message     | `is`                                                             |                       |            | A DLP result row exists.                                                                                                                                                                                                                             |
| `dlp.action`                   | enum    | message     | `equals`, `in`, `gte`, `lte`                                     |                       |            | Ordered: `allow` < `alert` < `require_approval` < `quarantine` < `block`. Effective DLP action.                                                                                                                                                      |
| `dlp.verdict`                  | enum    | message     | `equals`, `in`                                                   |                       |            | Values: `clean`, `suspicious`, `unknown`, `skipped`. DLP verdict.                                                                                                                                                                                    |
| `dlp.coverage`                 | enum    | message     | `equals`, `in`                                                   |                       |            | Values: `complete`, `partial`. DLP coverage.                                                                                                                                                                                                         |
| `dlp.max_severity`             | enum    | message     | `equals`, `in`, `gte`, `lte`                                     |                       |            | Ordered: `info` < `low` < `medium` < `high` < `critical`. Highest finding severity; unknown without findings.                                                                                                                                        |
| `dlp.categories`               | codes   | message     | `contains_any`, `contains_all`                                   |                       |            | Values: `payment_card`, `bank_account`, `national_id`, `passport`, `personal_info`, `confidential`, `source_code`, `credential`, `financial`, `custom`. Matched DLP categories.                                                                      |
| `dlp.detector_codes`           | codes   | message     | `contains_any`, `contains_all`                                   |                       |            | Reason codes of the DLP final.                                                                                                                                                                                                                       |
| `bec.deterministic_verdict`    | enum    | message     | `equals`, `in`                                                   |                       |            | Values: `clean`, `suspicious`, `malicious`, `unknown`, `skipped`. Deterministic BEC verdict.                                                                                                                                                         |
| `bec.rule_codes`               | codes   | message     | `contains_any`, `contains_all`                                   |                       |            | Active (unsuppressed) deterministic BEC rule codes.                                                                                                                                                                                                  |
| `bec.verdict`                  | enum    | message     | `equals`, `in`                                                   |                       | yes        | Values: `clean`, `suspicious`, `malicious`, `unknown`, `skipped`. BEC verdict including the AI layer (AI-derived).                                                                                                                                   |
| `bec.ai_raised`                | bool    | message     | `is`                                                             |                       | yes        | The AI layer raised the BEC verdict (AI-derived).                                                                                                                                                                                                    |
| `scan.outcome`                 | enum    | message     | `equals`, `in`                                                   |                       |            | Values: `scanned`, `scan_failed`, `not_scanned`. Round outcome (`not_scanned` = parse failure).                                                                                                                                                      |
| `scan.verdict`                 | enum    | message     | `equals`, `in`                                                   |                       |            | Values: `clean`, `spam`, `suspicious`, `malicious`, `unknown`, `timeout`, `error`. Round verdict.                                                                                                                                                    |
| `scan.reason_codes`            | codes   | message     | `contains_any`, `contains_all`                                   |                       |            | Round reason codes.                                                                                                                                                                                                                                  |
| `scan.failed_engines`          | codes   | message     | `contains_any`, `exists`                                         |                       |            | Values: `rspamd`, `attachment`, `url`, `bec`, `dlp`, `sandbox`. Engines that timed out, failed or are missing.                                                                                                                                       |
| `scan.unknown_engines`         | codes   | message     | `contains_any`, `exists`                                         |                       |            | Values: `rspamd`, `attachment`, `url`, `bec`, `dlp`, `sandbox`. Engines with an `unknown` outcome.                                                                                                                                                   |
| `time.window`                  | time    | message     | `within`                                                         |                       |            | Weekly local-time window in an IANA time zone.                                                                                                                                                                                                       |
| `time.date_range`              | time    | message     | `within`                                                         |                       |            | Inclusive local date range in an IANA time zone.                                                                                                                                                                                                     |

<!-- field-table:end -->

**Sender identity.** `raw` fields (envelope MAIL FROM and header From) are what the message claims and can be forged. `sender.authenticated.*` is the header From only when DMARC passes and no SPF/DKIM/ARC/DMARC failure was reported (inbound), or the envelope sender authenticated by the organization's connector (outbound and internal: the connector authenticates the organization, not the individual user, so department and user facts of the sender are as trustworthy as the tenant's own submission control). `sender.trusted` is true only when the BEC engine matched a trusted sender that authenticated as From, DMARC passed and no authentication failure was reported.

**Directory.** Departments are tenant directory groups (`/api/v1/departments`); a member is an address or a user account. Users are tenant accounts (`users.public_id`) that match an address equal to their e-mail while active. Membership is live: a change applies to the next evaluation without publishing a policy.

## 3. Operators

| Operator                        | Value                                                                     | True when                                                                                                                                                                      |
| ------------------------------- | ------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| `equals`                        | one value                                                                 | The fact equals the value (normalized)                                                                                                                                         |
| `in` / `not_in`                 | list (1..500)                                                             | The fact is / is not one of the values; for `id` fields: some / none of the fact's ids is listed                                                                               |
| `domain_in`                     | list of domains (1..500)                                                  | The domain equals a listed domain or ends with `.` + it (`a.example.com` is in `example.com`; `badexample.com` is not)                                                         |
| `glob`                          | list of patterns (1..10, ≤ 128 chars)                                     | Case-insensitive match where `*` is any run and `?` one character; a linear matcher, never a regular expression                                                                |
| `regex`                         | list (1..5) of `"pattern"` or `{ "pattern", "flags": "i" }` (≤ 256 chars) | RE2 search on the first 1 024 characters; backreferences, lookaround, possessive and atomic constructs and nested counted repetition over 1 000 are refused                    |
| `in_cidr`                       | list of CIDRs (1..100)                                                    | The address is inside a network; CIDRs must be canonical (no host bits) with a prefix in range                                                                                 |
| `eq`, `gt`, `gte`, `lt`, `lte`  | integer, or a vocabulary value for ordered fields                         | Numeric or rank comparison (`risk.level`, `risk.recommended_action`, `dlp.action`, `dlp.max_severity` are ordered weakest first)                                               |
| `between`                       | `[low, high]`                                                             | `low ≤ fact ≤ high`                                                                                                                                                            |
| `contains_any` / `contains_all` | list of codes (1..64)                                                     | The fact's code set contains any / all of them                                                                                                                                 |
| `exists`                        | none                                                                      | The fact has a value (a non-empty set for code sets); never unknown                                                                                                            |
| `is`                            | `true` / `false`                                                          | Boolean equality                                                                                                                                                               |
| `within`                        | time object                                                               | `time.window`: `{ timeZone, days: ["mon"…"sun"], from: "HH:MM", to: "HH:MM" \| "24:00" }`; `time.date_range`: `{ timeZone, from: "YYYY-MM-DD", to: "YYYY-MM-DD" }` (inclusive) |

**Time.** The evaluation time is a fact of the round (the scan completion time; for a parse failure the parse completion time), never the wall clock, so a dry-run reproduces the stored decision. Local time comes from the IANA zone of the condition (validated against the runtime's time-zone database; aliases such as `Asia/Kolkata` and `UTC` are accepted). A window with `from > to` wraps midnight and belongs to the day it starts on. An instant always has exactly one local time: in a spring-forward gap no instant falls inside the missing hour; in a fall-back overlap both instants with the repeated local time are inside. The ICU time-zone data version is recorded with every decision.

## 4. Quantifiers and three-valued logic

Every leaf is **true**, **false** or **unknown**. A fact that is missing (no authentication row, no risk row, no result for an attachment, an IP host's registrable domain, the authenticated sender of an unauthenticated message, sender departments of inbound mail) makes the leaf unknown. `all`, `any` and `not` follow Kleene logic:

| `a`     | `b`     | `all`   | `any`   | `not a` |
| ------- | ------- | ------- | ------- | ------- |
| true    | unknown | unknown | true    | false   |
| false   | unknown | false   | unknown | true    |
| unknown | unknown | unknown | unknown | unknown |

A rule matches only when `when` is **true**; an exception applies only when it is **true**. Missing data therefore never makes a rule fire and never makes an exception apply; the floor (§7) turns missing risk, DLP or scan data into holds.

List fields take a `quantifier` (`any` by default in `when`; `all` required in exceptions):

| List                                                                | `any`                                        | `all`                                          |
| ------------------------------------------------------------------- | -------------------------------------------- | ---------------------------------------------- |
| empty                                                               | false                                        | false                                          |
| complete                                                            | at least one element true                    | every element true                             |
| truncated (more than 1 000 recipients, 200 attachments or 500 URLs) | true if a seen element is true, else unknown | false if a seen element is false, else unknown |

## 5. Exceptions and identity restrictions

`unless` (per rule) and `exceptions` (per policy) remove a tenant rule's effect when they are true. They can never touch the platform default or the floor. They are restricted so that an attacker cannot trigger them:

- positive only: no `not`, no `not_in` (`exception_negation`);
- list conditions use `quantifier: "all"` (`exception_quantifier`): an exception covers a multi-recipient message only if it covers every recipient;
- the sender only through `sender.authenticated.*`, `sender.trusted`, `sender.department`, `sender.user` (`identity_unauthenticated`); never `sender.envelope.*` or `sender.header_from.*`;
- no AI-derived field (`ai_field_in_exception`).

The `when` of a rule whose disposition is `ALLOW` or which has `override: true` follows the same sender identity restriction: a relaxing rule must not be reachable by forging an address. Raw sender fields remain available to rules that tag, warn or hold (forging them can only make mail stricter).

## 6. Actions

| Action             | Parameters                                                                                                            | 5.2 effect                                                                                                                                                                                                            | Stored status                                                                                             |
| ------------------ | --------------------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------- |
| `ALLOW`            | —                                                                                                                     | Approve and deliver (one approval per ≤ 1 000 pending recipients)                                                                                                                                                     | `enforced`                                                                                                |
| `REQUIRE_APPROVAL` | —                                                                                                                     | Hold in `held_for_review`; released by the existing operator release (5.3 adds the approval workflow)                                                                                                                 | `enforced`                                                                                                |
| `QUARANTINE`       | —                                                                                                                     | Hold in `quarantined` (5.3 adds the store, digests and end-user release)                                                                                                                                              | `enforced`                                                                                                |
| `REJECT`           | `notifySender?: boolean`                                                                                              | Nothing delivered. Inbound: dropped without a bounce (`discard`). Outbound/internal: `reject`, and a non-delivery notice to the organization's sender (`notifySender`, default the tenant setting, itself default on) | `enforced`; notice `requested`                                                                            |
| `TAG`              | `label` (`[a-z0-9][a-z0-9._-]{0,31}`), `subjectPrefix?` (printable ASCII 1..32, no `:`), `addHeader?: boolean = true` | When delivered: `X-EG-Policy-Tag: <labels>` and the subject prefix in a policy copy (header edits only)                                                                                                               | `enforced` when written; `recorded` when no header/prefix is written; `not_applicable` when not delivered |
| `WARN`             | `level` (`caution` < `warning` < `danger`), `text?` (printable ASCII 1..128), `subjectPrefix?`                        | When delivered: `X-EG-Policy-Warning: <level>; <text>` and the prefix; **body banners are not supported in 5.2** (`bodyBanner: not_supported`)                                                                        | as TAG                                                                                                    |
| `URL_REWRITE`      | `ifNotRewritten?: "deliver" \| "quarantine" = "deliver"`                                                              | Requires delivery of the round's rewritten copy (rewriting happens at scan time under the tenant's URL settings). Not rewritten: `deliver` records the skip reason; `quarantine` raises the decision to QUARANTINE    | `enforced` (rewritten copy or quarantine raise) or `recorded`                                             |
| `ARCHIVE`          | —                                                                                                                     | `mail.message.archive_requested.v1` to the archive stage (**step 8.1** performs it)                                                                                                                                   | `requested`                                                                                               |
| `ALERT`            | `severity` (`info` < `warning` < `critical`)                                                                          | E-mail to the organization's users holding `policy:publish` (notification-worker, at least once); ids and policy names only, never message content                                                                    | `requested` (`recorded` when alerts are disabled)                                                         |

TAG, WARN and URL_REWRITE apply only when the final disposition is ALLOW (a URL_REWRITE that raised the decision to QUARANTINE is the exception: it applies). ARCHIVE and ALERT apply to every disposition. Header values are built only from validated policy data, never from message data.

## 7. Conflict resolution, the platform default and the floor

1. **Candidate rules** are the enabled rules of every active policy whose `direction` is the message direction or `any` and whose `directions` (if present) include it, ordered by policy priority, policy id, rule priority, rule id (all ascending).
2. For each candidate in order: a true policy-wide exception excepts the rule; else `when` must be true; then a true `unless` excepts it; else it **matches**. After the first matched rule with `stop = true`, later rules are not evaluated (they appear as `not_evaluated` in the trace).
3. **Tenant disposition** = the strictest disposition among matched rules (`allow < require_approval < quarantine < reject`); the decisive rule is the first matched rule carrying it. A low-priority REJECT is therefore never hidden by an earlier ALLOW unless that ALLOW stops evaluation.
4. **Recommendation** (`pol-default/1`): the 5.1 risk recommendation (maximum over the round's revisions) mapped `deliver → allow`, `tag → allow` plus a platform TAG `risk-<level>`, `require_approval`, `quarantine`, `block → reject`; plus rule **D2**: a deterministic BEC verdict `suspicious` or `malicious` recommends `quarantine`. The recommendation is **level-only** when every present risk revision is: scored, no hard block, no failure, no unknown engine, no missing child row (D2 `suspicious` counts as level-only; `malicious` does not).
5. **Floor** (mandatory): the strictest of every present revision that is not level-only (its whole recommendation: hard blocks, failures, unknown engines, missing child rows, scoring errors), the DLP binding (`alert → allow + mandatory TAG dlp-alert`, `require_approval`, `quarantine`, `block → reject`; a definite DLP result without its row → `quarantine`), a scanned round without its risk row → `quarantine`, a scan failure → `quarantine`, a parse failure → `quarantine`.
6. **Base** = the tenant disposition if it is at least the recommendation; a weaker tenant disposition only through an **override** (§8); otherwise the recommendation, with a recorded **clamp**. No tenant disposition → the recommendation.
7. **Final** = max(base, floor), then a URL_REWRITE `quarantine` raise, then the floor again. Revision 1 (sandbox) joins the recommendation and the floor by maximum: it can only make the decision stricter.

Non-terminal actions of every matched rule are merged in rule order: TAG labels union (sorted, at most 8), the first subject prefix (TAG before WARN), the strongest WARN level and the first WARN text, the strictest URL_REWRITE fallback, ARCHIVE once, the highest ALERT severity. Rules that read AI-derived fields (`bec.verdict`, `bec.ai_raised`) cannot carry REQUIRE_APPROVAL, QUARANTINE or REJECT (`ai_field_in_hold_rule`), and the platform holds use deterministic verdicts only: **an AI-only signal can tag or warn, never hold**.

**Platform tags** (the recommendation's `risk-<level>` and the floor's mandatory tags) are written as headers on inbound and internal mail (`tagging.platformTagHeader`, default on) and only recorded on outbound mail unless `tagging.platformTagOutbound` is on, so internal labels do not leak to external recipients.

## 8. Overrides

A tenant disposition weaker than the recommendation is kept only when **all** of these hold, and the decision then records `override = { applied, ref, from, to }` and the reason `policy.override.applied`:

- a matched rule with that disposition has `override: true` (publishing such a version is audited `policy.override_rules_published`);
- the tenant setting `allowRecommendationOverrides` is on (turning it on is audited `policy.settings_overrides_enabled`);
- the recommendation is level-only.

Otherwise the recommendation stands and a clamp is recorded (`override_not_allowed`, `override_disabled` or `not_level_only`). An override never goes below the floor: hard blocks, failures, unknown engines, the DLP binding and missing data cannot be overridden by any rule or setting.

## 9. Tenant settings

`PUT /api/v1/policy-settings` (strict, all keys optional; invalid stored settings fall back to the defaults with `policy.settings.invalid_fallback`):

| Key                            | Default |
| ------------------------------ | ------- |
| `allowRecommendationOverrides` | `false` |
| `notices.senderNonDelivery`    | `true`  |
| `alerts.enabled`               | `true`  |
| `tagging.platformTagHeader`    | `true`  |
| `tagging.platformTagOutbound`  | `false` |

A published change applies to the **next** evaluation (the snapshot is keyed by the organization's generation); a message already evaluated is never re-evaluated by a change.

## 10. Limits

Document ≤ 262 144 bytes (canonical JSON); rules per policy ≤ 100; nodes per rule (`when` + all `unless`) ≤ 64; depth ≤ 6 (root = 1); children per `all`/`any` ≤ 16; list values ≤ 500; string values ≤ 320 characters; globs ≤ 10 × 128; regexes ≤ 5 × 256; CIDRs ≤ 100; codes ≤ 64; exceptions ≤ 8 per rule and ≤ 8 per policy (≤ 64 nodes); actions ≤ 8 per rule; descriptions ≤ 256; active policies per organization ≤ 100 and active rules ≤ 5 000 (the api lowers both by environment). Facts considered per message: 1 000 recipients, 200 attachments, 500 URLs (more set the truncated flags of §4).

## 11. Worked examples

Each example shows the policy, the synthetic facts used by `POST /api/v1/policies/test` (fields not shown take the defaults of P23: an inbound message from `sender@example.com` to `recipient@example.net`, a clean risk revision, no authentication, DLP or BEC row) and the expected decision. The comment below each pair is the machine-checked expectation.

### Example 1: trusted partner allow-override

A partner's newsletters score `quarantine` (bulk-looking but level-only). The tenant allows them when the partner's domain authenticates, after enabling overrides. Without the setting, or with a hard block, the recommendation or the floor stands.

```json
{
  "dslVersion": "policy-dsl/1",
  "direction": "inbound",
  "priority": 10,
  "rules": [
    {
      "id": "partner-allow",
      "priority": 10,
      "description": "Authenticated partner mail is allowed over a level-only recommendation",
      "when": {
        "field": "sender.authenticated.domain",
        "op": "domain_in",
        "value": ["partner.example"]
      },
      "actions": [{ "type": "ALLOW" }],
      "override": true
    }
  ]
}
```

```json
{
  "sender": { "envelope": "news@mail.partner.example", "authenticated": true },
  "auth": { "spf": "pass", "dkim": "pass", "dmarc": "pass", "dmarcPolicy": "reject" },
  "risk": {
    "rev0": { "score": 600, "level": "high", "verdict": "spam", "recommendedAction": "quarantine" }
  }
}
```

<!-- check: {"settings": {"allowRecommendationOverrides": true}, "expect": {"disposition": "allow", "source": "tenant_rule", "reason": "policy.override.applied", "override": true}} -->

Expected: **allow**, decided by `partner-allow` with `policy.override.applied`; the platform tag of the recommendation is dropped. With `allowRecommendationOverrides` off: **quarantine** with clamp `override_disabled`.

### Example 2: department exception

Quarantine external mail with attachments, except when every recipient is in the finance department (whose invoices arrive this way).

```json
{
  "dslVersion": "policy-dsl/1",
  "direction": "inbound",
  "priority": 20,
  "rules": [
    {
      "id": "external-attachments",
      "priority": 10,
      "when": { "field": "attachments.count", "op": "gt", "value": 0 },
      "unless": [
        {
          "field": "recipient.department",
          "op": "in",
          "value": ["01930000-0000-7000-8000-0000000000f1"],
          "quantifier": "all"
        }
      ],
      "actions": [{ "type": "QUARANTINE" }]
    }
  ]
}
```

```json
{
  "recipients": [{ "address": "ap@corp.example" }, { "address": "cfo@corp.example" }],
  "attachments": [
    { "filename": "invoice-2026-11.pdf", "typeFamily": "document", "verdict": "clean" }
  ],
  "directory": {
    "departments": {
      "ap@corp.example": ["01930000-0000-7000-8000-0000000000f1"],
      "cfo@corp.example": ["01930000-0000-7000-8000-0000000000f1"]
    }
  }
}
```

<!-- check: {"expect": {"disposition": "allow", "source": "platform_default", "excepted": "unless[0]"}} -->

Expected: **allow** (the rule is excepted at `unless[0]`). Adding a recipient outside finance makes the exception false (quantifier `all`) and the message is **quarantined**.

### Example 3: executive impersonation warning

Mail that claims to come from the CEO's own domain but fails DMARC gets a danger warning and a subject prefix. Raw sender fields are allowed here because the rule only warns.

```json
{
  "dslVersion": "policy-dsl/1",
  "direction": "inbound",
  "priority": 30,
  "rules": [
    {
      "id": "exec-impersonation",
      "priority": 10,
      "when": {
        "all": [
          {
            "field": "sender.header_from.address",
            "op": "in",
            "value": ["ceo@corp.example", "cfo@corp.example"]
          },
          { "field": "auth.dmarc", "op": "in", "value": ["fail", "none", "temperror", "permerror"] }
        ]
      },
      "actions": [
        {
          "type": "WARN",
          "level": "danger",
          "text": "Possible executive impersonation",
          "subjectPrefix": "[CAUTION]"
        },
        { "type": "ALERT", "severity": "warning" }
      ]
    }
  ]
}
```

```json
{
  "sender": { "envelope": "billing@lookalike.example", "headerFrom": "CEO@corp.example" },
  "auth": { "spf": "pass", "dkim": "none", "dmarc": "fail", "dmarcPolicy": "none" }
}
```

<!-- check: {"expect": {"disposition": "allow", "headers": ["X-EG-Policy-Warning: danger; Possible executive impersonation"], "subjectPrefix": "[CAUTION]", "actions": ["ALLOW", "WARN", "ALERT"]}} -->

Expected: **allow** with `X-EG-Policy-Warning: danger; Possible executive impersonation`, subject prefix `[CAUTION]`, body banner `not_supported`, and an ALERT requested.

### Example 4: outbound card numbers need approval

Outbound mail with payment card numbers to anyone outside the company waits for approval. The DLP policy itself only alerts (floor: allow plus a mandatory `dlp-alert` tag); the tenant rule is stricter, so it decides.

```json
{
  "dslVersion": "policy-dsl/1",
  "direction": "outbound",
  "priority": 40,
  "rules": [
    {
      "id": "cards-external",
      "priority": 10,
      "when": {
        "all": [
          { "field": "dlp.categories", "op": "contains_any", "value": ["payment_card"] },
          {
            "field": "recipient.domain",
            "op": "not_in",
            "value": ["corp.example"],
            "quantifier": "any"
          }
        ]
      },
      "actions": [{ "type": "REQUIRE_APPROVAL" }, { "type": "ALERT", "severity": "info" }]
    }
  ]
}
```

```json
{
  "direction": "outbound",
  "sender": { "envelope": "sales@corp.example", "authenticated": true },
  "recipients": [{ "address": "buyer@customer.example" }],
  "dlp": { "action": "alert", "categories": ["payment_card"], "maxSeverity": "high" }
}
```

<!-- check: {"expect": {"disposition": "require_approval", "source": "tenant_rule", "floor": ["policy.floor.dlp_alert"]}} -->

Expected: **require_approval** (`held_for_review`, final action `require_approval`), decided by `cards-external`; the floor reason `policy.floor.dlp_alert` is recorded.

### Example 5: after-hours outbound quarantine across DST

Outbound mail sent between 19:00 and 07:00 New York time on weekdays is quarantined for review. The window follows New York's wall clock across the March DST change.

```json
{
  "dslVersion": "policy-dsl/1",
  "direction": "outbound",
  "priority": 50,
  "rules": [
    {
      "id": "after-hours",
      "priority": 10,
      "when": {
        "field": "time.window",
        "op": "within",
        "value": {
          "timeZone": "America/New_York",
          "days": ["mon", "tue", "wed", "thu", "fri"],
          "from": "19:00",
          "to": "07:00"
        }
      },
      "actions": [{ "type": "QUARANTINE" }]
    }
  ]
}
```

```json
{
  "direction": "outbound",
  "sender": { "envelope": "trader@corp.example", "authenticated": true },
  "evaluationTime": "2026-03-09T23:30:00.000Z"
}
```

<!-- check: {"expect": {"disposition": "quarantine", "source": "tenant_rule"}} -->

Expected: **quarantine**: 23:30 UTC on Monday 9 March 2026 is 19:30 EDT (DST began on 8 March). The same instant one week earlier (`2026-03-02T23:30:00.000Z`) is 18:30 EST and is delivered.

### Example 6: IP allow-list for a connector

Mail relayed by the tenant's scanning appliance is allowed and tagged. The client IP is not a sender identity, so an ALLOW rule may use it; the floor still applies (a hard block is rejected regardless).

```json
{
  "dslVersion": "policy-dsl/1",
  "direction": "inbound",
  "priority": 60,
  "rules": [
    {
      "id": "appliance",
      "priority": 10,
      "when": {
        "field": "client.ip",
        "op": "in_cidr",
        "value": ["198.51.100.0/24", "2001:db8:25::/48"]
      },
      "actions": [{ "type": "ALLOW" }, { "type": "TAG", "label": "via-appliance" }]
    }
  ]
}
```

```json
{
  "client": { "ip": "198.51.100.25" },
  "risk": {
    "rev0": {
      "score": 900,
      "level": "critical",
      "verdict": "malware",
      "recommendedAction": "block",
      "hardBlocks": [{ "id": "hb.malware_attachment", "action": "block" }]
    }
  }
}
```

<!-- check: {"expect": {"disposition": "reject", "source": "platform_default", "floor": ["policy.floor.hard_block"], "clamp": "override_not_allowed"}} -->

Expected: **reject** (inbound: dropped, final action `discard`): the hard block's floor and the recommendation are `reject`; the tenant ALLOW is clamped (`override_not_allowed`). Without the hard block the same message is **allow** with tag `via-appliance`.

### Example 7: block ISO attachments

Disk images are a common malware carrier; reject them outright.

```json
{
  "dslVersion": "policy-dsl/1",
  "direction": "any",
  "priority": 70,
  "rules": [
    {
      "id": "no-disk-images",
      "priority": 10,
      "when": {
        "any": [
          { "field": "attachment.extension", "op": "in", "value": ["iso", "img", "vhd", "vhdx"] },
          { "field": "attachment.type_family", "op": "equals", "value": "disk_image" }
        ]
      },
      "actions": [{ "type": "REJECT" }]
    }
  ]
}
```

```json
{ "attachments": [{ "filename": "Shipping-Docs.ISO", "verdict": "clean" }] }
```

<!-- check: {"expect": {"disposition": "reject", "source": "tenant_rule", "finalAction": "discard"}} -->

Expected: **reject** decided by `no-disk-images`; inbound, so the message is dropped without a bounce (final action `discard`). Outbound it would be `reject` with a sender non-delivery notice.

### Example 8: tag external mail

Every inbound message from outside the company gets a tag header and an `[EXTERNAL]` subject prefix. A TAG rule does not stop evaluation, so later rules still apply.

```json
{
  "dslVersion": "policy-dsl/1",
  "direction": "inbound",
  "priority": 80,
  "rules": [
    {
      "id": "external",
      "priority": 10,
      "when": { "field": "sender.envelope.domain", "op": "not_in", "value": ["corp.example"] },
      "actions": [{ "type": "TAG", "label": "external", "subjectPrefix": "[EXTERNAL]" }]
    }
  ]
}
```

```json
{ "sender": { "envelope": "someone@elsewhere.example" } }
```

<!-- check: {"expect": {"disposition": "allow", "headers": ["X-EG-Policy-Tag: external"], "subjectPrefix": "[EXTERNAL]", "finalAction": "tag"}} -->

Expected: **allow** with `X-EG-Policy-Tag: external` and subject prefix `[EXTERNAL]` in the delivered policy copy (final action `tag`).

### Example 9: require URL rewriting

Messages with links must be delivered as the rewritten copy; when the round could not be rewritten (for example a DKIM policy skip), quarantine them.

```json
{
  "dslVersion": "policy-dsl/1",
  "direction": "inbound",
  "priority": 90,
  "rules": [
    {
      "id": "links-rewritten",
      "priority": 10,
      "when": { "field": "urls.count", "op": "gt", "value": 0 },
      "actions": [{ "type": "URL_REWRITE", "ifNotRewritten": "quarantine" }]
    }
  ]
}
```

```json
{
  "urls": [{ "host": "docs.vendor.example", "verdict": "clean" }],
  "urlRewriteStatus": "skipped",
  "urlRewriteSkipReason": "dkim_policy"
}
```

<!-- check: {"expect": {"disposition": "quarantine", "source": "tenant_rule", "reason": "policy.url_rewrite.required"}} -->

Expected: **quarantine** with `policy.url_rewrite.required` (URL_REWRITE `enforced` through the hold). With `urlRewriteStatus: "rewritten"` the message is **allow** and the rewritten copy is delivered.

### Example 10: archive legal team mail

Mail to or from the legal department is archived (the archive stage is step 8.1; 5.2 requests it). ARCHIVE applies to every disposition and does not stop evaluation.

```json
{
  "dslVersion": "policy-dsl/1",
  "direction": "any",
  "priority": 100,
  "rules": [
    {
      "id": "legal-archive",
      "priority": 10,
      "when": {
        "any": [
          {
            "field": "recipient.department",
            "op": "in",
            "value": ["01930000-0000-7000-8000-0000000000f2"]
          },
          {
            "field": "sender.department",
            "op": "in",
            "value": ["01930000-0000-7000-8000-0000000000f2"]
          }
        ]
      },
      "actions": [{ "type": "ARCHIVE" }]
    }
  ]
}
```

```json
{
  "recipients": [{ "address": "counsel@corp.example" }],
  "directory": {
    "departments": { "counsel@corp.example": ["01930000-0000-7000-8000-0000000000f2"] }
  }
}
```

<!-- check: {"expect": {"disposition": "allow", "actions": ["ALLOW", "ARCHIVE"], "statuses": ["enforced", "requested"]}} -->

Expected: **allow** with ARCHIVE `requested` (`mail.message.archive_requested.v1`). On an inbound message the `sender.department` leaf is unknown (directory facts of the sender exist only outbound and internal); `any` still matches through the recipient.

### Example 11: alert on hard blocks

Notify the policy administrators whenever the platform finds a hard block, whatever the final decision.

```json
{
  "dslVersion": "policy-dsl/1",
  "direction": "any",
  "priority": 110,
  "rules": [
    {
      "id": "hard-block-alert",
      "priority": 10,
      "when": { "field": "risk.hard_blocks", "op": "exists" },
      "actions": [{ "type": "ALERT", "severity": "critical" }]
    }
  ]
}
```

```json
{
  "risk": {
    "rev0": {
      "score": 900,
      "level": "critical",
      "verdict": "phishing",
      "recommendedAction": "quarantine",
      "hardBlocks": [{ "id": "hb.known_phishing", "action": "quarantine" }]
    }
  }
}
```

<!-- check: {"expect": {"disposition": "quarantine", "source": "platform_default", "actions": ["QUARANTINE", "ALERT"], "statuses": ["enforced", "requested"]}} -->

Expected: **quarantine** (the recommendation and the hard-block floor) with ALERT `critical` requested.

### Example 12: what is refused

The validator refuses this document with every violation at once:

```json
{
  "dslVersion": "policy-dsl/1",
  "direction": "inbound",
  "priority": 120,
  "rules": [
    {
      "id": "spoofable-allow",
      "priority": 10,
      "when": { "field": "sender.envelope.domain", "op": "equals", "value": "partner.example" },
      "unless": [{ "not": { "field": "sender.trusted", "op": "is", "value": true } }],
      "actions": [{ "type": "ALLOW" }, { "type": "TAG", "label": "Partner\r\nX-Evil: 1" }]
    }
  ]
}
```

<!-- check: {"violations": [["rules[0].actions[1].label", "value_invalid"], ["rules[0].unless[0].not", "exception_negation"], ["rules[0].when.field", "identity_unauthenticated"]]} -->

Expected violations (sorted by path): `rules[0].actions[1].label` `value_invalid` (header injection), `rules[0].unless[0].not` `exception_negation`, `rules[0].when.field` `identity_unauthenticated` (an ALLOW rule cannot rely on the forgeable envelope sender).

## 12. The decision record

Every evaluation stores one `policy_execution_logs` row per message and lifecycle round (the api shows it as `PolicyEvaluationView`): the disposition, the decisive source (`tenant_rule`, `platform_default`, `floor`) with the policy, version and rule, the actions with their applicability and status, the matched rules, a trace (≤ 200 entries: `matched`, `not_matched`, `unknown`, `excepted`, `not_evaluated`, with the JSON path of the deciding condition), the floor, the recommendation, the override or clamps, reason codes (`policy.*`, the first is the decisive reason), an explanation from fixed English templates (≤ 24 lines; ids, codes and integers only, never addresses, domains, file names or URLs), the versions (DSL, evaluator, input, platform default, snapshot SHA-256, generation, tz data, policy versions) and the SHA-256 of the canonical input. A dry-run of a stored round with the same snapshot reproduces the stored decision.
