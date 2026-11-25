# Brief: API-mode protection (post-delivery, no mail-flow change)

Received from the product owner on 2026-11-25. Build after AI-6 and before ATP-1, as steps API-1, API-2 and API-3.

## Product owner's request

The product owner asked which is better: an MX-based (inline) gateway, or a gateway that receives a copy from the mail provider and works through the provider APIs without blocking mail flow. The answer given was a hybrid: MX inline where hard prevention is needed, and API mode for Microsoft 365 and Google Workspace customers who want zero mail-flow risk. The product owner then decided (verbatim): "yes please do all the posible feature before you start the atp".

## Goal

A tenant can be protected without changing its MX records. The gateway sees every message through the provider (journal copy or mailbox API), scans it with the existing pipeline, and removes or restores threats in the mailbox after delivery. It can also run alongside MX inline (hybrid).

## Scope

1. **Protection mode per tenant and domain:** `inline` (MX, today), `api` (copy or API only, never delivers) or `hybrid` (inline plus API post-delivery). Mode is shown on the domain and organization pages and is changeable with an audit entry.
2. **Mailbox connection for remediation.**
   - Reuse the 8.2 provider binding, wizard and guide framework (no second connector framework).
   - Add the mail scopes needed to read, move and delete messages:
     - Microsoft Graph: application permission `Mail.ReadWrite`.
     - Google: domain-wide delegation with the `gmail.modify` scope.
   - Consent is separate from the ATO scopes and can be revoked.
   - Credentials stay in the secret store and never reach chat or logs.
3. **Intake in API mode.**
   - Journal copy through the 8.6 journal-only intake, scanned in detect mode: never delivered, the verdict is stored.
   - Optionally, mailbox change feeds: Graph change notifications with a delta-query fallback, and Gmail history polling.
   - Duplicates between journal and API copies are removed by Internet Message-ID plus mailbox.
   - Lag from provider delivery to verdict is measured.
4. **Post-delivery remediation.**
   - A policy maps a verdict to a mailbox action:
     - move to the gateway's quarantine folder or label;
     - move to Junk;
     - tag with a category or label;
     - soft delete (recoverable);
     - hard delete (platform setting, off by default).
   - Default (applied, revisable): high-confidence malware and phishing are moved to the quarantine folder automatically; suspicious mail is tagged; nothing is hard-deleted.
   - Every action is idempotent, retried with back-off on provider throttling (429/503, Retry-After), audited, and reversible where the provider allows it.
5. **Restore and release.**
   - Admins, and users where policy allows, restore a remediated message to the inbox.
   - The 7.x quarantine release flow and approvals apply: API-mode quarantine items appear in the same quarantine pages with their location ("in mailbox quarantine folder").
6. **Retroactive clawback (search and purge).**
   - When a later signal flags a message (threat-intel indicator, late sandbox or URL verdict, campaign, admin decision), the gateway finds every copy across the tenant's mailboxes and remediates them. Copies are matched by Message-ID, attachment hash, URL, or sender plus subject plus time window.
   - Manual search and purge by admins.
   - Purges that touch more than N mailboxes (default 50) need a second approver, using the existing approval model.
7. **Internal (east-west) mail:** messages between users of the same tenant, seen through the journal or the API, are scanned and remediated the same way.
8. **User-reported phishing:**
   - A per-tenant report mailbox or alias; users forward suspicious mail to it.
   - The report is scanned, triaged in the portal, can trigger clawback of the same message, and the reporter gets feedback.
   - No Outlook or Gmail add-in in this program; that is a later option.
9. **Coverage and health:**
   - mailboxes covered versus total;
   - connection status;
   - intake lag;
   - remediation success and failure;
   - throttling.
     These appear on a portal page, in metrics and alerts, and in the AI report (when an API exists for it).
10. **AI assistant:** read tools for coverage, remediation history and clawback status. Remediation, restore and purge are confirmed writes. Bulk purge is high risk (password + TOTP), and hard delete is portal-only.

## Rules

- Tenant isolation and RBAC through the existing APIs.
- New permissions follow the existing naming (for example `remediation:read`, `remediation:write`, `remediation:purge`).
- No email bodies or attachments in MySQL.
- Message content is read from the provider only for scanning, and is stored in object storage under the existing retention.
- Idempotent asynchronous processing through the outbox and RabbitMQ.
- Every provider call is rate-limited per tenant.
- Tests use local fakes of Microsoft Graph and the Gmail API only: never real Microsoft or Google endpoints, never the public internet, synthetic fixtures only, no secret-shaped examples.
- Migrations for every database change.
- The portal and Playwright cover the new pages.
- Docs and runbooks: onboarding a tenant in API mode, consent, revoking, troubleshooting lag and throttling.

## Proposed split

| Step  | Content                                                                                                                                                                 |
| ----- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| API-1 | Protection mode, mailbox remediation consent (Graph/Gmail), API-mode intake (journal copy in detect mode, optional change feeds, dedupe, lag), coverage and health page |
| API-2 | Post-delivery remediation policy and actions, restore and release, quarantine integration, audit, throttling                                                            |
| API-3 | Retroactive clawback and manual search and purge (with approval), internal mail, user-reported phishing mailbox, assistant tools, acceptance                            |

## Product-owner questions (defaults applied; the product owner may revise them)

| No. | Question                          | Default                                                                                                                   |
| --- | --------------------------------- | ------------------------------------------------------------------------------------------------------------------------- |
| P1  | Automatic remediation action      | Move to the quarantine folder for high-confidence malware and phishing; tag suspicious mail; never hard-delete by default |
| P2  | Approval threshold for bulk purge | More than 50 mailboxes needs a second approver                                                                            |
| P3  | Change feeds                      | Journal copy is the primary intake; Graph notifications and Gmail history polling are optional per tenant                 |
| P4  | Report button                     | Report mailbox only; an Outlook or Gmail add-in is a later option                                                         |
