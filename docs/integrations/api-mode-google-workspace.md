# API-mode protection for Google Workspace (no MX change)

This page is the **template of the customer-specific API-mode guide** that the gateway generates for every Google Workspace provider connection (step API-1, [ADR-0098](../architecture/adr/0098-protection-modes-and-detect-mode-copies.md), [ADR-0099](../architecture/adr/0099-mailbox-access-consent-and-custody.md), [ADR-0100](../architecture/adr/0100-api-mode-intake-mailbox-worker.md)). Your own guide contains the values of your connection (domains, the bound journal intake source, the service account client ID and the delegated administrator) and the state of your statements: open **Mailbox protection → Setup → your connection** in the admin console (or `GET /api/v1/api-mode/connections/{connectionId}/setup-guide` with `Accept: text/markdown`, permission `remediation:read`) and use that one. This template shows the same guide for an example connection.

API mode is for domains whose MX records stay with Google Workspace. The gateway receives a **copy** of each message (a copy routed with "Also deliver to" through the [journal intake](journal-intake-google-workspace.md) and, optionally, the Gmail history feeds), scans it in **detect mode** and records the verdict per mailbox. Choose the protection mode of a domain in the add-domain wizard or on the domain page (`inline`, `api` or `hybrid`).

What the gateway does and does not do:

- It **never** changes your MX records, mail flow or Google Workspace configuration; it never delivers, forwards, delays or bounces a message from the API side. After delivery it can **remediate** detected threats inside the mailbox (step API-2, see [What remediation does in your tenant](#what-remediation-does-in-your-tenant)). A domain cannot switch to `api` while its MX still points to the gateway (choose `hybrid` or move the MX first).
- **Mailbox access** is a separate domain-wide delegation (permission profile `google.mailbox_remediation`: scopes `https://www.googleapis.com/auth/gmail.modify` and `https://www.googleapis.com/auth/admin.directory.user.readonly`), apart from the mail-flow and account takeover delegations. Granting, verifying and revoking it needs the console rights `integration:manage` and `remediation:write`. The gateway reads users, the Gmail history and the content of new Inbox messages it has no copy of, and (step API-2) uses the same `gmail.modify` scope to remediate threats; no further delegation is needed.
- History polling is **off by default** and never backfills existing mail. Service-account keys live only in the encrypted credential store; tokens stay in memory.

Placeholders in this template:

| Placeholder                                    | Stands for                                                                                        |
| ---------------------------------------------- | ------------------------------------------------------------------------------------------------- |
| `example.com`, `admin@example.com`             | A domain verified at the gateway and linked to your connection; your delegated administrator      |
| `journal-••••xamp@journal.gateway.example.net` | The intake address of your journal intake source (always masked here; reveal it in its own guide) |
| `11111111-2222-3333-4444-555555555555`         | The connection id and the journal source id                                                       |
| `111122223333444455556`, `C0example`           | The operator service account's client ID and your Google customer ID                              |

Related: [journal intake from Google Workspace](journal-intake-google-workspace.md), [Google Workspace connection](google-workspace.md), [API mode for Microsoft 365](api-mode-microsoft-365.md).

## What remediation does in your tenant

From step API-2 the gateway acts on the verdict of each mailbox copy according to your **remediation policy** (Mailbox protection → Remediation; default P1: high-confidence malware and phishing go to the quarantine label, other malware/phishing and suspicious or BEC mail is labelled, spam and bulk are left to Gmail's own filtering; **Detect only** records what would have happened without touching mailboxes and is the recommended start). Every action uses the Gmail API as the mailbox with the **same** `google.mailbox_remediation` delegation (`gmail.modify`); there is **no new scope** and nothing changes in your mail flow or Admin console settings.

| Action           | What happens in the mailbox                                                                                                                                                                                                                                                                                                     | Undo                                                                                  |
| ---------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------- |
| Quarantine label | The gateway creates (once per mailbox) a **hidden** label `Email Gateway/Quarantine` (hidden in the label list and the message list), adds it and removes `INBOX`: the message leaves the Inbox.                                                                                                                                | "Restore to inbox" on the quarantine page (approvals and end-user self-service apply) |
| Junk             | Adds `SPAM` and removes `INBOX`.                                                                                                                                                                                                                                                                                                | Restore to inbox                                                                      |
| Tag              | Adds the visible label `Email Gateway: Suspicious`; the message stays in the Inbox.                                                                                                                                                                                                                                             | Restore removes the label                                                             |
| Soft delete      | Moves the message to **Trash** (Gmail deletes it for good after 30 days).                                                                                                                                                                                                                                                       | Restore to inbox (untrash)                                                            |
| Hard delete      | **Not available on Google**: permanent deletion needs the full `https://mail.google.com/` scope, which the gateway does not request. A hard-delete rule moves the message to **Trash** instead and records `hard_delete_unsupported_provider`. Hard delete is off by default (`API_MODE_HARD_DELETE_ENABLED`) and never manual. | Restore to inbox while in Trash                                                       |

Notes:

- A hidden label is still searchable by the user (Gmail search by label name); P1 moves only high-confidence threats there.
- The gateway finds journal copies in the mailbox by their Message-ID (`rfc822msgid:`, Spam and Trash included); messages only in Sent and drafts are never touched.
- A restore always goes back to the **Inbox** (untrash, add `INBOX`, remove `SPAM` and the quarantine label). Labelled messages appear on the quarantine pages as "in mailbox quarantine folder" / "Junk" / "deleted items"; when such an entry expires, the message stays where it is.
- Hybrid domains: copies of messages the gateway already delivered inline are never remediated automatically.
- Remediation shares the connection's Gmail request budget and pauses when Google throttles (`429`, rate-limit `403`, `503` with `Retry-After`). An administrator can **pause remediation** per connection (restores continue). Removing the client ID from domain-wide delegation stops remediation; pending actions fail with `mailbox_access_revoked`.

## What your tenant policies do after delivery (step API-4)

From step API-4 ([ADR-0105](../architecture/adr/0105-api-mode-copy-policy-evaluation-and-policy-lane.md), [ADR-0106](../architecture/adr/0106-api-mode-detections-alerts-webhooks.md), [ADR-0107](../architecture/adr/0107-api-mode-onboarding-provider-ownership-scope-detect-only.md)) every copy is also evaluated against **your organization's policies** (custom rules, allow and block lists, the DLP policy, BEC, the platform default and the strictness floor) by the same evaluator the gateway uses inline, in **detect mode**: the message was already delivered by Google Workspace, so nothing is bounced, delayed, rewritten or re-routed. What a policy decides becomes a mailbox action through the remediation policy's **policy mapping** (Mailbox protection → Remediation):

| Your policy decides                                                        | Default action in the mailbox                                                                                              |
| -------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------- |
| Quarantine                                                                 | The hidden label `Email Gateway/Quarantine` (`INBOX` removed)                                                              |
| Require approval                                                           | The hidden label `Email Gateway/Quarantine` (`INBOX` removed), as a **review** entry: restoring it needs an approver       |
| Reject (discard / reject)                                                  | The hidden label `Email Gateway/Quarantine` (`INBOX` removed); the sender is **never** notified (no bounce after delivery) |
| Allow with a tag or warning                                                | The label `Email Gateway: Suspicious` (the message stays in the Inbox)                                                     |
| Allow                                                                      | nothing                                                                                                                    |
| Header or subject edits, warning banners, URL rewriting, encrypt, redirect | not possible after delivery: recorded as "not applicable" with the reason                                                  |
| Archive                                                                    | follows your journaling and archiving settings                                                                             |
| Alert                                                                      | the policy alert e-mail, marked "detected after delivery (API mode)"                                                       |

- Each mapping can be changed to Spam, soft delete, tag or nothing; **hard delete is never a mapping**.
- The policy decision and the threat verdict are two lanes: the **stronger** mailbox action wins. A tenant **allow** rule (for example a trusted sender) stops a verdict-only action, exactly as it does inline; hard blocks (malware, known phishing) are never overridden.
- **Outbound mail** sent by your users is evaluated too (DLP above all): a detection is recorded on the sender's mailbox and raises the `dlp_detected` alert and the `mailbox.dlp.detected` webhook, but the message has left: nothing in the sender's mailbox is ever moved or deleted.
- **Hybrid domains:** messages the gateway already filtered inline are not evaluated or acted on again.
- **Which mailboxes:** a domain's scope (all mailboxes, policy-directory departments or selected mailboxes) decides where actions apply; excluded mailboxes are still recorded but never acted on.
- **Detect-only start:** the add-domain wizard starts a new domain in detect only for 7 days (simulated actions, listed in History) and then reminds the administrators (or, if chosen, switches to enforce automatically).
- Turning it off: Mailbox protection → Settings → **Evaluate tenant policies on copies** (and **Detect outbound mail (DLP)**); the operator also has a platform switch. Detections, alerts and webhooks: Mailbox protection → Detections, the `threat_detected` / `dlp_detected` alerts and the `mailbox.threat.detected` / `mailbox.dlp.detected` webhook types.

## What clawback does in your tenant

From step API-3 the gateway can also act on mail that was **already delivered** when a threat becomes known later ([ADR-0103](../architecture/adr/0103-api-mode-clawback-search-and-purge.md)). It searches only the copies it recorded from the "Also deliver to" routing (and the optional history feeds); it never searches mailboxes live and never backfills mail from before onboarding.

- **Automatic clawback.** A later signal (the sandbox finishes and raises a message's risk, a URL is found malicious on dynamic inspection, a new high-confidence threat-intelligence indicator or malware hash matches earlier mail) finds every recorded copy by Message-ID, attachment hash, URL or sender and subject, and decides each copy again through your **remediation policy** with the signal's facts. Detect-only policies only record what would happen, a paused connection waits, and a clawback never weakens or replaces a stronger action (a labelled message can be moved; a quarantined one is left as it is). A copy that an administrator restored after the signal is not touched again. Automatic clawbacks that would reach more than 500 mailboxes (configurable) wait for an administrator.
- **Search and purge.** Administrators with `remediation:purge` search the recorded copies, review the frozen hit list and purge it to the quarantine label, Spam or Trash. A purge reaching more than **50 mailboxes** (configurable per organization) needs a **second administrator** with `remediation:purge` who did not request it. Hard delete is available only in the admin console with the platform setting `API_MODE_HARD_DELETE_ENABLED` and a second approver; on Google it moves messages to **Trash** (the gateway does not hold the full `https://mail.google.com/` scope).
- **Internal mail.** Messages between your own users that the routing copies are recorded per recipient and remediated the same way (setting "internal mail", on by default). Messages that only leave the organization are recognised and not recorded.
- **Restore.** A clawback can be restored in bulk: messages go back to the Inbox (untrashed while still in Trash), labels are removed; quarantine entries that need an approval are left for the quarantine page.

Every clawback uses the same Gmail API calls, delegation (`gmail.modify`) and request budget as remediation; it is audited with per-mailbox results. Report mailboxes are never searched or remediated.

## Report mailbox setup

Users report suspicious mail by forwarding it to a **report mailbox** of your organization; there is **no add-in** to install ([ADR-0104](../architecture/adr/0104-api-mode-internal-mail-and-reported-phishing.md)).

1. Create a dedicated **user mailbox** for reports in Google Workspace, for example `phish-report@example.com` (Google has no shared mailboxes; a Google Group is not a mailbox the gateway can read). Its domain must be linked to this connection with protection mode `api` or `hybrid`.
2. Keep the mailbox **inside the scope of the "Also deliver to" routing** (section 2: the organizational unit or group the routing setting applies to must include it), so the gateway receives a copy of every report. History feeds (section 4) are optional and only shorten the delay.
3. Designate it in the admin console (Mailbox protection, report mailboxes; permission `remediation:write`), or through `PUT /api/v1/api-mode/mailboxes/{mailboxId}/report-mailbox` or `POST /api/v1/api-mode/report-mailboxes` with the address. Up to five report mailboxes per organization; aliases of the mailbox are recognised.
4. Tell users to forward suspicious messages **as an attachment** (Gmail: More → Forward as attachment), which keeps the original headers. A normal (inline) forward also works; the gateway then reads the forwarded `From:`, `Subject:` and date lines.

Only senders on your organization's domains are accepted (no external reports, auto-replies or loops; at most 30 reports per person per hour). Reports are scanned, triaged by your analysts and never remove mail by themselves; an analyst can start a clawback from a report (the approval rules above apply). Reporters receive an acknowledgement and a result e-mail (both can be turned off) that never repeat the reported message's subject or content.

## The example guide

The block below is generated from the guide generator of `@email-gateway/provider-integrations` (`exampleApiModeGuideInput('google_workspace')`); a test fails when it no longer matches (`packages/provider-integrations/src/guides/api-mode-docs-templates.test.ts`).

<!-- BEGIN GENERATED GUIDE api-mode google_workspace (do not edit; see the note above) -->
<!-- prettier-ignore-start -->
## Google Workspace API-mode guide: Example Google Workspace

Generated 2026-11-26T00:00:00.000Z (`api-mode-guide/1`).
Permissions: `https://www.googleapis.com/auth/gmail.modify`, `https://www.googleapis.com/auth/admin.directory.user.readonly`.

> This guide contains the values of your own provider connection. The gateway never changes your Microsoft 365 or Google Workspace configuration: you apply every step yourself. Confirmations you record in the console are your statements (attestations), not proofs the gateway has checked. Never send client secrets or service-account keys by email or chat: upload them only in the console.

### Contents

1. [Overview and what API mode never does](#overview)
2. [Journal copies (primary intake): the "Also deliver to" routing](#journal)
3. [Mailbox access: domain-wide delegation](#mailbox-access)
4. [Optional: mailbox change feeds](#feeds)
5. [Verify coverage](#verify)
6. [Revoke mailbox access](#revoke)
7. [Troubleshooting lag and throttling](#troubleshooting)

<a id="overview"></a>

### 1. Overview and what API mode never does

API mode protects the mailboxes of "Example Google Workspace" (Google Workspace) without an MX change. Mail keeps flowing directly to your mailboxes; the gateway receives a copy of each message (a journal copy and, optionally, the mailbox change feeds), scans it with every engine and records a verdict per mailbox. Detections, coverage, intake lag and throttling are shown on the Mailbox protection page.

What API mode never does: it never changes your MX records or mail flow; it never delivers, forwards, delays, quarantines or bounces a message; it never changes your tenant configuration (you apply every step of this guide); it never reads existing mailbox content (no backfill: only messages that arrive after the feeds start); and it never stores credentials outside the encrypted credential store of the gateway.

In this release the gateway only reads mailboxes. The mailbox-access permission is write-capable because automatic removal of detected threats (move to a quarantine folder or label, tag) comes in a later release; every such action will be recorded and reversible. Mailbox access is a separate consent from the mail-flow and account takeover grants and can be revoked at any time.

<a id="overview-values"></a>

#### 1.1 Values for this connection

| Item | Value |
| --- | --- |
| Connection | `Example Google Workspace` |
| Customer ID | `C0example` |
| Domains | `example.com` |
| Change feeds | `off` |

<a id="journal"></a>

### 2. Journal copies (primary intake): the "Also deliver to" routing

The journal copy is the primary intake of API mode: it covers every mailbox, every folder and the full recipient list without per-mailbox API calls. It uses the journal intake source of type "Google Workspace copies" bound to this connection; copies of API-mode domains are scanned in detect mode and never delivered or archived unless journaling is enabled.

<a id="journal-source"></a>

#### 2.1 Create or check the journal intake source

The source "Example Google Workspace copies" is bound to this connection. Its own setup guide (Settings, Journaling, the source, Setup guide) has the exact steps and reveals the intake address to users with journaling management rights.

| Item | Value |
| --- | --- |
| Journal intake source | `Example Google Workspace copies` |
| Intake address (masked) | `journal-••••xamp@journal.gateway.example.net` |

<a id="journal-route"></a>

#### 2.2 Add the "Also deliver to" routing setting

In the Google Admin console (Apps, Google Workspace, Gmail, Routing), add the routing setting of the source with "Also deliver to" the intake address and the journal headers, exactly as its setup guide shows (template: docs/integrations/journal-intake-google-workspace.md).

<a id="mailbox-access"></a>

### 3. Mailbox access: domain-wide delegation

The gateway reads the user directory (coverage totals, address resolution) as a delegated administrator and the Gmail history and new Inbox messages of each mailbox as that mailbox, through domain-wide delegation of the two OAuth scopes below. Set it up in the console: Integrations, this connection, Grants, "Mailbox access for API mode".

The mailbox-access grant of this connection uses the operator service account (option A below).

<a id="delegation-client"></a>

#### 3.1 Choose the service account

Option A: use the operator service account (its client ID is shown below when offered). Option B: create your own: in the Google Cloud console create a service account, enable the Gmail API and the Admin SDK API for its project, create a JSON key and upload the key in the console. The key is stored only in the encrypted credential store.

| Item | Value |
| --- | --- |
| Operator service account client ID | `111122223333444455556` |

<a id="delegation-add"></a>

#### 3.2 Add the client ID to domain-wide delegation

In the Google Admin console open Security, Access and data control, API controls, Manage Domain Wide Delegation, and choose Add new. Enter the client ID and exactly the scopes below (comma-separated, nothing else), then Authorize. Changes can take some time to apply.

| Item | Value |
| --- | --- |
| Client ID | `111122223333444455556` |
| OAuth scopes | `https://www.googleapis.com/auth/gmail.modify,https://www.googleapis.com/auth/admin.directory.user.readonly` |

> **Warning:** gmail.modify allows changing messages of every mailbox of the domain. API mode only reads in this release; never add the scopes to a client ID used for anything else.

> **Attestation `api_mode.google.delegation_added`** (your statement, not a gateway check): Domain-wide delegation lists the mailbox-access client ID with exactly the scopes gmail.modify and admin.directory.user.readonly.
> Status: not confirmed yet

<a id="delegation-admin"></a>

#### 3.3 Name the delegated administrator

Directory reads impersonate an administrator account of your domain that may read users (a super administrator, or a delegated administrator with the Users read privilege). Enter its address with the grant in the console.

| Item | Value |
| --- | --- |
| Delegated administrator | `admin@example.com` |

<a id="feeds"></a>

### 4. Optional: mailbox change feeds

Change feeds are off by default. When you turn them on for this connection (Mailbox protection, Coverage, Feeds), the gateway follows the Gmail history (new messages with the INBOX label) of every in-scope mailbox by polling every few minutes, starting from the moment the feed starts (no backfill). Content is fetched only for messages no journal copy already delivered for that mailbox.

<a id="feeds-state"></a>

#### 4.1 Feed settings of this connection

Feeds need the active mailbox-access grant. Messages larger than the configured limit are recorded as too large and not scanned.

| Item | Value |
| --- | --- |
| Feeds | `off` |
| Mode | `polling (Gmail history)` |

<a id="verify"></a>

### 5. Verify coverage

<a id="verify-inventory"></a>

#### 5.1 Check the mailbox inventory and coverage

After the grant is verified, the gateway lists the users of your domain every few hours (or when you choose "Sync inventory") and keeps the mailboxes of your API-mode domains. A mailbox is covered when its change feed synced recently or a journal copy for it arrived within the last seven days; otherwise it is a gap.

<a id="verify-message"></a>

#### 5.2 Send a test message

Send a message from outside your organization to a protected mailbox. Within minutes it appears under Mailbox protection, Detections, with its verdict and the lag from delivery to verdict. It is delivered normally: API mode never holds it.

<a id="revoke"></a>

### 6. Revoke mailbox access

In the console (Integrations, this connection, Grants, "Mailbox access for API mode", Revoke) the gateway deletes the stored credentials and stops the feeds and the inventory at once; detection of journal copies continues.

<a id="revoke-provider"></a>

#### 6.1 Remove the client ID from domain-wide delegation

In the Google Admin console open Security, Access and data control, API controls, Manage Domain Wide Delegation, and delete the entry of the client ID. For your own service account, also delete its key in the Google Cloud console.

| Item | Value |
| --- | --- |
| Client ID | `111122223333444455556` |

<a id="troubleshooting"></a>

### 7. Troubleshooting lag and throttling

<a id="troubleshoot-lag"></a>

#### 7.1 Intake lag

The lag is the time from provider delivery to the verdict. High lag usually means delayed journal copies (check the journal source health) or a paused feed. Google Workspace routes the copy as an additional delivery; check the routing setting.

<a id="troubleshoot-throttling"></a>

#### 7.2 Throttling

The Gmail API limits requests per user and project. The gateway keeps a per-connection request budget and, when the provider answers with a throttling response, pauses the calls of that API for this connection for the time the provider asks (at most ten minutes) before it continues. Sustained throttling raises a health warning; other applications using the same quota can be the cause.

<a id="troubleshoot-cursor"></a>

#### 7.3 Feed restarts and gaps

When Gmail no longer has the stored history position of a mailbox, the gateway restarts the feed from the current state without backfill and marks a gap for that mailbox; the journal copy covers the interval.
<!-- prettier-ignore-end -->
<!-- END GENERATED GUIDE api-mode google_workspace -->
