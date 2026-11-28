# API-mode protection for Microsoft 365 (no MX change)

This page is the **template of the customer-specific API-mode guide** that the gateway generates for every Microsoft 365 provider connection (step API-1, [ADR-0098](../architecture/adr/0098-protection-modes-and-detect-mode-copies.md), [ADR-0099](../architecture/adr/0099-mailbox-access-consent-and-custody.md), [ADR-0100](../architecture/adr/0100-api-mode-intake-mailbox-worker.md)). Your own guide contains the values of your connection (tenant, domains, the bound journal intake source, the mailbox-access application) and the state of your statements: open **Mailbox protection → Setup → your connection** in the admin console (or `GET /api/v1/api-mode/connections/{connectionId}/setup-guide` with `Accept: text/markdown`, permission `remediation:read`) and use that one. This template shows the same guide for an example connection.

API mode is for domains whose MX records stay with Microsoft 365. The gateway receives a **copy** of each message (a journal copy through the [journal intake](journal-intake-microsoft-365.md) and, optionally, the mailbox change feeds), scans it in **detect mode** and records the verdict per mailbox. Choose the protection mode of a domain in the add-domain wizard or on the domain page (`inline`, `api` or `hybrid`).

What the gateway does and does not do:

- It **never** changes your MX records, mail flow or tenant configuration; it never delivers, forwards, delays or bounces a message from the API side. After delivery it can **remediate** detected threats inside the mailbox (step API-2, see [What remediation does in your tenant](#what-remediation-does-in-your-tenant)). A domain cannot switch to `api` while its MX still points to the gateway (choose `hybrid` or move the MX first).
- **Mailbox access** is a separate consent (permission profile `m365.mailbox_remediation`: Microsoft Graph application permissions `Mail.ReadWrite` and `User.Read.All`), apart from the mail-flow and account takeover grants. Granting, verifying and revoking it needs the console rights `integration:manage` and `remediation:write`. The gateway reads users, Inbox changes and the content of new messages it has no copy of, and (step API-2) uses the same `Mail.ReadWrite` permission to remediate threats; no further consent is needed.
- Change feeds are **off by default** and never backfill existing mail. Credentials live only in the encrypted credential store; tokens stay in memory.

Placeholders in this template:

| Placeholder                                    | Stands for                                                                                         |
| ---------------------------------------------- | -------------------------------------------------------------------------------------------------- |
| `example.com`                                  | A domain verified at the gateway and linked to your Microsoft 365 connection                       |
| `journal-••••xamp@journal.gateway.example.net` | The intake address of your journal intake source (always masked here; reveal it in its own guide)  |
| `11111111-2222-3333-4444-555555555555`         | The connection id, the tenant id, the journal source id and the operator application's client ID   |
| `<application-client-id>` and other `<…>`      | Values you fill in yourself (your application, enterprise application object ID, mailbox group DN) |

Related: [journal intake from Microsoft 365](journal-intake-microsoft-365.md), [Microsoft 365 connection](microsoft-365.md), [API mode for Google Workspace](api-mode-google-workspace.md).

## What remediation does in your tenant

From step API-2 the gateway acts on the verdict of each mailbox copy according to your **remediation policy** (Mailbox protection → Remediation; default P1: high-confidence malware and phishing go to the quarantine folder, other malware/phishing and suspicious or BEC mail is tagged, spam and bulk are left to Microsoft's own filtering; **Detect only** records what would have happened without touching mailboxes and is the recommended start). Every action uses Microsoft Graph with the **same** `m365.mailbox_remediation` consent (`Mail.ReadWrite`); there is **no new consent** and nothing changes in your mail flow or tenant settings.

| Action            | What happens in the mailbox                                                                                                                                                                                              | Undo                                                                                  |
| ----------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | ------------------------------------------------------------------------------------- |
| Quarantine folder | The gateway creates (once per mailbox) a **hidden** folder `Email Gateway Quarantine` under the mailbox root and moves the message there. The user does not see the folder in Outlook.                                   | "Restore to inbox" on the quarantine page (approvals and end-user self-service apply) |
| Junk              | Moved to the user's **Junk Email** folder.                                                                                                                                                                               | Restore to inbox                                                                      |
| Tag               | Adds the Outlook **category** `Email Gateway: Suspicious`; the message stays in the Inbox. Existing categories are kept.                                                                                                 | Restore removes the category                                                          |
| Soft delete       | Moved to **Recoverable Items → Deletions** (not browsable by the user; recoverable through "Recover deleted items" and by the gateway).                                                                                  | Restore to inbox                                                                      |
| Hard delete       | `permanentDelete`: irreversible. **Off by default**: it needs the platform setting `API_MODE_HARD_DELETE_ENABLED` **and** an explicit rule in your policy; it is never in a default or preset and never a manual action. | Not possible                                                                          |

Notes:

- Message ids change when Microsoft Graph moves a message; the gateway keeps the new id and finds the message again by its Internet Message-ID when needed (also for journal copies, which have no mailbox id). Drafts and copies in Sent Items are never touched.
- A restore always goes back to the **Inbox**. Moved messages appear on the quarantine pages as "in mailbox quarantine folder" / "Junk" / "deleted items"; when such an entry expires, the message stays where it is.
- Hybrid domains: copies of messages the gateway already delivered inline are never remediated automatically.
- Remediation shares the connection's Graph request budget and pauses when Microsoft Graph throttles (`429`/`503` with `Retry-After`). An administrator can **pause remediation** per connection (restores continue). Revoking the mailbox access stops remediation; pending actions fail with `mailbox_access_revoked`.

## What your tenant policies do after delivery (step API-4)

From step API-4 ([ADR-0105](../architecture/adr/0105-api-mode-copy-policy-evaluation-and-policy-lane.md), [ADR-0106](../architecture/adr/0106-api-mode-detections-alerts-webhooks.md), [ADR-0107](../architecture/adr/0107-api-mode-onboarding-provider-ownership-scope-detect-only.md)) every copy is also evaluated against **your organization's policies** (custom rules, allow and block lists, the DLP policy, BEC, the platform default and the strictness floor) by the same evaluator the gateway uses inline, in **detect mode**: the message was already delivered by Microsoft 365, so nothing is bounced, delayed, rewritten or re-routed. What a policy decides becomes a mailbox action through the remediation policy's **policy mapping** (Mailbox protection → Remediation):

| Your policy decides                                                        | Default action in the mailbox                                                                             |
| -------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------- |
| Quarantine                                                                 | The hidden `Email Gateway Quarantine` folder                                                              |
| Require approval                                                           | The hidden `Email Gateway Quarantine` folder, as a **review** entry: restoring it needs an approver       |
| Reject (discard / reject)                                                  | The hidden `Email Gateway Quarantine` folder; the sender is **never** notified (no bounce after delivery) |
| Allow with a tag or warning                                                | The category `Email Gateway: Suspicious` (the message stays in the Inbox)                                 |
| Allow                                                                      | nothing                                                                                                   |
| Header or subject edits, warning banners, URL rewriting, encrypt, redirect | not possible after delivery: recorded as "not applicable" with the reason                                 |
| Archive                                                                    | follows your journaling and archiving settings                                                            |
| Alert                                                                      | the policy alert e-mail, marked "detected after delivery (API mode)"                                      |

- Each mapping can be changed to Junk Email, soft delete, tag or nothing; **hard delete is never a mapping**.
- The policy decision and the threat verdict are two lanes: the **stronger** mailbox action wins. A tenant **allow** rule (for example a trusted sender) stops a verdict-only action, exactly as it does inline; hard blocks (malware, known phishing) are never overridden.
- **Outbound mail** sent by your users is evaluated too (DLP above all): a detection is recorded on the sender's mailbox and raises the `dlp_detected` alert and the `mailbox.dlp.detected` webhook, but the message has left: nothing in the sender's mailbox is ever moved or deleted.
- **Hybrid domains:** messages the gateway already filtered inline are not evaluated or acted on again.
- **Which mailboxes:** a domain's scope (all mailboxes, policy-directory departments or selected mailboxes) decides where actions apply; excluded mailboxes are still recorded but never acted on.
- **Detect-only start:** the add-domain wizard starts a new domain in detect only for 7 days (simulated actions, listed in History) and then reminds the administrators (or, if chosen, switches to enforce automatically).
- Turning it off: Mailbox protection → Settings → **Evaluate tenant policies on copies** (and **Detect outbound mail (DLP)**); the operator also has a platform switch. Detections, alerts and webhooks: Mailbox protection → Detections, the `threat_detected` / `dlp_detected` alerts and the `mailbox.threat.detected` / `mailbox.dlp.detected` webhook types.

## What clawback does in your tenant

From step API-3 the gateway can also act on mail that was **already delivered** when a threat becomes known later ([ADR-0103](../architecture/adr/0103-api-mode-clawback-search-and-purge.md)). It searches only the copies it recorded from the journal (and the optional feeds); it never searches mailboxes live and never backfills mail from before onboarding.

- **Automatic clawback.** A later signal (the sandbox finishes and raises a message's risk, a URL is found malicious on dynamic inspection, a new high-confidence threat-intelligence indicator or malware hash matches earlier mail) finds every recorded copy by Internet Message-ID, attachment hash, URL or sender and subject, and decides each copy again through your **remediation policy** with the signal's facts. Detect-only policies only record what would happen, a paused connection waits, and a clawback never weakens or replaces a stronger action (a tagged message can be moved; a quarantined one is left as it is). A copy that an administrator restored after the signal is not touched again. Automatic clawbacks that would reach more than 500 mailboxes (configurable) wait for an administrator.
- **Search and purge.** Administrators with `remediation:purge` search the recorded copies, review the frozen hit list and purge it to the quarantine folder, Junk or Recoverable Items. A purge reaching more than **50 mailboxes** (configurable per organization) needs a **second administrator** with `remediation:purge` who did not request it. Hard delete (`permanentDelete`, irreversible) is available only in the admin console, only when the platform setting `API_MODE_HARD_DELETE_ENABLED` is on, and always with a second approver.
- **Internal mail.** Messages between your own users that the journal rule reports are recorded per recipient and remediated the same way (setting "internal mail", on by default). Messages that only leave the organization are recognised and not recorded.
- **Restore.** A clawback can be restored in bulk: moved messages go back to the Inbox, tags are removed; hard-deleted messages cannot be restored, and quarantine entries that need an approval are left for the quarantine page.

Every clawback uses the same Microsoft Graph actions, consent (`Mail.ReadWrite`) and request budget as remediation; it is audited with per-mailbox results. Report mailboxes are never searched or remediated.

## Report mailbox setup

Users report suspicious mail by forwarding it to a **report mailbox** of your organization; there is **no add-in** to install ([ADR-0104](../architecture/adr/0104-api-mode-internal-mail-and-reported-phishing.md)).

1. Create a mailbox for reports in Microsoft 365, for example a **shared mailbox** `phish-report@example.com` (a shared mailbox needs no licence; a regular user mailbox also works). Its domain must be linked to this connection with protection mode `api` or `hybrid`.
2. Keep the mailbox **inside the scope of the journal rule** (section 2: a rule for all messages, or a distribution group that includes the report mailbox), so the gateway receives a copy of every report. Mailbox change feeds (section 5) are optional and only shorten the delay.
3. Designate it in the admin console (Mailbox protection, report mailboxes; permission `remediation:write`), or through `PUT /api/v1/api-mode/mailboxes/{mailboxId}/report-mailbox` or `POST /api/v1/api-mode/report-mailboxes` with the address. Up to five report mailboxes per organization; aliases of the mailbox are recognised.
4. Tell users to forward suspicious messages **as an attachment** (Outlook: More actions → Forward as attachment), which keeps the original headers. A normal (inline) forward also works; the gateway then reads the forwarded `From:`, `Subject:` and date lines. Outlook item attachments (`.msg`) that arrive unconverted cannot be read and are triaged without an identified original.

Only senders on your organization's domains are accepted (no external reports, auto-replies or loops; at most 30 reports per person per hour). Reports are scanned, triaged by your analysts and never remove mail by themselves; an analyst can start a clawback from a report (the approval rules above apply). Reporters receive an acknowledgement and a result e-mail (both can be turned off) that never repeat the reported message's subject or content.

## The example guide

The block below is generated from the guide generator of `@email-gateway/provider-integrations` (`exampleApiModeGuideInput('microsoft_365')`); a test fails when it no longer matches (`packages/provider-integrations/src/guides/api-mode-docs-templates.test.ts`).

<!-- BEGIN GENERATED GUIDE api-mode microsoft_365 (do not edit; see the note above) -->
<!-- prettier-ignore-start -->
## Microsoft 365 API-mode guide: Example Microsoft 365

Generated 2026-11-26T00:00:00.000Z (`api-mode-guide/1`).
Permissions: `Mail.ReadWrite`, `User.Read.All`.

> This guide contains the values of your own provider connection. The gateway never changes your Microsoft 365 or Google Workspace configuration: you apply every step yourself. Confirmations you record in the console are your statements (attestations), not proofs the gateway has checked. Never send client secrets or service-account keys by email or chat: upload them only in the console.

### Contents

1. [Overview and what API mode never does](#overview)
2. [Journal copies (primary intake): the journal rule](#journal)
3. [Mailbox access consent](#mailbox-access)
4. [Optional: limit mailbox access with Exchange Online RBAC for Applications](#mailbox-scope)
5. [Optional: mailbox change feeds](#feeds)
6. [Verify coverage](#verify)
7. [Revoke mailbox access](#revoke)
8. [Troubleshooting lag and throttling](#troubleshooting)

<a id="overview"></a>

### 1. Overview and what API mode never does

API mode protects the mailboxes of "Example Microsoft 365" (Microsoft 365) without an MX change. Mail keeps flowing directly to your mailboxes; the gateway receives a copy of each message (a journal copy and, optionally, the mailbox change feeds), scans it with every engine and records a verdict per mailbox. Detections, coverage, intake lag and throttling are shown on the Mailbox protection page.

What API mode never does: it never changes your MX records or mail flow; it never delivers, forwards, delays, quarantines or bounces a message; it never changes your tenant configuration (you apply every step of this guide); it never reads existing mailbox content (no backfill: only messages that arrive after the feeds start); and it never stores credentials outside the encrypted credential store of the gateway.

In this release the gateway only reads mailboxes. The mailbox-access permission is write-capable because automatic removal of detected threats (move to a quarantine folder or label, tag) comes in a later release; every such action will be recorded and reversible. Mailbox access is a separate consent from the mail-flow and account takeover grants and can be revoked at any time.

<a id="overview-values"></a>

#### 1.1 Values for this connection

| Item | Value |
| --- | --- |
| Connection | `Example Microsoft 365` |
| Tenant ID | `11111111-2222-3333-4444-555555555555` |
| Domains | `example.com` |
| Change feeds | `off` |

<a id="journal"></a>

### 2. Journal copies (primary intake): the journal rule

The journal copy is the primary intake of API mode: it covers every mailbox, every folder and the full recipient list without per-mailbox API calls. It uses the journal intake source of type "Microsoft 365 journaling" bound to this connection; copies of API-mode domains are scanned in detect mode and never delivered or archived unless journaling is enabled.

<a id="journal-source"></a>

#### 2.1 Create or check the journal intake source

The source "Example Microsoft 365 journaling" is bound to this connection. Its own setup guide (Settings, Journaling, the source, Setup guide) has the exact steps and reveals the intake address to users with journaling management rights.

| Item | Value |
| --- | --- |
| Journal intake source | `Example Microsoft 365 journaling` |
| Intake address (masked) | `journal-••••xamp@journal.gateway.example.net` |

<a id="journal-rule"></a>

#### 2.2 Create the journal rule

In the Microsoft Purview portal (Data lifecycle management, Exchange (legacy), Journal rules), create a journal rule for messages sent or received from everyone that sends journal reports to the intake address of the source, exactly as its setup guide shows (template: docs/integrations/journal-intake-microsoft-365.md). Messages that mailbox rules move out of the Inbox are covered by the journal copy, not by the change feeds.

<a id="mailbox-access"></a>

### 3. Mailbox access consent

The gateway reads the user directory (coverage totals, address resolution), the Inbox changes and the content of new messages through Microsoft Graph with the application permissions Mail.ReadWrite and User.Read.All. Grant them in the console: Integrations, this connection, Grants, "Mailbox access for API mode". Granting needs the integration management and API-mode management rights in the console and a Global Administrator or Privileged Role Administrator in Microsoft Entra.

The mailbox-access grant of this connection uses the operator application (option A below).

<a id="access-platform-app"></a>

#### 3.1 Option A: consent to the operator application

Choose the operator application as the method of the grant. The console opens the Microsoft admin consent page of "Email security gateway mailbox access"; review the two application permissions and accept. The gateway then verifies the permissions in a token for your tenant.

| Item | Value |
| --- | --- |
| Application (client) ID | `11111111-2222-3333-4444-555555555555` |
| Microsoft Graph application permission | `Mail.ReadWrite` |
| Microsoft Graph application permission | `User.Read.All` |

<a id="access-customer-app"></a>

#### 3.2 Option B: register your own application

In the Microsoft Entra admin center, open App registrations, New registration, and create a single-tenant application (for example "Email security gateway mailbox access"). Under API permissions add the Microsoft Graph application permissions below and choose "Grant admin consent". Under Certificates & secrets create a client secret, then enter the application (client) ID and the secret in the console. The secret is stored only in the encrypted credential store; renew it before it expires.

| Item | Value |
| --- | --- |
| Microsoft Graph application permission | `Mail.ReadWrite` |
| Microsoft Graph application permission | `User.Read.All` |

> **Warning:** Mail.ReadWrite applies to every mailbox of the tenant unless you scope it (next section). Grant it only to the application used for API mode, never to the mail-flow or account takeover applications.

<a id="mailbox-scope"></a>

### 4. Optional: limit mailbox access with Exchange Online RBAC for Applications

You can limit which mailboxes the application may access with an Exchange Online management scope instead of the tenant-wide Microsoft Graph consent. Mailboxes outside the scope are not inventoried or followed by the change feeds; unless journal copies for them arrive, they appear as coverage gaps on the Mailbox protection page.

<a id="mailbox-scope-commands"></a>

#### 4.1 Create the scope and the role assignment

Run these commands in Exchange Online PowerShell (Connect-ExchangeOnline) with the application's client ID, the object ID of its enterprise application and a group that contains the protected mailboxes. Then remove the tenant-wide Mail.ReadWrite consent of the application in Microsoft Entra (keep User.Read.All): RBAC for Applications adds to Entra consents, it does not restrict them.

```powershell
New-ServicePrincipal -AppId '11111111-2222-3333-4444-555555555555' -ObjectId '<enterprise-application-object-id>' -DisplayName 'Email security gateway mailbox access'
New-ManagementScope -Name 'Email security gateway API mode' -RecipientRestrictionFilter "MemberOfGroup -eq '<protected-mailboxes-group-distinguished-name>'"
New-ManagementRoleAssignment -App '11111111-2222-3333-4444-555555555555' -Role 'Application Mail.ReadWrite' -CustomResourceScope 'Email security gateway API mode'
```

> **Warning:** Role assignments of RBAC for Applications are not listed in the access token, so the console's permission check reports Mail.ReadWrite as missing for this grant once the Entra consent is removed. Scoped access is an advanced setup: check the coverage page after the change.

> **Attestation `api_mode.m365.app_access_scoped`** (your statement, not a gateway check): An Exchange Online RBAC for Applications scope limits the mailbox-access application to the mailboxes API mode protects; mailboxes outside the scope without journal copies appear as coverage gaps.
> Status: not confirmed yet

<a id="feeds"></a>

### 5. Optional: mailbox change feeds

Change feeds are off by default. When you turn them on for this connection (Mailbox protection, Coverage, Feeds), the gateway follows the Inbox of every in-scope mailbox with the Microsoft Graph delta query, starting from the moment the feed starts (no backfill). With "polling" each Inbox is checked every few minutes; with "change notifications" Microsoft Graph notifies the gateway of new messages (the gateway still polls hourly as a safety net). Content is fetched only for messages no journal copy already delivered for that mailbox.

<a id="feeds-state"></a>

#### 5.1 Feed settings of this connection

Feeds need the active mailbox-access grant. Messages larger than the configured limit are recorded as too large and not scanned.

| Item | Value |
| --- | --- |
| Feeds | `off` |
| Mode | `polling` |

<a id="verify"></a>

### 6. Verify coverage

<a id="verify-inventory"></a>

#### 6.1 Check the mailbox inventory and coverage

After the grant is verified, the gateway lists the users of your tenant every few hours (or when you choose "Sync inventory") and keeps the mailboxes of your API-mode domains. A mailbox is covered when its change feed synced recently or a journal copy for it arrived within the last seven days; otherwise it is a gap.

<a id="verify-message"></a>

#### 6.2 Send a test message

Send a message from outside your organization to a protected mailbox. Within minutes it appears under Mailbox protection, Detections, with its verdict and the lag from delivery to verdict. It is delivered normally: API mode never holds it.

<a id="revoke"></a>

### 7. Revoke mailbox access

In the console (Integrations, this connection, Grants, "Mailbox access for API mode", Revoke) the gateway deletes the stored credentials and stops the feeds and the inventory at once; detection of journal copies continues.

<a id="revoke-provider"></a>

#### 7.1 Remove the access in Microsoft Entra

Operator application: in the Microsoft Entra admin center open Enterprise applications, "Email security gateway mailbox access", and delete it (or remove its Mail.ReadWrite and User.Read.All permissions under Permissions). Your own application: delete its client secret or the app registration. If you scoped access, also remove the role assignment.

| Item | Value |
| --- | --- |
| Application (client) ID | `11111111-2222-3333-4444-555555555555` |

```powershell
Get-ManagementRoleAssignment -RoleAssignee '11111111-2222-3333-4444-555555555555' | Remove-ManagementRoleAssignment
```

<a id="troubleshooting"></a>

### 8. Troubleshooting lag and throttling

<a id="troubleshoot-lag"></a>

#### 8.1 Intake lag

The lag is the time from provider delivery to the verdict. High lag usually means delayed journal copies (check the journal source health) or a paused feed. Microsoft 365 may delay journal reports under load.

<a id="troubleshoot-throttling"></a>

#### 8.2 Throttling

Microsoft Graph limits requests per application and mailbox. The gateway keeps a per-connection request budget and, when the provider answers with a throttling response, pauses the calls of that API for this connection for the time the provider asks (at most ten minutes) before it continues. Sustained throttling raises a health warning; other applications using the same quota can be the cause.

<a id="troubleshoot-cursor"></a>

#### 8.3 Feed restarts and gaps

When Microsoft Graph no longer accepts the stored delta state of an Inbox, the gateway restarts the feed from the current state without backfill and marks a gap for that mailbox; the journal copy covers the interval. With change notifications, the notification endpoint of the gateway must be reachable from Microsoft Graph; missed notifications are caught by the safety poll.
<!-- prettier-ignore-end -->
<!-- END GENERATED GUIDE api-mode microsoft_365 -->
