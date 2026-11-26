# API-mode protection for Microsoft 365 (no MX change)

This page is the **template of the customer-specific API-mode guide** that the gateway generates for every Microsoft 365 provider connection (step API-1, [ADR-0098](../architecture/adr/0098-protection-modes-and-detect-mode-copies.md), [ADR-0099](../architecture/adr/0099-mailbox-access-consent-and-custody.md), [ADR-0100](../architecture/adr/0100-api-mode-intake-mailbox-worker.md)). Your own guide contains the values of your connection (tenant, domains, the bound journal intake source, the mailbox-access application) and the state of your statements: open **Mailbox protection → Setup → your connection** in the admin console (or `GET /api/v1/api-mode/connections/{connectionId}/setup-guide` with `Accept: text/markdown`, permission `remediation:read`) and use that one. This template shows the same guide for an example connection.

API mode is for domains whose MX records stay with Microsoft 365. The gateway receives a **copy** of each message (a journal copy through the [journal intake](journal-intake-microsoft-365.md) and, optionally, the mailbox change feeds), scans it in **detect mode** and records the verdict per mailbox. Choose the protection mode of a domain in the add-domain wizard or on the domain page (`inline`, `api` or `hybrid`).

What the gateway does and does not do:

- It **never** changes your MX records, mail flow or tenant configuration; it never delivers, forwards, delays, quarantines or bounces a message from the API side. A domain cannot switch to `api` while its MX still points to the gateway (choose `hybrid` or move the MX first).
- **Mailbox access** is a separate consent (permission profile `m365.mailbox_remediation`: Microsoft Graph application permissions `Mail.ReadWrite` and `User.Read.All`), apart from the mail-flow and account takeover grants. Granting, verifying and revoking it needs the console rights `integration:manage` and `remediation:write`. In this release the gateway only **reads** (users, Inbox changes, the content of new messages it has no copy of); removing threats from mailboxes comes with step API-2.
- Change feeds are **off by default** and never backfill existing mail. Credentials live only in the encrypted credential store; tokens stay in memory.

Placeholders in this template:

| Placeholder                                    | Stands for                                                                                         |
| ---------------------------------------------- | -------------------------------------------------------------------------------------------------- |
| `example.com`                                  | A domain verified at the gateway and linked to your Microsoft 365 connection                       |
| `journal-••••xamp@journal.gateway.example.net` | The intake address of your journal intake source (always masked here; reveal it in its own guide)  |
| `11111111-2222-3333-4444-555555555555`         | The connection id, the tenant id, the journal source id and the operator application's client ID   |
| `<application-client-id>` and other `<…>`      | Values you fill in yourself (your application, enterprise application object ID, mailbox group DN) |

Related: [journal intake from Microsoft 365](journal-intake-microsoft-365.md), [Microsoft 365 connection](microsoft-365.md), [API mode for Google Workspace](api-mode-google-workspace.md).

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
