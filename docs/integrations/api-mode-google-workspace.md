# API-mode protection for Google Workspace (no MX change)

This page is the **template of the customer-specific API-mode guide** that the gateway generates for every Google Workspace provider connection (step API-1, [ADR-0098](../architecture/adr/0098-protection-modes-and-detect-mode-copies.md), [ADR-0099](../architecture/adr/0099-mailbox-access-consent-and-custody.md), [ADR-0100](../architecture/adr/0100-api-mode-intake-mailbox-worker.md)). Your own guide contains the values of your connection (domains, the bound journal intake source, the service account client ID and the delegated administrator) and the state of your statements: open **Mailbox protection → Setup → your connection** in the admin console (or `GET /api/v1/api-mode/connections/{connectionId}/setup-guide` with `Accept: text/markdown`, permission `remediation:read`) and use that one. This template shows the same guide for an example connection.

API mode is for domains whose MX records stay with Google Workspace. The gateway receives a **copy** of each message (a copy routed with "Also deliver to" through the [journal intake](journal-intake-google-workspace.md) and, optionally, the Gmail history feeds), scans it in **detect mode** and records the verdict per mailbox. Choose the protection mode of a domain in the add-domain wizard or on the domain page (`inline`, `api` or `hybrid`).

What the gateway does and does not do:

- It **never** changes your MX records, mail flow or Google Workspace configuration; it never delivers, forwards, delays, quarantines or bounces a message from the API side. A domain cannot switch to `api` while its MX still points to the gateway (choose `hybrid` or move the MX first).
- **Mailbox access** is a separate domain-wide delegation (permission profile `google.mailbox_remediation`: scopes `https://www.googleapis.com/auth/gmail.modify` and `https://www.googleapis.com/auth/admin.directory.user.readonly`), apart from the mail-flow and account takeover delegations. Granting, verifying and revoking it needs the console rights `integration:manage` and `remediation:write`. In this release the gateway only **reads** (users, Gmail history, the content of new Inbox messages it has no copy of); removing threats from mailboxes comes with step API-2.
- History polling is **off by default** and never backfills existing mail. Service-account keys live only in the encrypted credential store; tokens stay in memory.

Placeholders in this template:

| Placeholder                                    | Stands for                                                                                        |
| ---------------------------------------------- | ------------------------------------------------------------------------------------------------- |
| `example.com`, `admin@example.com`             | A domain verified at the gateway and linked to your connection; your delegated administrator      |
| `journal-••••xamp@journal.gateway.example.net` | The intake address of your journal intake source (always masked here; reveal it in its own guide) |
| `11111111-2222-3333-4444-555555555555`         | The connection id and the journal source id                                                       |
| `111122223333444455556`, `C0example`           | The operator service account's client ID and your Google customer ID                              |

Related: [journal intake from Google Workspace](journal-intake-google-workspace.md), [Google Workspace connection](google-workspace.md), [API mode for Microsoft 365](api-mode-microsoft-365.md).

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
