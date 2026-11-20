# Journal intake from Google Workspace (Gmail "Also deliver to" copies)

This page is the **template of the customer-specific setup guide** that the gateway generates for every Google Workspace journal intake source (step 8.6, [ADR-0087](../architecture/adr/0087-journal-intake-path.md)). Your own guide contains the values of your source (its intake address, the header token, your connection and domains) and the state of your statements: open **Settings → Journaling → your source → Setup guide** in the admin console (or `GET /api/v1/journaling/intake-sources/{id}/setup-guide?format=markdown`, permission `journal:read`; the address and the token are shown in full only to users with `journal:manage`, audited) and use that one. This template shows the same guide for an example source.

How the layers fit together: [mail flow](../architecture/mail-flow.md). Your MX records and mail flow do not change.

What the gateway does and does not do:

- A Gmail **routing rule** in your Admin console adds the intake address as an additional recipient ("Also deliver to") of inbound, outbound and internal mail, adds the `X-Gm-Original-To` header and a custom header `X-EG-Journal-Token` with your source's secret token.
- The gateway accepts copies for your source only from Google's published ranges, over TLS, for an intake address that exists and is bound to your Google Workspace connection, and only when the copy carries exactly one header token of your source. Copies failing that proof are **accepted and discarded** (never bounced) and counted in the source health. The token header is **removed** before the copy is stored, so the archive never holds the credential.
- Google copies carry the **routed recipient** (`X-Gm-Original-To`), not a full journal envelope: Bcc recipients appear only for the mailboxes that received a copy.
- The gateway **never delivers, forwards, quarantines or bounces** a journaled message and never changes your Google Workspace configuration.

Placeholders in this template:

| Placeholder                                            | Stands for                                                            |
| ------------------------------------------------------ | --------------------------------------------------------------------- |
| `example.com`                                          | A domain verified at the gateway and linked to your Google connection |
| `journal-••••xamp@journal.gateway.example.net`         | Your source's intake address (masked; reveal it in the console)       |
| `••••enex`                                             | The `X-EG-Journal-Token` value (masked; reveal it in the console)     |
| `journal.gateway.example.net`, `*.gateway.example.net` | The operator's intake domain and gateway MX hosts                     |
| `11111111-2222-3333-4444-555555555555`                 | The source id                                                         |

Related: [Microsoft 365 intake](journal-intake-microsoft-365.md), [on-premises Exchange and SMTP intake](journal-intake-on-premises.md), [Google Workspace connection](google-workspace.md), [runbook](../runbooks/journal-intake.md).

## The example guide

The block below is generated from the guide generator of `@email-gateway/provider-integrations` (`exampleJournalIntakeGuideInput('google_workspace_copy')`); a test fails when it no longer matches.

<!-- BEGIN GENERATED GUIDE google_workspace_copy (do not edit; see the note above) -->
<!-- prettier-ignore-start -->
## Journal intake setup guide: Example Google Workspace copies

Generated 2026-11-20T00:00:00.000Z (`journal-intake-guide/1`).
Source type: Google Workspace copies.

> This guide contains the values of your own journal intake source. The gateway never changes your mail system: you apply every step yourself. Confirmations you record in the console are your statements (attestations), not proofs the gateway has checked. The intake address and token are masked: a user with journaling management rights can reveal them in the console.

### Contents

1. [Overview and what the gateway will never do](#overview)
2. [Your intake address](#intake-address)
3. [Google Workspace routing rule](#google-routing)
4. [Verify and monitor](#verify)

<a id="overview"></a>

### 1. Overview and what the gateway will never do

This guide sets up the journal intake source "Example Google Workspace copies" (Google Workspace copies). Your mail system sends a copy of every message to the intake address below; the gateway archives the copy (encrypted, retained and searchable under your archive settings). Your MX records and mail flow do not change.

The gateway only receives copies. It never delivers, forwards, quarantines or bounces a journaled message, and it never changes your configuration. Copies that fail the sender checks are discarded and shown in the source health; they are never returned to the sender.

<a id="intake-address"></a>

### 2. Your intake address

The intake address identifies this source. Treat it like a password: anyone who knows it and sends from your authorized systems can add copies to your archive. You can rotate it in the console at any time; the previous address keeps working for a short overlap.

<a id="intake-address-values"></a>

#### 2.1 Values for this source

The address is masked in this guide. A user with journaling management rights can reveal it in the console before applying the steps below.

| Item | Value |
| --- | --- |
| Intake address | `journal-••••xamp@journal.gateway.example.net` |
| X-EG-Journal-Token header value | `••••enex` |
| Source | `Example Google Workspace copies` |
| Provider connection | `Example Google Workspace` |
| TLS required | `yes` |

<a id="google-routing"></a>

### 3. Google Workspace routing rule

In the Google Admin console, open Apps, Google Workspace, Gmail, Routing, and add a routing setting at the top-level organizational unit.

<a id="google-route"></a>

#### 3.1 Add the "Also deliver to" route

Name the setting "Email security gateway journal". Under "Email messages to affect" select Inbound, Outbound, Internal - sending and Internal - receiving. Under "Also deliver to", add the intake address as an additional recipient.

| Item | Value |
| --- | --- |
| Also deliver to | `journal-••••xamp@journal.gateway.example.net` |

> **Attestation `journal.google.route_created`** (your statement, not a gateway check): The routing setting "Email security gateway journal" also delivers inbound, outbound and internal mail to the intake address.
> Status: not confirmed yet

<a id="google-headers"></a>

#### 3.2 Add the journal headers

In the same setting, under "Headers", select "Add X-Gm-Original-To header" and "Add custom headers", and add the custom header below. Copies without a matching header are discarded.

| Item | Value |
| --- | --- |
| Custom header name | `X-EG-Journal-Token` |
| Custom header value | `••••enex` |

> **Warning:** Google copies carry the recipient Gmail routed the message to (X-Gm-Original-To), not the full envelope of the original message: a blind-copied recipient is known only from the copy routed for that recipient.

> **Attestation `journal.google.headers_added`** (your statement, not a gateway check): The routing setting adds the X-Gm-Original-To header and the X-EG-Journal-Token header with the current token.
> Status: not confirmed yet

<a id="verify"></a>

### 4. Verify and monitor

<a id="verify-first-message"></a>

#### 4.1 Send a test message

Send a message that your configuration copies. The source becomes verified with the first accepted copy; the message then appears in archive search with the source "journal intake".

<a id="monitor-health"></a>

#### 4.2 Watch the source health

The console shows accepted and refused copies per day. When no copy arrives for the configured silence period, or copies are refused or discarded, the source turns silent or failing and your alert recipients are notified.

<a id="rotate-address"></a>

#### 4.3 Rotate the address

Rotating creates a new address and header token; the previous values stay valid for a short overlap. Update the steps above with the new values within the overlap.
<!-- prettier-ignore-end -->
<!-- END GENERATED GUIDE google_workspace_copy -->
