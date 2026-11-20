# Journal intake from Microsoft 365 (Exchange Online journaling)

This page is the **template of the customer-specific setup guide** that the gateway generates for every Microsoft 365 journal intake source (step 8.6, [ADR-0087](../architecture/adr/0087-journal-intake-path.md)). Your own guide contains the values of your source (its intake address, your connection and domains) and the state of your statements: open **Settings → Journaling → your source → Setup guide** in the admin console (or `GET /api/v1/journaling/intake-sources/{id}/setup-guide?format=markdown`, permission `journal:read`; the address is shown in full only to users with `journal:manage`, and that reveal is audited) and use that one. This template shows the same guide for an example source.

Journal intake is for organizations that want **journaling and archiving without routing mail through the gateway** (the archive-only plan, [ADR-0090](../architecture/adr/0090-archive-only-service-profile.md)), or that use the gateway and want copies of mail the gateway never sees (internal mail of the tenant). Your MX records and mail flow do not change. How the layers fit together: [mail flow](../architecture/mail-flow.md).

What the gateway does and does not do:

- A Microsoft Purview **journal rule** in your tenant sends a journal report of every message to a secret **intake address** of the gateway (`journal-<token>@<intake domain>`). The gateway unwraps the report, keeps the original message and the full journal envelope (To, Cc, **Bcc** and expanded distribution lists) and archives it encrypted under your archive settings.
- The gateway accepts journal reports for your source only from Microsoft's published ranges, over TLS, for an intake address that exists, and only when the report proves it comes from **your** tenant: the `X-MS-Exchange-CrossTenant-Id` header must be the tenant id of your Microsoft 365 connection (Integrations; the tenant is bound only after one of your domains is verified in it). Reports failing that proof are **accepted and discarded** (never bounced to a sender the gateway cannot trust) and counted in the source health.
- The gateway **never delivers, forwards, quarantines or bounces** a journaled message, and never changes your tenant. Every customer-side step below is yours; your confirmations in the console are statements, not checks.
- A connection for journal intake needs only the **Connect** and **Domains** steps of the Microsoft 365 connection wizard (read-only consent); no mail-flow change is needed.
- Pausing the source makes Microsoft 365 retry for up to two days; disabling it refuses every report permanently (Exchange Online then sends them to your alternate journaling mailbox).

Placeholders in this template:

| Placeholder                                            | Stands for                                                                   |
| ------------------------------------------------------ | ---------------------------------------------------------------------------- |
| `example.com`                                          | A domain verified at the gateway and linked to your Microsoft 365 connection |
| `journal-••••xamp@journal.gateway.example.net`         | Your source's intake address (masked; reveal it in the console)              |
| `journal.gateway.example.net`, `*.gateway.example.net` | The operator's intake domain and gateway MX hosts                            |
| `11111111-2222-3333-4444-555555555555`                 | The source id and the tenant id of your connection                           |

Related: [Google Workspace intake](journal-intake-google-workspace.md), [on-premises Exchange and SMTP intake](journal-intake-on-premises.md), [Microsoft 365 connection](microsoft-365.md); operator documentation in [deployment](../deployment/smtp-gateway.md) and the [runbook](../runbooks/journal-intake.md).

## The example guide

The block below is generated from the guide generator of `@email-gateway/provider-integrations` (`exampleJournalIntakeGuideInput('microsoft_365_journal')`); a test fails when it no longer matches (`packages/provider-integrations/src/guides/journal-intake-docs-templates.test.ts`).

<!-- BEGIN GENERATED GUIDE microsoft_365_journal (do not edit; see the note above) -->
<!-- prettier-ignore-start -->
## Journal intake setup guide: Example Microsoft 365 journaling

Generated 2026-11-20T00:00:00.000Z (`journal-intake-guide/1`).
Source type: Microsoft 365 journaling.

> This guide contains the values of your own journal intake source. The gateway never changes your mail system: you apply every step yourself. Confirmations you record in the console are your statements (attestations), not proofs the gateway has checked. The intake address and token are masked: a user with journaling management rights can reveal them in the console.

### Contents

1. [Overview and what the gateway will never do](#overview)
2. [Your intake address](#intake-address)
3. [Microsoft 365 journal rule](#m365-journaling)
4. [Verify and monitor](#verify)

<a id="overview"></a>

### 1. Overview and what the gateway will never do

This guide sets up the journal intake source "Example Microsoft 365 journaling" (Microsoft 365 journaling). Your mail system sends a copy of every message to the intake address below; the gateway archives the copy (encrypted, retained and searchable under your archive settings). Your MX records and mail flow do not change.

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
| Source | `Example Microsoft 365 journaling` |
| Provider connection | `Example Microsoft 365 (11111111-2222-3333-4444-555555555555)` |
| TLS required | `yes` |

<a id="m365-journaling"></a>

### 3. Microsoft 365 journal rule

Journal rules are managed in the Microsoft Purview portal (Data lifecycle management, Exchange (legacy), Journal rules) or with Exchange Online PowerShell (Connect-ExchangeOnline).

<a id="m365-ndr-mailbox"></a>

#### 3.1 Set the mailbox for undeliverable journal reports

Exchange Online requires an alternate mailbox that receives journal reports which cannot be delivered (for example while the intake address is paused). Use a dedicated mailbox in your tenant that is itself not journaled, and review it regularly.

```powershell
Set-TransportConfig -JournalingReportNdrTo 'journal-ndr@example.com'
```

> **Attestation `journal.m365.ndr_mailbox_set`** (your statement, not a gateway check): A mailbox for undeliverable journal reports is set and reviewed.
> Status: not confirmed yet

<a id="m365-journal-rule"></a>

#### 3.2 Create the journal rule

In Purview, create a journal rule named "Email security gateway journal" that sends journal reports to the intake address, for messages sent or received from everyone, and the message types you want to archive (all messages, internal only or external only).

| Item | Value |
| --- | --- |
| Send journal reports to | `journal-••••xamp@journal.gateway.example.net` |

```powershell
New-JournalRule -Name 'Email security gateway journal' -JournalEmailAddress 'journal-••••xamp@journal.gateway.example.net' -Scope Global -Enabled $true
```

> **Warning:** Journal rules journal only the mail of mailboxes in your tenant. Exchange Online does not journal to an Exchange Online mailbox; the intake address is external to your tenant, which is what Exchange Online requires. A new rule can take up to an hour to apply.

> **Attestation `journal.m365.rule_created`** (your statement, not a gateway check): The journal rule "Email security gateway journal" sends journal reports to the intake address.
> Status: not confirmed yet

<a id="m365-dkim"></a>

#### 3.3 Optional: sign with DKIM

The gateway accepts journal reports only from Microsoft 365 servers and checks that each report carries your bound tenant id. DKIM signatures of your domains are recorded as additional evidence when present; enabling DKIM signing in Microsoft Defender is recommended but not required.

| Item | Value |
| --- | --- |
| example.com | `DKIM signing recommended` |

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

Rotating creates a new address; the previous values stay valid for a short overlap. Update the steps above with the new values within the overlap.
<!-- prettier-ignore-end -->
<!-- END GENERATED GUIDE microsoft_365_journal -->
