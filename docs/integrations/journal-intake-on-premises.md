# Journal intake from on-premises Exchange and SMTP servers

This page is the **template of the customer-specific setup guides** that the gateway generates for on-premises journal intake sources (step 8.6, [ADR-0087](../architecture/adr/0087-journal-intake-path.md)): **Exchange Server journaling** (journal reports with the full envelope) and **SMTP BCC copies** (for example Postfix `always_bcc`). Your own guide contains the values of your source (its intake address, networks and domains) and the state of your statements: open **Settings → Journaling → your source → Setup guide** in the admin console (or `GET /api/v1/journaling/intake-sources/{id}/setup-guide?format=markdown`, permission `journal:read`) and use that one.

How the layers fit together: [mail flow](../architecture/mail-flow.md). Your MX records and mail flow do not change.

What the gateway does and does not do:

- Your server sends a copy of every message to the source's secret **intake address**, over TLS, from the **networks you registered** for the source (public CIDR ranges of at least /16 for IPv4 or /32 for IPv6, at most 32; ranges shared with Microsoft 365 or Google are refused because shared infrastructure is never a credential). Optionally the TLS client certificate must match registered SHA-256 fingerprints.
- Copies from any other address, without TLS (when required) or larger than the limit are refused in the SMTP session, so your server reports them to you; pausing the source makes your server retry later.
- Exchange journal reports are unwrapped to the original message with the full envelope (To, Cc, **Bcc**, expanded distribution lists, forwarding); a report the gateway cannot recognize is stored as received and flagged in the source health. **BCC copies carry only the header recipients.**
- The gateway **never delivers, forwards, quarantines or bounces** a journaled message and never changes your servers.

Placeholders in this template:

| Placeholder                                            | Stands for                                                      |
| ------------------------------------------------------ | --------------------------------------------------------------- |
| `example.com`                                          | A domain verified at the gateway                                |
| `198.51.100.0/24`, `2001:db8:10::/48`                  | The networks your server sends from                             |
| `journal-••••xamp@journal.gateway.example.net`         | Your source's intake address (masked; reveal it in the console) |
| `journal.gateway.example.net`, `*.gateway.example.net` | The operator's intake domain and gateway MX hosts               |
| `11111111-2222-3333-4444-555555555555`                 | The source id                                                   |

Related: [Microsoft 365 intake](journal-intake-microsoft-365.md), [Google Workspace intake](journal-intake-google-workspace.md), [runbook](../runbooks/journal-intake.md).

## Exchange Server journaling: the example guide

Generated from `exampleJournalIntakeGuideInput('exchange_onprem_journal')`; a test fails when it no longer matches.

<!-- BEGIN GENERATED GUIDE exchange_onprem_journal (do not edit; see the note above) -->
<!-- prettier-ignore-start -->
## Journal intake setup guide: Example On-premises Exchange journaling

Generated 2026-11-20T00:00:00.000Z (`journal-intake-guide/1`).
Source type: On-premises Exchange journaling.

> This guide contains the values of your own journal intake source. The gateway never changes your mail system: you apply every step yourself. Confirmations you record in the console are your statements (attestations), not proofs the gateway has checked. The intake address and token are masked: a user with journaling management rights can reveal them in the console.

### Contents

1. [Overview and what the gateway will never do](#overview)
2. [Your intake address](#intake-address)
3. [Exchange Server journaling](#onprem-journaling)
4. [Verify and monitor](#verify)

<a id="overview"></a>

### 1. Overview and what the gateway will never do

This guide sets up the journal intake source "Example On-premises Exchange journaling" (On-premises Exchange journaling). Your mail system sends a copy of every message to the intake address below; the gateway archives the copy (encrypted, retained and searchable under your archive settings). Your MX records and mail flow do not change.

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
| Source | `Example On-premises Exchange journaling` |
| TLS required | `yes` |

<a id="onprem-journaling"></a>

### 3. Exchange Server journaling

Run these commands in the Exchange Management Shell of your organization. Premium journaling (journal rules) needs Exchange Enterprise client access licenses; standard journaling configures the journal recipient per mailbox database instead.

<a id="onprem-journal-recipient"></a>

#### 3.1 Create the journal recipient

Create a mail contact for the intake address, so journal rules and mailbox databases can name it as their journal recipient.

```powershell
New-MailContact -Name 'Email security gateway journal' -ExternalEmailAddress 'journal-••••xamp@journal.gateway.example.net'
```

> **Attestation `journal.onprem.journal_recipient_created`** (your statement, not a gateway check): The journal recipient for the intake address exists and a journal rule or mailbox database journaling uses it.
> Status: not confirmed yet

<a id="onprem-journal-rule"></a>

#### 3.2 Create the journal rule (or database journaling)

Create a journal rule for all messages, set the mailbox for undeliverable journal reports, or, for standard journaling, set the journal recipient on each mailbox database.

```powershell
New-JournalRule -Name 'Email security gateway journal' -JournalEmailAddress 'Email security gateway journal' -Scope Global -Enabled $true
```

```powershell
Set-TransportConfig -JournalingReportNdrTo 'journal-ndr@example.com'
```

```powershell
Get-MailboxDatabase | Set-MailboxDatabase -JournalRecipient 'Email security gateway journal'
```

<a id="onprem-send-connector"></a>

#### 3.3 Send journal reports to the gateway over TLS

Create a Send connector for the intake domain that delivers to the gateway hosts and requires TLS with a certificate valid for the intake domain.

```powershell
New-SendConnector -Name 'Email security gateway journal' -Usage Custom -AddressSpaces 'SMTP:journal.gateway.example.net;1' -DNSRoutingEnabled $false -SmartHosts 'mx1.gateway.example.net','mx2.gateway.example.net' -RequireTLS $true -TlsAuthLevel DomainValidation -TlsDomain 'journal.gateway.example.net'
```

> **Attestation `journal.onprem.send_connector_tls`** (your statement, not a gateway check): A Send connector delivers mail for the intake domain to the gateway hosts and requires TLS.
> Status: not confirmed yet

<a id="source-networks"></a>

#### 3.4 Registered sending networks

The gateway accepts copies for this source only from these networks, and only over TLS. Mail from any other address is refused in the SMTP session (550 5.7.1). Update the networks in the console before your servers change addresses.

| Item | Value |
| --- | --- |
| Network 1 | `198.51.100.0/24` |
| Network 2 | `2001:db8:10::/48` |

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
<!-- END GENERATED GUIDE exchange_onprem_journal -->

## SMTP BCC copies: the example guide

Generated from `exampleJournalIntakeGuideInput('smtp_bcc')`; a test fails when it no longer matches.

<!-- BEGIN GENERATED GUIDE smtp_bcc (do not edit; see the note above) -->
<!-- prettier-ignore-start -->
## Journal intake setup guide: Example Generic SMTP BCC copies

Generated 2026-11-20T00:00:00.000Z (`journal-intake-guide/1`).
Source type: Generic SMTP BCC copies.

> This guide contains the values of your own journal intake source. The gateway never changes your mail system: you apply every step yourself. Confirmations you record in the console are your statements (attestations), not proofs the gateway has checked. The intake address and token are masked: a user with journaling management rights can reveal them in the console.

### Contents

1. [Overview and what the gateway will never do](#overview)
2. [Your intake address](#intake-address)
3. [BCC copies from your mail server](#smtp-bcc)
4. [Verify and monitor](#verify)

<a id="overview"></a>

### 1. Overview and what the gateway will never do

This guide sets up the journal intake source "Example Generic SMTP BCC copies" (Generic SMTP BCC copies). Your mail system sends a copy of every message to the intake address below; the gateway archives the copy (encrypted, retained and searchable under your archive settings). Your MX records and mail flow do not change.

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
| Source | `Example Generic SMTP BCC copies` |
| TLS required | `yes` |

<a id="smtp-bcc"></a>

### 3. BCC copies from your mail server

Configure your mail server to send a blind copy of every message to the intake address. The Postfix settings below are an example; other servers have equivalent options.

<a id="smtp-bcc-config"></a>

#### 3.1 Send a copy of every message

Use always\_bcc for all mail, or sender\_bcc\_maps / recipient\_bcc\_maps to copy a subset. Require TLS for the intake domain.

```text
# /etc/postfix/main.cf
always_bcc = journal-••••xamp@journal.gateway.example.net
smtp_tls_policy_maps = hash:/etc/postfix/tls_policy

# /etc/postfix/tls_policy (then: postmap /etc/postfix/tls_policy)
journal.gateway.example.net encrypt
```

> **Warning:** BCC copies carry only the recipients named in the To and Cc headers: blind-copied recipients of the original message are not known to the archive.

> **Attestation `journal.smtp.bcc_configured`** (your statement, not a gateway check): The mail server sends a BCC copy of the mail to archive to the intake address over TLS.
> Status: not confirmed yet

<a id="source-networks"></a>

#### 3.2 Registered sending networks

The gateway accepts copies for this source only from these networks, and only over TLS. Mail from any other address is refused in the SMTP session (550 5.7.1). Update the networks in the console before your servers change addresses.

| Item | Value |
| --- | --- |
| Network 1 | `198.51.100.0/24` |
| Network 2 | `2001:db8:10::/48` |

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
<!-- END GENERATED GUIDE smtp_bcc -->
