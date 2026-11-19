# Microsoft 365 (Exchange Online) through the email security gateway

This page is the **template of the customer-specific setup guide** that the gateway generates for every Microsoft 365 connection (step 8.2, [ADR-0080](../architecture/adr/0080-setup-wizard-explicit-authorization-and-guides.md)). Your own guide contains the values of your connection (tenant, domains, Microsoft 365 hosts, gateway hosts, probe address, route token) and the state of your statements: open **Integrations → your connection → Setup guide** in the admin console (or `GET /api/v1/provider-connections/{id}/setup-guide?format=markdown`, permission `integration:read`) and use that one. This template shows the same guide for an example connection.

What the gateway does and does not do:

- It requests **read-only** Microsoft Graph application permissions (`Organization.Read.All`, `Domain.Read.All`) through admin consent to the operator's app, or through an app registration of your own ([ADR-0076](../architecture/adr/0076-provider-integration-framework.md)). It reads the tenant identity and the verification of your domains; it never reads mail, users or mailboxes and **never changes your Exchange Online configuration** ([ADR-0080](../architecture/adr/0080-setup-wizard-explicit-authorization-and-guides.md)).
- Gateway-side changes (destination servers, the provider relay, activation) happen only after a preview, an explicit confirmation by an administrator holding the required permissions, and are audited.
- Outbound and internal mail from Exchange Online is accepted on the gateway's relay only from Microsoft's published ranges, for a sender domain linked to your connection, over TLS, and only when the message proves it comes from **your** tenant: the `X-MS-Exchange-CrossTenant-Id` header must be your tenant id and the message must carry an aligned DKIM signature of a linked domain ([ADR-0078](../architecture/adr/0078-provider-relay-tenant-attribution.md)). Failing messages are refused with `550 5.7.26`.
- Internal routing uses a per-connection route token and two transport rules to prevent loops ([ADR-0081](../architecture/adr/0081-provider-mail-flow-loop-prevention-and-failover.md)).
- Null-sender mail (non-delivery reports, `<>` auto-replies) is refused on the provider relay: keep NDRs on Microsoft's direct path.

Placeholders in this template:

| Placeholder                                              | Stands for                                                                                  |
| -------------------------------------------------------- | ------------------------------------------------------------------------------------------- |
| `example.com`                                            | A domain verified at the gateway and in your tenant                                         |
| `example-com.mail.protection.outlook.com`                | The Microsoft 365 MX target of that domain (as Microsoft reports it)                        |
| `*.gateway.example.net`, `192.0.2.0/28`, `2001:db8::/64` | The gateway's MX hosts, relay hosts, TLS name and egress addresses (your operator's values) |
| `11111111-2222-3333-4444-555555555555`                   | The tenant id, the operator's app (client) id and the connection id                         |
| `EXAMPLEROUTETOKEN…`                                     | The route token (shown in full only to users with `integration:manage`)                     |

Related: [destination servers](../domains/destination-servers.md) (inbound delivery), [Google Workspace](google-workspace.md), operator documentation in [deployment](../deployment/provider-integrations.md) and the [runbook](../runbooks/provider-integrations.md).

## The example guide

The block below is generated from the guide generator of `@email-gateway/provider-integrations` (`exampleSetupGuideInput('microsoft_365')`); a test fails when it no longer matches.

<!-- BEGIN GENERATED GUIDE (do not edit; see the note above) -->
<!-- prettier-ignore-start -->
## Microsoft 365 setup guide: Example Microsoft 365

Generated 2026-11-18T00:00:00.000Z (`setup-guide/1`).
Tenant: Example Organization (`11111111-2222-3333-4444-555555555555`).

> This guide contains the values of your own connection. The gateway never changes your Microsoft 365 configuration: you apply every step yourself. Confirmations you record in the console are your statements (attestations), not proofs the gateway has checked.

### Contents

1. [Overview and what the gateway will never do](#overview)
2. [Grant read-only access](#grant-access)
3. [Domains](#domains)
4. [Inbound mail](#inbound)
5. [Outbound mail](#outbound)
6. [Internal routing](#internal-routing)
7. [Validate and activate](#validate-activate)
8. [Failover and outages](#failover)
9. [Disconnect and clean up](#disconnect)

<a id="overview"></a>

### 1. Overview and what the gateway will never do

This guide connects Microsoft 365 to the email security gateway for the connection "Example Microsoft 365". Inbound mail reaches the gateway first (your MX records), is inspected and then delivered to Microsoft 365. Outbound and, optionally, internal mail is routed by Microsoft 365 to the gateway, inspected and delivered.

The gateway requests read-only access only: it reads your tenant identity and the verification state of your domains. It never reads or sends mail on your behalf, never reads users or mailboxes and never changes your Microsoft 365 configuration. Every change in Microsoft 365 below is made by you.

Changes on the gateway side (where the gateway delivers your mail, whether it accepts your outbound mail) are applied only after you review a preview and confirm it in the console.

<a id="grant-access"></a>

### 2. Grant read-only access

The gateway needs to read your tenant id and your domains. Choose one of the methods below; both grant exactly the same read-only permissions.

<a id="grant-admin-consent"></a>

#### 2.1 Grant admin consent to the gateway application (recommended)

In the console, choose "Grant consent in Microsoft". Sign in as a Global Administrator or Privileged Role Administrator of your tenant and accept. The application requests only the read-only application permissions listed below.

| Item | Value |
| --- | --- |
| Application (client) ID | `11111111-2222-3333-4444-555555555555` |
| Microsoft Graph application permissions | `Organization.Read.All, Domain.Read.All` |

<a id="domains"></a>

### 3. Domains

Each linked domain must be verified at the gateway (DNS TXT record) and verified in your Microsoft 365 tenant. The gateway's own verification is authoritative; the Microsoft 365 verification proves the domain belongs to this tenant.

<a id="domains-status"></a>

#### 3.1 Linked domains

| Item | Value |
| --- | --- |
| example.com | `gateway: active; Microsoft 365: verified` |

<a id="inbound"></a>

### 4. Inbound mail

Inbound mail arrives at the gateway (MX), is inspected and is delivered to Exchange Online through a partner connector that trusts only the gateway.

<a id="inbound-mx"></a>

#### 4.1 Point your MX records to the gateway

At your DNS provider, replace the MX records of each linked domain with the gateway hosts below. Lower the TTL a day in advance to shorten the switch-over.

```dns
example.com. 3600 IN MX 10 mx1.gateway.example.net.
example.com. 3600 IN MX 20 mx2.gateway.example.net.
```

<a id="inbound-destination"></a>

#### 4.2 Gateway destination

In the console, apply the Microsoft 365 destination for each domain (preview, then confirm). The host is your tenant's MX endpoint as Microsoft reports it.

| Item | Value |
| --- | --- |
| example.com | `example-com.mail.protection.outlook.com` |

<a id="inbound-connector"></a>

#### 4.3 Create the inbound partner connector

In Exchange Online PowerShell (Connect-ExchangeOnline), create a partner connector that accepts mail only from the gateway, identified by its TLS certificate. If you prefer IP addresses, use the second command instead.

```powershell
New-InboundConnector -Name 'Email security gateway' -ConnectorType Partner -SenderDomains * -RequireTls $true -TlsSenderCertificateName 'relay.gateway.example.net' -RestrictDomainsToCertificate $true
```

```powershell
New-InboundConnector -Name 'Email security gateway' -ConnectorType Partner -SenderDomains * -RequireTls $true -SenderIPAddresses '192.0.2.0/28','2001:db8::/64' -RestrictDomainsToIPAddresses $true
```

> **Attestation `m365.inbound_connector_created`** (your statement, not a gateway check): The inbound partner connector "Email security gateway" exists and accepts mail from the gateway only over TLS.
> Status: not confirmed yet

<a id="inbound-enhanced-filtering"></a>

#### 4.4 Enable Enhanced Filtering for Connectors

Enhanced Filtering lets Exchange Online evaluate SPF, DKIM and DMARC against the original sender instead of the gateway.

```powershell
Set-InboundConnector -Identity 'Email security gateway' -EFSkipLastIP $true
```

> **Attestation `m365.enhanced_filtering_enabled`** (your statement, not a gateway check): Enhanced Filtering for Connectors is enabled on the inbound connector.
> Status: not confirmed yet

<a id="inbound-lockdown"></a>

#### 4.5 Lock down direct delivery

Senders can still reach your tenant's MX endpoint directly, bypassing inspection. Reject or quarantine mail that does not arrive through the inbound connector, for example with a transport rule that applies to messages from outside the organization unless the message was received through the connector above. Exclude the providers that must reach you directly (if any) explicitly.

> **Attestation `m365.direct_delivery_locked_down`** (your statement, not a gateway check): Mail that does not arrive through the gateway is rejected or quarantined by Exchange Online.
> Status: not confirmed yet

<a id="outbound"></a>

### 5. Outbound mail

Exchange Online sends outbound mail through an outbound connector to the gateway relay. The gateway accepts it only when the message proves your tenant: the tenant id Exchange Online stamps on it and a DKIM signature of your own domain.

<a id="outbound-dkim"></a>

#### 5.1 Enable DKIM signing for each linked domain

Publish the two selector CNAME records Microsoft shows, then enable signing. Mail without an aligned DKIM signature is refused by the gateway relay.

```powershell
New-DkimSigningConfig -DomainName 'example.com' -Enabled $true
# If a configuration already exists:
Set-DkimSigningConfig -Identity 'example.com' -Enabled $true
```

<a id="outbound-spf"></a>

#### 5.2 Add the gateway to your SPF records

Keep your existing mechanisms and add the gateway include, so receivers accept mail the gateway relays for you. One SPF record per domain; at most 10 DNS lookups in total.

```dns
example.com. 3600 IN TXT "v=spf1 include:spf.protection.outlook.com include:spf.gateway.example.net ~all"
```

<a id="outbound-connector"></a>

#### 5.3 Create the outbound connector to the gateway

The connector sends mail for all recipient domains to the gateway relay hosts over TLS with certificate validation. Non-delivery reports (empty sender) are not accepted by the gateway relay and stay on the direct path.

```powershell
New-OutboundConnector -Name 'Email security gateway outbound' -ConnectorType Partner -RecipientDomains * -SmartHosts 'relay1.gateway.example.net','relay2.gateway.example.net' -UseMXRecord $false -TlsSettings DomainValidation -TlsDomain 'relay.gateway.example.net' -IsTransportRuleScoped $false
```

> **Attestation `m365.outbound_connector_created`** (your statement, not a gateway check): The outbound connector "Email security gateway outbound" exists with the gateway relay hosts as smart hosts.
> Status: not confirmed yet

<a id="outbound-validate"></a>

#### 5.4 Validate the outbound connector

In the Exchange admin center open Mail flow → Connectors → the outbound connector → Validate this connector, and enter the probe address. Start an outbound validation in the console to get a probe address.

<a id="internal-routing"></a>

### 6. Internal routing

Internal mail is routed to the gateway by a transport rule through a connector that only that rule uses. The gateway marks the copies it delivers back with a route token header, which the rule exempts, so mail does not loop; a second rule removes the header before delivery to mailboxes, so users never see the token.

The route token is masked. A user with permission to manage integrations sees the full value.

<a id="internal-connector"></a>

#### 6.1 Create the rule-scoped connector

```powershell
New-OutboundConnector -Name 'Email security gateway internal' -ConnectorType Partner -RecipientDomains * -SmartHosts 'relay1.gateway.example.net','relay2.gateway.example.net' -UseMXRecord $false -TlsSettings DomainValidation -TlsDomain 'relay.gateway.example.net' -IsTransportRuleScoped $true
```

<a id="internal-rules"></a>

#### 6.2 Create the two transport rules

Rule A (highest priority) routes internal mail to the gateway unless it carries the route token; rule B (lowest priority) removes the token header.

| Item | Value |
| --- | --- |
| Route token | `••••0000` |

```powershell
New-TransportRule -Name 'Route internal mail through the email security gateway' -Priority 0 -FromScope InOrganization -SentToScope InOrganization -RouteMessageOutboundConnector 'Email security gateway internal' -ExceptIfHeaderMatchesMessageHeader 'X-EG-Route-Token' -ExceptIfHeaderMatchesPatterns '^••••0000$'
New-TransportRule -Name 'Remove the gateway route token' -HeaderContainsMessageHeader 'X-EG-Route-Token' -HeaderContainsWords '••••0000' -RemoveHeader 'X-EG-Route-Token'
# Rule B must be the last rule:
Set-TransportRule -Identity 'Remove the gateway route token' -Priority ((Get-TransportRule).Count - 1)
```

> **Attestation `m365.internal_routing_rules_created`** (your statement, not a gateway check): The transport rules "Route internal mail through the email security gateway" and "Remove the gateway route token" exist with the current route token.
> Status: not confirmed yet

<a id="validate-activate"></a>

### 7. Validate and activate

Run a full validation in the console. It checks your access, the domains, MX and SPF records, the gateway destination (an SMTP connection without sending mail), the outbound probe and mail loops. What it cannot observe is listed as an attestation.

When every required check passes, activate outbound routing (and, if you want it, internal routing) in the console. Activation is a gateway-side change: review the preview and confirm it.

<a id="failover"></a>

### 8. Failover and outages

Every gateway relay host (relay1.gateway.example.net, relay2.gateway.example.net) is listed in your configuration, so mail moves to the next host when one is unavailable.

While the gateway is unreachable, Exchange Online queues outbound mail and retries for about 24 to 48 hours. This is the provider's documented behaviour, not a guarantee of the gateway.

The gateway delivers inbound mail to every destination host in priority order and retries deferred mail for up to 5 days.

The gateway never falls back to delivering around itself. An emergency bypass is a change you make on your side, and mail then leaves without inspection:

Emergency bypass: Set-OutboundConnector -Identity 'Email security gateway outbound' -Enabled $false and Disable-TransportRule -Identity 'Route internal mail through the email security gateway'. Re-enable both when the gateway is back.

<a id="disconnect"></a>

### 9. Disconnect and clean up

Disconnecting in the console stops the gateway relay for this tenant and removes its access; the gateway keeps delivering inbound mail to Microsoft 365 until you change your MX records.

Before you disconnect: point the MX records back to Microsoft 365, then remove the objects below. Remove the gateway application (Enterprise applications) or your own app registration.

<a id="disconnect-commands"></a>

#### 9.1 Remove the Exchange Online objects

```dns
example.com. 3600 IN MX 0 example-com.mail.protection.outlook.com.
```

```powershell
Remove-TransportRule -Identity 'Route internal mail through the email security gateway'
Remove-TransportRule -Identity 'Remove the gateway route token'
Remove-OutboundConnector -Identity 'Email security gateway internal'
Remove-OutboundConnector -Identity 'Email security gateway outbound'
Remove-InboundConnector -Identity 'Email security gateway'
```
<!-- prettier-ignore-end -->
<!-- END GENERATED GUIDE -->
