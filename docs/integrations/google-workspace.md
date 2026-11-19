# Google Workspace (Gmail) through the email security gateway

This page is the **template of the customer-specific setup guide** that the gateway generates for every Google Workspace connection (step 8.2, [ADR-0080](../architecture/adr/0080-setup-wizard-explicit-authorization-and-guides.md)). Your own guide contains the values of your connection (customer, domains, gateway hosts, probe address) and the state of your statements: open **Integrations → your connection → Setup guide** in the admin console (or `GET /api/v1/provider-connections/{id}/setup-guide?format=markdown`, permission `integration:read`) and use that one. This template shows the same guide for an example connection.

What the gateway does and does not do:

- It requests **read-only** Admin SDK scopes (`admin.directory.customer.readonly`, `admin.directory.domain.readonly`) through domain-wide delegation to the operator's service account, or a service account key of your own ([ADR-0076](../architecture/adr/0076-provider-integration-framework.md)). It reads the customer id and the verification of your domains; it never reads mail, users or mailboxes and **never changes your Gmail configuration** ([ADR-0080](../architecture/adr/0080-setup-wizard-explicit-authorization-and-guides.md)).
- Gateway-side changes (destination servers, the provider relay, activation) happen only after a preview, an explicit confirmation by an administrator holding the required permissions, and are audited.
- Outbound and internal mail from Gmail is accepted on the gateway's relay only from Google's published ranges, for a sender domain linked to your connection, over TLS, and only with a **fresh, aligned DKIM signature** of a linked domain that has not been replayed ([ADR-0078](../architecture/adr/0078-provider-relay-tenant-attribution.md)). Failing messages are refused with `550 5.7.26`. Enable "Authenticate email" (DKIM) for every linked domain before activation.
- Internal routing relies on a Gmail routing rule for internal sending; the gateway's hop limits are the loop backstop ([ADR-0081](../architecture/adr/0081-provider-mail-flow-loop-prevention-and-failover.md)).
- Null-sender mail is refused on the provider relay.

Placeholders in this template:

| Placeholder                                              | Stands for                                                                                  |
| -------------------------------------------------------- | ------------------------------------------------------------------------------------------- |
| `example.com`                                            | A domain verified at the gateway and in your Google Workspace                               |
| `*.gateway.example.net`, `192.0.2.0/28`, `2001:db8::/64` | The gateway's MX hosts, relay hosts, TLS name and egress addresses (your operator's values) |
| `111122223333444455556`                                  | The operator's service account client id (domain-wide delegation)                           |
| `gateway-reader@example.com`                             | The delegated administrator you name                                                        |
| `C0123abcd`                                              | Your Google Workspace customer id                                                           |
| `11111111-2222-3333-4444-555555555555`                   | The connection id                                                                           |

Related: [destination servers](../domains/destination-servers.md) (inbound delivery), [Microsoft 365](microsoft-365.md), operator documentation in [deployment](../deployment/provider-integrations.md) and the [runbook](../runbooks/provider-integrations.md).

## The example guide

The block below is generated from the guide generator of `@email-gateway/provider-integrations` (`exampleSetupGuideInput('google_workspace')`); a test fails when it no longer matches.

<!-- BEGIN GENERATED GUIDE (do not edit; see the note above) -->
<!-- prettier-ignore-start -->
## Google Workspace setup guide: Example Google Workspace

Generated 2026-11-18T00:00:00.000Z (`setup-guide/1`).
Tenant: Example Organization (`C0123abcd`).

> This guide contains the values of your own connection. The gateway never changes your Google Workspace configuration: you apply every step yourself. Confirmations you record in the console are your statements (attestations), not proofs the gateway has checked.

### Contents

1. [Overview and what the gateway will never do](#overview)
2. [Grant read-only access (domain-wide delegation)](#grant-access)
3. [Domains](#domains)
4. [Inbound mail](#inbound)
5. [Outbound mail](#outbound)
6. [Internal routing](#internal-routing)
7. [Validate and activate](#validate-activate)
8. [Failover and outages](#failover)
9. [Disconnect and clean up](#disconnect)

<a id="overview"></a>

### 1. Overview and what the gateway will never do

This guide connects Google Workspace to the email security gateway for the connection "Example Google Workspace". Inbound mail reaches the gateway first (your MX records), is inspected and then delivered to Google Workspace. Outbound and, optionally, internal mail is routed by Google Workspace to the gateway, inspected and delivered.

The gateway requests read-only access only: it reads your tenant identity and the verification state of your domains. It never reads or sends mail on your behalf, never reads users or mailboxes and never changes your Google Workspace configuration. Every change in Google Workspace below is made by you.

Changes on the gateway side (where the gateway delivers your mail, whether it accepts your outbound mail) are applied only after you review a preview and confirm it in the console.

<a id="grant-access"></a>

### 2. Grant read-only access (domain-wide delegation)

The gateway needs to read your customer id and your domains. Google Workspace grants this through domain-wide delegation of read-only Admin SDK scopes.

<a id="grant-delegation"></a>

#### 2.1 Authorize the gateway service account (recommended)

In the Google Admin console open Security → Access and data control → API controls → Manage domain-wide delegation → Add new. Enter the client ID and the scopes below (comma-separated) and authorize.

| Item | Value |
| --- | --- |
| Client ID | `111122223333444455556` |
| OAuth scopes | `https://www.googleapis.com/auth/admin.directory.customer.readonly,https://www.googleapis.com/auth/admin.directory.domain.readonly` |

<a id="grant-delegated-admin"></a>

#### 2.2 Name a delegated administrator

The service account reads the directory on behalf of an administrator of your domain. Use a dedicated administrator with a custom role that has only read access to domain settings and organization information, enter its address in the console and choose "I have authorized".

| Item | Value |
| --- | --- |
| Delegated administrator | `gateway-reader@example.com` |

<a id="domains"></a>

### 3. Domains

Each linked domain must be verified at the gateway (DNS TXT record) and verified in your Google Workspace tenant. The gateway's own verification is authoritative; the Google Workspace verification proves the domain belongs to this tenant.

<a id="domains-status"></a>

#### 3.1 Linked domains

| Item | Value |
| --- | --- |
| example.com | `gateway: active; Google Workspace: verified` |

<a id="inbound"></a>

### 4. Inbound mail

Inbound mail arrives at the gateway (MX), is inspected and is delivered to Gmail. Gmail is told that the gateway is your inbound gateway, so it evaluates the original sender.

<a id="inbound-mx"></a>

#### 4.1 Point your MX records to the gateway

At your DNS provider, replace the MX records of each linked domain with the gateway hosts below. Lower the TTL a day in advance to shorten the switch-over.

```dns
example.com. 3600 IN MX 10 mx1.gateway.example.net.
example.com. 3600 IN MX 20 mx2.gateway.example.net.
```

<a id="inbound-destination"></a>

#### 4.2 Gateway destination

In the console, apply the Google Workspace destination for each domain (preview, then confirm). The gateway delivers to the Google MX hosts in priority order.

| Item | Value |
| --- | --- |
| example.com | `aspmx.l.google.com (1), alt1.aspmx.l.google.com (5), alt2.aspmx.l.google.com (5), alt3.aspmx.l.google.com (10), alt4.aspmx.l.google.com (10)` |

<a id="inbound-gateway"></a>

#### 4.3 Configure the Gmail inbound gateway

In the Google Admin console open Apps → Google Workspace → Gmail → Spam, phishing and malware → Inbound gateway. Add the gateway addresses below and turn on "Require TLS for connections from the email gateways listed above".

| Item | Value |
| --- | --- |
| Gateway IP addresses | `192.0.2.0/28, 2001:db8::/64` |

> **Attestation `google.inbound_gateway_configured`** (your statement, not a gateway check): The Gmail inbound gateway lists the gateway addresses and requires TLS from them.
> Status: not confirmed yet

<a id="inbound-lockdown"></a>

#### 4.4 Reject mail that bypasses the gateway

In the same Inbound gateway setting turn on "Reject all mail not from gateway IPs", so senders cannot deliver to Google directly around inspection.

> **Attestation `google.reject_non_gateway_enabled`** (your statement, not a gateway check): Gmail rejects all mail that does not come from the gateway addresses.
> Status: not confirmed yet

<a id="outbound"></a>

### 5. Outbound mail

Gmail sends outbound mail to the gateway relay through a host and a routing rule. The gateway accepts it only with a fresh DKIM signature of your own domain.

<a id="outbound-dkim"></a>

#### 5.1 Turn on DKIM for each linked domain

In Apps → Google Workspace → Gmail → Authenticate email, generate a 2048-bit key for each domain below, publish the TXT record and choose "Start authentication".

| Item | Value |
| --- | --- |
| Domain | `example.com` |

<a id="outbound-spf"></a>

#### 5.2 Add the gateway to your SPF records

Keep your existing mechanisms and add the gateway include, so receivers accept mail the gateway relays for you. One SPF record per domain; at most 10 DNS lookups in total.

```dns
example.com. 3600 IN TXT "v=spf1 include:_spf.google.com include:spf.gateway.example.net ~all"
```

<a id="outbound-hosts"></a>

#### 5.3 Add the gateway as a host

In Apps → Google Workspace → Gmail → Hosts → Add route, name the route "Email security gateway", choose multiple hosts (or a single host if there is one), port 25, and turn on "Require mail to be transmitted via a secure (TLS) connection" and "Require CA signed certificate" with host name validation. Turn off "Perform MX lookup on host".

| Item | Value |
| --- | --- |
| Host | `relay1.gateway.example.net:25` |
| Host | `relay2.gateway.example.net:25` |

<a id="outbound-connector"></a>

#### 5.4 Route outbound mail through the gateway

In Apps → Google Workspace → Gmail → Routing → Configure, add a rule: messages to affect "Outbound" and "Internal - sending"; "Change route" to "Email security gateway". (Alternatively set the Outbound gateway under Spam, phishing and malware; a routing rule is preferred because it can also cover internal mail.)

> **Attestation `google.outbound_route_configured`** (your statement, not a gateway check): The host "Email security gateway" and the routing rule that sends outbound mail through it exist.
> Status: not confirmed yet

<a id="outbound-smtp-relay"></a>

#### 5.5 SMTP relay service for devices and applications

If devices or applications send through smtp-relay.gmail.com, open Routing → SMTP relay service and allow only addresses in your domains, require SMTP authentication and require TLS. Relayed mail then follows the same routing rule to the gateway.

> **Attestation `google.smtp_relay_configured`** (your statement, not a gateway check): The SMTP relay service requires authentication and TLS, so device and application mail follows the gateway route.
> Status: not confirmed yet

<a id="outbound-validate"></a>

#### 5.6 Send a probe message

Send any message from a user of a linked domain to the probe address. Start an outbound validation in the console to get a probe address.

<a id="internal-routing"></a>

### 6. Internal routing

The routing rule above includes "Internal - sending", so internal mail goes through the gateway. Mail returning from the gateway arrives through the inbound gateway as received mail and is not routed again; the gateway's hop limits stop any loop.

<a id="internal-rules"></a>

#### 6.1 Confirm internal sending is routed

Check that the routing rule affects "Internal - sending" messages.

> **Attestation `google.internal_routing_configured`** (your statement, not a gateway check): The gateway routing rule also applies to internal sending.
> Status: not confirmed yet

<a id="validate-activate"></a>

### 7. Validate and activate

Run a full validation in the console. It checks your access, the domains, MX and SPF records, the gateway destination (an SMTP connection without sending mail), the outbound probe and mail loops. What it cannot observe is listed as an attestation.

When every required check passes, activate outbound routing (and, if you want it, internal routing) in the console. Activation is a gateway-side change: review the preview and confirm it.

<a id="failover"></a>

### 8. Failover and outages

Every gateway relay host (relay1.gateway.example.net, relay2.gateway.example.net) is listed in your configuration, so mail moves to the next host when one is unavailable.

While the gateway is unreachable, Gmail queues outbound mail and retries for up to 5 days. This is the provider's documented behaviour, not a guarantee of the gateway.

The gateway delivers inbound mail to every destination host in priority order and retries deferred mail for up to 5 days.

The gateway never falls back to delivering around itself. An emergency bypass is a change you make on your side, and mail then leaves without inspection:

Emergency bypass: disable the routing rule (Apps → Google Workspace → Gmail → Routing). Re-enable it when the gateway is back.

<a id="disconnect"></a>

### 9. Disconnect and clean up

Disconnecting in the console stops the gateway relay for this customer and removes its access; the gateway keeps delivering inbound mail to Gmail until you change your MX records.

Before you disconnect: point the MX records back to Google, turn off "Reject all mail not from gateway IPs" and remove the inbound gateway, the routing rule and the host, then remove the domain-wide delegation entry.

<a id="disconnect-commands"></a>

#### 9.1 Restore the Google MX records

```dns
example.com. 3600 IN MX 1 aspmx.l.google.com.
example.com. 3600 IN MX 5 alt1.aspmx.l.google.com.
example.com. 3600 IN MX 5 alt2.aspmx.l.google.com.
example.com. 3600 IN MX 10 alt3.aspmx.l.google.com.
example.com. 3600 IN MX 10 alt4.aspmx.l.google.com.
```
<!-- prettier-ignore-end -->
<!-- END GENERATED GUIDE -->
