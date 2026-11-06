# Where the gateway delivers your mail: destination servers

Once your domain is active and its MX records point at the gateway, the gateway receives your inbound mail, inspects it, and delivers the clean messages to **your own mail servers**: your destination servers. This guide explains how to configure them for any mail server, and step by step for Microsoft 365 and Google Workspace. It also covers mail between your own domains and mail you send out through the gateway.

Throughout this guide, `example.com` stands for your domain and `gateway.example.net` for the gateway's own host names (MX hosts and the outbound host `out.gateway.example.net`). Always copy the exact values shown for your deployment in the admin portal. Setting up the domain itself (ownership, activation, MX, SPF, DKIM, DMARC) is described in [Adding your domain](onboarding.md).

## How delivery works

- **Inbound** (mail from the internet to `you@example.com`): the gateway delivers to the destination servers of `example.com`. Senders outside your organization never get delivery reports from the gateway (no backscatter); you see each recipient's status in the portal.
- **Between your own domains** (mail you send through the gateway to another domain of your organization): it never leaves for the internet. The gateway delivers it straight to that domain's destination servers, under your organization's internal policies. A failure is reported to the sender.
- **Outbound** (mail you send to anyone else, including other organizations that use this gateway): delivered to the recipient domain's public MX records, DKIM-signed for your domain. A failure is reported to the sender.
- Every recipient has its own delivery status: `queued`, `deferred` (the receiving server asked to try later or was unreachable; the gateway keeps retrying for up to 5 days), `delivered` (the receiving server accepted it with a 2xx reply), `bounced` (permanently refused), `expired` (not deliverable within 5 days), `failed` or `suppressed` (stopped by the gateway, with a reason). It is shown in the portal and returned by `GET /api/v1/messages/{messageId}/deliveries`.

## Configuring destination servers

You manage a domain's destination servers in the portal (domain → **Delivery**) or with the API. Changing where mail is delivered redirects **all** mail of the domain, so it needs the permission **`domain:routing_manage`** (granted to the _domain administrator_ and _organization administrator_ roles). Anyone with `domain:read` can view the configuration.

```http
PUT /api/v1/domains/{id}/destinations
```

The request replaces the whole configuration of the domain at once (`GET` shows it, `DELETE` removes it). It has three forms, one per provider; a domain uses one provider at a time.

### Custom servers (any mail server)

```json
{
  "provider": "custom",
  "servers": [
    { "host": "mx1.mail.example.com", "port": 25, "priority": 10, "tlsMode": "verify" },
    { "host": "mx2.mail.example.com", "port": 25, "priority": 20, "tlsMode": "verify" }
  ]
}
```

| Field            | Default         | Meaning                                                                          |
| ---------------- | --------------- | -------------------------------------------------------------------------------- |
| `host`           | (required)      | Host name or public IP address of your server                                    |
| `port`           | `25`            | SMTP port, 1–65535                                                               |
| `priority`       | `10`            | Lower is tried first (like MX preferences)                                       |
| `tlsMode`        | `opportunistic` | See [TLS modes](#tls-modes)                                                      |
| `tlsVerifyNames` | the host name   | Only for `verify`: the certificate names to accept, separated by `:` (see below) |

**Priority and failover.** For every delivery attempt the gateway tries your servers in priority order and moves to the next one when a server cannot be reached or answers with a temporary error; servers with the same priority are tried in the order they were added. Up to 10 servers per domain (the deployment may set a different limit). If every server fails, the message waits and is retried (after about 5, 10, 20, 40 minutes, then about hourly) for up to 5 days. A permanent refusal (5xx) from your server is final for that recipient: `bounced`.

#### TLS modes

| `tlsMode`       | Behaviour                                                                                                                                                                                                                           |
| --------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `none`          | Plain SMTP, never encrypted. Only for servers that cannot do TLS                                                                                                                                                                    |
| `opportunistic` | Encrypted when your server offers STARTTLS, without checking its certificate; plain otherwise                                                                                                                                       |
| `required`      | TLS 1.2 or newer is mandatory, the certificate is not checked. Without TLS the message waits (`deferred`)                                                                                                                           |
| `verify`        | TLS 1.2 or newer **and** a certificate from a public certificate authority whose name matches. Recommended. A certificate that does not match or has expired makes the message wait (`deferred`, "Server certificate not verified") |

Several servers of one domain may use different TLS modes; each server is checked with its own mode.

**Verify names** (`tlsVerifyNames`, `verify` only). Without a value the certificate must be valid for the host name itself. To accept other names, list them separated by `:`. `nexthop` stands for the host name; a name starting with a dot accepts every subdomain:

```
nexthop:mail.example.com:.mail.example.com
```

Wildcard certificates (`*.mail.example.com`) match one level of subdomains of their name.

#### Host names the gateway refuses

The gateway checks every server when you save it and again before every delivery. It refuses (HTTP `422`, with a reason):

| Reason                          | Examples                                                                                                                                                                                                                                                                                       |
| ------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `ip_not_public`                 | IP addresses that are not reachable on the internet: private (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`), loopback, link-local, shared (`100.64.0.0/10`), documentation, multicast, IPv6 unique-local. Dedicated deployments can allow private addresses for servers in your own network |
| `metadata_address`              | Cloud metadata addresses such as `169.254.169.254` (always refused)                                                                                                                                                                                                                            |
| `single_label`                  | Names without a dot, for example `exchange` or `mailserver`                                                                                                                                                                                                                                    |
| `internal_suffix`               | Names under `.local`, `.localhost`, `.localdomain`, `.internal`, `.intranet`, `.lan`, `.home.arpa`, `.svc`, `.cluster.local`, `.consul` (and suffixes your deployment adds)                                                                                                                    |
| `gateway_host`                  | The gateway's own host names: mail would loop                                                                                                                                                                                                                                                  |
| `invalid_host`                  | Malformed names, labels longer than 63 characters                                                                                                                                                                                                                                              |
| `port_not_allowed`              | A port outside 1–65535, or another port than the provider's                                                                                                                                                                                                                                    |
| `host_not_allowed_for_provider` | A host that does not belong to the chosen provider (presets below)                                                                                                                                                                                                                             |

Use a name that resolves to a public address of your server. The gateway does not deliver to internal addresses even if a public name resolves to one: such deliveries time out and stay `deferred`.

**Allow the gateway in.** Your servers must accept SMTP on the configured port from the gateway's outbound IP addresses (shown in the portal; they are the addresses in the gateway's SPF include). Restrict your server to those addresses, or better, require TLS and accept only the gateway's certificate, so nobody can bypass the gateway.

## Microsoft 365

Exchange Online accepts the gateway's deliveries through an **inbound connector**.

### 1. Find your Microsoft 365 host

In the Microsoft 365 admin center, go to **Settings → Domains → example.com → DNS records**. The **MX** record shows a "points to address" like `example-com.mail.protection.outlook.com`: dots of your domain become dashes, and Microsoft may add a suffix. Copy it exactly; it cannot be derived. (Newer tenants may show a host under `mx.microsoft`, for example `example-com.a-v1.mx.microsoft`; it is accepted too.)

### 2. Configure the gateway

```json
{ "provider": "microsoft_365", "host": "example-com.mail.protection.outlook.com" }
```

The preset always uses port 25 and `verify` with the names `nexthop:mail.protection.outlook.com:.mail.protection.outlook.com` (it cannot be lowered). One host per domain: Microsoft balances behind it. Hosts outside `*.mail.protection.outlook.com` and `*.mx.microsoft` are refused (`host_not_allowed_for_provider`).

### 3. Create the inbound connector in Exchange Online

In the **Exchange admin center → Mail flow → Connectors → Add a connector**:

1. **From:** Partner organization. **To:** Office 365.
2. Name it, for example "Email security gateway".
3. **Authenticating sent email:** either "By verifying that the IP address of the sending server matches one of these IP addresses" with the gateway's outbound IP addresses, or "By verifying that the subject name on the certificate … matches this domain name" with the gateway's outbound host name (`out.gateway.example.net`). The certificate option survives IP changes.
4. **Security restrictions:** "Reject email messages if they aren't sent over TLS" (and, with the certificate option, "and require that the subject name … matches").
5. Save and validate the connector.

Then turn on **Enhanced Filtering for Connectors** (Microsoft Defender portal → Email & collaboration → Policies → Threat policies → Enhanced filtering): select the connector and "Automatically detect and skip the last IP address". Microsoft's own filtering then sees the original sender's address instead of the gateway's, so SPF, DMARC and reputation keep working.

Mail that reaches Microsoft directly (anyone can connect to your `*.mail.protection.outlook.com` host, whatever your MX says) bypasses the gateway. Lock it down with a **mail flow (transport) rule** that rejects or quarantines messages from outside your organization that were not received from the gateway's IP addresses, following Microsoft's guidance for third-party filtering services.

### 4. Optional: send outbound mail through the gateway

The gateway accepts mail from your organization only through an **SMTP connector** of your organization that proves who is sending: **SMTP AUTH** on the submission port, or a **client certificate** that only you hold. It never trusts a sending IP address that other customers share.

That is a limitation with Exchange Online today: its connectors cannot use SMTP AUTH, and towards partner servers it identifies itself with Microsoft's certificate (subject `mail.protection.outlook.com`), which is the same for every Microsoft 365 customer, and from shared Microsoft IP ranges. A connector based on that certificate or those addresses would let any Microsoft 365 customer send as your domain. **Do not route Exchange Online's outbound mail to the gateway with such a connector.** Options:

- Send outbound mail from systems that can authenticate (applications, devices, an on-premises or hybrid Exchange server with its own certificate) through an SMTP connector with SMTP AUTH or your own client certificate.
- Keep Microsoft 365's outbound mail on Microsoft and use the gateway for inbound protection. Mail between your domains is then delivered by Microsoft as well.

Contact support if you need Exchange Online outbound through the gateway; it requires a sender proof that is unique to your organization.

## Google Workspace

Gmail accepts the gateway as an **inbound gateway**.

### 1. Configure the gateway

```json
{ "provider": "google_workspace" }
```

The gateway uses Google's published MX hosts with their priorities: `aspmx.l.google.com` (1), `alt1.aspmx.l.google.com` and `alt2.aspmx.l.google.com` (5), `alt3.aspmx.l.google.com` and `alt4.aspmx.l.google.com` (10), all on port 25 with `verify` and the names `nexthop:mx.google.com:.aspmx.l.google.com` (cannot be lowered). When the first host is unreachable the next ones are tried. Other hosts are refused (`host_not_allowed_for_provider`).

### 2. Set up the inbound gateway in Gmail

In the **Google Admin console → Apps → Google Workspace → Gmail → Spam, Phishing and Malware → Inbound gateway → Configure**:

1. **Gateway IPs:** add the gateway's outbound IP addresses (from the portal).
2. Tick **Reject all mail not from gateway IPs**, so nobody bypasses the gateway by connecting to Google directly.
3. Tick **Require TLS for connections from the email gateways listed above**.
4. Leave "Message is considered spam if the following header regexp matches" empty unless the gateway is configured to add a spam header for you.
5. Save. Changes can take up to an hour.

### 3. Optional: send outbound mail through the gateway

Gmail can route outgoing mail to another server (**Apps → Google Workspace → Gmail → Routing**, or the **Outbound gateway** setting). Point it at the gateway's submission host and port shown in the portal and require TLS. The gateway accepts it only through an **SMTP connector** of your organization that authenticates with **SMTP AUTH** (or a client certificate unique to your organization). Check that your Gmail routing option can authenticate that way: a route identified only by Google's sending IP addresses is refused, because those addresses are shared by all Google customers and would let anyone send as your domain. If your edition cannot authenticate the route, keep outbound mail on Google and use the gateway for inbound protection.

## Link protection rewrites messages: trust the gateway

With link protection on (the default for inbound mail; settings `rewrite.*` of the URL engine), the gateway replaces the links of a message with protected links (`https://protect.<gateway domain>/c/…`) that are checked again when someone clicks. **Rewriting changes the message body**, so a DKIM signature the original sender added **no longer verifies** at your mailbox platform. The gateway already checked SPF, DKIM, DMARC and ARC when it received the message (shown with the scan results); your mailbox platform has to rely on that:

- **Microsoft 365:** the inbound connector and **Enhanced Filtering for Connectors** above are required (Microsoft then evaluates the original sender's address; without it, rewritten mail from DMARC `p=reject` domains can be junked or rejected). Also exclude the gateway from Microsoft's own link rewriting if you do not want two rewrites (Defender Safe Links), or accept that Safe Links wraps the gateway's links.
- **Google Workspace:** the **inbound gateway** with "Reject all mail not from gateway IPs" above is required; Gmail then treats the gateway as the edge and does not fail DMARC on the changed body.
- **Other servers:** configure your server to accept the gateway as a trusted relay (skip DKIM/DMARC re-evaluation for mail from the gateway's outbound addresses, or honour the gateway's `Authentication-Results`).

If you cannot configure trust, ask your administrator to set `rewrite.dkimSignedPolicy` to `skip` (DKIM-signed messages are then delivered without rewriting) or to switch rewriting off for your organization. Messages that are **S/MIME or PGP signed or encrypted are never rewritten** (changing them would break the signature); their links are still scanned. The gateway does not add an ARC seal to rewritten mail yet.

## Mail between your own domains

When someone in your organization sends through the gateway to another active domain of your organization, the message is delivered to that domain's destination servers: Microsoft 365 or Google Workspace hosts, or your own servers. Configure destinations for every domain that receives mail, otherwise such mail waits (`deferred`, "Destination not configured") until a destination exists or 5 days have passed.

Recipients in domains of **other** organizations that also use this gateway are delivered through their public MX, like any internet recipient, so each organization's own policies apply.

## Troubleshooting

| Symptom (portal or API)                                          | What it means                                                                                                                                 | What to do                                                                                                                      |
| ---------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------- |
| `deferred`, error class `connect` or `timeout`                   | Your server could not be reached on the configured port, or did not answer                                                                    | Check that the host resolves to a public address, the port is open for the gateway's IP addresses, the server runs              |
| `deferred`, error class `tls`, "Server certificate not verified" | `verify`: the certificate does not match the host or verify names, is self-signed or expired. `required`: your server does not offer STARTTLS | Install a certificate from a public CA for the host name, or list the certificate's names in `tlsVerifyNames`                   |
| `deferred`, error class `no_destination`                         | The domain has no destination server                                                                                                          | Configure destinations (`PUT /api/v1/domains/{id}/destinations`)                                                                |
| `deferred`, error class `remote_4xx`                             | Your server asked to try later (greylisting, a rate limit, a busy mailbox, or a provider that does not yet accept the gateway)                | Check your inbound connector (Microsoft 365) or inbound gateway IPs (Google Workspace); the reply text is shown with the status |
| `bounced`                                                        | Your server refused the recipient permanently (for example an unknown mailbox)                                                                | Check the address; the reply text of your server is shown with the status                                                       |
| `422` when saving                                                | The host is refused ([reasons](#host-names-the-gateway-refuses))                                                                              | Use a public host name of your server                                                                                           |
