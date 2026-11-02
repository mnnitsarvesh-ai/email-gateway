# Adding your domain to the email gateway

This guide walks you through connecting a domain (for example `example.com`) to the email security gateway: proving that you own it, turning protection on, and pointing your mail at the gateway. It also explains each DNS record we ask you to publish and what to do when a check does not pass.

Throughout this guide, `example.com` stands for your domain and `gateway.example.net` for the gateway's own host names. Always copy the exact values shown for your domain in the admin portal or returned by the API (`GET /api/v1/domains/{id}/dns-records`): host names, selectors and tokens are unique to your domain and deployment.

## The order matters: verify → activate → switch MX

1. **Add the domain.** You receive a list of DNS records to publish.
2. **Prove ownership.** Publish the verification TXT record. We check automatically, or you can ask for a check at any time (`POST /api/v1/domains/{id}/verify`). Once the record is found, the domain is **verified**.
3. **Activate.** Turn the domain on (`PATCH /api/v1/domains/{id}/status` with `{"status": "active"}`). From this moment the gateway accepts mail for the domain.
4. **Switch your MX records** to the gateway and remove your old MX records.
5. **Publish SPF, DKIM and DMARC** so that mail the gateway sends on your behalf is trusted by receivers.

Activate **before** you change MX. DNS changes reach different parts of the internet at different times; if mail arrived at the gateway before the domain was active, it would be refused. Activation only requires ownership, not the MX change.

The status view (`GET /api/v1/domains/{id}/status`) tells you where you are: `readyForActivation` is true once ownership is verified, and `mailFlowReady` is true once the domain is active and its MX records point at the gateway.

## Domain names you can add

- Use the name as you see it, for example `example.com` or `Bücher.example`. International names are accepted and stored in their ASCII form (`xn--bcher-kva.example`); a trailing dot is ignored and letters are not case-sensitive.
- Subdomains such as `mail.example.com` are separate domains with their own ownership proof.
- Names that cannot receive internet mail (for example `localhost` or names ending in `.local` or `.internal`) and the gateway's own host names are refused.
- Your plan sets how many domains you can have; deleted domains do not count.
- A name that another organization has already verified cannot be added. If you believe you own it, contact support (see [If someone else owns your domain](#if-someone-else-owns-your-domain)).

## The records

Each record in the list has a **requirement**:

| Requirement   | Meaning                                                           |
| ------------- | ----------------------------------------------------------------- |
| `activation`  | Needed before you can activate the domain (the ownership record)  |
| `inbound`     | Needed for mail to reach the gateway (MX)                         |
| `outbound`    | Needed before mail can be sent through the gateway (SPF and DKIM) |
| `recommended` | Strongly recommended for deliverability and anti-spoofing (DMARC) |

The `name` column is relative to your domain: `@` means the domain itself (`example.com`), `_dmarc` means `_dmarc.example.com`. Some DNS providers want the relative name, others the full host name (`host`); both are shown.

### 1. Ownership (TXT)

| Type | Name                   | Value                                                           |
| ---- | ---------------------- | --------------------------------------------------------------- |
| TXT  | `_emailgateway-verify` | `emailgateway-verification=3f9c0e…` (40 hexadecimal characters) |

- Publish it at `_emailgateway-verify.example.com` exactly as shown, without extra spaces. Quotes added by your DNS provider are fine.
- Other TXT values at the same name do not interfere (for example, another provider's token).
- **Keep the record after verification.** We keep checking it; if it disappears we warn you (your domain stays active, but please restore it).
- A verification is valid for 7 days from the moment you add the domain (or restart verification). If ownership is not proven by then, the domain becomes **failed** with the reason `verification_expired`. Ask for a new check (`POST /verify`) to restart: the same token keeps working, so a record you already published still counts.

### 2. MX (inbound mail)

| Type | Name | Priority | Value                     |
| ---- | ---- | -------- | ------------------------- |
| MX   | `@`  | 10       | `mx1.gateway.example.net` |
| MX   | `@`  | 20       | `mx2.gateway.example.net` |

- Publish every MX record listed, with the priorities shown, **after activating the domain**.
- **Remove every other MX record.** As long as an old MX record remains, senders can deliver straight to your old server and bypass the gateway; the MX check stays `invalid` with the warning `mx_non_gateway_hosts` (and `mx_gateway_bypass_possible` when the gateway's records are there too).
- After the change, the check also asks other DNS resolvers. While they still see your old records the MX check is `invalid` with `mx_not_propagated`; this clears by itself as DNS caches expire (usually within your old records' TTL).

### 3. SPF (TXT at the domain itself)

| Type | Name | Value                                          |
| ---- | ---- | ---------------------------------------------- |
| TXT  | `@`  | `v=spf1 include:_spf.gateway.example.net ~all` |

A domain must have **exactly one** SPF record (a TXT value starting with `v=spf1`). Two SPF records make receivers reject the SPF check for all your mail (warning `spf_multiple_records`).

- **If you have no SPF record**, publish the value above.
- **If you already have one, merge** the gateway's include into it instead of adding a second record. We show the merged value for you. For example, if you have

  ```
  v=spf1 include:_spf.other-provider.example -all
  ```

  replace it with

  ```
  v=spf1 include:_spf.gateway.example.net include:_spf.other-provider.example -all
  ```

  Keep everything else, including your existing ending (`-all`, `~all` or `redirect=`).

- **The 10-lookup limit.** Receivers stop evaluating SPF after 10 DNS lookups (each `include:`, `a`, `mx`, `ptr`, `exists` and `redirect=` counts, including those inside the records you include). We count them for you (`spf.lookupCount` in the status view). Above 10 the check is `invalid` with `spf_lookup_limit_exceeded`: remove includes you no longer use, or replace `a`/`mx` mechanisms with `ip4:`/`ip6:` ranges. If one of your includes could not be looked up, the count is a lower bound (`spf_lookup_count_unknown`).
- Other warnings: `spf_plus_all` (`+all` lets anyone send as you; use `~all` or `-all`), `spf_ptr_mechanism` (`ptr` is deprecated and slow), `spf_record_too_long` (keep the record short; split it with includes), `spf_syntax_error:<term>` (a term we could not parse).

### 4. DKIM (TXT per selector)

| Type | Name                         | Value                                     |
| ---- | ---------------------------- | ----------------------------------------- |
| TXT  | `egr20261102k3f9._domainkey` | `v=DKIM1; k=rsa; p=MIIBIjANBgkqhkiG9w0B…` |

- The selector (`egr20261102k3f9` above) is unique to your domain. Copy the whole value; an RSA key is about 400 characters long.
- **Long values.** A single DNS text string can hold at most 255 characters, so a DKIM value must be split into several strings **inside the same TXT record**. Most DNS providers do this automatically when you paste the full value. If yours asks you to split it yourself, enter it as consecutive quoted strings with no separator, for example `"v=DKIM1; k=rsa; p=MIIBIjANBg…first part…" "…rest of the key…"`. Do not create two separate TXT records, and do not add spaces inside the key.
- If you asked for an Ed25519 key as well, you get a second selector (`ege…`) with `k=ed25519`; publish both.
- A key becomes **active** once its record is found and your ownership is verified.
- Warnings: `dkim_public_key_mismatch` (the published key is different: re-copy the value), `dkim_key_revoked_in_dns` (the record has an empty `p=`), `dkim_testing_mode` (`t=y` asks receivers to treat failures leniently; remove it once things work).

#### Rotating DKIM keys

Rotate a key when your security policy requires it or if you suspect it was exposed (`POST /api/v1/domains/{id}/dkim/rotate`, permission `domain:dkim_rotate`):

1. A new key with a new selector is created; its record is in the response and in the record list.
2. Publish the new record **next to** the old one (different names, so both can exist).
3. Once the new record is found, the new key becomes active and the old one enters an overlap period (7 days by default) during which it stays valid, so mail signed with it that is still on its way verifies.
4. After the overlap, the old key is retired and listed under `cleanup` in `GET /dns-records`: you can then delete its TXT record.

Only one rotation per key type can be in progress; rotate again after the new key is active. If you rotate before ever publishing the first key, it is simply replaced. A domain can be rotated at most 10 times per 24 hours (`429` with `Retry-After`).

### 5. DMARC (TXT at `_dmarc`)

| Type | Name     | Value                                                                  |
| ---- | -------- | ---------------------------------------------------------------------- |
| TXT  | `_dmarc` | `v=DMARC1; p=none; fo=1; rua=mailto:dmarc-reports@gateway.example.net` |

DMARC tells receivers what to do with mail that fails SPF and DKIM alignment, and where to send reports. Tighten it in steps; the status view shows your current stage (`dmarc.stage`), the next recommended record (`dmarc.recommendedValue`) and what to check first (`dmarc.nextStep`):

| Stage        | Policy         | Before moving on                                                                                      |
| ------------ | -------------- | ----------------------------------------------------------------------------------------------------- |
| `missing`    | none published | Publish `p=none` (monitoring only) with a report address                                              |
| `none`       | `p=none`       | Read the aggregate reports for a few weeks; make sure every legitimate sender passes SPF or DKIM      |
| `quarantine` | `p=quarantine` | Optionally start with `pct=25` and raise it to 100; then check that no legitimate mail is quarantined |
| `reject`     | `p=reject`     | Final stage: spoofed mail is refused                                                                  |

- **Report addresses.** `rua=` receives daily aggregate reports. We keep any addresses you already have and add the gateway's report mailbox when your deployment provides one; without one we suggest `mailto:dmarc-reports@example.com`. Several addresses are separated by commas.
- **Reports to another domain.** When a report address is in a different domain from yours (for example the gateway's mailbox), that receiving domain must authorize it with a record such as `example.com._report._dmarc.gateway.example.net TXT "v=DMARC1"`, otherwise receivers skip it (RFC 7489 §7.1). For the gateway's own report mailbox the gateway operator publishes this; for any other external address, ask its owner. The warning `dmarc_external_rua_needs_authorization` reminds you of this.
- Other warnings: `dmarc_policy_none` (monitoring only), `dmarc_pct_partial` (the policy applies to part of your mail), `dmarc_no_rua` (no reports), `dmarc_multiple_records` (keep exactly one), `dmarc_syntax_error`.
- DMARC never blocks activation.

## How checks work

- **When.** After you add a domain, the first check runs about a minute later. Until ownership is verified, checks repeat at growing intervals (1, 2, 4, 8 … minutes, then hourly) until the 7-day deadline. Afterwards, every record is checked every 30 minutes while something is not correct, and daily once everything is. `POST /verify` checks immediately (up to 6 times per minute per domain) and bypasses any cached DNS answer.
- **Record status.** `valid` (correct), `invalid` (present but wrong), `missing` (not published), `pending` (not checked yet). A record is `missing` both when the name does not exist and when it exists without a record of that type.
- **When DNS does not answer.** Sometimes a lookup gets no reliable answer: your DNS provider times out, returns a server error, or the network is disrupted. We record this as `lastOutcome: "indeterminate"` with the reason in `lastError` (for example `timeout: …` or `servfail: …`). **An indeterminate result never changes anything**: the domain keeps its status, each record keeps its last known status, and nothing is verified or failed because of it. The check is retried automatically with increasing delays (`checkFailures` counts consecutive attempts; `nextCheckAt` shows the next one). It is not an error on your side unless it persists, in which case check that your DNS provider's servers answer for the record's host.
- **After verification, DNS changes never switch your domain off.** If a record breaks later, its status and warnings change and you see it in the status view, but your domain stays active.

## Managing the domain

| Action   | Request                                                             | Allowed from                    |
| -------- | ------------------------------------------------------------------- | ------------------------------- |
| Activate | `PATCH /domains/{id}/status {"status": "active"}`                   | `verified`, `suspended`         |
| Suspend  | `PATCH /domains/{id}/status {"status": "suspended", "reason": "…"}` | `active` (a reason is required) |
| Delete   | `DELETE /domains/{id}`                                              | any status except `active`      |

- Suspending stops the gateway from accepting mail for the domain; resume by activating again.
- To delete an active domain, suspend it first (a safeguard against cutting off mail by mistake). Deleting revokes the domain's DKIM keys and releases the name; you can add it again later, and you will need to verify it again.
- Adding, verifying, activating, suspending and deleting need the `domain:manage` permission (Organization Admin and Domain Admin roles); reading needs `domain:read`; rotating DKIM keys needs `domain:dkim_rotate`.

## Troubleshooting

| What you see                                                 | What it means and what to do                                                                                                                                                                                                              |
| ------------------------------------------------------------ | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Status `pending_verification`, ownership `missing`           | The verification TXT is not visible yet. Check the name (`_emailgateway-verify.example.com`, not `_emailgateway-verify.example.com.example.com`, a common provider mistake) and wait for your provider to publish it, then `POST /verify` |
| Ownership `invalid`                                          | A TXT exists at the name but not with your token. Re-copy the value from the record list                                                                                                                                                  |
| `lastOutcome: indeterminate`                                 | DNS gave no reliable answer; nothing changed and a retry is scheduled (see above). If it persists for hours, ask your DNS provider whether their servers answer for that host                                                             |
| Status `failed`, reason `verification_expired`               | The 7-day window passed. Publish the record and call `POST /verify`: verification restarts with the same token                                                                                                                            |
| Status `failed`, reason `claimed_by_another_organization`    | Another organization proved ownership of this name first. See below                                                                                                                                                                       |
| `409 Domain is already registered with another organization` | The name is owned by another organization on this platform. See below                                                                                                                                                                     |
| `409 Organization limit reached: max_domains`                | Your plan's domain limit is reached; delete unused domains or contact your provider                                                                                                                                                       |
| `409 Domain is pending_verification` when activating         | Ownership is not verified yet                                                                                                                                                                                                             |
| `409 Suspend the domain before deleting it`                  | Suspend first, then delete                                                                                                                                                                                                                |
| `429` on `POST /verify`                                      | More than 6 checks in a minute; wait the number of seconds in `Retry-After`                                                                                                                                                               |
| `429` on `POST /dkim/rotate`                                 | More than 10 rotations of the domain in 24 hours; wait the number of seconds in `Retry-After`                                                                                                                                             |
| `400 … (too_long)` when adding                               | The name is longer than 226 characters: its DKIM record name would exceed the 253-character DNS limit                                                                                                                                     |
| `409 Verification already in progress`                       | A check is running; try again in a few seconds                                                                                                                                                                                            |
| MX `invalid` with `mx_non_gateway_hosts`                     | Remove the MX records that do not point at the gateway                                                                                                                                                                                    |
| MX `invalid` with `mx_not_propagated`                        | Your change has not reached every resolver yet; wait for the old records' TTL                                                                                                                                                             |
| MX warning `mx_propagation_unknown:…`                        | One of the extra resolvers did not answer; this is informational                                                                                                                                                                          |
| SPF `invalid` with `spf_multiple_records`                    | Merge them into one record                                                                                                                                                                                                                |
| SPF `invalid` without warnings                               | Your SPF record does not include the gateway yet; publish the merged value shown                                                                                                                                                          |
| SPF `invalid` with `spf_lookup_limit_exceeded`               | Reduce the number of lookups (see SPF above)                                                                                                                                                                                              |
| DKIM `invalid` with `dkim_public_key_mismatch`               | The value was truncated or altered (often by a provider that needs the value split into 255-character strings); paste it again                                                                                                            |
| DKIM key stays `pending` with the record `valid`             | The key activates after ownership is verified                                                                                                                                                                                             |
| Ownership record later `missing` on an active domain         | You removed the verification TXT; please restore it. Your domain stays active                                                                                                                                                             |

### If someone else owns your domain

Ownership goes to the first organization that proves it with the TXT record. If another organization on the platform holds your domain (for example a previous owner, or a test account), contact the gateway's support with proof of ownership. The platform operator can release the name after investigation; you then add and verify it as usual.
