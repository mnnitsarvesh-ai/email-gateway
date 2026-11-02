# ADR-0017: DNS resolution for domain onboarding: a resolver port, system or DNS-over-HTTPS upstreams, a TTL-capped Redis cache, and definitive vs indeterminate outcomes

**Status:** Accepted

**Context.** Step 2.1 (domain onboarding) decides whether a customer owns a domain, whether its MX records point at the gateway, and whether its SPF, DKIM and DMARC records are correct. These decisions grant or change mail-path behaviour for a tenant: a verified domain becomes globally owned (`domains.verified_name`, ADR-0014) and is later used to resolve the tenant of inbound mail. DNS is unreliable in ordinary ways (timeouts, `SERVFAIL` from a broken authoritative server, network partitions, resolver rate limits), and a lookup failure must never be confused with a negative answer. The brief asks for DNS-over-HTTPS or reliable resolution with caching and timeouts, and forbids marking a domain verified because a lookup timed out. Tests must be deterministic and must not depend on public DNS.

**Decision.**

1. **A port, two adapters.** `apps/api/src/dns` defines an abstract `DnsResolver` with `resolveTxt(name)` and `resolveMx(name)`. Two adapters implement it:
   - `SystemDnsResolver`: `node:dns` `Resolver` instances (c-ares, no search list) with configurable upstream servers (`DNS_SERVERS`, empty = the host's resolvers, e.g. a local Unbound or the VPC resolver), a per-try timeout (`DNS_TIMEOUT_MS`) and a try count (`DNS_TRIES`).
   - `DohDnsResolver`: RFC 8484 **wire format** (`GET ?dns=<base64url>`, `application/dns-message`, message id 0) over `fetch` against `DNS_DOH_URL` (default `https://cloudflare-dns.com/dns-query`), with the same timeout and tries. The wire codec is `dns-packet`. `https` is required outside `APP_ENV=local|ci`.
     `DNS_RESOLVER_MODE=system|doh` selects the adapter. `DNS_PROPAGATION_UPSTREAMS` adds extra upstreams of the same kind (IPs for `system`, URLs for `doh`) used only to check MX propagation.
2. **Four outcomes, two classes.** Every query returns exactly one of `answer`, `nxdomain`, `nodata` (definitive) or `indeterminate` with a reason (`timeout`, `servfail`, `refused`, `network`, `malformed`, `other`). Mapping for `node:dns`: `ENOTFOUND` → `nxdomain`, `ENODATA` → `nodata`, `ETIMEOUT` → `timeout`, `ESERVFAIL` → `servfail`, `EREFUSED` → `refused`, `ECONNREFUSED`/`ECONNRESET`/`EADDRGETNETWORKPARAMS` → `network`, `EBADRESP`/`EFORMERR`/`EBADNAME` → `malformed`, anything else → `other`. For DoH: RCODE 3 → `nxdomain`; RCODE 0 without records of the asked type (after following a CNAME chain in the answer) → `nodata`; RCODE 2 → `servfail`; RCODE 5 → `refused`; other RCODEs, HTTP errors, wrong content type, oversize (> 64 KiB) or undecodable bodies → `indeterminate`.
3. **Indeterminate never decides.** Verification logic treats `indeterminate` as "unknown": the domain status and the stored per-record status stay as they were, the attempt is recorded as evidence (`last_outcome = indeterminate`), and a retry is scheduled with exponential backoff. Only a definitive answer can verify a domain, fail a record or expire nothing earlier than its deadline. Verification expiry is time-based, never failure-count-based, so an outage cannot fail a pending claim early.
4. **Cache.** `CachingDnsResolver` wraps each adapter and caches **definitive** results in Redis (`KeyValueStore`, key `dns:v1:<upstream hash>:<type>:<name>`). Positive TTL = min(answer TTL, `DNS_CACHE_MAX_TTL_SECONDS`, default 300); negative TTL = min(SOA minimum / negative TTL when known, `DNS_CACHE_NEGATIVE_TTL_SECONDS`, default 60). `node:dns` does not expose TTLs for TXT and MX, so system-mode answers use the negative-TTL value (≤ 60 s) as their TTL. `indeterminate` results are never cached. User-triggered verification bypasses cache reads (it still writes), so a record the customer just published is seen immediately. A cache read or write failure is logged and the lookup proceeds uncached (the cache is an optimisation, not a security control).
5. **Deterministic tests.** Tests start an in-process authoritative DNS server (UDP and TCP, `node:dgram`/`node:net` with `dns-packet`) that serves mutable test zones and can inject `SERVFAIL`, `REFUSED` and timeouts per name, plus an in-process DoH endpoint backed by the same zones. `SystemDnsResolver` is pointed at it with `DNS_SERVERS=127.0.0.1:<port>`. No test resolves public names.

**Alternatives considered.**

- _Only `node:dns` (system resolver):_ simplest and fast with a local caching resolver, but in containers it inherits whatever resolver the platform provides; some managed resolvers rewrite or filter answers. Kept as the default, with DoH as a configuration choice.
- _Only DoH against a public provider:_ independent of the platform resolver and returns TTLs, but adds an external dependency and a privacy consideration (customer domain names go to a third party). Available, not mandatory.
- _DoH JSON API (`application/dns-json`):_ not standardised (Google and Cloudflare differ) and not served by most self-hosted DoH servers. Rejected for RFC 8484 wire format.
- _Querying the domain's authoritative nameservers directly (iterative resolution):_ the most "fresh" view and a natural propagation check, but requires our own iterative resolver logic, does not work through DoH, and fails behind egress firewalls that only allow the platform resolver. Propagation is checked across configured upstreams instead.
- _A CoreDNS/dnsmasq container in Compose for tests:_ realistic, but another container in an 8 GB VM, fixed ports, and zone changes through files or reloads. The in-process server lets each test change records and inject failures instantly.
- _Treating repeated timeouts as "missing":_ rejected; it would let an outage (or an attacker who can disrupt resolution) fail or downgrade a legitimate domain.

**Consequences.**

- Redis holds short-lived DNS answers; flushing Redis only costs extra lookups.
- System mode cannot report real TTLs or SOA minima for TXT/MX; cache lifetimes there are bounded by the negative-TTL cap. DoH mode reports them.
- Operators choose the trust anchor: the platform resolver (system) or a DoH provider. DNSSEC validation is delegated to the chosen upstream; the gateway does not validate signatures itself (the DoH `AD` bit is recorded as evidence only).
- `dns-packet` becomes a runtime dependency of `api`.
- Every verification decision carries evidence (upstream, outcome, reason, answers, duration, cache hit) in `domain_dns_records.evidence` / `domain_verifications.evidence`, so support can explain why a domain is or is not verified.
