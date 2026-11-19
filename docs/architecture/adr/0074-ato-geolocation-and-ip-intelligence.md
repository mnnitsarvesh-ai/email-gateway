# ADR-0074: Geolocation and IP intelligence for account takeover detection

**Status:** Accepted (2026-11-18, after the step 8.4 local verification: the stack suites `ato-smtp`, `ato-policy`, `ato-portal`, `ato-resilience`, Playwright and the regression gate; record [docs/plan/steps/24-account-takeover-core.md](../../plan/steps/24-account-takeover-core.md) §13, §14; CI and a cluster apply not done; identity-provider adapters step 8.5). Proposed by the step 8.4 architect on 2026-11-16 (file created by WP1 on 2026-11-18; data source approved by the product owner on 2026-11-16). Supersedes nothing. Design: [docs/plan/steps/24-account-takeover-core.md](../../plan/steps/24-account-takeover-core.md) §7 (placeholder ADR-ATO-5 before numbering).

**Context.** Geographic rules need IP geolocation; the repository has no GeoIP database and cannot ship one (licensing). VPN, proxy and anonymizer indicators may be used only where reliable intelligence exists and never as proof alone. IP reputation and breach intelligence must not duplicate the platform's threat intelligence, which ATP-1 will extend (feeds, tenant indicators, confidence and trust).

**Decision.**

1. Operator-provided MaxMind databases (GeoLite2/GeoIP2 City and ASN, provided later by the operator; Anonymous IP optional) read in-process from mounted MMDB files, reloaded on change, refreshed by MaxMind's `geoipupdate` sidecar, never shipped or downloaded by the gateway; licence terms documented.
2. Honest degradation: without a database the dependent rules are unavailable and say so; nothing is inferred from other sources; stale databases are flagged and alerted; locations above the accuracy limit are country-only.
3. Anonymizer flags only from the Anonymous IP database, always weak signals.
4. Every IP reputation lookup goes through url-security's `ReputationService` from one adapter in the ato-worker (platform threat feed, optional ATO DNSBL zones of exploited hosts only) with a namespaced cache; rules consume a normalized result with an optional confidence; tenant trusted and blocked networks in settings. ATP-1 extends `ReputationService` (feeds, tenant indicators, confidence and trust gating) without changes to ATO rules, tables or events.
5. Breach intelligence from platform `email` threat indicators loaded by an operator importer restricted to tenant domains; no third-party breach API.
6. Tests use a deterministic synthetic database over documentation ranges, allowed only in local and CI environments.

**Alternatives considered.** Shipping GeoLite2 in images (licence forbids redistribution and requires updates). A free IP-to-country CSV (less accurate, no ASN or accuracy radius, still needs updates). Online geolocation APIs (sends user IPs to a third party, latency). Tor exit lists as threat intelligence (conflates privacy tools with attacks). Querying third-party breach APIs (sends tenant addresses out). Reading `threat_indicators` directly for IPs (bypasses ATP-1's trust model).

**Consequences.** Geographic detection depends on the operator's MaxMind licence and update job; without it the product shows unavailable states; anonymizer detection needs a commercial database.
