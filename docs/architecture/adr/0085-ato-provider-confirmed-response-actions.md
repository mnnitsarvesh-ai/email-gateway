# ADR-0085: ATO provider-confirmed response actions

**Status:** Accepted (2026-11-20, after the step 8.5 local verification against the provider simulators: the stack suite `ato-idp` 7/7 on the live api, ato-worker, integration-worker, provider-fake and idp-simulator, the library, worker, api, notification and 8.2 integration suites, the 8.4 contract kit for both adapters, Playwright `ato-providers.spec.ts` 5/5 with the ATO, incident, provider-connection and navigation specs; record [docs/plan/steps/26-ato-provider-adapters.md](../../plan/steps/26-ato-provider-adapters.md) §16 WP6, §17; live verification against real Microsoft and Google tenants (PQ7), CI and a cluster apply not done). Proposed by the step 8.5 architect on 2026-11-17. Design: [docs/plan/steps/26-ato-provider-adapters.md](../../plan/steps/26-ato-provider-adapters.md). Amends ADR-0072 (8.4 response safeguards: "provider-dependent" rollback is made precise per action and provider). Supersedes nothing.

**Context.** Brief §7: approvals, idempotency, rollback and recovery, recorded actions, and never claiming success without provider confirmation. Provider APIs differ: some effects are immediate, some are visible only on read-back, some cannot be undone, some are not available through any supported API.

**Decision.**

1. The 8.4 state machine, approvals and automation rules are unchanged; adapters implement `execute`, `confirm` and `rollback` per the action matrix.
2. Confirmation is a provider `2xx` for immediate effects and a read-back showing the requested state for state changes; a confirmation timeout ends `failed` with `unconfirmed`, never `succeeded`.
3. Before its first write an adapter records the provider pre-state; a repeated execution with the same key only confirms; rollback restores only what the gateway changed (never re-enables an account, removes a membership or restores an organizational unit that was already in the target state).
4. MFA enforcement uses only tenant-designated controls (an Entra group targeted by the tenant's Conditional Access policy; a Google organizational unit with 2-Step Verification enforced); the gateway never edits tenant security policies.
5. Actions with no supported API are `unsupported` with a reason and manual guidance (for example Microsoft 365 mailbox-level forwarding).
6. Actions apply only to mailbox accounts with exactly one matching integration.

**Alternatives considered.** Treating `2xx` as confirmation everywhere (eventual consistency; some writes are queued). Creating Conditional Access policies or 2SV settings (changes tenant security posture beyond the incident). Exchange Online PowerShell for mailbox forwarding (unsupported runtime and credentials). Deleting inbox rules by default (destroys evidence; disable is reversible).

**Consequences.** Some actions stay `executing` for minutes; a few cannot be rolled back; tenants must prepare an MFA group or organizational unit to use `require_mfa`.
