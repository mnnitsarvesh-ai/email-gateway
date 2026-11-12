import type { UsageResponse } from '../organizations/services/organization-usage.service';

/** Explicit OpenAPI example of `GET /usage` (step 6.1 D14); illustrative values only. */
export const USAGE_EXAMPLE: UsageResponse = {
  organizationId: '01930c2e-7d1a-7000-8000-000000000001',
  period: { from: '2026-10-13T10:00:00.000Z', to: '2026-11-12T10:00:00.000Z' },
  users: { total: 42, active: 38, invited: 3, disabled: 1, locked: 0 },
  domains: { total: 3, verified: 3, pendingVerification: 0, active: 3, suspended: 0 },
  messages: { total: 51_230, inbound: 40_118, outbound: 10_902, internal: 210, today: 1_204 },
  quarantine: { active: 57 },
  apiKeys: { active: 2 },
  sessions: { active: 9 },
  limits: [
    { key: 'max_domains', value: 10, source: 'plan', used: 3 },
    { key: 'max_users', value: 250, source: 'plan', used: 42 },
    { key: 'messages_per_day', value: 100_000, source: 'plan', used: 1_204 },
  ],
};
