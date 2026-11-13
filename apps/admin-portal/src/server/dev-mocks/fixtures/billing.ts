import 'server-only';
import { SeededRandom, fixtureAnchor, hashString } from '../generator';
import { apiError, ok, type FixtureHandlers } from '../types';
import { PLANS, orgState, usageOf } from './organizations';
import { withPrincipal } from './reports';

export { DEV_MOCK_MARKER } from '../types';

/**
 * Plan, entitlements and metered usage (WP3). `pricing` is always null: the platform has no
 * prices, invoices or payment methods. Months in the future or older than 6 months + the
 * current one answer `400 usage_period_unavailable`, like the api.
 */

const monthIndex = (date: Date) => date.getUTCFullYear() * 12 + date.getUTCMonth();

export const fixtures: FixtureHandlers = {
  BillingController_plan_v1: (request) =>
    withPrincipal(request, (p) => {
      const org = orgState().orgs.get(p.organizationId);
      if (!org) return apiError(404, 'organization_not_found', 'Organization not found');
      const plan = PLANS[org.plan.code];
      return ok('BillingController_plan_v1', {
        organizationId: org.id,
        plan: { code: org.plan.code, name: org.plan.name, description: plan?.description ?? null },
        limits: [...(orgState().limits.get(org.id)?.values() ?? [])].map(
          ({ key, value, source }) => ({ key, value, source }),
        ),
        features: [...(orgState().features.get(org.id)?.values() ?? [])].map(
          ({ key, enabled, source }) => ({ key, enabled, source }),
        ),
        pricing: null,
        note: 'Prices, invoices and payment methods are not managed by the platform.',
      });
    }),

  BillingController_usage_v1: (request) =>
    withPrincipal(request, (p) => {
      const org = orgState().orgs.get(p.organizationId);
      if (!org) return apiError(404, 'organization_not_found', 'Organization not found');
      const anchor = new Date(fixtureAnchor());
      const month = request.query.get('month') ?? anchor.toISOString().slice(0, 7);
      const match = /^(\d{4})-(0[1-9]|1[0-2])$/.exec(month);
      if (!match) return apiError(400, 'validation_failed', ['month: use YYYY-MM']);
      const start = new Date(Date.UTC(Number(match[1]), Number(match[2]) - 1, 1));
      const diff = monthIndex(anchor) - monthIndex(start);
      if (diff < 0 || diff > 6) {
        return apiError(
          400,
          'usage_period_unavailable',
          `Usage for ${month} is not available (future months and months older than the message retention)`,
        );
      }
      const end =
        diff === 0
          ? new Date(fixtureAnchor())
          : new Date(Date.UTC(start.getUTCFullYear(), start.getUTCMonth() + 1, 1));
      const days = Math.max(1, Math.round((end.getTime() - start.getTime()) / 86_400_000));
      const r = new SeededRandom(hashString(`billing:${org.id}:${month}`));
      const empty = org.slug === 'bravo';
      const inbound = empty ? 0 : r.int(700, 1100) * days;
      const outbound = empty ? 0 : r.int(150, 300) * days;
      const internal = empty ? 0 : r.int(20, 60) * days;
      const users = r.int(20, 60);
      return ok('BillingController_usage_v1', {
        organizationId: org.id,
        month,
        from: start.toISOString(),
        to: end.toISOString(),
        messages: { total: inbound + outbound + internal, inbound, outbound, internal },
        users,
        domains: 3,
        apiKeys: r.int(0, 3),
        limits: [...(orgState().limits.get(org.id)?.values() ?? [])].map((l) => ({
          key: l.key,
          value: l.value,
          source: l.source,
          used: l.key === 'max_users' ? users : l.key === 'max_domains' ? 3 : null,
        })),
        generatedAt: new Date(fixtureAnchor() + 300_000).toISOString(),
      });
    }),

  UsageController_get_v1: (request) =>
    withPrincipal(request, (p) => {
      const org = orgState().orgs.get(p.organizationId);
      return org
        ? usageOf(org, request)
        : apiError(404, 'organization_not_found', 'Organization not found');
    }),
};
