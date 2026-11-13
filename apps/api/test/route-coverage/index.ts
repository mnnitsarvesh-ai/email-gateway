/**
 * Route coverage of step 6.1 (docs/plan/steps/18-rest-api.md §3.8): the concatenation of the
 * three manifests, one entry per route the api serves —
 *
 * - `legacy.ts` (WP4): every pre-6.1 route except the messages module, plus the probes and the
 *   Prometheus scrape;
 * - `messages.ts` (WP2): the messages module (pre-6.1 lifecycle and scans, the 6.1 data routes);
 * - `insights.ts` (WP3): audit logs, reports, usage, billing, threat-intelligence lookup;
 * - `webhooks.ts` (step 6.2 WP3): webhooks, delivery history, replays, notification settings
 *   and preferences.
 *
 * Consumed by `test/route-inventory.e2e.test.ts`, which fails when a served route has no entry,
 * when an entry names a route that does not exist, or when a named test file is missing or does
 * not carry the marker comment `@covers <method> <path>`.
 */
import { COVERAGE as INSIGHTS } from './insights';
import { COVERAGE as LEGACY } from './legacy';
import { COVERAGE as MESSAGES } from './messages';
import { COVERAGE as WEBHOOKS } from './webhooks';

/** The §3.8 manifest entry (each manifest declares the same structure). */
export interface RouteCoverage {
  /** `get /api/v1/messages/:messageId` — Nest path syntax, lower-case method. */
  route: string;
  /** Repo-relative test files that contain the marker comment `@covers <route>`. */
  e2e: string;
  integration: string;
  /** File with the cross-tenant assertion, or why none applies. */
  crossTenant:
    string | { na: 'public' | 'self-only' | 'platform-only' | 'no-tenant-data'; why: string };
  cursor?: 'v0' | 'v1';
}

/** Which manifest an entry comes from (reported by the inventory on a failure). */
export type CoverageArea = 'legacy' | 'messages' | 'insights' | 'webhooks';

export const COVERAGE_BY_AREA: Readonly<Record<CoverageArea, readonly RouteCoverage[]>> =
  Object.freeze({ legacy: LEGACY, messages: MESSAGES, insights: INSIGHTS, webhooks: WEBHOOKS });

export const COVERAGE: readonly RouteCoverage[] = Object.freeze([
  ...LEGACY,
  ...MESSAGES,
  ...INSIGHTS,
  ...WEBHOOKS,
]);
