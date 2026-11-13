import 'server-only';
import type { ListItem } from '@/lib/api/types';
import { SeededRandom, fixtureAnchor, paginate, stableUuid } from '../generator';
import { apiError, type FixtureHandlers } from '../types';
import { orgSlug, withPrincipal } from './reports';

export { DEV_MOCK_MARKER } from '../types';

/**
 * Time-of-click events (WP3): 200 synthetic clicks per organization over 14 days, newest first,
 * filtered like the api (range ≤ 31 days, default 24 h; decision and verdict comma lists;
 * messageId). `bravo` has none.
 */

type Click = ListItem<'UrlProtectionController_clicks_v1'>;

const HOSTS: [string, string, Click['verdict'], Click['decision']][] = [
  ['docs.example.com', 'example.com', 'clean', 'allowed'],
  ['www.example.org', 'example.org', 'clean', 'allowed'],
  ['login.evil-example.test', 'evil-example.test', 'malicious', 'blocked'],
  ['short.example.net', 'example.net', 'unknown', 'warned'],
  ['invoice-portal.bad-example.test', 'bad-example.test', 'suspicious', 'warned'],
  ['files.example.com', 'example.com', 'clean', 'allowed'],
];

function clicksOf(organizationId: string): Click[] {
  if (orgSlug(organizationId) === 'bravo') return [];
  const r = new SeededRandom(`clicks:${organizationId}`);
  const anchor = fixtureAnchor();
  return Array.from({ length: 200 }, (_, i) => {
    const [host, registrableDomain, verdict, base] = r.pick(HOSTS);
    const decision: Click['decision'] =
      base === 'warned' && r.bool(0.3) ? 'continued' : r.bool(0.03) ? 'expired' : base;
    return {
      id: stableUuid(`click:${organizationId}:${i}`),
      clickedAt: new Date(anchor - i * 1.6 * 3_600_000 - r.int(0, 3_000_000)).toISOString(),
      decision,
      verdict: decision === 'expired' ? null : verdict,
      reasonCodes:
        verdict === 'malicious'
          ? ['U_FEED_MATCH']
          : verdict === 'suspicious'
            ? ['U_LOOKALIKE']
            : [],
      messageId: stableUuid(`message:${organizationId}:${r.int(1, 60)}`),
      urlSeq: r.int(0, 4),
      host,
      registrableDomain,
      clientNetwork: `203.0.113.0/24`,
    };
  });
}

export const fixtures: FixtureHandlers = {
  UrlProtectionController_clicks_v1: (request) =>
    withPrincipal(request, (p) => {
      const q = request.query;
      const to = q.get('to') ? Date.parse(q.get('to') ?? '') : Date.now();
      const from = q.get('from') ? Date.parse(q.get('from') ?? '') : to - 86_400_000;
      if (!Number.isFinite(from) || !Number.isFinite(to))
        return apiError(400, 'validation_failed', ['from: must be an ISO 8601 date-time']);
      if (to - from > 31 * 86_400_000 + 3_600_000)
        return apiError(400, 'validation_failed', ['from: the range is longer than 31 days']);
      const decisions = q.get('decision')?.split(',');
      const verdicts = q.get('verdict')?.split(',');
      const messageId = q.get('messageId');
      const rows = clicksOf(p.organizationId);
      if (messageId && !rows.some((c) => c.messageId === messageId))
        return apiError(404, 'message_not_found', 'Message not found');
      const filtered = rows.filter((c) => {
        const t = Date.parse(c.clickedAt);
        return (
          t >= from &&
          t < to &&
          (!decisions || decisions.includes(c.decision)) &&
          (!verdicts || (c.verdict !== null && verdicts.includes(c.verdict))) &&
          (!messageId || c.messageId === messageId)
        );
      });
      return { status: 200, body: paginate(filtered, q) };
    }),
};
