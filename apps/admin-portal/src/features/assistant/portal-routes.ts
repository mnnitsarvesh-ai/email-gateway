import { NAV_ITEMS } from '@/lib/navigation';

/**
 * The internal portal routes the assistant may link to (step AI-1 D9): every navigation href plus
 * the detail and sub pages below (`:param` = one path segment). A link anywhere else (another
 * origin, a protocol, a BFF or API path, an OAuth callback, a traversal) is rendered as text. The
 * unit test checks every pattern against the `app/(console)` pages, so a renamed page cannot leave
 * a dead or unchecked pattern behind.
 */
export const DETAIL_ROUTE_PATTERNS: readonly string[] = [
  '/assistant',
  // Step AI-R (D9): the full-size page of a chat report (a UUID only, see PARAM_RULES).
  '/assistant/reports/:reportId',
  '/archive/:messageId',
  '/ato/accounts/:accountId',
  '/ato/providers/:integrationId',
  '/domains/:domainId',
  '/domains/onboarding',
  '/ediscovery/:caseId',
  '/ediscovery/:caseId/searches/:searchId',
  '/incidents/:incidentId',
  '/incidents/:incidentId/report',
  '/integrations/api-keys',
  '/integrations/providers',
  '/integrations/providers/:connectionId',
  '/legal-holds/:holdId',
  '/messages/:messageId',
  '/messages/:messageId/scans',
  '/organizations/:organizationId',
  '/policies/:policyId',
  '/policies/:policyId/compare',
  '/policies/:policyId/versions/:versionNo',
  '/policies/risk-profile/:versionId',
  '/quarantine/:entryId',
  '/quarantine/approvals',
  '/quarantine/approvals/:approvalId',
  '/quarantine/me',
  '/quarantine/me/:entryId',
  '/quarantine/releases/:releaseId',
  '/quarantine/settings',
  '/roles/:roleKey',
  '/settings/journaling/intake/:sourceId',
  '/users/:userId',
  '/webhooks/:webhookId',
];

/** Pages that are never link targets (ceremonies and error pages). */
const EXCLUDED_SEGMENTS = new Set(['consent-callback', 'forbidden', 'new']);

const PARAM = /^[A-Za-z0-9][A-Za-z0-9._~-]{0,127}$/;
/** Parameters narrower than PARAM (step AI-R: a report link is `/assistant/reports/<uuid>`). */
const PARAM_RULES: Readonly<Record<string, RegExp>> = {
  ':reportId': /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i,
};
const QUERY = /^[A-Za-z][A-Za-z0-9_]{0,31}=[A-Za-z0-9_.,:-]{0,128}$/;
const MAX_HREF = 512;

function patternsOf(): ReadonlyArray<readonly string[]> {
  const all = new Set<string>([...NAV_ITEMS.map((item) => item.href), ...DETAIL_ROUTE_PATTERNS]);
  return [...all].map((pattern) => pattern.split('/').slice(1));
}

const PATTERNS = patternsOf();

function segmentMatches(pattern: string, segment: string): boolean {
  if (pattern.startsWith(':'))
    return (
      PARAM.test(segment) &&
      !EXCLUDED_SEGMENTS.has(segment) &&
      (PARAM_RULES[pattern]?.test(segment) ?? true)
    );
  return pattern === segment;
}

/**
 * Returns the normalized href when `href` is an allow-listed internal portal route (a path from
 * the root, optional `?key=value&…` with plain values, no fragment, no encoded characters), else
 * `null`. Pure; used by the Markdown renderer and by result cards.
 */
export function safePortalHref(href: string): string | null {
  if (typeof href !== 'string' || href.length === 0 || href.length > MAX_HREF) return null;
  if (!href.startsWith('/') || href.startsWith('//')) return null;
  if (/[\s\\%#@]/.test(href)) return null;
  const [path = '', query, ...rest] = href.split('?');
  if (rest.length > 0) return null;
  const segments = path === '/' ? [] : path.split('/').slice(1);
  if (segments.some((segment) => segment === '' || segment === '.' || segment === '..'))
    return null;
  const matched = PATTERNS.some(
    (pattern) =>
      pattern.length === segments.length &&
      pattern.every((part, index) => segmentMatches(part, segments[index] ?? '')),
  );
  if (!matched) return null;
  if (query !== undefined) {
    if (query === '' || !query.split('&').every((pair) => QUERY.test(pair))) return null;
  }
  return href;
}
