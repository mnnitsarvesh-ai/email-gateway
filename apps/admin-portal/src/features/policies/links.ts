/** Policy routes (step 7.1 §3.1, step 7.3 design B17 and §4.6). */
const enc = encodeURIComponent;

export type PolicyDetailTab = 'overview' | 'versions' | 'audit';
export type PolicyPanel = 'test' | 'dry-run';

/** `/policies/{id}` (`?tab=` only when not the overview). */
export const policyHref = (policyId: string, tab?: PolicyDetailTab) =>
  `/policies/${enc(policyId)}${tab && tab !== 'overview' ? `?tab=${tab}` : ''}`;

export const policiesTabHref = (tab: string) => `/policies?tab=${enc(tab)}`;
export const POLICY_BUILDER_HREF = '/policies/builder';
export const NEW_POLICY_HREF = '/policies/new';

/** `/policies/{id}/versions/{n}` with the optional `?panel=` and `?highlight=` (§4.6). */
export function policyVersionHref(
  policyId: string,
  versionNo: number,
  params: { panel?: PolicyPanel; highlight?: string } = {},
): string {
  const search = new URLSearchParams();
  if (params.panel) search.set('panel', params.panel);
  if (params.highlight) search.set('highlight', params.highlight);
  const query = search.toString();
  return `/policies/${enc(policyId)}/versions/${versionNo}${query ? `?${query}` : ''}`;
}

/** `/policies/{id}/compare?from=&to=` (defaults on the page: the active and the newest version). */
export function policyCompareHref(policyId: string, from?: number | null, to?: number | null) {
  const search = new URLSearchParams();
  if (from) search.set('from', String(from));
  if (to) search.set('to', String(to));
  const query = search.toString();
  return `/policies/${enc(policyId)}/compare${query ? `?${query}` : ''}`;
}

/** The execution history filtered to one policy (the existing `policyId` filter). */
export const policyExecutionsHref = (policyId: string) =>
  `/policies?tab=executions&policyId=${enc(policyId)}`;

export const riskProfileVersionHref = (versionId: string) =>
  `/policies/risk-profile/${enc(versionId)}`;

export const messageHref = (messageId: string) => `/messages/${enc(messageId)}`;
