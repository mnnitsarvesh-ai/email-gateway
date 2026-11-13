/** Policy routes (design §3.1). */
export const policyHref = (policyId: string) => `/policies/${encodeURIComponent(policyId)}`;
export const policiesTabHref = (tab: string) => `/policies?tab=${encodeURIComponent(tab)}`;
export const POLICY_BUILDER_HREF = '/policies/builder';
