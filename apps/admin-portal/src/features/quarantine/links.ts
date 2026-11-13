/** Quarantine routes (design §3.1; several are linked from notification and digest e-mails). */
const enc = encodeURIComponent;

export const entryHref = (entryId: string) => `/quarantine/${enc(entryId)}`;
export const selfEntryHref = (entryId: string) => `/quarantine/me/${enc(entryId)}`;
export const approvalHref = (approvalId: string) => `/quarantine/approvals/${enc(approvalId)}`;
export const releaseHref = (releaseId: string) => `/quarantine/releases/${enc(releaseId)}`;
export const quarantineTabHref = (tab: string) => `/quarantine?tab=${enc(tab)}`;
/** The BFF download door (design P12): the browser navigates here; the token is never stored. */
export const downloadHref = (token: string) => `/bff/api/v1/quarantine/downloads/${enc(token)}`;
