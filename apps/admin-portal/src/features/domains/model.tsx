import { ToneBadge } from '@/components/domain/tone-badge';
import type { ListItem, SuccessBody } from '@/lib/api/types';
import type { Tone } from '@/lib/design/tokens';
import { humanize } from '@/lib/format';

export type DomainSummary = ListItem<'DomainsController_list_v1'>;
export type DomainDetail = SuccessBody<'DomainsController_get_v1'>;
export type DomainStatus = DomainSummary['status'];
export type DomainStatusView = SuccessBody<'DomainDnsController_status_v1'>;
export type DnsRecord = SuccessBody<'DomainDnsController_dnsRecords_v1'>['records'][number];
export type RecordStatus = DnsRecord['status'];

export const DOMAIN_STATUSES: readonly DomainStatus[] = [
  'pending_verification',
  'verified',
  'failed',
  'active',
  'suspended',
  'disabled',
];

const DOMAIN_STATUS_TONE: Record<DomainStatus, Tone> = {
  pending_verification: 'warning',
  verified: 'info',
  failed: 'danger',
  active: 'success',
  suspended: 'orange',
  disabled: 'neutral',
};

export const DOMAIN_STATUS_LABEL: Record<DomainStatus, string> = {
  pending_verification: 'Pending verification',
  verified: 'Verified',
  failed: 'Failed',
  active: 'Active',
  suspended: 'Suspended',
  disabled: 'Disabled',
};

export function DomainStatusBadge({ status }: { status: DomainStatus }) {
  return (
    <ToneBadge tone={DOMAIN_STATUS_TONE[status] ?? 'neutral'}>
      {DOMAIN_STATUS_LABEL[status] ?? humanize(status)}
    </ToneBadge>
  );
}

const RECORD_STATUS_TONE: Record<RecordStatus, Tone> = {
  pending: 'info',
  valid: 'success',
  invalid: 'danger',
  missing: 'warning',
};

export function RecordStatusBadge({ status }: { status: RecordStatus }) {
  return <ToneBadge tone={RECORD_STATUS_TONE[status] ?? 'neutral'}>{humanize(status)}</ToneBadge>;
}

/** Owned domains (ownership proven): the states from which activation and mail flow follow. */
export function isOwned(status: DomainStatus): boolean {
  return status === 'verified' || status === 'active' || status === 'suspended';
}

export const PURPOSE_LABEL: Record<DnsRecord['purpose'], string> = {
  verification: 'Ownership',
  mx: 'MX',
  spf: 'SPF',
  dkim: 'DKIM',
  dmarc: 'DMARC',
  mta_sts: 'MTA-STS',
  tls_rpt: 'TLS-RPT',
};

export const REQUIREMENT_LABEL: Record<DnsRecord['requirement'], string> = {
  activation: 'Required to activate',
  inbound: 'Required for inbound mail',
  outbound: 'Required for outbound mail',
  recommended: 'Recommended',
};

/** One record as a zone-file line (for "Copy all"). */
export function zoneLine(record: DnsRecord): string {
  const value = record.type === 'TXT' ? `"${record.value}"` : record.value;
  const priority =
    record.priority !== null && record.priority !== undefined ? ` ${record.priority}` : '';
  return `${record.host}. IN ${record.type}${priority} ${value}`;
}

const RESERVED_TLDS = new Set(['local', 'invalid', 'arpa', 'onion', 'internal', 'alt']);
/** Longest name whose derived record hosts stay within 253 characters (docs/api/README.md). */
export const DOMAIN_NAME_MAX = 226;

/**
 * Client-side mirror of the api's domain name rules (docs/api/README.md "Names"): trimmed, one
 * trailing dot ignored, lower case, at least two labels of letters, digits and hyphens (IDN
 * letters allowed: the api converts them to punycode), no `_`, `*` or IP literals, at most 226
 * characters, never `localhost` or a reserved suffix. The api stays authoritative (environment
 * dependent reservations such as `example.com` are only known there).
 */
export function normalizeDomainName(
  input: string,
): { ok: true; name: string } | { ok: false; message: string } {
  const name = input.trim().replace(/\.$/, '').toLowerCase();
  if (!name) return { ok: false, message: 'Enter a domain name.' };
  if (name.length > DOMAIN_NAME_MAX)
    return { ok: false, message: `Use at most ${DOMAIN_NAME_MAX} characters.` };
  if (/^[0-9.]+$/.test(name) || name.includes(':'))
    return { ok: false, message: 'Enter a domain name, not an IP address.' };
  const labels = name.split('.');
  if (labels.length < 2)
    return { ok: false, message: 'Enter a full domain name such as example.org.' };
  for (const label of labels) {
    if (label.length === 0) return { ok: false, message: 'The name has an empty label (..).' };
    if (label.length > 63) return { ok: false, message: 'Each label has at most 63 characters.' };
    if (!/^[\p{L}\p{N}-]+$/u.test(label))
      return { ok: false, message: 'Use letters, digits and hyphens only (no _, * or spaces).' };
    if (label.startsWith('-') || label.endsWith('-'))
      return { ok: false, message: 'A label cannot start or end with a hyphen.' };
  }
  const tld = labels[labels.length - 1] ?? '';
  if (name === 'localhost' || labels.includes('localhost') || RESERVED_TLDS.has(tld))
    return { ok: false, message: 'This name is reserved and cannot be added.' };
  return { ok: true, name };
}
