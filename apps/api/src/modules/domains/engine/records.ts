import { dkimRecordHost, dkimTxtValue } from './dkim';
import { recommendDmarc } from './dmarc';
import type { GatewayDnsConfig } from './gateway-dns-config';
import { recommendSpf } from './spf';
import type {
  AnyDnsRecordPurpose,
  DkimAlgorithm,
  DnsRecordPurpose,
  DnsRecordRequirement,
} from './types';
import { verificationRecord } from './verification';

/** One record the customer publishes (D6), upserted by `recordKey`. */
export interface ExpectedRecord {
  /** `verification`, `mx:<gateway host>`, `spf`, `dkim:<selector>`, `dmarc`. */
  recordKey: string;
  purpose: DnsRecordPurpose;
  type: 'TXT' | 'MX';
  /** FQDN. */
  host: string;
  /** TXT value, or `<priority> <host>` for MX. */
  value: string;
  dkimSelector?: string;
}

/** DKIM key statuses whose record must be published (pending, active, rotating). */
const PUBLISHED_KEY_STATUSES = new Set(['pending', 'active', 'rotating']);

export interface BuildExpectedRecordsInput {
  /** Normalized ASCII domain name. */
  domain: string;
  /** Null when the domain has no verification row (nothing to publish for ownership). */
  verificationToken: string | null;
  /** Keys to publish; when `status` is given, only pending/active/rotating keys are kept. */
  dkimKeys: ReadonlyArray<{
    selector: string;
    algorithm: DkimAlgorithm;
    publicKeyDns: string;
    status?: string;
  }>;
  gateway: GatewayDnsConfig;
  /** Current SPF/DMARC recommendations; defaults are the "missing" recommendations (D7/D8). */
  recommendations?: { spf?: string; dmarc?: string };
}

/** Builds the D6 record set in a stable order: verification, mx:*, spf, dkim:*, dmarc. */
export function buildExpectedRecords(input: BuildExpectedRecordsInput): ExpectedRecord[] {
  const { domain, gateway } = input;
  const records: ExpectedRecord[] = [];
  if (input.verificationToken !== null) {
    const { host, value } = verificationRecord(
      domain,
      input.verificationToken,
      gateway.verificationLabel,
    );
    records.push({ recordKey: 'verification', purpose: 'verification', type: 'TXT', host, value });
  }
  for (const mx of gateway.mxHosts) {
    records.push({
      recordKey: `mx:${mx.host}`,
      purpose: 'mx',
      type: 'MX',
      host: domain,
      value: `${mx.priority} ${mx.host}`,
    });
  }
  records.push({
    recordKey: 'spf',
    purpose: 'spf',
    type: 'TXT',
    host: domain,
    value: input.recommendations?.spf ?? recommendSpf(null, gateway.spfInclude),
  });
  for (const key of input.dkimKeys) {
    if (key.status !== undefined && !PUBLISHED_KEY_STATUSES.has(key.status)) continue;
    records.push({
      recordKey: `dkim:${key.selector}`,
      purpose: 'dkim',
      type: 'TXT',
      host: dkimRecordHost(key.selector, domain),
      value: dkimTxtValue(key.algorithm, key.publicKeyDns),
      dkimSelector: key.selector,
    });
  }
  records.push({
    recordKey: 'dmarc',
    purpose: 'dmarc',
    type: 'TXT',
    host: `_dmarc.${domain}`,
    value: input.recommendations?.dmarc ?? recommendDmarc(null, domain, gateway).recommendedValue,
  });
  return records;
}

/** Splits a stored MX value `<priority> <host>`. */
export function parseMxRecordValue(value: string): { priority: number; host: string } | null {
  const match = /^(\d{1,5}) (\S+)$/.exec(value);
  return match ? { priority: Number(match[1]), host: match[2]! } : null;
}

const REQUIREMENTS: Record<AnyDnsRecordPurpose, DnsRecordRequirement> = {
  verification: 'activation',
  mx: 'inbound',
  spf: 'outbound',
  dkim: 'outbound',
  dmarc: 'recommended',
  mta_sts: 'recommended',
  tls_rpt: 'recommended',
};

/** What a record is needed for (D6). */
export function requirementOf(purpose: AnyDnsRecordPurpose): DnsRecordRequirement {
  return REQUIREMENTS[purpose];
}

/** Name relative to the domain: `@` for the apex, `_dmarc`, `<selector>._domainkey`, …. */
export function relativeName(host: string, domain: string): string {
  const h = host.toLowerCase().replace(/\.$/, '');
  const d = domain.toLowerCase().replace(/\.$/, '');
  if (h === d) return '@';
  if (h.endsWith(`.${d}`)) return h.slice(0, -(d.length + 1));
  return h;
}

const INSTRUCTIONS: Record<AnyDnsRecordPurpose, string> = {
  verification:
    'Add this TXT record to prove you control the domain; keep it published after verification so ownership can be monitored.',
  mx: 'Point the domain at the gateway with these MX records and remove every other MX record once the domain is active.',
  spf: 'Add this include to your existing SPF record; do not create a second SPF record.',
  dkim: 'Publish this TXT record exactly as shown so receivers can verify mail the gateway signs with this selector.',
  dmarc:
    'Publish this DMARC record at _dmarc and tighten the policy step by step as the aggregate reports confirm your legitimate mail passes.',
  mta_sts: 'MTA-STS records are not managed by the gateway yet.',
  tls_rpt: 'TLS-RPT records are not managed by the gateway yet.',
};

/** One plain sentence per purpose, shown next to the record. */
export function instructionsFor(purpose: AnyDnsRecordPurpose): string {
  return INSTRUCTIONS[purpose];
}
