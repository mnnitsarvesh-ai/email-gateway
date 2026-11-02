import type { MxAnswer } from '../../../dns/dns-resolver';

/** Same values as the Prisma enum `DnsCheckOutcome` (step 2.1 migration). */
export type DnsCheckOutcome = 'valid' | 'invalid' | 'missing' | 'indeterminate';

/** Same values as the Prisma enum `DkimAlgorithm`. */
export type DkimAlgorithm = 'rsa_2048' | 'ed25519';

/** `domain_dns_records.purpose` values this step generates (D6; mta_sts/tls_rpt are not). */
export type DnsRecordPurpose = 'verification' | 'mx' | 'spf' | 'dkim' | 'dmarc';

/** Every `DnsRecordPurpose` of the schema, including the ones not generated yet. */
export type AnyDnsRecordPurpose = DnsRecordPurpose | 'mta_sts' | 'tls_rpt';

/** What a record is needed for (derived from the purpose, never stored). */
export type DnsRecordRequirement = 'activation' | 'inbound' | 'outbound' | 'recommended';

export type DmarcStage = 'missing' | 'none' | 'quarantine' | 'reject';

export interface RecordCheckResult {
  /** As in D6: `verification`, `mx:<host>`, `spf`, `dkim:<selector>`, `dmarc`. */
  recordKey: string;
  outcome: DnsCheckOutcome;
  /** Present for definitive outcomes; what was observed (joined TXT values / "prio host" lines). */
  observedValue: string | null;
  /** Recommended value after this check (SPF/DMARC may change; others = expected). */
  expectedValue: string;
  warnings: string[];
  /** JSON-safe evidence, ≤ 8 KiB serialized: upstream(s), outcome/reason, answers, durationMs, fromCache. */
  evidence: Record<string, unknown>;
}

export interface DomainCheckReport {
  checkedAt: Date;
  records: RecordCheckResult[];
  mx: {
    /** Primary resolver's MX answer; [] for NXDOMAIN/NODATA; null when indeterminate. */
    observed: MxAnswer[] | null;
    propagation: Array<{ upstream: string; outcome: DnsCheckOutcome }>;
  };
  spf: { lookupCount: number; lookupCountExact: boolean; recommendedValue: string };
  dmarc: {
    stage: DmarcStage;
    partial: boolean;
    recommendedValue: string;
    nextStep: string;
  };
  /** True when any record's outcome is indeterminate. */
  indeterminate: boolean;
}
