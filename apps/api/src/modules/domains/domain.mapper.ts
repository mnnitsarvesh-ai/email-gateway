import { domainToUnicode } from 'node:url';
import type { DnsCheckOutcome, DnsRecordStatus, DomainStatus } from '@email-gateway/database';
import { toIso, toIsoOrNull } from '../../http/serialization';
import { PUBLISHED_KEY_STATUSES } from './domain/dkim-rotation';
import { warningsOf } from './domain/apply-report';
import {
  type CheckGroup,
  groupOf,
  mailFlowReady,
  readyForActivation,
  worstOf,
} from './domain/readiness';
import { DAY_MS, RETIRED_KEY_LISTING_DAYS } from './domains.constants';
import type {
  CleanupRecordView,
  DkimKeyView,
  DnsRecordView,
  DomainDetail,
  DomainStatusView,
  DomainSummary,
  VISIBLE_DOMAIN_STATUSES,
} from './dto/domains.schemas';
import { dkimRecordHost } from './engine/dkim';
import { recommendDmarc } from './engine/dmarc';
import type { GatewayDnsConfig } from './engine/gateway-dns-config';
import { instructionsFor, parseMxRecordValue, relativeName, requirementOf } from './engine/records';
import { verificationRecord } from './engine/verification';
import type { DkimKeyRow } from './repositories/dkim-keys.repository';
import type { DnsRecordRow } from './repositories/dns-records.repository';
import type { DomainRow } from './repositories/domains.repository';
import type { MxObservationRow } from './repositories/mx-observations.repository';
import type { VerificationRow } from './repositories/verifications.repository';

/**
 * Response mappers of the domains API (§4). Public ids only, ISO dates, never `bigint`, never a
 * private key (the repositories do not even select it).
 */

type VisibleStatus = (typeof VISIBLE_DOMAIN_STATUSES)[number];

function visibleStatus(status: DomainStatus): VisibleStatus {
  if (status === 'deleted') throw new Error('A deleted domain is never serialized');
  return status;
}

export function toDomainSummary(row: DomainRow): DomainSummary {
  return {
    id: row.publicId,
    name: row.name,
    unicodeName: domainToUnicode(row.name) || row.name,
    status: visibleStatus(row.status),
    statusReason: row.statusReason,
    inboundEnabled: row.inboundEnabled,
    outboundEnabled: row.outboundEnabled,
    verifiedAt: toIsoOrNull(row.verifiedAt),
    activatedAt: toIsoOrNull(row.activatedAt),
    lastCheckedAt: toIsoOrNull(row.lastCheckedAt),
    nextCheckAt: toIsoOrNull(row.nextCheckAt),
    createdAt: toIso(row.createdAt),
    updatedAt: toIso(row.updatedAt),
  };
}

export function toDkimKeyView(key: DkimKeyRow, domainName: string): DkimKeyView {
  return {
    selector: key.selector,
    algorithm: key.algorithm,
    status: key.status,
    host: dkimRecordHost(key.selector, domainName),
    createdAt: toIso(key.createdAt),
    activatedAt: toIsoOrNull(key.activatedAt),
    retireAfter: toIsoOrNull(key.retireAfter),
    retiredAt: toIsoOrNull(key.retiredAt),
  };
}

function recentlyRetired(key: DkimKeyRow, now: Date): boolean {
  return (
    key.status === 'retired' &&
    key.retiredAt !== null &&
    now.getTime() - key.retiredAt.getTime() <= RETIRED_KEY_LISTING_DAYS * DAY_MS
  );
}

export interface DomainDetailParts {
  domain: DomainRow;
  verification: VerificationRow | null;
  dkimKeys: readonly DkimKeyRow[];
  verificationLabel: string;
  now: Date;
}

export function toDomainDetail(parts: DomainDetailParts): DomainDetail {
  const { domain, verification, now } = parts;
  const record = verification
    ? verificationRecord(domain.name, verification.token, parts.verificationLabel)
    : null;
  return {
    ...toDomainSummary(domain),
    statusChangedAt: toIsoOrNull(domain.statusChangedAt),
    verification:
      verification && record
        ? {
            method: 'dns_txt',
            host: record.host,
            value: record.value,
            status: verification.status,
            attempts: verification.attempts,
            lastCheckedAt: toIsoOrNull(verification.lastCheckedAt),
            lastOutcome: verification.lastOutcome,
            lastError: verification.lastError,
            expiresAt: toIso(verification.expiresAt),
            verifiedAt: toIsoOrNull(verification.verifiedAt),
          }
        : null,
    dkimKeys: parts.dkimKeys
      .filter((key) => key.status !== 'retired' || recentlyRetired(key, now))
      .map((key) => toDkimKeyView(key, domain.name)),
  };
}

export function toDnsRecordView(record: DnsRecordRow, domainName: string): DnsRecordView {
  const mx = record.recordType === 'MX' ? parseMxRecordValue(record.expectedValue) : null;
  return {
    key: record.recordKey,
    purpose: record.purpose,
    requirement: requirementOf(record.purpose),
    type: record.recordType,
    host: record.host,
    name: relativeName(record.host, domainName),
    value: mx ? mx.host : record.expectedValue,
    priority: mx ? mx.priority : null,
    status: record.status,
    lastOutcome: record.lastOutcome,
    observedValue: record.observedValue,
    lastCheckedAt: toIsoOrNull(record.lastCheckedAt),
    lastError: record.lastError,
    warnings: warningsOf(record.evidence),
    instructions: instructionsFor(record.purpose),
  };
}

/** TXT records of DKIM selectors retired in the last 30 days, which the customer can delete. */
export function toCleanupRecords(
  keys: readonly DkimKeyRow[],
  domainName: string,
  now: Date,
): CleanupRecordView[] {
  return keys
    .filter((key) => recentlyRetired(key, now))
    .map((key) => ({
      type: 'TXT' as const,
      host: dkimRecordHost(key.selector, domainName),
      reason: 'retired_dkim_selector' as const,
      retiredAt: toIso(key.retiredAt!),
    }));
}

const OUTCOME_SEVERITY: Readonly<Record<DnsCheckOutcome, number>> = {
  valid: 0,
  missing: 1,
  invalid: 2,
  indeterminate: 3,
};

interface GroupCheck {
  status: DnsRecordStatus;
  lastOutcome: DnsCheckOutcome | null;
  lastCheckedAt: string | null;
  warnings: string[];
}

function groupCheck(rows: readonly DnsRecordRow[]): GroupCheck {
  let lastOutcome: DnsCheckOutcome | null = null;
  let lastCheckedAt: Date | null = null;
  const warnings = new Set<string>();
  for (const row of rows) {
    if (
      row.lastOutcome !== null &&
      (lastOutcome === null || OUTCOME_SEVERITY[row.lastOutcome] > OUTCOME_SEVERITY[lastOutcome])
    ) {
      lastOutcome = row.lastOutcome;
    }
    if (row.lastCheckedAt && (!lastCheckedAt || row.lastCheckedAt > lastCheckedAt)) {
      lastCheckedAt = row.lastCheckedAt;
    }
    for (const warning of warningsOf(row.evidence)) warnings.add(warning);
  }
  return {
    status: worstOf(rows.map((r) => r.status)),
    lastOutcome,
    lastCheckedAt: toIsoOrNull(lastCheckedAt),
    warnings: [...warnings],
  };
}

function evidenceField(row: DnsRecordRow | undefined, field: string): unknown {
  const evidence = row?.evidence;
  return evidence !== null && typeof evidence === 'object' && !Array.isArray(evidence)
    ? (evidence as Record<string, unknown>)[field]
    : undefined;
}

const OUTCOMES = new Set<string>(['valid', 'invalid', 'missing', 'indeterminate']);
const DMARC_STAGES = new Set<string>(['missing', 'none', 'quarantine', 'reject']);

function propagationOf(
  rows: readonly DnsRecordRow[],
): Array<{ upstream: string; outcome: DnsCheckOutcome }> {
  const value = evidenceField(
    rows.find((r) => Array.isArray(evidenceField(r, 'propagationOutcomes'))),
    'propagationOutcomes',
  );
  if (!Array.isArray(value)) return [];
  return value.flatMap((item: unknown) => {
    const entry = item as { upstream?: unknown; outcome?: unknown } | null;
    return typeof entry?.upstream === 'string' &&
      typeof entry.outcome === 'string' &&
      OUTCOMES.has(entry.outcome)
      ? [{ upstream: entry.upstream, outcome: entry.outcome as DnsCheckOutcome }]
      : [];
  });
}

export interface StatusViewParts {
  domain: DomainRow;
  records: readonly DnsRecordRow[];
  dkimKeys: readonly DkimKeyRow[];
  mx: readonly MxObservationRow[];
  gateway: GatewayDnsConfig;
}

/** The stored state as `DomainStatusView` (§4); no DNS lookups. */
export function toStatusView(parts: StatusViewParts): DomainStatusView {
  const { domain, records } = parts;
  const groups: Record<CheckGroup, DnsRecordRow[]> = {
    ownership: [],
    mx: [],
    spf: [],
    dkim: [],
    dmarc: [],
  };
  for (const record of records) {
    const group = groupOf(record.purpose);
    if (group) groups[group].push(record);
  }
  const mx = groupCheck(groups.mx);
  const spfRow = groups.spf[0];
  const dmarcRow = groups.dmarc[0];
  const lookupCount = evidenceField(spfRow, 'lookupCount');
  const stage = evidenceField(dmarcRow, 'stage');
  const nextStep = evidenceField(dmarcRow, 'nextStep');
  const recordStatus = new Map(records.map((r) => [r.recordKey, r.status]));
  const defaultDmarc = recommendDmarc(null, domain.name, parts.gateway);

  return {
    domainId: domain.publicId,
    name: domain.name,
    status: visibleStatus(domain.status),
    statusReason: domain.statusReason,
    readyForActivation: readyForActivation(domain.status),
    mailFlowReady: mailFlowReady(domain.status, mx.status),
    lastCheckedAt: toIsoOrNull(domain.lastCheckedAt),
    nextCheckAt: toIsoOrNull(domain.nextCheckAt),
    checkFailures: domain.checkFailures,
    checks: {
      ownership: groupCheck(groups.ownership),
      mx: {
        ...mx,
        observed: parts.mx.map((row) => ({
          priority: row.priority,
          host: row.host,
          pointsToGateway: row.pointsToGateway,
        })),
        propagation: propagationOf(groups.mx),
      },
      spf: {
        ...groupCheck(groups.spf),
        lookupCount: typeof lookupCount === 'number' ? lookupCount : null,
        recommendedValue: spfRow?.expectedValue ?? '',
      },
      dkim: {
        ...groupCheck(groups.dkim),
        selectors: parts.dkimKeys
          .filter((key) => PUBLISHED_KEY_STATUSES.has(key.status))
          .map((key) => ({
            selector: key.selector,
            algorithm: key.algorithm,
            keyStatus: key.status,
            recordStatus: recordStatus.get(`dkim:${key.selector}`) ?? 'pending',
          })),
      },
      dmarc: {
        ...groupCheck(groups.dmarc),
        stage:
          typeof stage === 'string' && DMARC_STAGES.has(stage)
            ? (stage as 'missing' | 'none' | 'quarantine' | 'reject')
            : 'missing',
        recommendedValue: dmarcRow?.expectedValue ?? defaultDmarc.recommendedValue,
        nextStep: typeof nextStep === 'string' ? nextStep : defaultDmarc.nextStep,
      },
    },
  };
}
