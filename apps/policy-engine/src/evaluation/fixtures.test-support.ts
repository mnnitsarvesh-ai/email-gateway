import { canonicalJson, sha256Hex } from '@email-gateway/policy-dsl';
import type { RoundFacts } from './facts.repository';

/** Fixed completion time of the fixture round. */
export const COMPLETED = new Date('2026-11-10T10:00:00.000Z');

/** The required engines of a fixture round and their clean finals. */
export const ENGINES = ['rspamd', 'attachment', 'url', 'bec', 'dlp'] as const;

/**
 * A clean revision-0 `message_risk_scores` row as the 5.1 scorer stores it (level-only:
 * scored, no hard block, no failure, every engine definite). JSON columns as stored.
 */
export function cleanRiskRow(
  overrides: Partial<RoundFacts['risk'][number]> = {},
): RoundFacts['risk'][number] {
  return {
    revision: 0,
    status: 'scored',
    score: 40,
    level: 'none',
    verdict: 'clean',
    recommendedAction: 'deliver',
    hardBlocks: [],
    reasonCodes: [],
    failures: [],
    engines: ENGINES.map((engine) => ({ engine, status: 'definite', outcome: 'clean' })),
    evidence: { aiRaiseOnly: false },
    ...overrides,
  };
}

/** The P8 rows of a clean scanned round (no attachments, no URLs). */
export function cleanFacts(
  options: {
    direction?: 'inbound' | 'outbound' | 'internal';
    recipients?: string[];
    risk?: RoundFacts['risk'];
    trigger?: RoundFacts['trigger'];
    round?: number;
  } = {},
): RoundFacts {
  const direction = options.direction ?? 'inbound';
  const trigger = options.trigger ?? 'scanned';
  const round = options.round ?? 0;
  const recipients = options.recipients ?? ['bob@corp.example'];
  const failed = trigger === 'scan_failed';
  return {
    trigger,
    message: {
      direction,
      envelopeFrom: direction === 'inbound' ? 'alice@partner.example' : 'bob@corp.example',
      headerFrom: direction === 'inbound' ? 'alice@partner.example' : 'bob@corp.example',
      clientIp: '198.51.100.7',
      clientName: 'mx1.partner.example',
      sizeBytes: 1234,
      recipientCount: recipients.length,
      attachmentCount: 0,
      lifecycleRound: round,
    },
    recipients: recipients.map((address, rcptSeq) => ({ rcptSeq, address })),
    scan:
      trigger === 'parse_failed'
        ? null
        : {
            scanId: 900n,
            lifecycleRound: round,
            scanKind: round === 0 ? 'initial' : 'rescan',
            status: failed ? 'timed_out' : 'completed',
            scanVerdict: failed ? 'timeout' : 'clean',
            reasonCodes: [],
            requiredEngines: [...ENGINES],
            completedAt: COMPLETED,
          },
    parseFailedAt: trigger === 'parse_failed' ? COMPLETED : null,
    finals:
      trigger === 'parse_failed'
        ? []
        : ENGINES.map((engine) => ({
            engine,
            outcome: failed && engine === 'url' ? 'timeout' : 'clean',
            reasonCodes: [],
          })),
    auth:
      trigger === 'parse_failed'
        ? null
        : { spf: 'pass', dkim: 'pass', dmarc: 'pass', dmarcPolicy: 'reject', arc: 'none' },
    bec:
      trigger === 'parse_failed'
        ? null
        : { deterministicVerdict: 'clean', verdict: 'clean', rules: [] },
    dlp:
      trigger === 'parse_failed'
        ? null
        : { action: 'allow', verdict: 'clean', coverage: 'complete', categories: [] },
    risk: options.risk ?? (trigger === 'parse_failed' ? [] : [cleanRiskRow()]),
    attachments: [],
    attachmentResults: [],
    urls: [],
    urlResults: [],
    urlRewrite: trigger === 'parse_failed' ? null : { status: 'skipped', skipReason: 'no_urls' },
  };
}

/** A `policy-dsl/1` definition and its canonical hash. */
export function definition(
  direction: 'inbound' | 'outbound' | 'internal' | 'any',
  rules: unknown[],
  priority = 100,
): { definition: Record<string, unknown>; definitionSha256: string } {
  const doc = { dslVersion: 'policy-dsl/1', direction, priority, rules };
  return { definition: doc, definitionSha256: sha256Hex(canonicalJson(doc)) };
}

export const POLICY_A = '0190f0f0-0000-7000-8000-0000000000a1';
export const POLICY_B = '0190f0f0-0000-7000-8000-0000000000b2';

/** Rules used by the tests. */
export const RULES = {
  tagExternal: {
    id: 'tag-external',
    priority: 10,
    when: { field: 'direction', op: 'equals', value: 'inbound' },
    actions: [{ type: 'TAG', label: 'external', subjectPrefix: '[EXT]' }],
  },
  quarantineInbound: {
    id: 'quarantine-all',
    priority: 10,
    when: { field: 'direction', op: 'equals', value: 'inbound' },
    actions: [{ type: 'QUARANTINE' }],
  },
  holdInbound: {
    id: 'hold-all',
    priority: 10,
    when: { field: 'direction', op: 'equals', value: 'inbound' },
    actions: [{ type: 'REQUIRE_APPROVAL' }],
  },
  rejectAny: (direction: 'inbound' | 'outbound') => ({
    id: 'reject-all',
    priority: 10,
    when: { field: 'direction', op: 'equals', value: direction },
    actions: [{ type: 'REJECT' }],
  }),
  archiveAlert: {
    id: 'archive-alert',
    priority: 20,
    when: { field: 'direction', op: 'equals', value: 'inbound' },
    actions: [{ type: 'ARCHIVE' }, { type: 'ALERT', severity: 'warning' }],
  },
  departmentException: (departmentId: string) => ({
    id: 'quarantine-unless-dept',
    priority: 10,
    when: { field: 'direction', op: 'equals', value: 'inbound' },
    unless: [{ field: 'recipient.department', op: 'in', value: [departmentId], quantifier: 'all' }],
    actions: [{ type: 'QUARANTINE' }],
  }),
};
