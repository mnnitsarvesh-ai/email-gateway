import {
  buildSyntheticInput,
  compileSnapshot,
  evaluatePolicy,
  evaluationResultToRow,
  type PolicyEvaluationResult,
  type PolicySnapshotSource,
  type SyntheticFacts,
} from '@email-gateway/policy-dsl';
import {
  buildScoringInput,
  platformProfile,
  riskResultToRowJson,
  scoreRisk,
} from '@email-gateway/risk-scoring';

/**
 * Policy definitions and stored evaluation rows for the step 5.2 api tests (unit, e2e and
 * integration). A stored row is built exactly as the policy-engine maps it
 * (`evaluationResultToRow`), with the engine-owned columns added.
 */

/** Quarantine inbound mail from a sender domain (a tenant rule). */
export const quarantineDomainDefinition = (domain = 'bad.example', priority = 100) => ({
  dslVersion: 'policy-dsl/1',
  direction: 'inbound',
  priority,
  rules: [
    {
      id: 'quarantine-domain',
      priority: 10,
      when: { field: 'sender.envelope.domain', op: 'equals', value: domain },
      actions: [{ type: 'QUARANTINE' }, { type: 'TAG', label: 'blocked-domain' }],
    },
  ],
});

/** Tag every inbound message (non-terminal, keeps the platform recommendation). */
export const tagAllDefinition = (label = 'external', priority = 200) => ({
  dslVersion: 'policy-dsl/1',
  direction: 'inbound',
  priority,
  rules: [
    {
      id: 'tag-all',
      priority: 10,
      when: { field: 'direction', op: 'equals', value: 'inbound' },
      actions: [{ type: 'TAG', label }],
    },
  ],
});

/** Quarantine unless every recipient is in the department (a department exception, P5). */
export const departmentExceptionDefinition = (departmentId: string) => ({
  dslVersion: 'policy-dsl/1',
  direction: 'inbound',
  priority: 50,
  rules: [
    {
      id: 'quarantine-except-finance',
      priority: 10,
      when: { field: 'direction', op: 'equals', value: 'inbound' },
      unless: [
        {
          field: 'recipient.department',
          op: 'in',
          value: [departmentId],
          quantifier: 'all',
        },
      ],
      actions: [{ type: 'QUARANTINE' }],
    },
  ],
});

/** An ALLOW override rule (P9.6) on an authenticated sender domain. */
export const overrideDefinition = (domain = 'partner.example') => ({
  dslVersion: 'policy-dsl/1',
  direction: 'inbound',
  priority: 10,
  rules: [
    {
      id: 'trusted-partner',
      priority: 1,
      when: { field: 'sender.authenticated.domain', op: 'equals', value: domain },
      actions: [{ type: 'ALLOW' }],
      override: true,
    },
  ],
});

/** A stored `policy_execution_logs` row (as the engine writes it) of a synthetic evaluation. */
export function storedEvaluation(
  facts: SyntheticFacts,
  source: PolicySnapshotSource,
  extra: { scanId?: bigint | null; evaluatedAt?: Date; durationUs?: number } = {},
): { result: PolicyEvaluationResult; row: Record<string, unknown> } {
  const result = evaluatePolicy(buildSyntheticInput(facts), compileSnapshot(source));
  const json = evaluationResultToRow(result);
  const row = {
    ...json,
    scanId: extra.scanId ?? (json.scanId === null ? null : BigInt(json.scanId)),
    policyGeneration: BigInt(json.policyGeneration),
    durationUs: extra.durationUs ?? 420,
    evaluatedAt: extra.evaluatedAt ?? new Date('2026-11-11T10:00:00.000Z'),
  };
  return { result, row };
}

/** A finished, clean inbound round (rspamd + risk revision 0) as the replica returns it. */
export function cleanRound(options: {
  messageId: bigint;
  receivedAt: Date;
  organizationId: bigint;
  scanId: bigint;
  envelopeFrom?: string;
  recipients?: string[];
  rspamd?: { outcome: 'clean' | 'spam'; codes: string[]; score: string };
}) {
  const completedAt = new Date(options.receivedAt.getTime() + 5_000);
  const rspamd = options.rspamd ?? { outcome: 'clean' as const, codes: [], score: '1.5' };
  const recipients = options.recipients ?? ['alice@acme.example'];
  const finals = [
    {
      engine: 'rspamd',
      outcome: rspamd.outcome,
      errorCode: null,
      reasonCodes: rspamd.codes,
      score: rspamd.score,
      engineVersion: '3.13.2',
      settingsVersion: 'rspamd-map/2;p=000000000000;t=none',
      attempt: 1,
      completedAt,
    },
  ];
  const auth = { spf: 'pass', dkim: 'pass', dmarc: 'pass', dmarcPolicy: 'reject', arc: 'none' };
  const risk = scoreRisk(
    buildScoringInput(
      {
        scan: {
          requiredEngines: ['rspamd'],
          scanKind: 'initial',
          lifecycleRound: 0,
          status: 'completed',
        },
        message: { direction: 'inbound', attachmentCount: 0, recipientCount: recipients.length },
        finals,
        auth: auth as never,
        bec: null,
        dlp: null,
      },
      0,
    ),
    platformProfile('rsk-default/1'),
  );
  const riskJson = riskResultToRowJson(risk);
  return {
    message: {
      id: options.messageId,
      publicId: '',
      receivedAt: options.receivedAt,
      organizationId: options.organizationId,
      direction: 'inbound' as const,
      envelopeFrom: options.envelopeFrom ?? 'sender@partner.example',
      headerFrom: options.envelopeFrom ?? 'sender@partner.example',
      clientIp: '198.51.100.7',
      clientName: 'mail.partner.example',
      sizeBytes: 2048,
      recipientCount: recipients.length,
      attachmentCount: 0,
      lifecycleRound: 0,
    },
    scan: {
      id: options.scanId,
      messageId: options.messageId,
      receivedAt: options.receivedAt,
      organizationId: options.organizationId,
      lifecycleRound: 0,
      scanKind: 'initial' as const,
      status: 'completed' as const,
      scanVerdict: rspamd.outcome === 'clean' ? 'clean' : 'spam',
      reasonCodes: rspamd.codes,
      requiredEngines: ['rspamd'],
      completedAt,
    },
    rows: {
      recipients: recipients.map((address, rcptSeq) => ({ rcptSeq, address })),
      finals: finals.map((f) => ({
        engine: f.engine,
        outcome: f.outcome,
        reasonCodes: f.reasonCodes,
      })),
      auth,
      bec: null,
      dlp: null,
      risk: [
        {
          revision: 0,
          status: riskJson.status,
          score: riskJson.score,
          level: riskJson.level,
          verdict: riskJson.verdict,
          recommendedAction: riskJson.recommendedAction,
          hardBlocks: riskJson.hardBlocks,
          reasonCodes: riskJson.reasonCodes,
          failures: riskJson.failures,
          engines: riskJson.engines,
          evidence: riskJson.evidence,
        },
      ],
      attachments: [],
      attachmentResults: [],
      urls: [],
      urlResults: [],
      urlRewrite: null,
    },
    riskJson,
    finals,
    auth,
    completedAt,
  };
}
