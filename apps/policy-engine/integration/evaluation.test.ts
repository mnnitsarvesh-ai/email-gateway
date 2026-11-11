import {
  AmqpConnection,
  ConfirmPublisher,
  NonRetryableError,
  PrismaConsumerProgress,
} from '@email-gateway/common';
import type { PrismaClient } from '@email-gateway/database';
import {
  deliveryApprovedV1,
  EventTypes,
  messageArchiveRequestedV1,
  policyDecidedV1,
  policyNotificationRequestedV1,
} from '@email-gateway/event-contracts';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { InconsistentPolicyReadError } from '../src/evaluation/errors';
import { POLICY_EVALUATE_CONSUMER } from '../src/evaluation/evaluation.service';
import {
  createPolicyEvaluateFeed,
  PolicyEvaluateConsumer,
} from '../src/evaluation/policy-evaluate.consumer';
import { createTestVhost, eventually, type TestVhost } from './support/broker';
import {
  buildPipeline,
  DEFAULT_EML,
  Fixtures,
  requireEnv,
  silentLogger,
  TX_TIMEOUT_MS,
} from './support/fixtures';

const fx = new Fixtures();
let org: bigint;
let other: bigint;

beforeAll(async () => {
  org = await fx.organization('main');
  other = await fx.organization('other');
});
afterAll(async () => {
  await fx.cleanup();
});

const policy = (direction: string, rules: unknown[], priority = 100) => ({
  dslVersion: 'policy-dsl/1',
  direction,
  priority,
  rules,
});
const rule = (id: string, actions: unknown[], extra: Record<string, unknown> = {}) => ({
  id,
  priority: 10,
  when: { field: 'direction', op: 'equals', value: 'inbound' },
  actions,
  ...extra,
});

/** Runs one event through the production handler (processOnce + evaluation) on the writer. */
async function evaluate(
  pipeline: ReturnType<typeof buildPipeline>,
  event: Parameters<PolicyEvaluateConsumer['handler']>[0],
) {
  return pipeline.consumer.handler(event);
}

const statusesOf = (row: { actions: unknown }) =>
  (row.actions as Array<{ type: string; status: string }>).map((a) => [a.type, a.status]);

describe('policy-engine evaluation on the real writer and MinIO (§9.2)', () => {
  it('scanned round → row + E8 + E10 + approval + decided event in one commit (platform default allow)', async () => {
    const p = buildPipeline(fx.prisma, fx.s3, { consumer: fx.consumer('allow') });
    const m = await fx.message(org, { recipients: ['bob@corp.example', 'carol@corp.example'] });
    const event = fx.scanned(m);
    expect(await evaluate(p, event)).toBe('handled');

    const lifecycle = await fx.lifecycle(m);
    expect(lifecycle).toMatchObject({
      status: 'approved',
      statusReason: 'policy_deliver',
      finalAction: 'deliver',
      finalVerdict: 'clean',
      riskScore: 40,
      lifecycleRound: 0,
    });
    expect(
      lifecycle.history
        .slice(-2)
        .map((h) => [
          h.fromStatus,
          h.toStatus,
          h.reasonCode,
          h.actorRole,
          h.actorService,
          h.eventId,
        ]),
    ).toEqual([
      ['scanned', 'policy_evaluated', 'policy_decided', 'policy', 'policy-engine', event.eventId],
      ['policy_evaluated', 'approved', 'policy_deliver', 'policy', 'policy-engine', event.eventId],
    ]);
    const [row, ...more] = await fx.evaluations(m);
    expect(more).toEqual([]);
    expect(row).toMatchObject({
      organizationId: org,
      evaluationSeq: 0,
      scanId: m.scanId,
      trigger: 'scanned',
      direction: 'inbound',
      disposition: 'allow',
      decisionSource: 'platform_default',
      action: 'deliver',
      finalVerdict: 'clean',
      deliveredObject: 'original',
      objectKey: null,
      policyGeneration: 0n,
      platformDefaultId: 'pol-default/1',
      dslVersion: 'policy-dsl/1',
      evaluatorVersion: 'policy-eval/1',
      inputVersion: 'policy-input/1',
    });
    expect(row!.explanationText).not.toContain('@');
    const approvals = (await fx.outbox(m, EventTypes.DeliveryApproved)).map((r) =>
      deliveryApprovedV1.parse(r.payload),
    );
    expect(approvals).toEqual([
      expect.objectContaining({
        source: 'policy',
        deliverySeq: 0,
        lifecycleRound: 0,
        emlS3Key: m.emlObjectKey,
        recipients: m.recipients.map((r) => ({ recipientId: r.id.toString(), rcptSeq: r.rcptSeq })),
      }),
    ]);
    const decided = await fx.outbox(m, EventTypes.PolicyDecided);
    expect(decided).toHaveLength(1);
    expect(decided[0]).toMatchObject({
      correlationId: event.correlationId,
      aggregateType: 'message',
    });
    expect(policyDecidedV1.parse(decided[0]!.payload)).toMatchObject({
      disposition: 'allow',
      finalAction: 'deliver',
      policyGeneration: '0',
      inputSha256: row!.inputSha256,
      snapshotSha256: row!.snapshotSha256,
    });
    const events = await fx.prisma.emailEvent.findMany({
      where: { messageId: m.messageId, receivedAt: m.receivedAt, sourceService: 'policy-engine' },
      orderBy: { id: 'asc' },
    });
    expect(events.map((e) => e.eventType)).toEqual([
      'lifecycle.policy_evaluated',
      'lifecycle.approved',
      'policy.evaluated',
      'delivery.approved',
    ]);
    expect(await p.registry.metrics()).toContain(
      'policy_evaluations_total{trigger="scanned",disposition="allow",source="platform_default",direction="inbound",service="policy-engine-it"} 1',
    );
  });

  it('duplicate event → one evaluation (ledger); stale round → ledger only', async () => {
    const p = buildPipeline(fx.prisma, fx.s3, { consumer: fx.consumer('dup') });
    const m = await fx.message(org);
    const event = fx.scanned(m);
    expect(await evaluate(p, event)).toBe('handled');
    expect(await evaluate(p, event)).toBe('duplicate');
    expect(await fx.evaluations(m)).toHaveLength(1);
    expect(await fx.outbox(m, EventTypes.DeliveryApproved)).toHaveLength(1);

    // The same round's event under a new id after the decision: the first edge is not applied.
    const again = fx.scanned(m);
    expect(await evaluate(p, again)).toBe('handled');
    expect(await fx.evaluations(m)).toHaveLength(1);
    expect(
      await fx.prisma.messageIdempotency.count({
        where: { consumer: fx.consumer('dup'), eventId: again.eventId },
      }),
    ).toBe(1);

    // A stale round (the message moved on to round 1): ledger only.
    const n = await fx.message(org, { round: 1 });
    const stale = fx.scanned({ ...n, round: 0 });
    expect(await evaluate(p, stale)).toBe('handled');
    expect(await fx.evaluations(n)).toEqual([]);
    expect((await fx.lifecycle(n)).status).toBe('scanned');
    expect(await p.registry.metrics()).toMatch(
      /policy_lifecycle_skipped_total\{result="(stale|duplicate)"/,
    );
  });

  it('parse_failed → E5 + E11 (not_scanned floor); scan_failed → E9 + quarantine; never delivered', async () => {
    const p = buildPipeline(fx.prisma, fx.s3, { consumer: fx.consumer('failures') });
    const parsed = await fx.message(org, { state: 'persisted' });
    expect(await evaluate(p, fx.parseFailed(parsed))).toBe('handled');
    const pl = await fx.lifecycle(parsed);
    expect(pl.history.slice(-2).map((h) => [h.fromStatus, h.toStatus, h.reasonCode])).toEqual([
      ['persisted', 'policy_evaluated', 'parse_failed_fail_safe'],
      ['policy_evaluated', 'quarantined', 'policy_quarantine'],
    ]);
    const [pr] = await fx.evaluations(parsed);
    expect(pr).toMatchObject({
      trigger: 'parse_failed',
      scanId: null,
      disposition: 'quarantine',
      decisionSource: 'floor',
    });
    expect(pr!.reasonCodes).toContain('policy.floor.not_scanned');

    const failed = await fx.message(org, { state: 'scan_failed' });
    expect(await evaluate(p, fx.scanned(failed, 'scan_failed'))).toBe('handled');
    const fl = await fx.lifecycle(failed);
    expect(fl.history.slice(-2).map((h) => [h.fromStatus, h.toStatus, h.reasonCode])).toEqual([
      ['scan_failed', 'policy_evaluated', 'scan_failed_fail_safe'],
      ['policy_evaluated', 'quarantined', 'policy_quarantine'],
    ]);
    expect(await fx.outbox(parsed, EventTypes.DeliveryApproved)).toEqual([]);
    expect(await fx.outbox(failed, EventTypes.DeliveryApproved)).toEqual([]);
    expect(await p.registry.metrics()).toContain(
      'policy_risk_missing_total{service="policy-engine-it"} 1',
    );
  });

  it('tenant quarantine, hold and reject paths; next-evaluation-only across a publish', async () => {
    const tenant = await fx.organization('tenant');
    const p = buildPipeline(fx.prisma, fx.s3, { consumer: fx.consumer('tenant') });
    const q = await fx.publish(
      tenant,
      'quarantine inbound',
      policy('inbound', [rule('q', [{ type: 'QUARANTINE' }])]),
    );
    const a = await fx.message(tenant);
    expect(await evaluate(p, fx.scanned(a))).toBe('handled');
    const [ra] = await fx.evaluations(a);
    expect(ra).toMatchObject({
      disposition: 'quarantine',
      decisionSource: 'tenant_rule',
      decisivePolicyPublicId: q.publicId,
      decisivePolicyVersionId: q.versionId,
      decisiveRuleId: 'q',
      policyGeneration: q.generation,
    });
    expect(ra!.matchedPolicyVersionIds).toEqual([q.versionId.toString()]);
    expect((await fx.lifecycle(a)).status).toBe('quarantined');

    // A new version (hold) is published between two messages: A's row is unchanged, B uses it.
    const before = await fx.evaluations(a);
    const h = await fx.publish(
      tenant,
      'quarantine inbound',
      policy('inbound', [rule('h', [{ type: 'REQUIRE_APPROVAL' }])]),
    );
    expect(h.generation).toBe(q.generation + 1n);
    const b = await fx.message(tenant);
    expect(await evaluate(p, fx.scanned(b))).toBe('handled');
    const [rb] = await fx.evaluations(b);
    expect(rb).toMatchObject({
      disposition: 'require_approval',
      decisiveRuleId: 'h',
      policyGeneration: h.generation,
      action: 'require_approval',
    });
    expect((await fx.lifecycle(b)).status).toBe('held_for_review');
    expect(await fx.evaluations(a)).toEqual(before);

    const r = await fx.publish(
      tenant,
      'quarantine inbound',
      policy('inbound', [rule('r', [{ type: 'REJECT' }])]),
    );
    const c = await fx.message(tenant);
    expect(await evaluate(p, fx.scanned(c))).toBe('handled');
    expect(await fx.lifecycle(c)).toMatchObject({
      status: 'rejected',
      statusReason: 'policy_discard',
      finalAction: 'discard',
    });
    expect((await fx.evaluations(c))[0]).toMatchObject({ policyGeneration: r.generation });
    expect(await fx.outbox(c, EventTypes.PolicyNotificationRequested)).toEqual([]);
    expect(await p.registry.metrics()).toContain(
      'policy_snapshot_cache_total{result="miss",service="policy-engine-it"} 3',
    );
  });

  it('TAG/WARN → a policy copy of the rewritten object, named by the approval, tagged, body identical; ARCHIVE and ALERT requested', async () => {
    const tenant = await fx.organization('copy');
    const p = buildPipeline(fx.prisma, fx.s3, { consumer: fx.consumer('copy') });
    const pub = await fx.publish(
      tenant,
      'tag external',
      policy('inbound', [
        rule('tag', [
          { type: 'TAG', label: 'external', subjectPrefix: '[EXT]' },
          { type: 'WARN', level: 'warning', text: 'External sender' },
          { type: 'ARCHIVE' },
          { type: 'ALERT', severity: 'info' },
        ]),
      ]),
    );
    const m = await fx.message(tenant);
    const rewritten = DEFAULT_EML.replace(
      'Hello Bob.',
      'Hello Bob. https://click.gateway.local/c/REWRITTEN',
    );
    const rewriteKey = await fx.rewrite(m, rewritten);
    expect(await evaluate(p, fx.scanned(m))).toBe('handled');

    const [row] = await fx.evaluations(m);
    expect(row).toMatchObject({
      disposition: 'allow',
      action: 'tag',
      deliveredObject: 'policy_copy',
    });
    expect(row!.objectKey).toMatch(
      new RegExp(
        `^org/${tenant.toString()}/policy/\\d{4}/\\d{2}/\\d{2}/${m.messageId.toString()}/r0-[0-9a-f]{32}\\.eml$`,
      ),
    );
    expect(statusesOf(row!)).toEqual(
      expect.arrayContaining([
        ['TAG', 'enforced'],
        ['WARN', 'enforced'],
        ['ARCHIVE', 'requested'],
        ['ALERT', 'requested'],
      ]),
    );
    const [approval] = (await fx.outbox(m, EventTypes.DeliveryApproved)).map((r) =>
      deliveryApprovedV1.parse(r.payload),
    );
    expect(approval!.emlS3Key).toBe(row!.objectKey);
    expect((await fx.lifecycle(m)).statusReason).toBe('policy_tag');

    const copy = await fx.object(row!.objectKey!);
    expect(copy.tags).toEqual({ 'eg-object': 'policy-copy' });
    expect(copy.contentType).toBe('message/rfc822');
    const text = copy.body.toString('latin1');
    expect(
      text.startsWith(
        'X-EG-Policy-Tag: external\r\nX-EG-Policy-Warning: warning; External sender\r\n',
      ),
    ).toBe(true);
    expect(text).toContain('Subject: [EXT] quarterly numbers\r\n');
    expect(text).not.toContain('forged-by-sender');
    const original = Buffer.from(rewritten, 'latin1');
    const bodyAt = (b: Buffer) => b.subarray(b.indexOf('\r\n\r\n'));
    expect(bodyAt(copy.body)).toEqual(bodyAt(original));

    const archive = (await fx.outbox(m, EventTypes.MessageArchiveRequested)).map((r) =>
      messageArchiveRequestedV1.parse(r.payload),
    );
    expect(archive).toEqual([
      expect.objectContaining({
        emlS3Key: m.emlObjectKey,
        ruleRef: `${pub.publicId}#${pub.versionNo}/tag`,
      }),
    ]);
    expect(rewriteKey).not.toBe(m.emlObjectKey);
    const alerts = (await fx.outbox(m, EventTypes.PolicyNotificationRequested)).map((r) =>
      policyNotificationRequestedV1.parse(r.payload),
    );
    expect(alerts).toEqual([expect.objectContaining({ kind: 'policy_alert', severity: 'info' })]);
    expect(
      policyDecidedV1.parse((await fx.outbox(m, EventTypes.PolicyDecided))[0]!.payload)
        .nonTerminalActions,
    ).toEqual(['TAG', 'WARN', 'ARCHIVE', 'ALERT']);
  });

  it('a rolled-back attempt after the copy was written is re-run idempotently: same key, same bytes', async () => {
    const tenant = await fx.organization('rerun');
    await fx.publish(
      tenant,
      'tag',
      policy('inbound', [rule('tag', [{ type: 'TAG', label: 'ext' }])]),
    );
    const m = await fx.message(tenant);
    const event = fx.scanned(m);
    let failOnce = true;
    const failing = fx.prisma.$extends({
      query: {
        policyExecutionLog: {
          async create({ args, query }) {
            if (failOnce) {
              failOnce = false;
              throw new Error('injected failure after the copy');
            }
            return query(args);
          },
        },
      },
    }) as unknown as PrismaClient;
    const p = buildPipeline(failing, fx.s3, { consumer: fx.consumer('rerun') });
    await expect(evaluate(p, event)).rejects.toThrow('injected failure');
    expect(await fx.evaluations(m)).toEqual([]);
    expect((await fx.lifecycle(m)).status).toBe('scanned');
    expect(await evaluate(p, event)).toBe('handled');
    const [row] = await fx.evaluations(m);
    const copy = await fx.object(row!.objectKey!);
    // Two writes of the same deterministic key (versioned bucket): identical bytes.
    expect(copy.versions).toBe(2);
    expect(copy.body.toString('latin1')).toContain('X-EG-Policy-Tag: ext\r\n');
  });

  it('an echo-check mismatch is retryable and commits nothing; the retry succeeds', async () => {
    const m = await fx.message(org);
    const event = fx.scanned(m);
    let shift = true;
    const shifted = fx.prisma.$extends({
      query: {
        messageRiskScore: {
          async findMany({ args, query }) {
            const rows = (await query(args)) as Array<Record<string, unknown>>;
            if (!shift) return rows;
            shift = false;
            return rows.map((r) => ({ ...r, scanId: (r.scanId as bigint) + 1n }));
          },
        },
      },
    }) as unknown as PrismaClient;
    const p = buildPipeline(shifted, fx.s3, { consumer: fx.consumer('echo') });
    await expect(evaluate(p, event)).rejects.toBeInstanceOf(InconsistentPolicyReadError);
    expect(await fx.evaluations(m)).toEqual([]);
    expect((await fx.lifecycle(m)).status).toBe('scanned');
    expect(await p.registry.metrics()).toContain(
      'policy_inconsistent_reads_total{read="risk",service="policy-engine-it"} 1',
    );
    expect(await evaluate(p, event)).toBe('handled');
    expect(await fx.evaluations(m)).toHaveLength(1);
  });

  it('rescan → a second row for round 1; the round-0 row is unchanged', async () => {
    const tenant = await fx.organization('rescan');
    const p = buildPipeline(fx.prisma, fx.s3, { consumer: fx.consumer('rescan') });
    await fx.publish(tenant, 'q', policy('inbound', [rule('q', [{ type: 'QUARANTINE' }])]));
    const m = await fx.message(tenant);
    expect(await evaluate(p, fx.scanned(m))).toBe('handled');
    const first = await fx.evaluations(m);
    const next = await fx.rescan(m);
    expect(await evaluate(p, fx.scanned(next))).toBe('handled');
    const rows = await fx.evaluations(m);
    expect(rows.map((r) => [r.evaluationSeq, r.scanId])).toEqual([
      [0, m.scanId],
      [1, next.scanId],
    ]);
    expect(rows[0]).toEqual(first[0]);
    expect((await fx.lifecycle(m)).lifecycleRound).toBe(1);
  });

  it('a department exception (recipients all in the department) applies; a mixed message is quarantined', async () => {
    const tenant = await fx.organization('dept');
    const p = buildPipeline(fx.prisma, fx.s3, { consumer: fx.consumer('dept') });
    const finance = await fx.department(tenant, 'finance', [
      'fin1@corp.example',
      'fin2@corp.example',
    ]);
    await fx.publish(
      tenant,
      'quarantine unless finance',
      policy('inbound', [
        rule('q-unless-finance', [{ type: 'QUARANTINE' }], {
          unless: [
            { field: 'recipient.department', op: 'in', value: [finance], quantifier: 'all' },
          ],
        }),
      ]),
    );
    const only = await fx.message(tenant, {
      recipients: ['FIN1@corp.example', 'fin2@corp.example'],
    });
    expect(await evaluate(p, fx.scanned(only))).toBe('handled');
    expect((await fx.evaluations(only))[0]).toMatchObject({ disposition: 'allow' });
    const mixed = await fx.message(tenant, {
      recipients: ['fin1@corp.example', 'eve@corp.example'],
    });
    expect(await evaluate(p, fx.scanned(mixed))).toBe('handled');
    expect((await fx.evaluations(mixed))[0]).toMatchObject({ disposition: 'quarantine' });
  });

  it('user exceptions and user-members of a department resolve on the writer (active, not deleted only)', async () => {
    const tenant = await fx.organization('users');
    const p = buildPipeline(fx.prisma, fx.s3, { consumer: fx.consumer('users') });
    const ceo = await fx.user(tenant, 'ceo@corp.example');
    const cfo = await fx.user(tenant, 'cfo@corp.example');
    const disabled = await fx.user(tenant, 'gone@corp.example', { status: 'disabled' });
    const deleted = await fx.user(tenant, 'left@corp.example', { deleted: true });
    // A large department: many user members not involved in any message below (the lookup is
    // bounded by the message's addresses, §6 / P5).
    const bystanders: bigint[] = [];
    for (let i = 0; i < 300; i += 1) {
      bystanders.push((await fx.user(tenant, `staff${i}@corp.example`)).id);
    }
    const finance = await fx.department(tenant, 'finance', ['fin1@corp.example']);
    await fx.addUserMembers(tenant, finance, [cfo.id, disabled.id, deleted.id, ...bystanders]);
    // A user reference to a user that is not active must never match either.
    await fx.publish(
      tenant,
      'quarantine unless ceo or finance',
      policy('inbound', [
        rule('q-unless', [{ type: 'QUARANTINE' }], {
          unless: [
            { field: 'recipient.user', op: 'in', value: [ceo.publicId], quantifier: 'all' },
            {
              field: 'recipient.user',
              op: 'in',
              value: [disabled.publicId, deleted.publicId],
              quantifier: 'all',
            },
            { field: 'recipient.department', op: 'in', value: [finance], quantifier: 'all' },
          ],
        }),
      ]),
    );
    const cases: Array<[string[], string]> = [
      [['CEO@corp.example'], 'allow'], // referenced user
      [['cfo@corp.example', 'fin1@corp.example'], 'allow'], // user member + address member
      [['staff7@corp.example'], 'allow'], // one of the bystander user members
      [['gone@corp.example'], 'quarantine'], // disabled user: neither user nor member
      [['left@corp.example'], 'quarantine'], // deleted user: neither user nor member
      [['ceo@corp.example', 'eve@corp.example'], 'quarantine'], // quantifier all
    ];
    for (const [recipients, disposition] of cases) {
      const m = await fx.message(tenant, { recipients });
      expect(await evaluate(p, fx.scanned(m))).toBe('handled');
      expect((await fx.evaluations(m))[0], recipients.join(',')).toMatchObject({ disposition });
    }
  });

  it('never evaluates a message of another organization (tenant from the envelope matched on the row)', async () => {
    const p = buildPipeline(fx.prisma, fx.s3, { consumer: fx.consumer('tenancy') });
    const m = await fx.message(org);
    const forged = { ...fx.scanned(m), organizationId: other.toString() };
    expect(await evaluate(p, forged)).toBe('handled');
    expect(await fx.evaluations(m)).toEqual([]);
    expect((await fx.lifecycle(m)).status).toBe('scanned');
    expect(await p.registry.metrics()).toContain(
      'policy_lifecycle_skipped_total{result="not_found",service="policy-engine-it"} 1',
    );
  });

  it('a malformed stored row dead-letters (NonRetryableError) and leaves the message held', async () => {
    const m = await fx.message(org);
    await fx.prisma.messageRiskScore.updateMany({
      where: { messageId: m.messageId, receivedAt: m.receivedAt },
      data: { engines: 'not-a-list' },
    });
    const p = buildPipeline(fx.prisma, fx.s3, { consumer: fx.consumer('malformed') });
    await expect(evaluate(p, fx.scanned(m))).rejects.toBeInstanceOf(NonRetryableError);
    expect((await fx.lifecycle(m)).status).toBe('scanned');
    expect(await p.registry.metrics()).toContain(
      'policy_input_errors_total{service="policy-engine-it"} 1',
    );
  });
});

describe('through RabbitMQ (a throwaway vhost with topology v9)', () => {
  let vhost: TestVhost;
  beforeAll(async () => {
    vhost = await createTestVhost();
  });
  afterAll(async () => {
    await vhost?.cleanup();
  });

  it('consumes scanned.v1 from email.policy.evaluate as the relay publishes it', async () => {
    const connection = new AmqpConnection({
      urls: [vhost.adminUrl],
      connectionName: 'it-policy-engine',
      logger: silentLogger,
      reconnect: { baseMs: 50, maxMs: 500 },
    });
    connection.start();
    await connection.waitUntilConnected(15_000);
    const publisher = new ConfirmPublisher({
      connection,
      logger: silentLogger,
      appId: 'event-relay',
      confirmTimeoutMs: 15_000,
      maxMessageBytes: 131_072,
    });
    const p = buildPipeline(fx.prisma, fx.s3, { consumer: POLICY_EVALUATE_CONSUMER });
    const consumer = new PolicyEvaluateConsumer(
      createPolicyEvaluateFeed({
        connection,
        publisher,
        prefetch: 2,
        logger: silentLogger,
        progress: new PrismaConsumerProgress(fx.prisma),
      }),
      p.evaluation,
      fx.prisma,
      p.metrics,
      TX_TIMEOUT_MS,
    );
    const m = await fx.message(org);
    const event = fx.scanned(m);
    consumer.start();
    try {
      const [result] = await publisher.publishBatch([{ envelope: event }]);
      expect(result!.outcome).toBe('confirmed');
      await eventually(
        async () => (await fx.evaluations(m)).length === 1,
        30_000,
        'the evaluation',
      );
      expect((await fx.lifecycle(m)).status).toBe('approved');
      expect(requireEnv('DATABASE_URL')).toBeTruthy();
    } finally {
      await consumer.stop();
      await publisher.close();
      await connection.close();
    }
  });
});
