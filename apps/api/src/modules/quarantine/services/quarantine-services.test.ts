import { HttpException } from '@nestjs/common';
import { MetricsService } from '@email-gateway/common';
import {
  EventTypes,
  quarantineNotificationRequestedV1,
  quarantineReleaseRequestedV1,
} from '@email-gateway/event-contracts';
import { verifyDownloadToken } from '@email-gateway/quarantine';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { InMemoryKeyValueStore } from '../../../../test/support/in-memory-key-value-store';
import { ORG, OTHER_ORG, QuarantineWorld } from '../../../../test/support/in-memory-quarantine';
import type { AuditService } from '../../../audit/audit.service';
import type { Principal, UserPrincipal } from '../../../auth-contracts/principal';
import { scopeFromPrincipal, systemScope } from '../../../auth-contracts/tenant-scope';
import type { TransactionRunner } from '../../../database/transaction-runner';
import { CodedHttpException } from '../../../http/coded-exception';
import { IdempotencyService } from '../../../http/idempotency/idempotency.service';
import type { ReauthenticationService } from '../../auth/services/reauthentication.service';
import type { MessageLifecycleRepository } from '../../messages/repositories/message-lifecycle.repository';
import type { LifecycleGateway } from '../../messages/services/lifecycle-gateway';
import type { QuarantineConfig } from '../quarantine.constants';
import { InconsistentQuarantineReadError } from '../quarantine.errors';
import type { QuarantineFactsRepository } from '../repositories/quarantine-facts.repository';
import type { QuarantineReadRepository } from '../repositories/quarantine-read.repository';
import type { QuarantineWriteRepository } from '../repositories/quarantine-write.repository';
import { QuarantineApprovalsService } from './quarantine-approvals.service';
import { QuarantineBulkService } from './quarantine-bulk.service';
import { QuarantineContext } from './quarantine-context';
import { QuarantineDispositionService } from './quarantine-disposition.service';
import { QuarantineDownloadService } from './quarantine-download.service';
import { QuarantineEntryOps } from './quarantine-entry-ops';
import { QuarantineMetrics } from './quarantine-metrics';
import type { QuarantineObjectStore } from './quarantine-object-store';
import type { Precheck, QuarantinePrecheckService } from './quarantine-precheck.service';
import { QuarantineQueryService } from './quarantine-query.service';
import { QuarantineReleaseService } from './quarantine-release.service';
import { QuarantineSettingsService } from './quarantine-settings.service';
import { QuarantineWriter } from './quarantine-writer';

const KEY_HEX = 'ab'.repeat(32);
const config: QuarantineConfig = {
  QUARANTINE_MAX_HOLD_DAYS: 60,
  QUARANTINE_MAX_REVIEW_DAYS: 13,
  LIFECYCLE_DEADLINE_QUARANTINED_HOURS: 2160,
  LIFECYCLE_DEADLINE_HELD_FOR_REVIEW_HOURS: 336,
  QUARANTINE_TX_TIMEOUT_MS: 120_000,
  QUARANTINE_RELEASE_MAX_VERDICT_AGE_HOURS: 72,
  QUARANTINE_RELEASE_SIGNATURE_MAX_LAG_HOURS: 24,
  QUARANTINE_MANUAL_FROM_REJECT_MAX_DAYS: 30,
  QUARANTINE_SEARCH_MAX_RANGE_DAYS: 62,
  QUARANTINE_SEARCH_MAX_PAGE_SIZE: 100,
  QUARANTINE_PREVIEW_MAX_BODY_BYTES: 262_144,
  QUARANTINE_PREVIEW_MAX_TEXT_CHARS: 100_000,
  QUARANTINE_PREVIEW_RATE_PER_MINUTE: 60,
  QUARANTINE_DOWNLOAD_TOKEN_KEY: KEY_HEX,
  QUARANTINE_DOWNLOAD_TOKEN_TTL_SECONDS: 60,
  QUARANTINE_DOWNLOAD_MAX_BYTES: 26_214_400,
  QUARANTINE_DOWNLOAD_GRANTS_PER_HOUR: 20,
  QUARANTINE_BULK_MAX_ITEMS: 3,
  QUARANTINE_BULK_MAX_ITEMS_PER_MINUTE: 10,
  QUARANTINE_BULK_REQUESTS_PER_MINUTE: 20,
  QUARANTINE_BULK_DEADLINE_MS: 25_000,
  POLICY_PLATFORM_DEFAULT: 'pol-default/1',
};

const scope = systemScope(ORG);
const client = { ip: '203.0.113.9', userAgent: null };
const ALL = [
  'quarantine:read',
  'quarantine:preview',
  'quarantine:release',
  'quarantine:approve',
  'quarantine:reject',
  'quarantine:delete',
  'quarantine:manage',
  'quarantine:download',
  'quarantine:request_release',
];

function user(id: bigint, permissions: string[] = ALL, mfa = true): UserPrincipal {
  return {
    kind: 'user',
    userId: id,
    userPublicId: `0190a5b2-7c3d-7e4f-8a1b-${id.toString(16).padStart(12, '0')}`,
    organizationId: ORG,
    organizationPublicId: '0190a5b2-7c3d-7e4f-8a1b-0000000000aa',
    organizationKind: 'customer',
    sessionId: 's',
    mfaAuthenticated: mfa,
    mfaEnrollmentRequired: false,
    permissions: new Set(permissions),
  };
}

const releasePrecheck = (
  outcome: Precheck['decision']['outcome'],
  reasons: string[] = [],
): Precheck => ({
  decision: {
    outcome,
    approvalReasons: reasons as Precheck['decision']['approvalReasons'],
    staleness: {
      stale: outcome === 'rescan_required',
      causes: outcome === 'rescan_required' ? ['verdict_age'] : [],
      verdictAgeHours: 1,
      signatureLagHours: null,
    },
    summary: null,
    ...(outcome === 'refused' && {
      refusal: { code: 'quarantine_hard_block_release_disabled' as const, cause: 'hard_block' },
    }),
  },
  document: { source: 'test' },
});

function setup() {
  const world = new QuarantineWorld();
  const metricsService = new MetricsService({ service: 'api-test' });
  const metrics = new QuarantineMetrics(metricsService);
  const runner = { run: vi.fn((fn: (tx: unknown) => Promise<unknown>) => fn({})) };
  const idempotency = new IdempotencyService(
    runner as unknown as TransactionRunner,
    world.idempotencyRepository(),
  );
  const audit = world.auditService() as unknown as AuditService;
  const writer = new QuarantineWriter(
    config,
    runner as unknown as TransactionRunner,
    idempotency,
    audit,
    metrics,
  );
  const writes = world.writer() as unknown as QuarantineWriteRepository;
  const reads = world.reader() as unknown as QuarantineReadRepository;
  const facts = world.facts() as unknown as QuarantineFactsRepository;
  const objects = world.objects() as unknown as QuarantineObjectStore;
  const lifecycle = world.lifecycle() as unknown as LifecycleGateway;
  const context = new QuarantineContext(config, reads, writes, metricsService);
  const ops = new QuarantineEntryOps(writes, lifecycle);
  let nextPrecheck: Precheck = releasePrecheck('approval_required', ['no_scan_round']);
  const precheck = {
    run: vi.fn(() => Promise.resolve(nextPrecheck)),
  } as unknown as QuarantinePrecheckService;
  const release = new QuarantineReleaseService(
    writer,
    ops,
    writes,
    reads,
    context,
    precheck,
    metrics,
  );
  const disposition = new QuarantineDispositionService(
    config,
    writer,
    ops,
    writes,
    context,
    objects,
    lifecycle,
    { insertEmailEvent: () => Promise.resolve() } as unknown as MessageLifecycleRepository,
    metrics,
  );
  const approvals = new QuarantineApprovalsService(
    writer,
    ops,
    writes,
    reads,
    context,
    precheck,
    disposition,
    metrics,
  );
  const kv = new InMemoryKeyValueStore();
  const bulk = new QuarantineBulkService(
    config,
    kv,
    runner as unknown as TransactionRunner,
    world.idempotencyRepository(),
    release,
    disposition,
    approvals,
    writer,
    metrics,
  );
  const reauth = { verify: vi.fn(() => Promise.resolve({ ok: true })) };
  const downloads = new QuarantineDownloadService(
    config,
    writer,
    ops,
    writes,
    facts,
    objects,
    context,
    reauth as unknown as ReauthenticationService,
    metrics,
  );
  const queries = new QuarantineQueryService(config, reads, writes, context, writer, metrics);
  const settings = new QuarantineSettingsService(reads, writes, context, writer, metrics);
  world.identities.set(10n, { email: 'operator@acme.example', verified: true });
  return {
    world,
    reads,
    runner,
    writer,
    release,
    disposition,
    approvals,
    bulk,
    downloads,
    queries,
    settings,
    kv,
    reauth,
    setPrecheck: (p: Precheck) => {
      nextPrecheck = p;
    },
  };
}

async function failure(
  promise: Promise<unknown>,
): Promise<{ status: number; code?: string; details?: unknown }> {
  try {
    await promise;
  } catch (error) {
    if (error instanceof CodedHttpException) {
      return { status: error.getStatus(), code: error.code, details: error.details };
    }
    if (error instanceof HttpException) return { status: error.getStatus() };
    throw error;
  }
  throw new Error('expected a failure');
}

let t: ReturnType<typeof setup>;
beforeEach(() => {
  t = setup();
});

const input = <B>(entryId: string, body: B, key = 'key-1', principal: Principal = user(10n)) => ({
  principal,
  // Self routes need a member scope (Q15: no platform overrides); the world ignores the via.
  scope: principal.permissions.has('quarantine:self') ? scopeFromPrincipal(principal) : scope,
  entryId,
  key,
  body,
  client,
});

describe('QuarantineReleaseService (Q13.1)', () => {
  it('approval_required: a release_approval request, entry pending_approval, notification, audit', async () => {
    const entry = t.world.addEntry();
    const res = await t.release.release(input(entry.publicId, { reason: 'checked' }));
    expect(res).toMatchObject({
      statusCode: 202,
      replayed: false,
      body: {
        outcome: 'approval_requested',
        state: 'pending_approval',
        approvalReasons: ['no_scan_round'],
      },
    });
    expect(t.world.entries[0]).toMatchObject({ state: 'pending_approval', rowVersion: 2 });
    expect(t.world.approvals[0]).toMatchObject({
      kind: 'release_approval',
      requestedByUserId: 10n,
    });
    expect(t.world.outbox).toHaveLength(1);
    expect(quarantineNotificationRequestedV1.parse(t.world.outbox[0]!.payload)).toMatchObject({
      kind: 'approval_requested',
      refs: { approvalRequestIds: [t.world.approvals[0]!.publicId] },
    });
    expect(t.world.auditActions()).toEqual(['quarantine.release_requested']);
    expect(t.world.actions[0]).toMatchObject({ action: 'release_blocked', reason: 'checked' });
    expect(t.world.actions[0]!.idempotencyKey).toMatch(/^[0-9a-f]{64}$/);
  });

  it('release: entry releasing, pending release log, valid outbox event; replay changes nothing', async () => {
    t.setPrecheck(releasePrecheck('release'));
    const entry = t.world.addEntry();
    const res = await t.release.release(input(entry.publicId, { reason: 'checked' }));
    expect(res.body).toMatchObject({ outcome: 'queued', state: 'releasing' });
    const event = t.world.outbox.find(
      (o) => o.eventType === EventTypes.QuarantineReleaseRequested,
    )!;
    const payload = quarantineReleaseRequestedV1.parse(event.payload);
    expect(payload).toMatchObject({
      entryIds: [entry.publicId],
      mode: 'operator',
      approvalRequestId: null,
      requestedBy: { type: 'user' },
    });
    expect(event.aggregateType).toBe('message');
    expect(t.world.releases).toHaveLength(1);
    const again = await t.release.release(input(entry.publicId, { reason: 'checked' }));
    expect(again).toMatchObject({ replayed: true, body: res.body });
    expect(t.world.releases).toHaveLength(1);
  });

  it('rescan_required and refusals: only the audited refusal is written', async () => {
    const entry = t.world.addEntry();
    t.setPrecheck(releasePrecheck('rescan_required'));
    expect(await failure(t.release.release(input(entry.publicId, { reason: 'x' })))).toMatchObject({
      status: 409,
      code: 'quarantine_rescan_required',
      details: { staleness: 'verdict_age' },
    });
    t.setPrecheck(releasePrecheck('refused'));
    expect(
      await failure(t.release.release(input(entry.publicId, { reason: 'x' }, 'key-2'))),
    ).toMatchObject({
      code: 'quarantine_hard_block_release_disabled',
    });
    expect(t.world.auditActions()).toEqual([
      'quarantine.release_refused',
      'quarantine.release_refused',
    ]);
    expect(t.world.audits[0]!.metadata).toMatchObject({
      outcome: 'rescan_required',
      errorCode: 'quarantine_rescan_required',
    });
    expect(t.world.entries[0]!.state).toBe('held');
    expect(t.world.idempotency.size).toBe(0);
  });

  it('state conflicts, version conflicts, another tenant (404)', async () => {
    const entry = t.world.addEntry({ state: 'rejected' });
    expect((await failure(t.release.release(input(entry.publicId, { reason: 'x' })))).code).toBe(
      'quarantine_state_conflict',
    );
    const held = t.world.addEntry();
    expect(
      (
        await failure(
          t.release.release(input(held.publicId, { reason: 'x', expectedRowVersion: 9 }, 'k2')),
        )
      ).code,
    ).toBe('quarantine_version_conflict');
    const foreign = t.world.addEntry({ organizationId: OTHER_ORG });
    expect(
      (await failure(t.release.release(input(foreign.publicId, { reason: 'x' }, 'k3')))).code,
    ).toBe('quarantine_entry_not_found');
  });

  it('self-release: own address only, the self-service bounds, mode self', async () => {
    const mailbox = user(20n, ['quarantine:self']);
    t.world.identities.set(20n, { email: 'alice@acme.example', verified: true });
    const own = t.world.addEntry({ address: 'alice@acme.example' });
    const other = t.world.addEntry({ address: 'bob@acme.example' });
    // Self-release is off by default.
    expect(
      await failure(t.release.selfRelease(input(own.publicId, { reason: 'x' }, 'a', mailbox))),
    ).toMatchObject({
      status: 403,
      code: 'quarantine_self_release_not_allowed',
      details: { cause: 'self_release_disabled' },
    });
    t.world.settings.set(ORG, { settings: { endUser: { selfRelease: true } }, rowVersion: 1 });
    expect(
      (await failure(t.release.selfRelease(input(other.publicId, { reason: 'x' }, 'b', mailbox))))
        .code,
    ).toBe('quarantine_entry_not_found');
    t.setPrecheck(releasePrecheck('release'));
    const ok = await t.release.selfRelease(input(own.publicId, { reason: 'x' }, 'c', mailbox));
    expect(ok.body).toMatchObject({ outcome: 'queued' });
    expect(t.world.releases[0]!.mode).toBe('self');
    expect(t.world.actions.at(-1)!.action).toBe('self_release');
    expect(t.world.auditActions()).toContain('quarantine.self_released');
    // An operator (no verified address of the entry, no quarantine:self) is not a mailbox user.
    expect(
      (await failure(t.release.selfRelease(input(own.publicId, { reason: 'x' }, 'd')))).status,
    ).toBe(403);
  });
});

describe('QuarantineDispositionService (Q16, Q17)', () => {
  it('reject: recipient discarded, E17 on the last entry, sender notice only for outbound', async () => {
    const outbound = t.world.addEntry({ direction: 'outbound' });
    const res = await t.disposition.reject(input(outbound.publicId, { reason: 'spam' }));
    expect(res.body).toMatchObject({
      state: 'rejected',
      messageTransition: 'E17',
      purge: 'pending',
    });
    expect(t.world.messageOf(outbound).recipients[0]!.status).toBe('discarded');
    expect(t.world.transitions[0]).toMatchObject({
      to: 'rejected',
      reason: 'quarantine_deleted',
      expectedFrom: ['quarantined'],
    });
    const notice = t.world.outbox.find(
      (o) => o.eventType === EventTypes.QuarantineNotificationRequested,
    )!;
    expect(quarantineNotificationRequestedV1.parse(notice.payload)).toMatchObject({
      kind: 'sender_rejected',
    });
    expect(notice.aggregateType).toBe('quarantine');

    const inbound = t.world.addEntry();
    await t.disposition.reject(
      input(inbound.publicId, { reason: 'spam', notifySender: true }, 'k2'),
    );
    expect(
      t.world.outbox.filter((o) => o.eventType === EventTypes.QuarantineNotificationRequested),
    ).toHaveLength(1);
    expect(t.world.audits.map((a) => a.metadata?.senderNotified)).toEqual([true, false]);
  });

  it('held_for_review rejects through E18; another live entry keeps the message', async () => {
    const review = t.world.addEntry({
      messageState: 'held_for_review',
      kind: 'review',
      state: 'pending_approval',
    });
    const res = await t.disposition.reject(input(review.publicId, { reason: 'no' }));
    expect(res.body.messageTransition).toBe('E18');
    expect(t.world.transitions[0]!.reason).toBe('review_rejected');
  });

  it('delete: refused under a legal hold (audited), allowed otherwise with a purge row', async () => {
    const entry = t.world.addEntry();
    // Swap in a legal hold through the writer repository the service uses.
    const original = (t.disposition as unknown as { writes: { disposalFacts: unknown } }).writes;
    original.disposalFacts = () =>
      Promise.resolve({
        legalHolds: [{ id: 7n, criteria: {} }],
        archive: null,
        retentionPolicyDays: [],
        emailArchives: [],
        evaluationActions: [],
      });
    expect(
      await failure(t.disposition.delete(input(entry.publicId, { reason: 'gone' }))),
    ).toMatchObject({
      status: 409,
      code: 'quarantine_legal_hold',
      details: { legalHoldId: '7' },
    });
    expect(t.world.entries[0]!.state).toBe('held');
    expect(t.world.auditActions()).toEqual(['quarantine.delete_refused']);
    original.disposalFacts = () =>
      Promise.resolve({
        legalHolds: [],
        archive: null,
        retentionPolicyDays: [],
        emailArchives: [],
        evaluationActions: [],
      });
    const done = await t.disposition.delete(input(entry.publicId, { reason: 'gone' }, 'k2'));
    expect(done.body).toMatchObject({
      state: 'deleted',
      messageTransition: 'E17',
      purge: 'pending',
    });
    expect(t.world.purges).toEqual([{ messageId: entry.messageId, status: 'pending' }]);
  });
});

describe('QuarantineApprovalsService (Q14)', () => {
  async function requested(requester: UserPrincipal) {
    const entry = t.world.addEntry({ address: 'alice@acme.example' });
    await t.release.requestRelease(input(entry.publicId, { reason: 'please' }, 'req', requester));
    return { entry, approval: t.world.approvals[0]! };
  }
  const decide = (approvalId: string, principal: Principal, key = 'dec') => ({
    principal,
    scope,
    approvalId,
    key,
    body: { reason: 'decided' },
    client,
  });

  it('SoD: the requester and the recipient are refused, a second user approves', async () => {
    const { approval } = await requested(user(10n));
    expect(await failure(t.approvals.approve(decide(approval.publicId, user(10n))))).toMatchObject({
      status: 403,
      code: 'quarantine_approval_forbidden',
      details: { reason: 'requester' },
    });
    t.world.identities.set(30n, { email: 'alice@acme.example', verified: true });
    expect(
      await failure(t.approvals.approve(decide(approval.publicId, user(30n), 'd2'))),
    ).toMatchObject({
      details: { reason: 'recipient' },
    });
    t.world.identities.set(40n, { email: 'carol@acme.example', verified: true });
    const ok = await t.approvals.approve(decide(approval.publicId, user(40n), 'd3'));
    expect(ok.body).toMatchObject({ status: 'approved', entryState: 'releasing' });
    expect(t.world.approvals[0]).toMatchObject({ status: 'approved', decidedByUserId: 40n });
    expect(
      (t.world.approvals[0] as unknown as { deciderPermissionsHash: string })
        .deciderPermissionsHash,
    ).toMatch(/^[0-9a-f]{64}$/);
    expect(t.world.releases[0]!.mode).toBe('approved');
    expect(t.world.outbox.some((o) => o.eventType === EventTypes.QuarantineReleaseRequested)).toBe(
      true,
    );
    // The requester (a user) is told about the decision.
    const decided = t.world.outbox
      .filter((o) => o.eventType === EventTypes.QuarantineNotificationRequested)
      .map((o) => quarantineNotificationRequestedV1.parse(o.payload));
    expect(decided.map((d) => d.kind)).toEqual(['approval_requested', 'approval_decided']);
  });

  it('SoD: a release requested with an API key is never approved or denied by the key creator', async () => {
    // Key 7 was created by user 10, who also holds quarantine:approve.
    t.world.apiKeyCreators.set(7n, 10n);
    const key = {
      kind: 'api_key' as const,
      apiKeyId: 7n,
      apiKeyPublicId: '0190a5b2-7c3d-7e4f-8a1b-00000000cccc',
      organizationId: ORG,
      organizationPublicId: 'x',
      permissions: new Set(ALL),
    };
    const entry = t.world.addEntry({ address: 'alice@acme.example' });
    await t.release.requestRelease(input(entry.publicId, { reason: 'via key' }, 'rk', key));
    const approval = t.world.approvals.at(-1)!;
    expect(approval).toMatchObject({
      requestedByType: 'api_key',
      requestedByUserId: null,
      requestedByApiKeyId: 7n,
    });
    for (const call of [t.approvals.approve, t.approvals.deny] as const) {
      expect(
        await failure(call.call(t.approvals, decide(approval.publicId, user(10n), 'creator'))),
      ).toMatchObject({
        status: 403,
        code: 'quarantine_approval_forbidden',
        details: { reason: 'requester' },
      });
    }
    expect(t.world.approvals.at(-1)).toMatchObject({ status: 'pending' });
    // Another approver may decide.
    t.world.identities.set(40n, { email: 'carol@acme.example', verified: true });
    const ok = await t.approvals.approve(decide(approval.publicId, user(40n), 'other'));
    expect(ok.body).toMatchObject({ status: 'approved' });
  });

  it('deny of a release request returns the entry to held; deny of a policy review rejects it', async () => {
    const { approval } = await requested(user(10n));
    t.world.identities.set(40n, { email: 'carol@acme.example', verified: true });
    const denied = await t.approvals.deny(decide(approval.publicId, user(40n)));
    expect(denied.body).toMatchObject({ status: 'denied', entryState: 'held' });

    const review = t.world.addEntry({
      messageState: 'held_for_review',
      kind: 'review',
      state: 'pending_approval',
    });
    await t.world.writer().createApproval(
      {},
      {
        organizationId: ORG,
        quarantineMessageId: review.id,
        kind: 'policy_review',
        approvalReasons: ['review'],
        requestedByType: 'system',
        requestedByUserId: null,
        requestedByApiKeyId: null,
        requestReason: null,
        expiresAt: new Date(Date.now() + 86_400_000),
      },
    );
    const pr = t.world.approvals.at(-1)!;
    review.approvalRequestId = pr.id;
    const res = await t.approvals.deny(decide(pr.publicId, user(40n), 'd2'));
    expect(res.body).toMatchObject({ entryState: 'rejected', messageTransition: 'E18' });
    // A policy review cannot be cancelled.
    expect(await failure(t.approvals.cancel(decide(pr.publicId, user(40n), 'd3')))).toMatchObject({
      status: 409,
    });
  });

  it('cancel: by the requester or an approver only; API keys never approve', async () => {
    const { approval } = await requested(user(10n));
    expect(
      (
        await failure(
          t.approvals.cancel(decide(approval.publicId, user(50n, ['quarantine:release']))),
        )
      ).status,
    ).toBe(403);
    const ok = await t.approvals.cancel(decide(approval.publicId, user(10n), 'c2'));
    expect(ok.body).toMatchObject({ status: 'cancelled', entryState: 'held' });
    const key = {
      kind: 'api_key' as const,
      apiKeyId: 1n,
      apiKeyPublicId: '0190a5b2-7c3d-7e4f-8a1b-00000000bbbb',
      organizationId: ORG,
      organizationPublicId: 'x',
      permissions: new Set(ALL),
    };
    const second = t.world.addEntry();
    await t.release.requestRelease(input(second.publicId, { reason: 'please' }, 'r2'));
    expect(
      await failure(t.approvals.approve(decide(t.world.approvals.at(-1)!.publicId, key, 'k9'))),
    ).toMatchObject({
      details: { reason: 'api_key' },
    });
  });
});

describe('QuarantineBulkService (Q18)', () => {
  it('limits, permissions, per-item results, the per-minute counter and the deadline', async () => {
    const op = user(10n);
    expect(
      await failure(
        t.bulk.bulk(op, scope, 'b1', { action: 'reject', ids: [], reason: 'x' }, client),
      ),
    ).toMatchObject({
      code: 'quarantine_bulk_limit',
      details: { cause: 'empty' },
    });
    expect(
      (
        await failure(
          t.bulk.bulk(
            user(10n, ['quarantine:read']),
            scope,
            'b1',
            { action: 'reject', ids: [t.world.addEntry().publicId], reason: 'x' },
            client,
          ),
        )
      ).status,
    ).toBe(403);
    expect(
      (
        await failure(
          t.bulk.bulk(
            user(10n, ALL, false),
            scope,
            'b1',
            { action: 'approve', ids: [t.world.addEntry().publicId], reason: 'x' },
            client,
          ),
        )
      ).status,
    ).toBe(403);

    const a = t.world.addEntry();
    const b = t.world.addEntry();
    let now = 1_000_000;
    const clock = () => now;
    // The second item starts after the deadline.
    const res = await t.bulk.bulk(
      op,
      scope,
      'b2',
      { action: 'delete', ids: [a.publicId, b.publicId], reason: 'x' },
      client,
      () => {
        const v = clock();
        now += 20_000;
        return v;
      },
    );
    expect(res.body.results).toEqual([
      { id: a.publicId, status: 'done' },
      { id: b.publicId, status: 'skipped', code: 'deadline' },
    ]);
    expect(res.body.counts).toMatchObject({ done: 1, skipped: 1 });
    // Replay of the whole response.
    const replay = await t.bulk.bulk(
      op,
      scope,
      'b2',
      { action: 'delete', ids: [a.publicId, b.publicId], reason: 'x' },
      client,
    );
    expect(replay).toMatchObject({ replayed: true, body: res.body });
    expect(
      await failure(
        t.bulk.bulk(op, scope, 'b2', { action: 'reject', ids: [a.publicId], reason: 'x' }, client),
      ),
    ).toMatchObject({ status: 422 });
    // 2 items counted in this minute; 3 + 3 more pass (8), then 3 more exceed 10.
    const ids = () => [
      t.world.addEntry().publicId,
      t.world.addEntry().publicId,
      t.world.addEntry().publicId,
    ];
    const fixed = () => 1_000_000;
    await t.bulk.bulk(
      op,
      scope,
      'b3',
      { action: 'reject', ids: ids(), reason: 'x' },
      client,
      fixed,
    );
    await t.bulk.bulk(
      op,
      scope,
      'b4',
      { action: 'reject', ids: ids(), reason: 'x' },
      client,
      fixed,
    );
    expect(
      await failure(
        t.bulk.bulk(op, scope, 'b5', { action: 'reject', ids: ids(), reason: 'x' }, client, fixed),
      ),
    ).toMatchObject({
      status: 429,
      code: 'quarantine_bulk_rate_limited',
    });
    expect(t.world.auditActions().filter((x) => x === 'quarantine.bulk')).toHaveLength(3);
  });
});

describe('QuarantineDownloadService (Q12)', () => {
  it('grant → token bound to org/user/entry; download consumes it once; another user is refused', async () => {
    const entry = t.world.addEntry();
    const op = user(10n);
    expect(
      await failure(
        t.downloads.grant(op, scope, entry.publicId, { object: 'eml', password: 'pw' }, client),
      ),
    ).toMatchObject({
      code: 'quarantine_download_disabled',
    });
    t.world.settings.set(ORG, { settings: { download: { enabled: true } }, rowVersion: 1 });
    t.reauth.verify.mockResolvedValueOnce({ ok: false, reason: 'password' } as never);
    expect(
      await failure(
        t.downloads.grant(op, scope, entry.publicId, { object: 'eml', password: 'bad' }, client),
      ),
    ).toMatchObject({
      status: 401,
      code: 'quarantine_reauth_failed',
    });
    const grant = await t.downloads.grant(
      op,
      scope,
      entry.publicId,
      { object: 'eml', password: 'pw' },
      client,
    );
    const check = verifyDownloadToken(grant.token, KEY_HEX, { now: new Date() });
    expect(check).toMatchObject({
      ok: true,
      payload: { org: '1', usr: op.userPublicId, ent: entry.publicId, obj: 'eml', part: null },
    });
    expect(
      await failure(t.downloads.download(user(11n), scope, grant.token, client)),
    ).toMatchObject({
      status: 404,
      code: 'quarantine_download_token_invalid',
    });
    const file = await t.downloads.download(op, scope, grant.token, client);
    expect(file).toMatchObject({ sizeBytes: 3, filename: `message-${entry.publicId}.eml.bin` });
    expect(await failure(t.downloads.download(op, scope, grant.token, client))).toMatchObject({
      status: 410,
      code: 'quarantine_download_token_used',
    });
    expect(t.world.auditActions()).toEqual([
      'quarantine.download_refused',
      'quarantine.download_granted',
      'quarantine.downloaded',
    ]);
  });

  it('the download.enabled gate is a writer read: a lagging replica cannot re-open downloads', async () => {
    const entry = t.world.addEntry();
    // The replica still has the old document (enabled); the writer has downloads switched off.
    vi.spyOn(t.reads, 'settings').mockResolvedValue({
      settings: { download: { enabled: true } },
      rowVersion: 1,
    });
    t.world.settings.set(ORG, { settings: { download: { enabled: false } }, rowVersion: 2 });
    expect(
      await failure(
        t.downloads.grant(
          user(10n),
          scope,
          entry.publicId,
          { object: 'eml', password: 'pw' },
          client,
        ),
      ),
    ).toMatchObject({ status: 403, code: 'quarantine_download_disabled' });
    expect(t.reauth.verify).not.toHaveBeenCalled();
  });

  it('malware gating refuses hard-blocked entries (audited)', async () => {
    t.world.settings.set(ORG, { settings: { download: { enabled: true } }, rowVersion: 1 });
    const entry = t.world.addEntry({ hardBlocks: ['hb.malware.attachment'], hasHardBlock: true });
    expect(
      await failure(
        t.downloads.grant(
          user(10n),
          scope,
          entry.publicId,
          { object: 'eml', password: 'pw' },
          client,
        ),
      ),
    ).toMatchObject({
      status: 409,
      code: 'quarantine_download_blocked',
      details: { reason: 'hard_block' },
    });
    expect(t.world.grants).toHaveLength(0);
    expect(t.world.auditActions()).toEqual(['quarantine.download_refused']);
  });
});

describe('QuarantineQueryService (Q9, Q10) and settings (Q24)', () => {
  const window = () => ({
    from: new Date(Date.now() - 86_400_000).toISOString(),
    to: new Date(Date.now() + 86_400_000).toISOString(),
  });

  it('keyset pages with a filter-bound cursor and one audit row per search', async () => {
    for (let i = 0; i < 3; i += 1) t.world.addEntry();
    const p1 = await t.queries.search(user(10n), scope, { ...window(), limit: 2 }, client);
    expect(p1.items).toHaveLength(2);
    expect(p1.nextCursor).not.toBeNull();
    expect(
      await failure(
        t.queries.search(
          user(10n),
          scope,
          { ...window(), limit: 2, reason: ['spam'], cursor: p1.nextCursor! },
          client,
        ),
      ),
    ).toMatchObject({
      code: 'quarantine_cursor_invalid',
    });
    expect(t.world.auditActions()).toEqual(['quarantine.searched']);
    expect(t.world.audits[0]!.metadata).toMatchObject({ resultCount: 2, self: false });
  });

  it('detail: allowedActions by permission, a view action and an audit row', async () => {
    const entry = t.world.addEntry();
    const detail = await t.queries.detail(
      user(10n, ['quarantine:read', 'quarantine:reject']),
      scope,
      entry.publicId,
      client,
    );
    expect(detail.allowedActions).toEqual(['reject']);
    expect(detail.subject).toBeNull();
    expect(t.world.actions.map((a) => a.action)).toEqual(['view']);
    expect(t.world.auditActions()).toEqual(['quarantine.entry_viewed']);
  });

  it('self search is empty when end-user access is off', async () => {
    t.world.identities.set(20n, { email: 'alice@acme.example', verified: true });
    t.world.addEntry({ address: 'alice@acme.example' });
    t.world.settings.set(ORG, { settings: { endUser: { enabled: false } }, rowVersion: 1 });
    const mailbox = user(20n, ['quarantine:self']);
    const page = await t.queries.selfSearch(mailbox, scopeFromPrincipal(mailbox), window(), client);
    expect(page.items).toEqual([]);
  });

  it('settings PUT: violations by path, CAS, changed paths audited', async () => {
    expect(
      await failure(
        t.settings.put(
          user(10n),
          scope,
          { settings: { review: { days: 0 } }, expectedRowVersion: 0 },
          client,
        ),
      ),
    ).toMatchObject({
      code: 'quarantine_settings_invalid',
    });
    const ok = await t.settings.put(
      user(10n),
      scope,
      { settings: { alerts: { minIntervalMinutes: 30 } }, expectedRowVersion: 0 },
      client,
    );
    expect(ok).toMatchObject({ rowVersion: 1, effective: { alerts: { minIntervalMinutes: 30 } } });
    expect(
      await failure(
        t.settings.put(user(10n), scope, { settings: {}, expectedRowVersion: 0 }, client),
      ),
    ).toMatchObject({
      code: 'quarantine_settings_conflict',
    });
    expect(t.world.audits[0]!.metadata).toMatchObject({
      changedPaths: ['alerts.minIntervalMinutes'],
    });
  });
});

describe('QuarantineWriter (§6)', () => {
  it('retries an inconsistent read once, then answers 503 inconsistent_read', async () => {
    let calls = 0;
    const out = await t.writer.run(() => {
      calls += 1;
      if (calls === 1) throw new InconsistentQuarantineReadError('entry');
      return Promise.resolve('ok');
    });
    expect(out).toBe('ok');
    expect(
      await failure(
        t.writer.run(() => Promise.reject(new InconsistentQuarantineReadError('entry'))),
      ),
    ).toMatchObject({
      status: 503,
      code: 'inconsistent_read',
    });
    expect(t.runner.run).toHaveBeenCalledWith(expect.any(Function), {
      timeoutMs: 120_000,
      maxWaitMs: 10_000,
    });
  });
});
