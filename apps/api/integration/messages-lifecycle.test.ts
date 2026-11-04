/**
 * Message lifecycle API (step 3.3 L10-L12) against the real MySQL writer and replica, with
 * messages put into their states by SQL fixtures (L8.6): RBAC, rescan (E19) and release
 * (E14/E15) with every refusal of L10.4, Idempotency-Key replay and key reuse (exactly one
 * history, outbox and audit row), concurrent requests, release approvals that satisfy the
 * delivery planner's provenance check, and the reads through the replica, through the writer
 * fallback, with history pagination and legacy rows.
 */
import { createHash, randomUUID } from 'node:crypto';
import { PrismaReadService } from '@email-gateway/common';
import {
  deliveryApprovedV1,
  EventTypes,
  messageRescanRequestedV1,
  messageStateChangedV1,
} from '@email-gateway/event-contracts';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { RESCAN_NOTE } from '../src/modules/messages/domain/lifecycle-operations';
import { createIntegrationApp, type IntegrationApp } from './support/app';
import {
  createFixtures,
  type FixtureOrganization,
  type Fixtures,
  unknownId,
} from './support/fixtures';
import { apiKeyHeader, bearer, loginWithMfa } from './support/http';
import {
  deleteLifecycleFixtures,
  insertDeliveries,
  insertLifecycleMessage,
  insertQuarantineEntry,
  LifecycleApi,
  type LifecycleMessage,
  writerState,
} from './support/lifecycle';
import { pauseLiveRelay } from './support/live-relay';

const POLL = { timeout: 15_000, interval: 200 };
const ALL = ['message:read', 'message:rescan', 'quarantine:release'];
const reason = 'operator reviewed the message headers';
/** The delivery planner's provenance window (delivery-planner.ts PROVENANCE_SKEW_MS). */
const PROVENANCE_SKEW_MS = 5 * 60_000;

const sha = (text: string) => createHash('sha256').update(text).digest('hex');
const key = () => `it-${randomUUID()}`;

let ctx: IntegrationApp;
let fx: Fixtures;
let org: FixtureOrganization;
let api: LifecycleApi;
let apiKeyPublicId: string;

async function auditRows(resourceId: string, action: string) {
  return ctx.prisma.auditLog.findMany({
    where: { organizationId: org.id, resourceType: 'message', resourceId, action },
  });
}

/** `email_recipients.status` of the message on the writer, by `rcpt_seq`. */
async function recipientStatuses(message: LifecycleMessage): Promise<string[]> {
  const rows = await ctx.prisma.emailRecipient.findMany({
    where: { messageId: message.id, receivedAt: message.receivedAt },
    select: { status: true },
    orderBy: { rcptSeq: 'asc' },
  });
  return rows.map((r) => r.status);
}

/**
 * The planner's `assertApprovalIssued` (delivery-worker, step 3.2 review round 1), as a query:
 * an outbox row with the approval's event id, type and organization, created at most 5 minutes
 * before the message's received_at, whose payload parses and equals the published payload (the
 * relay publishes the stored payload unchanged).
 */
async function approvalIssued(eventId: string, message: LifecycleMessage): Promise<unknown> {
  const row = await ctx.prisma.messageOutbox.findFirst({
    where: {
      eventId,
      eventType: EventTypes.DeliveryApproved,
      organizationId: message.organizationId,
      createdAt: { gte: new Date(message.receivedAt.getTime() - PROVENANCE_SKEW_MS) },
    },
    select: { payload: true, aggregateType: true, aggregateId: true, correlationId: true },
  });
  expect(row, `approval ${eventId} has no outbox row`).not.toBeNull();
  expect(row!.aggregateType).toBe('message');
  expect(row!.aggregateId).toBe(message.id.toString());
  const issued = deliveryApprovedV1.safeParse(row!.payload);
  expect(issued.success).toBe(true);
  // The relay builds the envelope payload from the stored payload: the copy equals it.
  const delivered = deliveryApprovedV1.parse(JSON.parse(JSON.stringify(row!.payload)));
  expect(delivered).toStrictEqual(issued.data);
  return issued.data;
}

let resumeLiveRelay: (() => Promise<void>) | undefined;

beforeAll(async () => {
  // A live event-relay would publish this suite's approval/rescan rows (L16, live-relay.ts).
  resumeLiveRelay = await pauseLiveRelay();
  ctx = await createIntegrationApp();
  fx = createFixtures(ctx);
  org = await fx.createOrganization();
  fx.registerCleanup(() => deleteLifecycleFixtures(ctx, [org.id]));
  const rawKey = await fx.createApiKey(org, ALL);
  api = new LifecycleApi(ctx, apiKeyHeader(rawKey));
  const keyRow = await ctx.prisma.apiKey.findFirstOrThrow({
    where: { organizationId: org.id },
    select: { publicId: true },
  });
  apiKeyPublicId = keyRow.publicId;
}, 180_000);

afterAll(async () => {
  try {
    await fx?.cleanup();
    await ctx?.close();
  } finally {
    await resumeLiveRelay?.();
  }
}, 180_000);

describe('RBAC (L10.1, L12)', () => {
  it('message:read reads; rescan and release need their permissions; read_only_user gets 403', async () => {
    const message = await insertLifecycleMessage(ctx, org, { state: 'quarantined' });
    const readOnly = await fx.createUser(org, { roles: ['read_only_user'] });
    const reader = new LifecycleApi(
      ctx,
      bearer((await loginWithMfa(ctx, fx, readOnly)).accessToken),
    );
    await expect
      .poll(async () => (await reader.lifecycle(message.publicId)).status, POLL)
      .toBe(200);
    await reader.history(message.publicId).expect(200);
    const body = { expectedVersion: message.version, reason };
    await reader.rescan(message.publicId, body, key()).expect(403);
    await reader.release(message.publicId, body, key()).expect(403);

    // Each write permission alone allows only its route.
    const rescanOnly = new LifecycleApi(
      ctx,
      apiKeyHeader(await fx.createApiKey(org, ['message:rescan'])),
    );
    await rescanOnly.release(message.publicId, body, key()).expect(403);
    await rescanOnly.lifecycle(message.publicId).expect(403);
    const releaseOnly = new LifecycleApi(
      ctx,
      apiKeyHeader(await fx.createApiKey(org, ['quarantine:release'])),
    );
    await releaseOnly.rescan(message.publicId, body, key()).expect(403);
    expect((await writerState(ctx, message)).row).toMatchObject({ status: 'quarantined' });

    // security_analyst holds message:rescan and quarantine:release (seed catalog).
    const analyst = await fx.createUser(org, { roles: ['security_analyst'] });
    const analystApi = new LifecycleApi(
      ctx,
      bearer((await loginWithMfa(ctx, fx, analyst)).accessToken),
    );
    const res = await analystApi.rescan(message.publicId, body, key()).expect(202);
    expect(res.body.state).toBe('scanning');
    const history = (await writerState(ctx, message)).history.at(-1)!;
    expect(history).toMatchObject({ actorType: 'user', actorId: analyst.publicId });
  });
});

describe('POST /messages/{messageId}/rescan (L10.2)', () => {
  it('moves the message to scanning with a new round and writes rescan_requested.v1', async () => {
    const message = await insertLifecycleMessage(ctx, org, { state: 'quarantined' });
    const idempotencyKey = key();
    const res = await api
      .rescan(message.publicId, { expectedVersion: message.version, reason }, idempotencyKey)
      .expect(202);
    expect(res.headers['idempotency-replayed']).toBeUndefined();
    expect(res.body).toEqual({
      messageId: message.publicId,
      state: 'scanning',
      version: message.version + 1,
      lifecycleRound: 1,
      rescanEventId: expect.any(String),
      note: RESCAN_NOTE,
    });

    const state = await writerState(ctx, message);
    expect(state.row).toEqual({
      status: 'scanning',
      version: message.version + 1,
      lifecycleRound: 1,
      statusReason: 'admin_rescan',
    });
    const last = state.history.at(-1)!;
    expect(last).toMatchObject({
      version: message.version + 1,
      fromStatus: 'quarantined',
      toStatus: 'scanning',
      reasonCode: 'admin_rescan',
      lifecycleRound: 1,
      actorRole: 'operator',
      actorService: 'api',
      actorType: 'api_key',
      actorId: apiKeyPublicId,
      eventId: null,
      transitionKey: sha(`api:${org.id}:message.rescan:${idempotencyKey}`),
    });
    expect(last.correlationId).toMatch(/^api:/);

    const [stateChanged, rescan] = state.outbox;
    expect(state.outbox).toHaveLength(2);
    expect(stateChanged).toMatchObject({
      eventType: EventTypes.MessageStateChanged,
      eventId: last.stateEventId,
      organizationId: org.id,
    });
    expect(messageStateChangedV1.parse(stateChanged!.payload)).toMatchObject({
      previousState: 'quarantined',
      state: 'scanning',
      actorRole: 'operator',
      actorType: 'api_key',
      actorService: 'api',
      lifecycleRound: 1,
    });
    expect(rescan).toMatchObject({
      eventType: EventTypes.MessageRescanRequested,
      eventId: res.body.rescanEventId,
      organizationId: org.id,
      aggregateType: 'message',
      aggregateId: message.id.toString(),
      correlationId: last.correlationId,
    });
    expect(messageRescanRequestedV1.parse(rescan!.payload)).toEqual({
      messageId: message.id.toString(),
      receivedAt: message.receivedAt.toISOString(),
      direction: 'inbound',
      emlS3Key: message.emlObjectKey,
      lifecycleRound: 1,
      scanKind: 'rescan',
      requestedAt: expect.any(String),
      requestedBy: 'api_key',
    });
    expect(state.events.map((e) => e.eventType)).toEqual(['lifecycle.scanning']);
    expect(state.events[0]).toMatchObject({ actorType: 'api_key', actorId: apiKeyPublicId });

    const audits = await auditRows(message.publicId, 'message.rescan_requested');
    expect(audits).toHaveLength(1);
    expect(audits[0]).toMatchObject({
      actorType: 'api_key',
      actorId: apiKeyPublicId,
      metadata: {
        fromState: 'quarantined',
        toState: 'scanning',
        version: message.version + 1,
        lifecycleRound: 1,
        reason,
        idempotencyKeyHash: sha(idempotencyKey),
        eventIds: [last.stateEventId, res.body.rescanEventId],
      },
    });
    expect(JSON.stringify(audits[0]!.metadata)).not.toContain(idempotencyKey);

    // A rescan of the rescan (E19 from scanning, "the request was lost") opens round 2.
    const again = await api
      .rescan(message.publicId, { expectedVersion: message.version + 1, reason }, key())
      .expect(202);
    expect(again.body).toMatchObject({ version: message.version + 2, lifecycleRound: 2 });
  });

  it('replays the same request: same status and body, replay header, exactly one effect', async () => {
    const message = await insertLifecycleMessage(ctx, org, { state: 'scan_failed' });
    const idempotencyKey = key();
    const body = { expectedVersion: message.version, reason };
    const first = await api.rescan(message.publicId, body, idempotencyKey).expect(202);
    const second = await api.rescan(message.publicId, body, idempotencyKey).expect(202);
    expect(second.headers['idempotency-replayed']).toBe('true');
    expect(second.body).toEqual(first.body);

    const state = await writerState(ctx, message);
    const keyHash = sha(`api:${org.id}:message.rescan:${idempotencyKey}`);
    expect(state.history.filter((h) => h.transitionKey === keyHash)).toHaveLength(1);
    expect(
      state.outbox.filter((o) => o.eventType === EventTypes.MessageRescanRequested),
    ).toHaveLength(1);
    expect(await auditRows(message.publicId, 'message.rescan_requested')).toHaveLength(1);
    const records = await ctx.prisma.apiIdempotencyKey.findMany({
      where: { organizationId: org.id, idempotencyKey },
    });
    expect(records).toHaveLength(1);
    expect(records[0]).toMatchObject({
      operation: 'message.rescan',
      principal: `api_key:${apiKeyPublicId}`,
      resourceId: message.publicId,
      statusCode: 202,
      response: first.body,
    });
    expect(records[0]!.expiresAt.getTime() - records[0]!.createdAt.getTime()).toBeCloseTo(
      24 * 3600_000,
      -4,
    );
  });

  it('refuses the same key with another body (422) and a missing key (400)', async () => {
    const message = await insertLifecycleMessage(ctx, org, { state: 'scanned' });
    const idempotencyKey = key();
    await api
      .rescan(message.publicId, { expectedVersion: message.version, reason }, idempotencyKey)
      .expect(202);
    const reused = await api
      .rescan(
        message.publicId,
        { expectedVersion: message.version, reason: 'a different operator reason' },
        idempotencyKey,
      )
      .expect(422);
    expect(reused.body).toMatchObject({ statusCode: 422, code: 'idempotency_key_reused' });
    // The same key on another message or operation is a reuse too.
    const other = await insertLifecycleMessage(ctx, org, { state: 'scanned' });
    await api
      .rescan(other.publicId, { expectedVersion: other.version, reason }, idempotencyKey)
      .expect(422);
    await api
      .release(message.publicId, { expectedVersion: message.version, reason }, idempotencyKey)
      .expect(422);

    const missing = await api
      .rescan(other.publicId, { expectedVersion: other.version, reason })
      .expect(400);
    expect(missing.body.code).toBe('idempotency_key_required');
    expect((await writerState(ctx, other)).row.status).toBe('scanned');
  });

  it('409 message_version_conflict for a stale version (not stored: the key works after the fix)', async () => {
    const message = await insertLifecycleMessage(ctx, org, { state: 'policy_evaluated' });
    const idempotencyKey = key();
    const stale = await api
      .rescan(message.publicId, { expectedVersion: message.version - 1, reason }, idempotencyKey)
      .expect(409);
    expect(stale.body).toMatchObject({
      statusCode: 409,
      code: 'message_version_conflict',
      currentState: 'policy_evaluated',
      currentVersion: message.version,
    });
    const state = await writerState(ctx, message);
    expect(state.history).toHaveLength(message.version + 1);
    expect(state.outbox).toHaveLength(0);
    expect(state.events).toHaveLength(0); // recordIgnored: false
    await api
      .rescan(message.publicId, { expectedVersion: message.version, reason }, idempotencyKey)
      .expect(202);
  });

  it('409 message_state_conflict from a state E19 does not allow', async () => {
    for (const state of ['persisted', 'delivery_pending', 'delivered'] as const) {
      const message = await insertLifecycleMessage(ctx, org, { state });
      const res = await api
        .rescan(message.publicId, { expectedVersion: message.version, reason }, key())
        .expect(409);
      expect(res.body).toMatchObject({
        code: 'message_state_conflict',
        currentState: state,
        currentVersion: message.version,
      });
      expect((await writerState(ctx, message)).outbox).toHaveLength(0);
    }
  });

  it('serializes concurrent requests: same key → one effect and a replay; same version → one conflict', async () => {
    const message = await insertLifecycleMessage(ctx, org, { state: 'held_for_review' });
    const idempotencyKey = key();
    const body = { expectedVersion: message.version, reason };
    const [a, b] = await Promise.all([
      api.rescan(message.publicId, body, idempotencyKey),
      api.rescan(message.publicId, body, idempotencyKey),
    ]);
    expect([a.status, b.status]).toEqual([202, 202]);
    expect(a.body).toEqual(b.body);
    expect([a, b].filter((r) => r.headers['idempotency-replayed'] === 'true').length).toBe(1);
    let state = await writerState(ctx, message);
    expect(state.history.filter((h) => h.toStatus === 'scanning')).toHaveLength(1);

    const next = { expectedVersion: message.version + 1, reason };
    const results = await Promise.all([
      api.rescan(message.publicId, next, key()),
      api.rescan(message.publicId, next, key()),
    ]);
    expect(results.map((r) => r.status).sort()).toEqual([202, 409]);
    expect(results.find((r) => r.status === 409)!.body.code).toBe('message_version_conflict');
    state = await writerState(ctx, message);
    expect(state.row).toMatchObject({ version: message.version + 2, lifecycleRound: 2 });
  });
});

describe('POST /messages/{messageId}/release (L10.3)', () => {
  it('quarantined → approved (E14): approvals with deliverySeq max + 1 that pass the planner check', async () => {
    const message = await insertLifecycleMessage(ctx, org, {
      state: 'quarantined',
      recipients: [
        { address: 'a@acme.example', status: 'quarantined' },
        { address: 'b@acme.example', status: 'delivered' },
        { address: 'c@acme.example', status: 'pending' },
        { address: 'd@acme.example', status: 'bounced' },
      ],
    });
    await insertDeliveries(ctx, message, [0, 1]);
    const idempotencyKey = key();
    const res = await api
      .release(message.publicId, { expectedVersion: message.version, reason }, idempotencyKey)
      .expect(202);
    expect(res.body).toEqual({
      messageId: message.publicId,
      state: 'approved',
      version: message.version + 1,
      lifecycleRound: 1,
      deliverySeq: 2,
      approvalEventIds: [expect.any(String)],
      recipientCount: 2,
    });
    const state = await writerState(ctx, message);
    expect(state.row).toEqual({
      status: 'approved',
      version: message.version + 1,
      lifecycleRound: 1,
      statusReason: 'quarantine_release',
    });
    expect(state.history.at(-1)).toMatchObject({
      fromStatus: 'quarantined',
      toStatus: 'approved',
      reasonCode: 'quarantine_release',
      actorRole: 'operator',
      lifecycleRound: 1,
    });

    const approvalId = res.body.approvalEventIds[0] as string;
    const payload = await approvalIssued(approvalId, message);
    expect(payload).toEqual({
      messageId: message.id.toString(),
      receivedAt: message.receivedAt.toISOString(),
      deliverySeq: 2,
      source: 'quarantine_release',
      emlS3Key: message.emlObjectKey,
      recipients: [
        { recipientId: message.recipientIds[0]!.toString(), rcptSeq: 0 },
        { recipientId: message.recipientIds[2]!.toString(), rcptSeq: 2 },
      ],
      approvedAt: expect.any(String),
      lifecycleRound: 1,
    });
    // The approval's event id is a UUIDv7.
    expect(approvalId).toMatch(
      /^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/,
    );
    const approvals = state.outbox.filter((o) => o.eventType === EventTypes.DeliveryApproved);
    expect(approvals.map((o) => o.eventId)).toEqual([approvalId]);
    expect(approvals[0]!.correlationId).toMatch(/^api:/);

    expect(state.events.map((e) => e.eventType)).toEqual([
      'lifecycle.approved',
      'delivery.approved',
    ]);
    expect(state.events[1]).toMatchObject({
      sourceService: 'api',
      eventId: approvalId,
      actorType: 'api_key',
      actorId: apiKeyPublicId,
      details: {
        source: 'quarantine_release',
        approvalEventId: approvalId,
        deliverySeq: 2,
        recipientCount: 2,
      },
    });
    const audits = await auditRows(message.publicId, 'message.quarantine_released');
    expect(audits).toHaveLength(1);
    expect(audits[0]!.metadata).toMatchObject({
      fromState: 'quarantined',
      toState: 'approved',
      deliverySeq: 2,
      recipientCount: 2,
      idempotencyKeyHash: sha(idempotencyKey),
      eventIds: [state.history.at(-1)!.stateEventId, approvalId],
    });

    // Replay: same body, one approval, one audit row.
    const replay = await api
      .release(message.publicId, { expectedVersion: message.version, reason }, idempotencyKey)
      .expect(202);
    expect(replay.headers['idempotency-replayed']).toBe('true');
    expect(replay.body).toEqual(res.body);
    expect(
      (await writerState(ctx, message)).outbox.filter(
        (o) => o.eventType === EventTypes.DeliveryApproved,
      ),
    ).toHaveLength(1);
    expect(await auditRows(message.publicId, 'message.quarantine_released')).toHaveLength(1);
  });

  it('turns the released quarantined recipients into pending; the others keep their status', async () => {
    const message = await insertLifecycleMessage(ctx, org, {
      state: 'quarantined',
      recipients: [
        { address: 'q1@acme.example', status: 'quarantined' },
        { address: 'q2@acme.example', status: 'quarantined' },
        { address: 'p@acme.example', status: 'pending' },
        { address: 'd@acme.example', status: 'delivered' },
      ],
    });
    await api
      .release(message.publicId, { expectedVersion: message.version, reason }, key())
      .expect(202);
    expect(await recipientStatuses(message)).toEqual([
      'pending',
      'pending',
      'pending',
      'delivered',
    ]);
  });

  it('a release of more than 1000 recipients: two approvals, every released recipient pending', async () => {
    const recipients = Array.from({ length: 1001 }, (_, i) => ({
      address: `bulk${i}@acme.example`,
      status: 'quarantined' as const,
    }));
    const message = await insertLifecycleMessage(ctx, org, { state: 'quarantined', recipients });
    const res = await api
      .release(message.publicId, { expectedVersion: message.version, reason }, key())
      .expect(202);
    expect(res.body).toMatchObject({ recipientCount: 1001, deliverySeq: 1 });
    const ids = res.body.approvalEventIds as string[];
    expect(ids).toHaveLength(2);
    const chunks = await Promise.all(ids.map((id) => approvalIssued(id, message)));
    expect(chunks.map((c) => (c as { recipients: unknown[] }).recipients.length)).toEqual([
      1000, 1,
    ]);
    const statuses = await recipientStatuses(message);
    expect(statuses).toHaveLength(1001);
    expect(statuses.every((s) => s === 'pending')).toBe(true);
  });

  it('held_for_review → approved (E15, review_release), deliverySeq 1 without deliveries', async () => {
    const message = await insertLifecycleMessage(ctx, org, { state: 'held_for_review' });
    const res = await api
      .release(message.publicId, { expectedVersion: message.version, reason }, key())
      .expect(202);
    expect(res.body).toMatchObject({ deliverySeq: 1, lifecycleRound: 1, recipientCount: 2 });
    expect((await writerState(ctx, message)).row.statusReason).toBe('review_release');
    await approvalIssued(res.body.approvalEventIds[0] as string, message);
  });

  it('409 quarantine_workflow_required with per-recipient quarantine entries', async () => {
    const message = await insertLifecycleMessage(ctx, org, { state: 'quarantined' });
    await insertQuarantineEntry(ctx, message);
    const res = await api
      .release(message.publicId, { expectedVersion: message.version, reason }, key())
      .expect(409);
    expect(res.body).toMatchObject({
      code: 'quarantine_workflow_required',
      currentState: 'quarantined',
      currentVersion: message.version,
    });
    expect((await writerState(ctx, message)).row.status).toBe('quarantined');
  });

  it('409 no_releasable_recipients when no recipient is pending or quarantined', async () => {
    const message = await insertLifecycleMessage(ctx, org, {
      state: 'quarantined',
      recipients: [{ address: 'x@acme.example', status: 'delivered' }],
    });
    const res = await api
      .release(message.publicId, { expectedVersion: message.version, reason }, key())
      .expect(409);
    expect(res.body.code).toBe('no_releasable_recipients');
    expect((await writerState(ctx, message)).outbox).toHaveLength(0);
  });

  it('409 message_state_conflict from approved, scanning and delivered; 409 version conflict first', async () => {
    for (const state of ['approved', 'scanning', 'delivered'] as const) {
      const message = await insertLifecycleMessage(ctx, org, { state });
      const res = await api
        .release(message.publicId, { expectedVersion: message.version, reason }, key())
        .expect(409);
      expect(res.body).toMatchObject({ code: 'message_state_conflict', currentState: state });
    }
    const stale = await insertLifecycleMessage(ctx, org, { state: 'quarantined' });
    await insertQuarantineEntry(ctx, stale);
    const res = await api
      .release(stale.publicId, { expectedVersion: stale.version + 3, reason }, key())
      .expect(409);
    expect(res.body.code).toBe('message_version_conflict');
  });

  it('404 for an unknown message', async () => {
    const res = await api.release(unknownId(), { expectedVersion: 0, reason }, key()).expect(404);
    expect(res.body).toMatchObject({ code: 'message_not_found' });
    await api.rescan(unknownId(), { expectedVersion: 0, reason }, key()).expect(404);
  });
});

describe('GET /messages/{messageId}/lifecycle and /history (L12)', () => {
  it('reads through the replica: state, counts, parse, deliverySeq and actions', async () => {
    expect(ctx.get(PrismaReadService).status().mode).toBe('reader');
    const message = await insertLifecycleMessage(ctx, org, {
      state: 'quarantined',
      recipients: [
        { address: 'a@acme.example', status: 'quarantined' },
        { address: 'b@acme.example', status: 'quarantined' },
        { address: 'c@acme.example', status: 'delivered' },
      ],
    });
    await insertDeliveries(ctx, message, [0]);
    await ctx.prisma.emailMessageParse.create({
      data: {
        receivedAt: message.receivedAt,
        messageId: message.id,
        organizationId: org.id,
        status: 'parsed',
        parserVersion: 'fixture',
        startedAt: message.receivedAt,
        completedAt: new Date(message.receivedAt.getTime() + 500),
      },
    });
    await expect
      .poll(
        async () =>
          ((await api.lifecycle(message.publicId)).body as { parse?: { status?: string } }).parse
            ?.status,
        POLL,
      )
      .toBe('parsed');
    const res = await api.lifecycle(message.publicId).expect(200);
    expect(res.body).toEqual({
      messageId: message.publicId,
      receivedAt: message.receivedAt.toISOString(),
      direction: 'inbound',
      state: 'quarantined',
      statusReason: null,
      version: message.version,
      lifecycleRound: 0,
      statusChangedAt: message.receivedAt.toISOString(),
      parse: {
        status: 'parsed',
        completedAt: new Date(message.receivedAt.getTime() + 500).toISOString(),
      },
      recipients: { total: 3, byStatus: { delivered: 1, quarantined: 2 } },
      deliverySeq: 0,
      actions: { rescan: true, release: true },
    });
    const text = JSON.stringify(res.body);
    expect(text).not.toContain(`"${message.id.toString()}"`);
    expect(text).not.toContain('acme.example');
  });

  it('pages the history oldest first, shows legacy rows and operator rows', async () => {
    const message = await insertLifecycleMessage(ctx, org, { state: 'quarantined', legacy: true });
    await api
      .rescan(message.publicId, { expectedVersion: message.version, reason }, key())
      .expect(202);
    const versions: number[] = [];
    let cursor: string | null = null;
    const pages: unknown[][] = [];
    await expect
      .poll(
        async () =>
          ((await api.history(message.publicId, '?limit=10')).body as { data?: unknown[] }).data
            ?.length,
        POLL,
      )
      .toBe(4);
    do {
      const query: string = `?limit=3${cursor ? `&cursor=${cursor}` : ''}`;
      const res = await api.history(message.publicId, query).expect(200);
      pages.push(res.body.data as unknown[]);
      for (const entry of res.body.data as Array<{ version: number }>) versions.push(entry.version);
      cursor = res.body.nextCursor as string | null;
    } while (cursor !== null);
    expect(versions).toEqual([0, 1, 2, 3]);
    expect(pages.map((p) => p.length)).toEqual([3, 1]);
    const all = (await api.history(message.publicId, '?limit=10').expect(200)).body.data;
    expect(all[0]).toEqual({
      version: 0,
      fromState: null,
      toState: 'received',
      reasonCode: 'lifecycle_backfill',
      lifecycleRound: 0,
      actor: { role: 'legacy', type: 'system', service: 'legacy', id: null },
      causationEventId: null,
      correlationId: null,
      occurredAt: null,
      changedAt: message.receivedAt.toISOString(),
    });
    expect(all[3]).toMatchObject({
      version: 3,
      fromState: 'quarantined',
      toState: 'scanning',
      reasonCode: 'admin_rescan',
      lifecycleRound: 1,
      actor: { role: 'operator', type: 'api_key', service: 'api', id: apiKeyPublicId },
      correlationId: expect.stringMatching(/^api:/),
    });
    await api.history(message.publicId, '?cursor=not-a-cursor').expect(400);
  });

  it('404 for an unknown message', async () => {
    expect((await api.lifecycle(unknownId()).expect(404)).body.code).toBe('message_not_found');
    await api.history(unknownId()).expect(404);
  });

  it('exposes the operation metric on /metrics', async () => {
    const text = (await ctx.http.get('/metrics').expect(200)).text;
    expect(text).toMatch(
      /api_message_lifecycle_operations_total\{operation="rescan",outcome="applied"/,
    );
    expect(text).toMatch(
      /api_message_lifecycle_operations_total\{operation="rescan",outcome="replayed"/,
    );
    expect(text).toMatch(
      /api_message_lifecycle_operations_total\{operation="release",outcome="conflict"/,
    );
    expect(text).toMatch(
      /lifecycle_transitions_total\{from="quarantined",to="scanning",result="applied"/,
    );
  });
});

describe('reads with the replica unusable (writer fallback)', () => {
  let fallback: IntegrationApp;

  beforeAll(async () => {
    // An unreachable replica: PrismaReadService probes, fails and reads from the writer.
    fallback = await createIntegrationApp({
      DATABASE_READ_URL: 'mysql://reader:unused@127.0.0.1:1/email_gateway',
    });
  });

  afterAll(async () => {
    await fallback?.close();
  });

  it('answers from the writer immediately after a write', async () => {
    expect(fallback.get(PrismaReadService).status().mode).toBe('writer-fallback');
    const viaFallback = new LifecycleApi(fallback, api.headers);
    const message = await insertLifecycleMessage(ctx, org, { state: 'held_for_review' });
    const res = await viaFallback.lifecycle(message.publicId).expect(200);
    expect(res.body).toMatchObject({ state: 'held_for_review', version: message.version });
    await viaFallback
      .release(message.publicId, { expectedVersion: message.version, reason }, key())
      .expect(202);
    // Read-after-write on the writer: the new state shows at once.
    const after = await viaFallback.lifecycle(message.publicId).expect(200);
    expect(after.body).toMatchObject({
      state: 'approved',
      statusReason: 'review_release',
      version: message.version + 1,
      lifecycleRound: 1,
      actions: { rescan: false, release: false },
    });
    const history = await viaFallback.history(message.publicId).expect(200);
    expect(history.body.data.at(-1)).toMatchObject({
      toState: 'approved',
      reasonCode: 'review_release',
    });
  });
});
