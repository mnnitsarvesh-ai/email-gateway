/**
 * Step AI-2 mail-operation write tools through chat (docs/plan/steps/29-ai-chat-confirmations-
 * mail-writes.md D1, D2, D4, §9 item 4; the `testedBy` of the 20 quarantine, message, recipient
 * suppression and saved-view writes in docs/assistant/UI_TO_CHAT_CAPABILITY_MATRIX.md): each write
 * is proposed through a directive turn (`/tool <name> <json>`, the deterministic fake provider;
 * never a real LLM), confirmed through `POST /assistant/confirmations/{id}/confirm` (password +
 * TOTP for the high-risk ones unless the session's window is open) and the api's state is
 * asserted on the writer. The api listens on its ephemeral loopback port: precondition reads and
 * confirmed writes go through the real pipeline (RBAC, MFA, separation of duties, idempotency).
 *
 * Covered: quarantine release (direct → queued; approval required → `202` executed with the
 * approval pending; the requester approving their own request is refused by the api and the
 * confirmation fails; another user approves through chat), reject, delete (re-auth), request
 * release, approvals deny and cancel, manual quarantine, quarantine settings, the self-service
 * release / request / preferences of a mailbox user, bulk (preview of the first 25 of 26 items,
 * re-auth), message rescan and release (the api's `409 quarantine_workflow_required` as a failed
 * confirmation), recipient suppression create / delete (re-auth), saved view create / update /
 * remove. `Idempotency-Key` = the confirmation id where the route requires one, and a request
 * with that key replays the stored answer. A lagging replica (a REPEATABLE READ snapshot standing
 * in for the replica) never hides a change from the confirm-time re-read (AI-2 review).
 *
 * Messages, rounds and entries are SQL fixtures (as the quarantine suite builds them). Synthetic
 * `it-*` organizations only.
 */
// @covers post /api/v1/assistant/conversations/:conversationId/turns
// @covers post /api/v1/assistant/confirmations/:confirmationId/confirm
// @covers post /api/v1/quarantine/entries/:entryId/release
// @covers post /api/v1/quarantine/entries/:entryId/reject
// @covers post /api/v1/quarantine/entries/:entryId/delete
// @covers post /api/v1/quarantine/entries/:entryId/request-release
// @covers post /api/v1/quarantine/entries
// @covers post /api/v1/quarantine/approvals/:approvalId/approve
// @covers post /api/v1/quarantine/approvals/:approvalId/deny
// @covers post /api/v1/quarantine/approvals/:approvalId/cancel
// @covers post /api/v1/quarantine/bulk
// @covers put /api/v1/quarantine/settings
// @covers post /api/v1/quarantine/me/entries/:entryId/release
// @covers post /api/v1/quarantine/me/entries/:entryId/request-release
// @covers put /api/v1/quarantine/me/preferences
// @covers post /api/v1/messages/:messageId/rescan
// @covers post /api/v1/messages/:messageId/release
// @covers post /api/v1/recipients/suppressions
// @covers delete /api/v1/recipients/suppressions/:suppressionId
// @covers post /api/v1/saved-views
// @covers put /api/v1/saved-views/:viewId
// @covers delete /api/v1/saved-views/:viewId
import { randomUUID } from 'node:crypto';
import { PrismaReadService, type ReaderStatus } from '@email-gateway/common';
import type { Prisma } from '@email-gateway/database';
import { afterAll, beforeAll, describe, expect, it, vi } from 'vitest';
import type { IntegrationApp } from './support/app';
import {
  ALL_TENANT_PERMISSIONS,
  call,
  clearAssistantCounters,
  confirm,
  confirmationRow,
  createAssistantApp,
  directive,
  enableAssistant,
  executionRow,
  member,
  type Member,
  memberWith,
  platformMember,
  propose,
  type Proposal,
  reauthOf,
  recordLoopback,
  type RecordedCall,
  waitForRead,
} from './support/assistant';
import {
  createFixtures,
  type FixtureOrganization,
  type Fixtures,
  uniqueSuffix,
} from './support/fixtures';
import { idem } from './support/http';
import { insertLifecycleMessage, type LifecycleMessage } from './support/lifecycle';
import { pauseLiveRelay } from './support/live-relay';
import { deleteMessagesData } from './support/messages-data';
import {
  deleteQuarantineFixtures,
  type EntryOptions,
  type FixtureEntry,
  insertApproval,
  insertCompletedRound,
  insertEntry,
} from './support/quarantine';

const Q = '/api/v1/quarantine';
const STALE = 999;
const reason = 'reviewed through the assistant';

let ctx: IntegrationApp;
let fx: Fixtures;
let org: FixtureOrganization;
let admin: Member;
let admin2: Member;
let mailbox: Member;
let resumeLiveRelay: (() => Promise<void>) | undefined;

interface Confirmed {
  proposal: Proposal;
  res: Awaited<ReturnType<typeof confirm>>;
  calls: RecordedCall[];
}

/** Proposes `tool` as `who` through a directive turn and confirms it (re-auth when needed). */
async function chat(who: Member, tool: string, args: Record<string, unknown>): Promise<Confirmed> {
  const proposal = await propose(ctx, who, directive(tool, args));
  expect(proposal.confirmation.tool).toBe(tool);
  const recorder = recordLoopback(ctx);
  try {
    const reauth =
      proposal.confirmation.requiresReauth && !proposal.confirmation.reauthFresh
        ? await reauthOf(fx, who)
        : undefined;
    const res = await confirm(ctx, who, proposal, reauth ? { reauth } : {});
    return { proposal, res, calls: [...recorder.calls] };
  } finally {
    recorder.restore();
  }
}

/** The confirmed write's loopback call (exactly one non-GET request). */
function writeOf(result: Confirmed): RecordedCall {
  const writes = result.calls.filter((c) => c.method !== 'GET');
  expect(writes).toHaveLength(1);
  return writes[0]!;
}

/** An executed confirmation with this HTTP status; returns the write's loopback call. */
function executed(result: Confirmed, httpStatus: number): RecordedCall {
  expect(result.res.status, JSON.stringify(result.res.body)).toBe(200);
  expect(result.res.body.confirmation).toMatchObject({
    status: 'executed',
    result: { httpStatus, error: null },
  });
  expect(result.res.body.execution).toMatchObject({
    tool: result.proposal.confirmation.tool,
    status: 'succeeded',
    httpStatus,
  });
  return writeOf(result);
}

/** A failed confirmation: the confirm worked (200), the operation refused. */
function failed(result: Confirmed, httpStatus: number, code: string): RecordedCall {
  expect(result.res.status, JSON.stringify(result.res.body)).toBe(200);
  expect(result.res.body.confirmation).toMatchObject({
    status: 'failed',
    result: { httpStatus, error: code },
  });
  expect(result.res.body.execution).toMatchObject({
    status: 'failed',
    httpStatus,
    errorCode: code,
  });
  expect(result.res.body.execution.card).toMatchObject({ kind: 'error' });
  return writeOf(result);
}

/** A `required`-idempotency route: the key is the confirmation id and is stored. */
async function keyedByConfirmation(result: Confirmed): Promise<void> {
  expect(writeOf(result).idempotencyKey).toBe(result.proposal.confirmation.id);
  const stored = await ctx.prisma.apiIdempotencyKey.findFirst({
    where: { organizationId: org.id, idempotencyKey: result.proposal.confirmation.id },
  });
  expect(stored).not.toBeNull();
}

/** Replays the stored request of a confirmation with `Idempotency-Key` = its id. */
async function replay(result: Confirmed, who: Member = admin) {
  const row = await confirmationRow(ctx, result.proposal.confirmation.id);
  const request = row.request as { method: string; path: string; body: object | null };
  const method = request.method.toLowerCase() as 'post' | 'put' | 'delete';
  const req = call(ctx, who.headers, method, request.path).set(
    idem(result.proposal.confirmation.id),
  );
  return request.body === null ? req : req.send(request.body);
}

/** Audit rows of `action` carrying the result execution's correlation id. */
async function operationAudited(result: Confirmed, action: string): Promise<void> {
  const execution = await executionRow(ctx, result.res.body.execution.id as string);
  const rows = await ctx.prisma.auditLog.findMany({
    where: { organizationId: org.id, action, correlationId: execution.correlationId },
  });
  expect(rows.length, action).toBeGreaterThanOrEqual(1);
}

const entryRow = (publicId: string) =>
  ctx.prisma.quarantineMessage.findFirstOrThrow({ where: { publicId } });

/** A held entry on a fresh `quarantined` message, visible on the replica to `reader`. */
async function heldEntry(
  o: EntryOptions & {
    recipient?: string;
    messageState?: 'quarantined' | 'held_for_review';
    round?: boolean;
    reader?: Member;
  } = {},
): Promise<{ message: LifecycleMessage; entry: FixtureEntry }> {
  const message = await insertLifecycleMessage(ctx, org, {
    state: o.messageState ?? 'quarantined',
    recipients: [
      { address: o.recipient ?? `rcpt-${uniqueSuffix()}@acme.example`, status: 'quarantined' },
    ],
  });
  const { messageState: _s, recipient: _r, round, reader, ...entryOptions } = o;
  const entry = await insertEntry(ctx, message, entryOptions);
  if (round) await insertCompletedRound(ctx, message);
  const who = reader ?? admin;
  const self = who === mailbox;
  await waitForRead(ctx, who, `${Q}/${self ? 'me/' : ''}entries/${entry.publicId}`);
  return { message, entry };
}

beforeAll(async () => {
  // Releases and rescans write outbox rows; a live event-relay must not publish them.
  resumeLiveRelay = await pauseLiveRelay();
  const assistant = await createAssistantApp();
  ctx = assistant.ctx;
  fx = createFixtures(ctx);
  const operator = await platformMember(ctx, fx);
  org = await fx.createOrganization();
  fx.registerCleanup(() => deleteMessagesData(ctx, [org.id]));
  fx.registerCleanup(() => deleteQuarantineFixtures(ctx, [org.id]));
  const role = await fx.createCustomRole(org, [...ALL_TENANT_PERMISSIONS]);
  admin = await member(ctx, fx, org, [role]);
  admin2 = await member(ctx, fx, org, [role]);
  mailbox = await memberWith(
    ctx,
    fx,
    org,
    { permissions: ['quarantine:self'] },
    { mfa: false, email: `mailbox-${uniqueSuffix()}@acme.example` },
  );
  await enableAssistant(ctx, operator, org, admin);
}, 180_000);

afterAll(async () => {
  try {
    if (ctx && org) await clearAssistantCounters(ctx, [org.id]);
    await fx?.cleanup();
    await ctx?.close();
  } finally {
    await resumeLiveRelay?.();
  }
}, 180_000);

describe('quarantine entries through chat', () => {
  it('quarantine_entries_release (direct): queued, keyed by the confirmation id, replayable', async () => {
    const { entry } = await heldEntry({ round: true });
    const before = await entryRow(entry.publicId);
    const result = await chat(admin, 'quarantine_entries_release', {
      entryId: entry.publicId,
      body: { reason, expectedRowVersion: STALE },
    });
    expect(result.proposal.confirmation.risk).toBe('medium');
    executed(result, 202);
    expect(result.res.body.execution.card).toBeDefined();
    await keyedByConfirmation(result);
    const row = await confirmationRow(ctx, result.proposal.confirmation.id);
    expect((row.request as { body: { expectedRowVersion: number } }).body.expectedRowVersion).toBe(
      before.rowVersion,
    );
    expect((await entryRow(entry.publicId)).status).toBe('releasing');
    // The same request with the confirmation id as key answers the stored response.
    const again = await replay(result);
    expect(again.status).toBe(202);
    expect(again.headers['idempotency-replayed']).toBe('true');
    expect(
      await ctx.prisma.quarantineReleaseLog.count({ where: { quarantineMessageId: entry.id } }),
    ).toBe(1);
  });

  it('approval required: 202 executed with the approval pending; own approval refused; another user approves', async () => {
    const { entry } = await heldEntry();
    const released = await chat(admin, 'quarantine_entries_release', {
      entryId: entry.publicId,
      body: { reason },
    });
    executed(released, 202);
    const approval = await ctx.prisma.quarantineApprovalRequest.findFirstOrThrow({
      where: { organizationId: org.id, quarantineMessageId: entry.id },
    });
    expect(approval).toMatchObject({
      kind: 'release_approval',
      status: 'pending',
      requestedByUserId: admin.user.id,
    });
    expect((await entryRow(entry.publicId)).status).toBe('pending_approval');
    await waitForRead(ctx, admin, `${Q}/approvals/${approval.publicId}`);

    // Separation of duties stays in the api: the requester's own approval fails.
    const own = await chat(admin, 'quarantine_approvals_approve', {
      approvalId: approval.publicId,
      body: { reason },
    });
    failed(own, 403, 'quarantine_approval_forbidden');
    expect(
      (await ctx.prisma.quarantineApprovalRequest.findUniqueOrThrow({ where: { id: approval.id } }))
        .status,
    ).toBe('pending');

    const approved = await chat(admin2, 'quarantine_approvals_approve', {
      approvalId: approval.publicId,
      body: { reason },
    });
    executed(approved, 202);
    await keyedByConfirmation(approved);
    expect(
      await ctx.prisma.quarantineApprovalRequest.findUniqueOrThrow({ where: { id: approval.id } }),
    ).toMatchObject({ status: 'approved', decidedByUserId: admin2.user.id });
    expect((await entryRow(entry.publicId)).status).toBe('releasing');
    await operationAudited(approved, 'quarantine.approval_approved');
  });

  it('quarantine_entries_reject (medium) and quarantine_entries_delete (high, re-auth)', async () => {
    const a = await heldEntry();
    const rejected = await chat(admin, 'quarantine_entries_reject', {
      entryId: a.entry.publicId,
      body: { reason },
    });
    executed(rejected, 200);
    await keyedByConfirmation(rejected);
    expect((await entryRow(a.entry.publicId)).status).toBe('rejected');

    const b = await heldEntry();
    const proposal = await propose(
      ctx,
      admin2,
      directive('quarantine_entries_delete', { entryId: b.entry.publicId, body: { reason } }),
    );
    expect(proposal.confirmation).toMatchObject({ risk: 'high', requiresReauth: true });
    expect((await confirm(ctx, admin2, proposal)).status).toBe(401);
    const res = await confirm(ctx, admin2, proposal, { reauth: await reauthOf(fx, admin2) });
    expect(res.status, JSON.stringify(res.body)).toBe(200);
    expect(res.body.confirmation).toMatchObject({
      status: 'executed',
      result: { httpStatus: 200 },
    });
    expect((await entryRow(b.entry.publicId)).status).toBe('deleted');
    expect((await confirmationRow(ctx, proposal.confirmation.id)).reauthUsed).toBe(true);
  });

  it('quarantine_entries_request_release, quarantine_approvals_cancel and quarantine_approvals_deny', async () => {
    const { entry } = await heldEntry();
    const requested = await chat(admin, 'quarantine_entries_request_release', {
      entryId: entry.publicId,
      body: { reason },
    });
    executed(requested, 202);
    await keyedByConfirmation(requested);
    const approval = await ctx.prisma.quarantineApprovalRequest.findFirstOrThrow({
      where: { organizationId: org.id, quarantineMessageId: entry.id, status: 'pending' },
    });
    expect(approval.kind).toBe('release_request');
    await waitForRead(ctx, admin, `${Q}/approvals/${approval.publicId}`);
    const cancelled = await chat(admin, 'quarantine_approvals_cancel', {
      approvalId: approval.publicId,
      body: { reason },
    });
    executed(cancelled, 200);
    expect(
      (await ctx.prisma.quarantineApprovalRequest.findUniqueOrThrow({ where: { id: approval.id } }))
        .status,
    ).toBe('cancelled');
    expect((await entryRow(entry.publicId)).status).toBe('held');

    // Deny of a policy review rejects the entry (E18).
    const review = await heldEntry({
      kind: 'review',
      messageState: 'held_for_review',
      state: 'pending_approval',
    });
    const pr = await insertApproval(ctx, review.entry, org.id, {
      kind: 'policy_review',
      reasons: ['review'],
    });
    await waitForRead(ctx, admin, `${Q}/approvals/${pr.publicId}`);
    const denied = await chat(admin, 'quarantine_approvals_deny', {
      approvalId: pr.publicId,
      body: { reason },
    });
    executed(denied, 200);
    expect((await entryRow(review.entry.publicId)).status).toBe('rejected');
    await operationAudited(denied, 'quarantine.approval_denied');
  });

  it('quarantine_entries_manual (low): a held_for_review message is quarantined (E16)', async () => {
    const review = await heldEntry({
      kind: 'review',
      messageState: 'held_for_review',
      state: 'pending_approval',
    });
    await insertApproval(ctx, review.entry, org.id, { kind: 'policy_review', reasons: ['review'] });
    await waitForRead(ctx, admin, `/api/v1/messages/${review.message.publicId}`);
    const result = await chat(admin, 'quarantine_entries_manual', {
      body: { messageId: review.message.publicId, reason },
    });
    expect(result.proposal.confirmation.risk).toBe('low');
    executed(result, 201);
    await keyedByConfirmation(result);
    expect(await entryRow(review.entry.publicId)).toMatchObject({
      kind: 'quarantine',
      status: 'held',
    });
  });

  it('quarantine_tools_bulk (high): previews the first 25 of 26 items, re-authenticated', async () => {
    const entries: FixtureEntry[] = [];
    for (let i = 0; i < 26; i += 1) {
      const message = await insertLifecycleMessage(ctx, org, {
        state: 'quarantined',
        recipients: [
          { address: `bulk-${i}-${uniqueSuffix()}@acme.example`, status: 'quarantined' },
        ],
      });
      entries.push(await insertEntry(ctx, message, {}));
    }
    for (const entry of entries) await waitForRead(ctx, admin, `${Q}/entries/${entry.publicId}`);
    const ids = entries.map((e) => e.publicId);
    const proposal = await propose(
      ctx,
      admin2,
      directive('quarantine_tools_bulk', { body: { action: 'reject', ids, reason } }),
    );
    expect(proposal.confirmation).toMatchObject({ risk: 'high', requiresReauth: true });
    const impact = proposal.confirmation.summary!.impact;
    expect(impact).toContain('26 entries are processed with "reject".');
    expect(impact).toContain('Current state of the previewed items: 25 held.');
    expect(impact).toContain('1 more not previewed.');
    const row = await confirmationRow(ctx, proposal.confirmation.id);
    const preconditions = row.preconditions as { items: unknown[]; total: number };
    expect(preconditions.items).toHaveLength(25);
    expect(preconditions.total).toBe(26);

    const reauth = proposal.confirmation.reauthFresh ? undefined : await reauthOf(fx, admin2);
    const res = await confirm(ctx, admin2, proposal, reauth ? { reauth } : {});
    expect(res.status, JSON.stringify(res.body)).toBe(200);
    expect(res.body.confirmation).toMatchObject({
      status: 'executed',
      result: { httpStatus: 200 },
    });
    const states = await ctx.prisma.quarantineMessage.findMany({
      where: { publicId: { in: ids } },
      select: { status: true },
    });
    expect(states.every((s) => s.status === 'rejected')).toBe(true);
    expect(
      await ctx.prisma.apiIdempotencyKey.count({
        where: { organizationId: org.id, idempotencyKey: proposal.confirmation.id },
      }),
    ).toBe(1);
  });
});

describe('quarantine settings and self-service through chat', () => {
  it('quarantine_tools_put_settings (medium), then the mailbox user’s self-service writes', async () => {
    const settings = await chat(admin, 'quarantine_tools_put_settings', {
      body: {
        settings: { endUser: { selfRelease: true, selfReleaseReasons: ['spam'] } },
        expectedRowVersion: STALE,
      },
    });
    executed(settings, 200);
    expect(writeOf(settings).idempotencyKey).toBeNull();
    const stored = await ctx.prisma.quarantineSettings.findFirstOrThrow({
      where: { organizationId: org.id },
    });
    expect(stored.settings).toMatchObject({ endUser: { selfRelease: true } });
    await waitForRead(ctx, admin, `${Q}/settings`, (b) => b.rowVersion === stored.rowVersion);

    // Self release of the mailbox user's own spam entry (fresh clean round).
    const own = await heldEntry({
      recipient: mailbox.user.email,
      reason: 'spam',
      riskLevel: 'low',
      round: true,
      reader: mailbox,
    });
    const released = await chat(mailbox, 'quarantine_self_release', {
      entryId: own.entry.publicId,
      body: { reason: 'mine' },
    });
    executed(released, 202);
    await keyedByConfirmation(released);
    expect((await entryRow(own.entry.publicId)).status).toBe('releasing');

    // A reason self-release does not cover: request it instead.
    const bulky = await heldEntry({
      recipient: mailbox.user.email,
      reason: 'bulk',
      riskLevel: 'low',
      reader: mailbox,
    });
    const requested = await chat(mailbox, 'quarantine_self_request_release', {
      entryId: bulky.entry.publicId,
      body: { reason: 'mine' },
    });
    executed(requested, 202);
    expect((await entryRow(bulky.entry.publicId)).status).toBe('pending_approval');

    const prefs = await chat(mailbox, 'quarantine_self_put_preferences', {
      body: { digestOptOut: true },
    });
    executed(prefs, 200);
    expect(prefs.proposal.confirmation.risk).toBe('low');
    const page = await call(ctx, mailbox.headers, 'get', `${Q}/me/preferences`);
    expect(page.body.digestOptOut).toBe(true);
  });
});

describe('message lifecycle through chat', () => {
  it('message_lifecycle_rescan (medium): 202, keyed by the confirmation id', async () => {
    const message = await insertLifecycleMessage(ctx, org, { state: 'scan_failed' });
    await waitForRead(ctx, admin, `/api/v1/messages/${message.publicId}`);
    const result = await chat(admin, 'message_lifecycle_rescan', {
      messageId: message.publicId,
      body: { reason: 'rescan requested in chat', expectedVersion: STALE },
    });
    executed(result, 202);
    await keyedByConfirmation(result);
    const row = await ctx.prisma.emailMessage.findFirstOrThrow({ where: { id: message.id } });
    expect(row).toMatchObject({ status: 'scanning', lifecycleRound: 1 });
    const again = await replay(result);
    expect(again.status).toBe(202);
    expect(again.headers['idempotency-replayed']).toBe('true');
    expect(again.body).toMatchObject({ messageId: message.publicId, state: 'scanning' });
  });

  it('message_lifecycle_release: the api’s 409 quarantine_workflow_required fails the confirmation', async () => {
    const { message } = await heldEntry();
    await waitForRead(ctx, admin, `/api/v1/messages/${message.publicId}`);
    const result = await chat(admin, 'message_lifecycle_release', {
      messageId: message.publicId,
      body: { reason: 'release requested in chat', expectedVersion: 0 },
    });
    const write = failed(result, 409, 'quarantine_workflow_required');
    expect(write.idempotencyKey).toBe(result.proposal.confirmation.id);
    expect(
      (await ctx.prisma.emailMessage.findFirstOrThrow({ where: { id: message.id } })).status,
    ).toBe('quarantined');
  });
});

describe('recipient suppressions and saved views through chat', () => {
  it('recipient_suppressions_create (low) and recipient_suppressions_delete (high, re-auth)', async () => {
    const address = `chat-${randomUUID().slice(0, 8)}@example.org`;
    const created = await chat(admin, 'recipient_suppressions_create', { body: { address } });
    executed(created, 201);
    await keyedByConfirmation(created);
    const row = await ctx.prisma.deliverySuppression.findFirstOrThrow({
      where: { organizationId: org.id, address },
    });
    expect(row).toMatchObject({ reason: 'manual', createdByUserId: admin.user.id });
    await operationAudited(created, 'recipient_suppression.created');
    const id = row.id.toString();
    await waitForRead(ctx, admin, `/api/v1/recipients/suppressions/${id}`);

    const proposal = await propose(
      ctx,
      admin2,
      directive('recipient_suppressions_delete', { suppressionId: id }),
    );
    expect(proposal.confirmation).toMatchObject({ risk: 'high', requiresReauth: true });
    const reauth = proposal.confirmation.reauthFresh ? undefined : await reauthOf(fx, admin2);
    const res = await confirm(ctx, admin2, proposal, reauth ? { reauth } : {});
    expect(res.status, JSON.stringify(res.body)).toBe(200);
    expect(res.body.confirmation.status).toBe('executed');
    expect(await ctx.prisma.deliverySuppression.count({ where: { id: row.id } })).toBe(0);
  });

  it('saved_views_create (low), saved_views_update (medium) and saved_views_remove (low)', async () => {
    const definition = {
      version: 1,
      filters: { verdict: 'phishing' },
      sort: '-receivedAt',
      range: { kind: 'relative', preset: '24h' },
      columns: null,
    };
    const name = `it chat view ${randomUUID().slice(0, 8)}`;
    const created = await chat(admin, 'saved_views_create', {
      body: { kind: 'message_explorer', name, definition },
    });
    executed(created, 201);
    expect(writeOf(created).idempotencyKey).toBeNull();
    const view = await ctx.prisma.savedView.findFirstOrThrow({
      where: { organizationId: org.id, userId: admin.user.id, name },
    });
    await waitForRead(ctx, admin, `/api/v1/saved-views/${view.publicId}`);

    const renamed = `${name} renamed`;
    const updated = await chat(admin, 'saved_views_update', {
      viewId: view.publicId,
      body: { name: renamed, definition, expectedRowVersion: STALE },
    });
    executed(updated, 200);
    const after = await ctx.prisma.savedView.findUniqueOrThrow({ where: { id: view.id } });
    expect(after).toMatchObject({ name: renamed, rowVersion: view.rowVersion + 1 });
    await waitForRead(
      ctx,
      admin,
      `/api/v1/saved-views/${view.publicId}`,
      (b) => b.name === renamed,
    );

    const removed = await chat(admin, 'saved_views_remove', { viewId: view.publicId });
    executed(removed, 204);
    expect(await ctx.prisma.savedView.count({ where: { id: view.id } })).toBe(0);
  });
});

/**
 * A lagging replica (step AI-2 review): `PrismaReadService` is put in `reader` mode on a
 * REPEATABLE READ transaction of the writer whose snapshot is taken now, so every replica read
 * of the api (the GET routes) keeps seeing the state of this moment while the writer moves on;
 * reads inside `runReadsOnWriter` still go to the writer. Returns the restore function.
 */
async function laggingReplica(): Promise<() => Promise<void>> {
  const service = ctx.get(PrismaReadService);
  const state = service as unknown as { reader: unknown; current: ReaderStatus };
  let release!: () => void;
  const held = new Promise<void>((resolve) => (release = resolve));
  let snapshot!: Prisma.TransactionClient;
  let transaction: Promise<unknown> | undefined;
  const opened = new Promise<void>((resolve, reject) => {
    transaction = ctx.prisma
      .$transaction(
        async (tx) => {
          // The first consistent read fixes the snapshot of every table.
          await tx.organization.count({ where: { id: org.id } });
          snapshot = tx;
          resolve();
          await held;
        },
        { isolationLevel: 'RepeatableRead', maxWait: 10_000, timeout: 120_000 },
      )
      .catch(reject);
  });
  await opened;
  const saved = { reader: state.reader, current: state.current };
  const probe = vi
    .spyOn(service, 'probe')
    .mockImplementation(() => Promise.resolve(service.status()));
  state.reader = snapshot;
  state.current = { mode: 'reader', lagSeconds: 0, maxLagSeconds: saved.current.maxLagSeconds };
  return async () => {
    state.reader = saved.reader;
    state.current = saved.current;
    probe.mockRestore();
    release();
    await transaction;
  };
}

describe('replica lag (step AI-2 review: precondition reads on the writer)', () => {
  it('a change hidden by a lagging replica refuses the confirmation (state_changed), nothing is sent', async () => {
    const { entry } = await heldEntry();
    // quarantine_entries_request_release has no route CAS: only the state digest guards it.
    const proposal = await propose(
      ctx,
      admin,
      directive('quarantine_entries_request_release', {
        entryId: entry.publicId,
        body: { reason },
      }),
    );
    expect(proposal.confirmation.tool).toBe('quarantine_entries_request_release');
    const restore = await laggingReplica();
    const recorder = recordLoopback(ctx);
    try {
      // Rejected meanwhile, on the writer.
      await ctx.prisma.quarantineMessage.update({
        where: { id: entry.id },
        data: { status: 'rejected', rowVersion: { increment: 1 } },
      });
      // The api's ordinary reads still see the lagging replica: the entry looks held.
      const stale = await call(ctx, admin.headers, 'get', `${Q}/entries/${entry.publicId}`);
      expect(stale.status).toBe(200);
      expect(stale.body).toMatchObject({ state: 'held' });

      const res = await confirm(ctx, admin, proposal);
      expect(res.status, JSON.stringify(res.body)).toBe(409);
      expect(res.body.code).toBe('assistant_confirmation_state_changed');
      expect(recorder.calls.map((c) => c.method)).toEqual(['GET']);
      expect(await confirmationRow(ctx, proposal.confirmation.id)).toMatchObject({
        status: 'failed',
        errorCode: 'assistant_confirmation_state_changed',
        executionStartedAt: null,
      });
      expect(
        await ctx.prisma.quarantineApprovalRequest.count({
          where: { organizationId: org.id, quarantineMessageId: entry.id },
        }),
      ).toBe(0);
    } finally {
      recorder.restore();
      await restore();
    }
  });
});
