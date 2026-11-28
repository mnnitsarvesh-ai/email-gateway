/**
 * Step API-2 api on the real writer and replica (docs/plan/steps/36-api-mode-remediation.md R10,
 * R12, R13, R16, §3.4, §9.4): the remediation policy with CAS (the generated `scope_key` unique
 * key), audit rows in the same transaction, the manual remediate / restore / retry requests (the
 * action rows the mailbox-worker executes: `action_key`, `pending`, due now, re-armed on the same
 * key), the restore of a quarantined copy through the quarantine release (release log, entry
 * `releasing`, `restore_inbox` row, never a `release_requested` outbox event), the quarantine
 * routes on mailbox-located entries (location block and filter, approval by a second user,
 * reject without lifecycle edge, delete queueing the soft delete), manual quarantine of a copy
 * (404), the history from the replica (cursors, provider ids never returned), cross-tenant 404s,
 * the overview's remediation block, the organization purge of the two new tables and the
 * assistant registry's remediation reads. Synthetic `it-*` organizations only.
 */
// @covers get /api/v1/api-mode/remediation-policy
// @covers put /api/v1/api-mode/remediation-policy
// @covers put /api/v1/api-mode/remediation-policy/domains/:domainId
// @covers delete /api/v1/api-mode/remediation-policy/domains/:domainId
// @covers get /api/v1/api-mode/remediations
// @covers get /api/v1/api-mode/remediations/:remediationId
// @covers post /api/v1/api-mode/remediations/:remediationId/retry
// @covers post /api/v1/api-mode/detections/:detectionId/remediate
// @covers post /api/v1/api-mode/detections/:detectionId/restore
import { createHash, randomUUID } from 'node:crypto';
import { OPERATION_TOOLS } from '@email-gateway/assistant';
import { RedisService, S3Service, uuidv7 } from '@email-gateway/common';
import {
  DEFAULT_REMEDIATION_POLICY,
  canonicalPolicySha256,
  remediationActionKey,
} from '@email-gateway/mailbox-api';
import type { Response, Test } from 'supertest';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { systemScope } from '../src/auth-contracts/tenant-scope';
import { KeyValueStore } from '../src/kv/key-value-store';
import { ApiModeTenantDataRepository } from '../src/modules/tenant-data/api-mode-tenant-data.repository';
import { ProviderTenantDataRepository } from '../src/modules/tenant-data/provider-tenant-data.repository';
import { QuarantineTenantDataRepository } from '../src/modules/tenant-data/quarantine-tenant-data.repository';
import { InMemoryKeyValueStore } from '../test/support/in-memory-key-value-store';
import { createIntegrationApp, type IntegrationApp } from './support/app';
import { createFixtures, type FixtureOrganization, type Fixtures } from './support/fixtures';
import { bearer, loginWithMfa, uniqueIp } from './support/http';
import { deleteMessagesData } from './support/messages-data';
import { insertDomain, type InsertedDomain } from './support/smtp';

const BASE = '/api/v1/api-mode';
const Q = '/api/v1/quarantine';
const REASON = 'Integration: remediation';
const POLL = { timeout: 15_000, interval: 200 };
const sha256 = (v: string) => createHash('sha256').update(v).digest('hex');
const P1 = structuredClone(DEFAULT_REMEDIATION_POLICY.document);

let ctx: IntegrationApp;
let fx: Fixtures;
let orgA: FixtureOrganization;
let orgB: FixtureOrganization;
let adminA: Record<string, string>;
let admin2A: Record<string, string>;
let readerA: Record<string, string>;
let remediatorA: Record<string, string>;
let adminB: Record<string, string>;
let domainA: InsertedDomain;
let worldA: World;
let worldB: World;

interface World {
  org: FixtureOrganization;
  domain: InsertedDomain;
  apiConnectionId: bigint;
  connectionPublicId: string;
  mailboxId: bigint;
  address: string;
}

interface SeededCopy {
  id: bigint;
  publicId: string;
  receivedAt: Date;
  messageId: bigint;
  messagePublicId: string;
}

function call(
  who: Record<string, string>,
  method: 'get' | 'post' | 'put' | 'delete',
  path: string,
  body?: object,
  key: string | null = method === 'get' ? null : `it-${randomUUID()}`,
): Test {
  let req = ctx.http[method](path).set(who).set('X-Forwarded-For', uniqueIp());
  if (key !== null) req = req.set('Idempotency-Key', key);
  return body === undefined ? req : req.send(body);
}

async function eventually(make: () => Test, accept: (res: Response) => boolean): Promise<Response> {
  let last: Response | undefined;
  await expect
    .poll(async () => {
      last = await make();
      return accept(last);
    }, POLL)
    .toBe(true);
  return last!;
}

/** A bound connection, its API-mode row and one mailbox (+ the active grant when `grant`). */
async function seedWorld(org: FixtureOrganization, domain: InsertedDomain, grant: boolean) {
  const p = ctx.prisma;
  const connection = await p.providerConnection.create({
    data: {
      organizationId: org.id,
      provider: 'microsoft_365',
      displayName: `Remediation ${randomUUID().slice(0, 6)}`,
      status: 'active',
      externalTenantId: '7c1d2e3f-4a5b-4c6d-8e7f-0a1b2c3d4e5f',
      activeTenantKey: `microsoft_365:${randomUUID()}`,
      tenantVerifiedAt: new Date(),
    },
    select: { id: true, publicId: true },
  });
  if (grant) {
    await p.providerConnectionGrant.create({
      data: {
        organizationId: org.id,
        connectionId: connection.id,
        profile: 'm365.mailbox_remediation',
        profileVersion: 1,
        authMethod: 'platform_app',
        status: 'active',
        requestedPermissions: ['Mail.ReadWrite', 'User.Read.All'],
        observedPermissions: ['Mail.ReadWrite', 'User.Read.All'],
        verifiedAt: new Date(),
      },
    });
  }
  const api = await p.apiModeConnection.create({
    data: {
      publicId: uuidv7(),
      organizationId: org.id,
      providerConnectionId: connection.id,
      provider: 'microsoft_365',
      healthStatus: 'healthy',
    },
    select: { id: true },
  });
  const address = `rem-${randomUUID().slice(0, 8)}@${domain.name}`;
  const mailbox = await p.apiMailbox.create({
    data: {
      publicId: uuidv7(),
      organizationId: org.id,
      apiConnectionId: api.id,
      providerUserId: `user-${randomUUID()}`,
      primaryAddress: address,
      domainId: domain.id,
      status: 'active',
    },
    select: { id: true },
  });
  return {
    org,
    domain,
    apiConnectionId: api.id,
    connectionPublicId: connection.publicId,
    mailboxId: mailbox.id,
    address,
  };
}

/** A scanned copy with its registry message (`mailbox_api`, `journaled`) and recipient row. */
async function seedCopy(
  w: World,
  patch: { verdict?: 'phishing' | 'suspicious' | 'malware'; state?: string; action?: string } = {},
): Promise<SeededCopy> {
  const p = ctx.prisma;
  const receivedAt = new Date(Date.now() - 60_000 - Math.floor(Math.random() * 1000));
  const identity = await p.messageIdentity.create({
    data: { organizationId: w.org.id, ingestKey: `v2:mbx:${sha256(randomUUID())}`, receivedAt },
    select: { id: true, publicId: true },
  });
  await p.emailMessage.create({
    data: {
      id: identity.id,
      receivedAt,
      organizationId: w.org.id,
      domainId: w.domain.id,
      direction: 'inbound',
      status: 'journaled',
      statusChangedAt: receivedAt,
      version: 2,
      ingestSource: 'mailbox_api',
      envelopeFrom: 'billing@fabrikam.example',
      headerFrom: 'billing@fabrikam.example',
      subject: 'Invoice overdue',
      internetMessageId: `<${randomUUID()}@fabrikam.example>`,
      sizeBytes: 1024,
      recipientCount: 1,
      attachmentCount: 0,
      emlObjectKey: `org/${w.org.id}/eml/fixture/${randomUUID()}.eml`,
      emlSha256: sha256('copy'),
    },
  });
  await p.emailRecipient.create({
    data: {
      receivedAt,
      messageId: identity.id,
      organizationId: w.org.id,
      rcptSeq: 0,
      address: w.address,
      status: 'journaled',
      direction: 'inbound',
    },
  });
  const publicId = uuidv7();
  const copy = await p.apiMessageCopy.create({
    data: {
      publicId,
      receivedAt,
      organizationId: w.org.id,
      apiConnectionId: w.apiConnectionId,
      mailboxId: w.mailboxId,
      messageId: identity.id,
      source: 'graph',
      seenApi: true,
      providerMessageId: `AAMk-${randomUUID()}`,
      status: 'scanned',
      verdict: patch.verdict ?? 'phishing',
      riskScore: 910,
      verdictAt: new Date(receivedAt.getTime() + 5_000),
      remediationState: (patch.state ?? 'none') as 'none',
      remediationAction: (patch.action ?? null) as 'tag' | null,
    },
    select: { id: true },
  });
  return {
    id: copy.id,
    publicId,
    receivedAt,
    messageId: identity.id,
    messagePublicId: identity.publicId,
  };
}

/** A succeeded (or other status) policy action of the copy, as the mailbox-worker leaves it. */
async function seedAction(
  w: World,
  copy: SeededCopy,
  action: 'move_quarantine' | 'tag' | 'move_junk',
  status: 'succeeded' | 'failed' = 'succeeded',
) {
  const row = await ctx.prisma.apiRemediationAction.create({
    data: {
      publicId: uuidv7(),
      organizationId: w.org.id,
      apiConnectionId: w.apiConnectionId,
      mailboxId: w.mailboxId,
      copyId: copy.id,
      copyReceivedAt: copy.receivedAt,
      messageId: copy.messageId,
      action,
      generation: 0,
      actionKey: remediationActionKey(copy.publicId, action, 0),
      trigger: 'policy',
      status,
      requestedByType: 'system',
      attempts: status === 'failed' ? 8 : 1,
      lastErrorCode: status === 'failed' ? 'provider_unavailable' : null,
      providerRefs: {
        before: [`AAMk-${randomUUID()}`],
        after: [`AAMk-${randomUUID()}`],
        container: action === 'tag' ? null : 'quarantine_folder',
      },
      verdictAt: new Date(Date.now() - 10_000),
      startedAt: new Date(Date.now() - 6_000),
      completedAt: new Date(Date.now() - 5_000),
    },
    select: { id: true, publicId: true },
  });
  if (status === 'succeeded') {
    await ctx.prisma.apiMessageCopy.updateMany({
      where: { id: copy.id, receivedAt: copy.receivedAt },
      data: { remediationState: 'remediated', remediationAction: action, lastActionId: row.id },
    });
  }
  return row;
}

/** The mailbox-located entry of a quarantine-folder remediation (as the mailbox-worker writes it). */
async function seedMailboxEntry(
  w: World,
  copy: SeededCopy,
  actionId: bigint,
  o: { hardBlock?: boolean; container?: 'quarantine_folder' | 'deleted_items' } = {},
) {
  const recipient = await ctx.prisma.emailRecipient.findFirstOrThrow({
    where: { messageId: copy.messageId, receivedAt: copy.receivedAt, rcptSeq: 0 },
    select: { id: true },
  });
  const now = new Date();
  const hardBlocks = o.hardBlock ? ['hb.known_phishing'] : [];
  const entry = await ctx.prisma.quarantineMessage.create({
    data: {
      organizationId: w.org.id,
      messageId: copy.messageId,
      messageReceivedAt: copy.receivedAt,
      lifecycleRound: 0,
      recipientId: recipient.id,
      rcptSeq: 0,
      recipientAddress: w.address,
      direction: 'inbound',
      kind: 'quarantine',
      origin: 'api_remediation',
      reason: 'phishing',
      status: 'held',
      envelopeFrom: 'billing@fabrikam.example',
      headerFrom: 'billing@fabrikam.example',
      hasAttachments: false,
      attachmentCount: 0,
      sizeBytes: 1024,
      riskScore: 910,
      riskLevel: 'high',
      riskVerdict: 'phishing',
      hasHardBlock: hardBlocks.length > 0,
      hardBlocks,
      reasonCodes: [],
      floorReasons: [],
      primaryEngine: hardBlocks.length > 0 ? 'rspamd' : 'none',
      explanationText: 'Removed from the mailbox by the API-mode remediation policy (rule p1).',
      emlObjectKey: `org/${w.org.id}/eml/fixture/${randomUUID()}.eml`,
      quarantinedAt: now,
      expiresAt: new Date(now.getTime() + 30 * 86_400_000),
      stateChangedAt: now,
      location: 'mailbox',
      mailboxContainer: o.container ?? 'quarantine_folder',
      apiCopyId: copy.id,
      apiCopyReceivedAt: copy.receivedAt,
      apiMailboxId: w.mailboxId,
      apiRemediationActionId: actionId,
    },
    select: { id: true, publicId: true },
  });
  await ctx.prisma.apiRemediationAction.update({
    where: { id: actionId },
    data: { quarantineEntryId: entry.id },
  });
  return entry;
}

const window = () => ({
  from: new Date(Date.now() - 86_400_000).toISOString(),
  to: new Date(Date.now() + 86_400_000).toISOString(),
});

beforeAll(async () => {
  ctx = await createIntegrationApp(
    { REDIS_DKIM_URL: '' },
    {
      override: (builder) =>
        builder
          .overrideProvider(RedisService)
          .useValue({ healthName: 'redis', checkHealth: () => Promise.resolve() })
          .overrideProvider(S3Service)
          .useValue({ healthName: 's3', checkHealth: () => Promise.resolve() })
          .overrideProvider(KeyValueStore)
          .useValue(new InMemoryKeyValueStore()),
    },
  );
  fx = createFixtures(ctx);
  orgA = await fx.createOrganization({ planCode: 'enterprise' });
  orgB = await fx.createOrganization({ planCode: 'enterprise' });
  const login = async (org: FixtureOrganization, roles: string[]) => {
    const user = await fx.createUser(org, { roles, mfa: true });
    return bearer((await loginWithMfa(ctx, fx, user)).accessToken);
  };
  adminA = await login(orgA, ['organization_admin']);
  admin2A = await login(orgA, ['organization_admin']);
  readerA = await login(orgA, ['read_only_user']);
  remediatorA = await login(orgA, [
    await fx.createCustomRole(orgA, ['remediation:read', 'remediation:write']),
  ]);
  adminB = await login(orgB, ['organization_admin']);
  domainA = await insertDomain(ctx, orgA, { status: 'verified', label: 'apirem' });
  const domainB = await insertDomain(ctx, orgB, { status: 'verified', label: 'apirem' });
  worldA = await seedWorld(orgA, domainA, true);
  worldB = await seedWorld(orgB, domainB, true);

  const orgs = [orgA, orgB];
  fx.registerCleanup(async () => {
    const where = { organizationId: { in: orgs.map((o) => o.id) } };
    for (const org of orgs) {
      await ctx.get(QuarantineTenantDataRepository).purgeOrganization(systemScope(org.id));
      await ctx.get(ApiModeTenantDataRepository).purgeOrganization(systemScope(org.id));
      await ctx.get(ProviderTenantDataRepository).purgeOrganization(systemScope(org.id));
    }
    await ctx.prisma.messageOutbox.deleteMany({ where });
    await deleteMessagesData(
      ctx,
      orgs.map((o) => o.id),
    );
    await ctx.prisma.auditLog.deleteMany({ where });
  });
}, 120_000);

afterAll(async () => {
  await fx?.cleanup();
  await ctx?.close();
});

describe('remediation policy (R13 #1-#4) on the writer', () => {
  it('GET default → PUT create (expectedRowVersion null) → CAS → domain override → DELETE; audit rows', async () => {
    const initial = await call(adminA, 'get', `${BASE}/remediation-policy`);
    expect(initial.status).toBe(200);
    expect(initial.body.organization).toMatchObject({
      source: 'platform_default',
      rowVersion: null,
    });
    const body = { mode: 'detect_only', document: P1, reason: REASON, expectedRowVersion: null };
    const created = await call(adminA, 'put', `${BASE}/remediation-policy`, body);
    expect(created.status, JSON.stringify(created.body)).toBe(200);
    expect(created.body).toMatchObject({ rowVersion: 1, created: true, scope: 'organization' });
    const row = await ctx.prisma.apiRemediationPolicy.findFirstOrThrow({
      where: { organizationId: orgA.id, domainId: null },
    });
    expect(row).toMatchObject({
      mode: 'detect_only',
      documentSha256: canonicalPolicySha256(P1),
      rowVersion: 1,
      scopeKey: 0n,
    });
    const audit = await ctx.prisma.auditLog.findFirst({
      where: { organizationId: orgA.id, action: 'api_mode.remediation_policy_updated' },
      orderBy: { id: 'desc' },
    });
    expect(audit?.metadata).toMatchObject({ scope: 'organization', from: null, reason: REASON });
    // A second create loses the CAS (the unique (organization_id, scope_key) backs it).
    const again = await call(adminA, 'put', `${BASE}/remediation-policy`, body);
    expect(again.status).toBe(409);
    expect(again.body).toMatchObject({
      code: 'api_mode_remediation_policy_conflict',
      currentRowVersion: 1,
    });
    const updated = await call(adminA, 'put', `${BASE}/remediation-policy`, {
      ...body,
      mode: 'enforce',
      expectedRowVersion: 1,
    });
    expect(updated.body).toMatchObject({ rowVersion: 2, mode: 'enforce' });
    // Domain override, then removal.
    const domainPath = `${BASE}/remediation-policy/domains/${domainA.publicId}`;
    const override = await call(adminA, 'put', domainPath, body);
    expect(override.status).toBe(200);
    expect(
      await ctx.prisma.apiRemediationPolicy.findFirst({
        where: { organizationId: orgA.id, domainId: domainA.id },
        select: { scopeKey: true },
      }),
    ).toEqual({ scopeKey: domainA.id });
    const view = await eventually(
      () => call(adminA, 'get', `${BASE}/remediation-policy`),
      (res) => res.body.domains?.length === 1 && res.body.organization?.rowVersion === 2,
    );
    expect(view.body.domains[0]).toMatchObject({ domainId: domainA.publicId, mode: 'detect_only' });
    const removed = await call(adminA, 'delete', domainPath);
    expect(removed.status).toBe(204);
    expect(
      await ctx.prisma.apiRemediationPolicy.count({
        where: { organizationId: orgA.id, domainId: domainA.id },
      }),
    ).toBe(0);
    // Hard delete is refused while the platform setting is off; nothing written.
    const hard = await call(adminA, 'put', `${BASE}/remediation-policy`, {
      ...body,
      expectedRowVersion: 2,
      document: {
        v: 1,
        rules: [{ id: 'nuke', when: { verdicts: ['malware'] }, action: 'hard_delete' }],
      },
    });
    expect(hard.status).toBe(422);
    expect(hard.body.code).toBe('api_mode_hard_delete_disabled');
    // Another organization's domain is 404; the read-only user may read, not write.
    expect((await call(adminB, 'put', domainPath, body)).body.code).toBe('domain_not_found');
    expect((await call(readerA, 'get', `${BASE}/remediation-policy`)).status).toBe(200);
    expect((await call(readerA, 'put', `${BASE}/remediation-policy`, body)).status).toBe(403);
  });
});

describe('manual requests (R12) on the writer', () => {
  it('remediate: the pending admin row of the copy key, copy pending, replay; re-armed on the same key', async () => {
    const copy = await seedCopy(worldA);
    const key = `it-${randomUUID()}`;
    const path = `${BASE}/detections/${copy.publicId}/remediate`;
    const res = await call(
      adminA,
      'post',
      path,
      { action: 'move_quarantine', reason: 'campaign' },
      key,
    );
    expect(res.status, JSON.stringify(res.body)).toBe(202);
    const row = await ctx.prisma.apiRemediationAction.findFirstOrThrow({
      where: { organizationId: orgA.id, copyId: copy.id },
    });
    expect(row).toMatchObject({
      publicId: res.body.remediation.id,
      action: 'move_quarantine',
      actionKey: remediationActionKey(copy.publicId, 'move_quarantine', 0),
      generation: 0,
      trigger: 'admin',
      status: 'pending',
      requestedByType: 'user',
      requestReason: 'campaign',
      attempts: 0,
      leaseUntil: null,
      apiConnectionId: worldA.apiConnectionId,
      mailboxId: worldA.mailboxId,
      messageId: copy.messageId,
    });
    expect(row.decision).toEqual({ requestedAction: 'move_quarantine', reason: 'campaign' });
    expect(Math.abs(row.nextAttemptAt!.getTime() - Date.now())).toBeLessThan(60_000);
    const stored = await ctx.prisma.apiMessageCopy.findFirstOrThrow({
      where: { id: copy.id, receivedAt: copy.receivedAt },
    });
    expect(stored).toMatchObject({
      remediationState: 'pending',
      remediationAction: 'move_quarantine',
      lastActionId: row.id,
    });
    const replay = await call(
      adminA,
      'post',
      path,
      { action: 'move_quarantine', reason: 'campaign' },
      key,
    );
    expect(replay.headers['idempotency-replayed']).toBe('true');
    expect(replay.body).toEqual(res.body);
    expect(await ctx.prisma.apiRemediationAction.count({ where: { copyId: copy.id } })).toBe(1);
    // The worker failed it; a new request of the same action and generation re-arms the row.
    await ctx.prisma.apiRemediationAction.update({
      where: { id: row.id },
      data: { status: 'failed', attempts: 8, lastErrorCode: 'provider_unavailable' },
    });
    await ctx.prisma.apiMessageCopy.updateMany({
      where: { id: copy.id, receivedAt: copy.receivedAt },
      data: { remediationState: 'failed' },
    });
    const rearm = await call(adminA, 'post', path, { action: 'move_quarantine', reason: 'retry' });
    expect(rearm.status).toBe(202);
    expect(rearm.body.remediation.id).toBe(row.publicId);
    expect(
      await ctx.prisma.apiRemediationAction.findUniqueOrThrow({ where: { id: row.id } }),
    ).toMatchObject({
      status: 'pending',
      attempts: 0,
      lastErrorCode: null,
      requestReason: 'retry',
    });
    // While it is pending, another request is refused.
    const busy = await call(adminA, 'post', path, { action: 'tag', reason: 'x' });
    expect(busy.body.code).toBe('api_mode_remediation_in_progress');
    // Hard delete never manual; another organization's detection 404.
    expect(
      (await call(adminA, 'post', path, { action: 'hard_delete', reason: 'x' })).body.code,
    ).toBe('api_mode_hard_delete_not_manual');
    expect((await call(adminB, 'post', path, { action: 'tag', reason: 'x' })).body.code).toBe(
      'api_mode_detection_not_found',
    );
    expect((await call(readerA, 'post', path, { action: 'tag', reason: 'x' })).status).toBe(403);
  });

  it('restore of a tag: a remove_tag row reversing the succeeded tag', async () => {
    const copy = await seedCopy(worldA, { verdict: 'suspicious' });
    const tag = await seedAction(worldA, copy, 'tag');
    const res = await call(adminA, 'post', `${BASE}/detections/${copy.publicId}/restore`, {
      reason: 'false positive',
    });
    expect(res.status, JSON.stringify(res.body)).toBe(202);
    expect(res.body).toMatchObject({ via: 'mailbox_action', release: null });
    const reversal = await ctx.prisma.apiRemediationAction.findFirstOrThrow({
      where: { copyId: copy.id, action: 'remove_tag' },
    });
    expect(reversal).toMatchObject({
      reversesActionId: tag.id,
      status: 'pending',
      trigger: 'admin',
      actionKey: remediationActionKey(copy.publicId, 'remove_tag', 0),
    });
  });

  it('restore of a quarantined copy: quarantine:release required; then release log, entry releasing, restore_inbox row, no release_requested event', async () => {
    const copy = await seedCopy(worldA);
    const moved = await seedAction(worldA, copy, 'move_quarantine');
    const entry = await seedMailboxEntry(worldA, copy, moved.id);
    const path = `${BASE}/detections/${copy.publicId}/restore`;
    const denied = await call(remediatorA, 'post', path, { reason: 'fp' });
    expect(denied.status).toBe(403);
    expect(denied.body.code).toBe('quarantine_permission_required');
    const ok = await call(adminA, 'post', path, { reason: 'fp' });
    expect(ok.status, JSON.stringify(ok.body)).toBe(202);
    expect(ok.body).toMatchObject({
      via: 'quarantine_release',
      release: { outcome: 'queued', entryId: entry.publicId, state: 'releasing' },
    });
    const stored = await ctx.prisma.quarantineMessage.findUniqueOrThrow({
      where: { id: entry.id },
    });
    expect(stored.status).toBe('releasing');
    const log = await ctx.prisma.quarantineReleaseLog.findFirstOrThrow({
      where: { quarantineMessageId: entry.id },
    });
    expect(log).toMatchObject({ status: 'pending', mode: 'operator', releasedTo: worldA.address });
    expect(log.precheck).toMatchObject({ source: 'api_mailbox_precheck', outcome: 'release' });
    const restore = await ctx.prisma.apiRemediationAction.findFirstOrThrow({
      where: { copyId: copy.id, action: 'restore_inbox' },
    });
    expect(restore).toMatchObject({
      trigger: 'release',
      status: 'pending',
      reversesActionId: moved.id,
      quarantineEntryId: entry.id,
      releaseLogId: log.id,
      generation: 0,
    });
    expect(
      await ctx.prisma.messageOutbox.count({
        where: {
          organizationId: orgA.id,
          eventType: 'mail.quarantine.release_requested.v1',
          aggregateId: copy.messageId.toString(),
        },
      }),
    ).toBe(0);
    // The message lifecycle is untouched (copies end `journaled`).
    expect(
      (
        await ctx.prisma.emailMessage.findFirstOrThrow({
          where: { id: copy.messageId, receivedAt: copy.receivedAt },
        })
      ).status,
    ).toBe('journaled');
    expect(
      await ctx.prisma.auditLog.count({
        where: { organizationId: orgA.id, action: 'api_mode.restore_requested' },
      }),
    ).toBeGreaterThanOrEqual(1);
  });

  it('retry: a failed row back to pending (attempts reset), not twice', async () => {
    const copy = await seedCopy(worldA, { verdict: 'malware' });
    const failed = await seedAction(worldA, copy, 'move_junk', 'failed');
    const path = `${BASE}/remediations/${failed.publicId}/retry`;
    const res = await call(adminA, 'post', path);
    expect(res.status, JSON.stringify(res.body)).toBe(202);
    expect(
      await ctx.prisma.apiRemediationAction.findUniqueOrThrow({ where: { id: failed.id } }),
    ).toMatchObject({ status: 'pending', attempts: 0, lastErrorCode: null, completedAt: null });
    const again = await call(adminA, 'post', path);
    expect(again.status).toBe(409);
    expect(again.body).toMatchObject({
      code: 'api_mode_remediation_not_retryable',
      cause: 'pending',
    });
    expect((await call(adminB, 'post', path)).body.code).toBe('api_mode_remediation_not_found');
  });

  it('retry: a failed row of an older generation is refused (stale_generation); the copy is unchanged', async () => {
    const copy = await seedCopy(worldA, { verdict: 'malware', state: 'restored' });
    await ctx.prisma.apiMessageCopy.updateMany({
      where: { id: copy.id, receivedAt: copy.receivedAt },
      data: { remediationGeneration: 1 },
    });
    const failed = await seedAction(worldA, copy, 'move_junk', 'failed');
    const res = await call(adminA, 'post', `${BASE}/remediations/${failed.publicId}/retry`);
    expect(res.status, JSON.stringify(res.body)).toBe(409);
    expect(res.body).toMatchObject({
      code: 'api_mode_remediation_not_retryable',
      cause: 'stale_generation',
    });
    expect(
      await ctx.prisma.apiRemediationAction.findUniqueOrThrow({ where: { id: failed.id } }),
    ).toMatchObject({ status: 'failed' });
    expect(
      await ctx.prisma.apiMessageCopy.findFirstOrThrow({ where: { id: copy.id } }),
    ).toMatchObject({ remediationState: 'restored', remediationGeneration: 1 });
  });
});

describe('quarantine routes on mailbox-located entries (R10)', () => {
  it('location block and filter; approval by a second user queues the restore; reject and delete; manual quarantine of a copy is 404', async () => {
    const copy = await seedCopy(worldA);
    const moved = await seedAction(worldA, copy, 'move_quarantine');
    const entry = await seedMailboxEntry(worldA, copy, moved.id, { hardBlock: true });
    const list = await eventually(
      () => call(adminA, 'get', `${Q}/entries`).query({ ...window(), location: 'mailbox' }),
      (res) =>
        ((res.body as { items?: Array<{ id: string }> }).items ?? []).some(
          (i) => i.id === entry.publicId,
        ),
    );
    const item = list.body.items.find((i: { id: string }) => i.id === entry.publicId);
    expect(item.location).toMatchObject({
      kind: 'mailbox',
      container: 'quarantine_folder',
      mailboxAddress: worldA.address,
      provider: 'microsoft_365',
      connectionId: worldA.connectionPublicId,
      detectionId: copy.publicId,
    });
    expect(
      list.body.items.every((i: { location: { kind: string } }) => i.location.kind === 'mailbox'),
    ).toBe(true);
    // A hard-blocked entry needs a second approver.
    const requested = await call(adminA, 'post', `${Q}/entries/${entry.publicId}/release`, {
      reason: 'check',
    });
    expect(requested.status, JSON.stringify(requested.body)).toBe(202);
    expect(requested.body).toMatchObject({
      outcome: 'approval_requested',
      approvalReasons: ['hard_block'],
    });
    expect(
      await ctx.prisma.apiRemediationAction.count({
        where: { copyId: copy.id, action: 'restore_inbox' },
      }),
    ).toBe(0);
    const self = await call(
      adminA,
      'post',
      `${Q}/approvals/${requested.body.approvalRequestId}/approve`,
      {
        reason: 'ok',
      },
    );
    expect(self.status).toBe(403);
    const approved = await call(
      admin2A,
      'post',
      `${Q}/approvals/${requested.body.approvalRequestId}/approve`,
      { reason: 'ok' },
    );
    expect(approved.status, JSON.stringify(approved.body)).toBe(202);
    expect(approved.body).toMatchObject({ status: 'approved', entryState: 'releasing' });
    expect(
      await ctx.prisma.apiRemediationAction.findFirstOrThrow({
        where: { copyId: copy.id, action: 'restore_inbox' },
      }),
    ).toMatchObject({ trigger: 'release', status: 'pending', quarantineEntryId: entry.id });

    // Reject: entry rejected, no lifecycle edge, the recipient row unchanged.
    const c2 = await seedCopy(worldA);
    const m2 = await seedAction(worldA, c2, 'move_quarantine');
    const e2 = await seedMailboxEntry(worldA, c2, m2.id);
    const rejected = await call(adminA, 'post', `${Q}/entries/${e2.publicId}/reject`, {
      reason: 'confirmed',
    });
    expect(rejected.status, JSON.stringify(rejected.body)).toBe(200);
    expect(rejected.body).toMatchObject({
      state: 'rejected',
      messageTransition: null,
      purge: null,
    });
    expect(
      await ctx.prisma.emailRecipient.findFirstOrThrow({
        where: { messageId: c2.messageId, receivedAt: c2.receivedAt },
        select: { status: true },
      }),
    ).toEqual({ status: 'journaled' });
    expect(
      await ctx.prisma.quarantineObjectPurge.count({ where: { messageId: c2.messageId } }),
    ).toBe(0);

    // Delete: entry deleted, mailbox_deleted action, soft_delete queued, no purge.
    const c3 = await seedCopy(worldA);
    const m3 = await seedAction(worldA, c3, 'move_quarantine');
    const e3 = await seedMailboxEntry(worldA, c3, m3.id);
    const deleted = await call(adminA, 'post', `${Q}/entries/${e3.publicId}/delete`, {
      reason: 'cleanup',
    });
    expect(deleted.status, JSON.stringify(deleted.body)).toBe(200);
    expect(deleted.body).toMatchObject({ state: 'deleted', purge: null });
    expect(
      await ctx.prisma.quarantineAction.findFirst({
        where: { quarantineMessageId: e3.id, action: 'mailbox_deleted' },
        select: { result: true },
      }),
    ).toEqual({ result: 'soft_delete_queued' });
    expect(
      await ctx.prisma.apiRemediationAction.findFirstOrThrow({
        where: { copyId: c3.id, action: 'soft_delete' },
      }),
    ).toMatchObject({ trigger: 'admin', status: 'pending', quarantineEntryId: e3.id });
    expect(
      await ctx.prisma.quarantineObjectPurge.count({ where: { messageId: c3.messageId } }),
    ).toBe(0);

    // Manual quarantine of the copy's registry message: 404 (gateway messages only).
    const manual = await call(adminA, 'post', `${Q}/entries`, {
      messageId: copy.messagePublicId,
      reason: 'x',
    });
    expect(manual.status).toBe(404);
    // Another organization sees none of it.
    expect((await call(adminB, 'get', `${Q}/entries/${entry.publicId}`)).status).toBe(404);
  });
});

describe('history and views from the replica (R13)', () => {
  it('cursor pages, provider ids never returned, cross-tenant 404, detection fields, overview backlog', async () => {
    const copy = await seedCopy(worldA);
    const moved = await seedAction(worldA, copy, 'move_quarantine');
    const first = await eventually(
      () => call(adminA, 'get', `${BASE}/remediations`).query({ limit: '1' }),
      (res) => res.body.data?.length === 1 && typeof res.body.nextCursor === 'string',
    );
    const second = await call(adminA, 'get', `${BASE}/remediations`).query({
      limit: '1',
      cursor: first.body.nextCursor,
    });
    expect(second.status).toBe(200);
    expect(second.body.data[0].id).not.toBe(first.body.data[0].id);
    const detail = await eventually(
      () => call(adminA, 'get', `${BASE}/remediations/${moved.publicId}`),
      (res) => res.status === 200,
    );
    expect(detail.body).toMatchObject({
      id: moved.publicId,
      detectionId: copy.publicId,
      providerRefs: { container: 'quarantine_folder', before: 1, after: 1 },
    });
    expect(JSON.stringify([first.body, second.body, detail.body])).not.toContain('AAMk-');
    expect((await call(adminB, 'get', `${BASE}/remediations/${moved.publicId}`)).status).toBe(404);
    const listB = await call(adminB, 'get', `${BASE}/remediations`);
    expect(listB.body.data.map((r: { id: string }) => r.id)).not.toContain(moved.publicId);
    const detection = await eventually(
      () => call(adminA, 'get', `${BASE}/detections/${copy.publicId}`),
      (res) => res.body.remediationState === 'remediated',
    );
    expect(detection.body).toMatchObject({
      remediationAction: 'move_quarantine',
      remediationId: moved.publicId,
    });
    const filtered = await call(adminA, 'get', `${BASE}/detections`).query({
      remediationState: 'remediated',
    });
    expect(
      filtered.body.data.every(
        (d: { remediationState: string }) => d.remediationState === 'remediated',
      ),
    ).toBe(true);
    const overview = await eventually(
      () => call(adminA, 'get', `${BASE}/overview`),
      (res) => (res.body.remediation?.backlog?.pending ?? 0) >= 1,
    );
    expect(overview.body.remediation.backlog.oldestPendingAgeSeconds).toEqual(expect.any(Number));
  });
});

describe('organization purge of the remediation tables (§3.4)', () => {
  it('deletes api_remediation_actions and api_remediation_policies of the organization only', async () => {
    const copy = await seedCopy(worldB);
    await seedAction(worldB, copy, 'tag');
    await ctx.prisma.apiRemediationPolicy.create({
      data: {
        publicId: uuidv7(),
        organizationId: orgB.id,
        domainId: worldB.domain.id,
        mode: 'enforce',
        document: P1 as never,
        documentSha256: canonicalPolicySha256(P1),
      },
    });
    const beforeA = await ctx.prisma.apiRemediationAction.count({
      where: { organizationId: orgA.id },
    });
    const counts = await ctx
      .get(ApiModeTenantDataRepository)
      .purgeOrganization(systemScope(orgB.id), 1);
    expect(counts.api_remediation_actions).toBeGreaterThanOrEqual(1);
    expect(counts.api_remediation_policies).toBe(1);
    expect(counts.api_mailboxes).toBe(1);
    expect(counts.api_mode_connections).toBe(1);
    expect(
      await ctx.prisma.apiRemediationAction.count({ where: { organizationId: orgB.id } }),
    ).toBe(0);
    expect(
      await ctx.prisma.apiRemediationPolicy.count({ where: { organizationId: orgB.id } }),
    ).toBe(0);
    expect(
      await ctx.prisma.apiRemediationAction.count({ where: { organizationId: orgA.id } }),
    ).toBe(beforeA);
    // A re-run finds nothing left.
    expect(
      Object.values(
        await ctx.get(ApiModeTenantDataRepository).purgeOrganization(systemScope(orgB.id)),
      ),
    ).toEqual(Array(13).fill(0));
  });
});

describe('assistant registry (R16; step API-3 C15)', () => {
  it('the three remediation reads are enabled read tools; since API-3 the six writes are confirmed write tools', () => {
    const byId = new Map(OPERATION_TOOLS.map((t) => [t.operationId, t]));
    for (const id of [
      'ApiModeRemediationController_getPolicy_v1',
      'ApiModeRemediationController_list_v1',
      'ApiModeRemediationController_detail_v1',
    ]) {
      expect(byId.get(id), id).toMatchObject({ enabled: true, access: 'read' });
    }
    for (const [id, risk] of [
      ['ApiModeRemediationController_putPolicy_v1', 'high'],
      ['ApiModeRemediationController_remediate_v1', 'medium'],
      ['ApiModeRemediationController_restore_v1', 'high'],
    ] as const) {
      expect(byId.get(id), id).toMatchObject({ enabled: true, access: 'write', risk });
    }
  });
});
