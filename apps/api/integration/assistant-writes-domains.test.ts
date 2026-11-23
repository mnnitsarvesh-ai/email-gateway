/**
 * Step AI-3 domain administration tools through chat (docs/plan/steps/30-ai-chat-identity-
 * tenant-admin.md D2, D6, D7, §9 item 4; the `testedBy` of the 10 domain writes in
 * docs/assistant/UI_TO_CHAT_CAPABILITY_MATRIX.md): each write is proposed through a directive
 * turn (the deterministic fake provider; never a real LLM) by an MFA-enrolled
 * `organization_admin` and confirmed through the confirm route (password + TOTP for the
 * high-risk ones unless the session's re-authentication window is open); the api's own state and
 * the operation's own audit row (correlated to the result execution) are asserted on the writer.
 *
 * DNS is deterministic: the app resolves against an in-process `TestDnsServer` with the gateway
 * DNS settings of the domain suites (no test resolves a public name). The lifecycle: create
 * (medium) → publish the ownership TXT and the DKIM record → verify (medium) → activate (high) →
 * DKIM rotation (high, legacy idempotency: `Idempotency-Key` = the confirmation id, a replay
 * answers the stored response) → suspend (high) → delete (high). Destinations: replace (high; the
 * card lists the old and the new servers), the changed-state refusal when the destinations change
 * through the api between proposal and confirm, delete (high). Recipient validation: add (low),
 * set (medium), remove (high).
 *
 * Synthetic `it-*` organizations and `.test` / `.example` names only.
 */
// @covers post /api/v1/assistant/conversations
// @covers post /api/v1/assistant/conversations/:conversationId/turns
// @covers post /api/v1/assistant/confirmations/:confirmationId/confirm
// @covers post /api/v1/domains
// @covers get /api/v1/domains/:id
// @covers get /api/v1/domains/:id/status
// @covers post /api/v1/domains/:id/verify
// @covers patch /api/v1/domains/:id/status
// @covers post /api/v1/domains/:id/dkim/rotate
// @covers delete /api/v1/domains/:id
// @covers get /api/v1/domains/:id/destinations
// @covers put /api/v1/domains/:id/destinations
// @covers delete /api/v1/domains/:id/destinations
// @covers get /api/v1/domains/:id/recipient-validation
// @covers put /api/v1/domains/:id/recipient-validation
// @covers post /api/v1/domains/:id/recipients
// @covers post /api/v1/domains/:id/recipients/remove
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { TestDnsServer } from '../test/support/dns/test-dns-server';
import type { IntegrationApp } from './support/app';
import {
  auditByCorrelation,
  call,
  type ChatWrite,
  clearAssistantCounters,
  confirm,
  confirmationRow,
  createAssistantApp,
  credentialKeys,
  credentialKeysInResult,
  directive,
  enableAssistant,
  member,
  type Member,
  platformMember,
  propose,
  proposeAndConfirm,
  type RecordedCall,
  resultCorrelationId,
  waitForRead,
} from './support/assistant';
import {
  DomainApi,
  domainRow,
  domainTestEnv,
  publishFromApi,
  publishGatewaySpf,
  resetVerifyLimit,
  uniqueDomainName,
} from './support/domains';
import { createFixtures, type FixtureOrganization, type Fixtures } from './support/fixtures';
import { idem } from './support/http';
import { insertDomain, type InsertedDomain } from './support/smtp';

let dns: TestDnsServer;
let ctx: IntegrationApp;
let fx: Fixtures;
let org: FixtureOrganization;
let admin: Member;
let api: DomainApi;

const chat = (tool: string, args: Record<string, unknown>): Promise<ChatWrite> =>
  proposeAndConfirm(ctx, fx, admin, tool, args);

/** Asserts an executed confirmation with this HTTP status; returns the write's loopback call. */
function executed(result: ChatWrite, httpStatus: number): RecordedCall {
  expect(result.res.status, JSON.stringify(result.res.body)).toBe(200);
  expect(result.res.body.confirmation).toMatchObject({
    status: 'executed',
    result: { httpStatus, error: null },
  });
  expect(result.res.body.execution).toMatchObject({
    tool: result.proposal.confirmation.tool,
    decision: 'allowed',
    status: 'succeeded',
    httpStatus,
  });
  const writes = result.calls.filter((c) => c.method !== 'GET');
  expect(writes).toHaveLength(1);
  return writes[0]!;
}

/** The operation's own audit row carries the result execution's correlation id. */
async function operationAudited(result: ChatWrite, action: string) {
  const correlationId = await resultCorrelationId(ctx, result.res);
  const rows = (await auditByCorrelation(ctx, org.id, correlationId)).filter(
    (r) => r.action === action,
  );
  expect(rows, action).toHaveLength(1);
  expect(rows[0]!.actorId).toBe(admin.user.publicId);
  return rows[0]!;
}

async function credentialFree(result: ChatWrite): Promise<void> {
  expect(credentialKeys(result.proposal.confirmation)).toEqual([]);
  expect(credentialKeys(result.res.body.confirmation)).toEqual([]);
  const row = await confirmationRow(ctx, result.proposal.confirmation.id);
  expect(credentialKeys(row.preconditions)).toEqual([]);
}

const settingsOf = async (publicId: string) =>
  (
    await ctx.prisma.domain.findUniqueOrThrow({
      where: { publicId },
      include: { settings: true },
    })
  ).settings;

beforeAll(async () => {
  dns = await TestDnsServer.start({ defaultTtl: 60 });
  publishGatewaySpf(dns);
  ({ ctx } = await createAssistantApp({ env: domainTestEnv(dns) }));
  fx = createFixtures(ctx);
  const operator = await platformMember(ctx, fx);
  org = await fx.createOrganization();
  admin = await member(ctx, fx, org, ['organization_admin']);
  api = new DomainApi(ctx, admin.headers);
  await enableAssistant(ctx, operator, org, admin);
}, 180_000);

afterAll(async () => {
  if (ctx && org) await clearAssistantCounters(ctx, [org.id]);
  await fx?.cleanup();
  await ctx?.close();
  await dns?.close();
});

describe('the domain lifecycle through chat', () => {
  const name = uniqueDomainName('chat');
  let id: string;

  it('domains_create (medium): pending verification with its DNS records', async () => {
    const result = await chat('domains_create', { body: { name } });
    expect(result.proposal.confirmation).toMatchObject({ risk: 'medium', requiresReauth: false });
    expect(result.proposal.confirmation.summary!.impact.length).toBeGreaterThanOrEqual(1);
    expect(JSON.stringify(result.proposal.confirmation.summary!.target)).toContain(name);
    executed(result, 201);
    const row = await ctx.prisma.domain.findFirstOrThrow({
      where: { organizationId: org.id, name },
    });
    id = row.publicId;
    expect(row.status).toBe('pending_verification');
    await operationAudited(result, 'domain.created');
    await credentialFree(result);
  });

  it('domain_dns_verify (medium): verified once the ownership TXT is published', async () => {
    await waitForRead(ctx, admin, `/api/v1/domains/${id}/dns-records`);
    await publishFromApi(api, dns, id, ['verification', 'dkim']);
    await resetVerifyLimit(ctx, id);
    const result = await chat('domain_dns_verify', { id });
    expect(result.proposal.confirmation).toMatchObject({ risk: 'medium', requiresReauth: false });
    executed(result, 200);
    expect(result.res.body.execution.httpStatus).toBe(200);
    expect((await domainRow(ctx, id)).status).toBe('verified');
    await operationAudited(result, 'domain.verified');
    await credentialFree(result);
  });

  it('domains_change_status (high): activated', async () => {
    const result = await chat('domains_change_status', { id, body: { status: 'active' } });
    expect(result.proposal.confirmation).toMatchObject({ risk: 'high', requiresReauth: true });
    executed(result, 200);
    expect((await domainRow(ctx, id)).status).toBe('active');
    const audit = await operationAudited(result, 'domain.status_changed');
    expect(audit.metadata).toMatchObject({ from: 'verified', to: 'active' });
  });

  it('domain_dns_rotate (high, legacy idempotency): a new key; a replay answers the stored 201', async () => {
    const before = (await domainRow(ctx, id)).dkimKeys.length;
    const result = await chat('domain_dns_rotate', { id });
    expect(result.proposal.confirmation.risk).toBe('high');
    expect(result.proposal.confirmation.summary!.reversible).toBe(false);
    const write = executed(result, 201);
    expect(write).toMatchObject({
      method: 'POST',
      path: `/api/v1/domains/${id}/dkim/rotate`,
      idempotencyKey: result.proposal.confirmation.id,
    });
    const keys = (await domainRow(ctx, id)).dkimKeys;
    expect(keys).toHaveLength(before + 1);
    expect(keys.filter((k) => k.status === 'pending')).toHaveLength(1);
    await operationAudited(result, 'domain.dkim_rotation_started');
    // The api's response (DNS record, never key material) left no credential key in the card.
    expect(credentialKeysInResult(null, result.res.body.execution.card)).toEqual([]);
    expect(JSON.stringify(result.res.body)).not.toMatch(/PRIVATE KEY/);
    await credentialFree(result);

    // The same request (no body: the model sent none) with the same key.
    const stored = (await confirmationRow(ctx, result.proposal.confirmation.id)).request as {
      body: Record<string, unknown> | null;
    };
    const replay = await call(ctx, admin.headers, 'post', write.path, stored.body ?? undefined).set(
      idem(result.proposal.confirmation.id),
    );
    expect(replay.status).toBe(201);
    expect(replay.headers['idempotency-replayed']).toBe('true');
    expect((await domainRow(ctx, id)).dkimKeys).toHaveLength(before + 1);
  });

  it('domains_change_status (high): suspended with a reason', async () => {
    const result = await chat('domains_change_status', {
      id,
      body: { status: 'suspended', reason: 'Suspended through chat' },
    });
    executed(result, 200);
    expect(await domainRow(ctx, id)).toMatchObject({
      status: 'suspended',
      statusReason: 'Suspended through chat',
    });
    await operationAudited(result, 'domain.status_changed');
  });

  it('domains_remove (high): the suspended domain is deleted, its DKIM keys revoked', async () => {
    const result = await chat('domains_remove', { id });
    expect(result.proposal.confirmation).toMatchObject({ risk: 'high', requiresReauth: true });
    expect(result.proposal.confirmation.summary!.reversible).toBe(false);
    executed(result, 204);
    const row = await domainRow(ctx, id);
    expect(row.status).toBe('deleted');
    expect(row.deletedAt).not.toBeNull();
    for (const key of row.dkimKeys) {
      expect(key).toMatchObject({ status: 'revoked', privateKeyCiphertext: null });
    }
    await operationAudited(result, 'domain.deleted');
  });
});

describe('destinations through chat', () => {
  let domain: InsertedDomain;
  const destinations = (publicId: string) =>
    ctx.prisma.domainMailServer.findMany({
      where: { domain: { publicId }, role: 'inbound_destination' },
      orderBy: { host: 'asc' },
    });

  beforeAll(async () => {
    domain = await insertDomain(ctx, org, { label: 'chat-dest' });
    const res = await call(
      ctx,
      admin.headers,
      'put',
      `/api/v1/domains/${domain.publicId}/destinations`,
      {
        provider: 'custom',
        servers: [{ host: 'old-mx.tenant-mail.example', priority: 10 }],
      },
    );
    expect(res.status, JSON.stringify(res.body)).toBe(200);
  });

  it('domain_destinations_replace (high): the card lists the old and the new servers', async () => {
    const result = await chat('domain_destinations_replace', {
      id: domain.publicId,
      body: {
        provider: 'custom',
        servers: [
          { host: 'new-mx1.tenant-mail.example', priority: 10 },
          { host: 'new-mx2.tenant-mail.example', priority: 20 },
        ],
      },
    });
    expect(result.proposal.confirmation).toMatchObject({ risk: 'high', requiresReauth: true });
    const summary = result.proposal.confirmation.summary!;
    const servers = summary.changes.find((c) => c.label === 'Servers');
    expect(servers?.before).toContain('old-mx.tenant-mail.example');
    expect(servers?.after).toContain('new-mx1.tenant-mail.example');
    expect(servers?.after).toContain('new-mx2.tenant-mail.example');
    expect(summary.warnings).toContain(
      'All inbound mail for this domain will be delivered to these servers.',
    );
    executed(result, 200);
    expect((await destinations(domain.publicId)).map((s) => s.host)).toEqual([
      'new-mx1.tenant-mail.example',
      'new-mx2.tenant-mail.example',
    ]);
    const audit = await operationAudited(result, 'domain.destinations_replaced');
    expect(audit.metadata).toMatchObject({
      provider: 'custom',
      previous: { provider: 'custom', hosts: ['old-mx.tenant-mail.example'] },
    });
    await credentialFree(result);
  });

  it('refuses the confirm when the destinations changed through the api after the proposal', async () => {
    const proposal = await propose(
      ctx,
      admin,
      directive('domain_destinations_replace', {
        id: domain.publicId,
        body: { provider: 'custom', servers: [{ host: 'chat-mx.tenant-mail.example' }] },
      }),
    );
    const portal = await call(
      ctx,
      admin.headers,
      'put',
      `/api/v1/domains/${domain.publicId}/destinations`,
      {
        provider: 'custom',
        servers: [{ host: 'portal-mx.tenant-mail.example' }],
      },
    );
    expect(portal.status).toBe(200);
    const res = await confirm(ctx, admin, proposal);
    expect(res.status).toBe(409);
    expect(res.body.code).toBe('assistant_confirmation_state_changed');
    expect((await confirmationRow(ctx, proposal.confirmation.id)).status).toBe('failed');
    expect((await destinations(domain.publicId)).map((s) => s.host)).toEqual([
      'portal-mx.tenant-mail.example',
    ]);
  });

  it('domain_destinations_remove (high): no destination left', async () => {
    const result = await chat('domain_destinations_remove', { id: domain.publicId });
    expect(result.proposal.confirmation).toMatchObject({ risk: 'high', requiresReauth: true });
    expect(JSON.stringify(result.proposal.confirmation.summary!.changes)).toContain(
      'portal-mx.tenant-mail.example',
    );
    executed(result, 204);
    expect(await destinations(domain.publicId)).toEqual([]);
    await operationAudited(result, 'domain.destinations_removed');
  });
});

describe('recipient validation through chat', () => {
  let domain: InsertedDomain;
  const localParts = async (): Promise<string[]> =>
    (
      await ctx.prisma.domainRecipientAddress.findMany({
        where: { domainId: domain.id },
        orderBy: { localPart: 'asc' },
      })
    ).map((r) => r.localPart);

  beforeAll(async () => {
    domain = await insertDomain(ctx, org, { label: 'chat-rcpt' });
  });

  it('domain_recipients_add (low)', async () => {
    const result = await chat('domain_recipients_add', {
      id: domain.publicId,
      body: { localParts: ['postmaster', 'alice'] },
    });
    expect(result.proposal.confirmation).toMatchObject({ risk: 'low', requiresReauth: false });
    executed(result, 200);
    expect(await localParts()).toEqual(['alice', 'postmaster']);
    await operationAudited(result, 'domain.recipients_added');
  });

  it('domain_recipients_set (medium): enforced allow-list', async () => {
    const result = await chat('domain_recipients_set', {
      id: domain.publicId,
      body: { mode: 'allow_list', enforcement: 'reject' },
    });
    expect(result.proposal.confirmation).toMatchObject({ risk: 'medium', requiresReauth: false });
    expect(result.proposal.confirmation.summary!.impact.length).toBeGreaterThanOrEqual(1);
    executed(result, 200);
    expect(await settingsOf(domain.publicId)).toMatchObject({
      recipientValidation: 'list',
      rejectUnknownRecipients: true,
    });
    const audit = await operationAudited(result, 'domain.recipient_validation_changed');
    expect(audit.metadata).toMatchObject({
      from: { mode: 'accept_all' },
      to: { mode: 'allow_list', enforcement: 'reject' },
    });
  });

  it('domain_recipients_remove (high)', async () => {
    const result = await chat('domain_recipients_remove', {
      id: domain.publicId,
      body: { localParts: ['alice'] },
    });
    expect(result.proposal.confirmation).toMatchObject({ risk: 'high', requiresReauth: true });
    executed(result, 200);
    expect(await localParts()).toEqual(['postmaster']);
    await operationAudited(result, 'domain.recipients_removed');
    await credentialFree(result);
  });
});
