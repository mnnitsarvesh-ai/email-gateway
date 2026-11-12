/**
 * Inbound recipient validation (step 2.2 D3, §4.1) against real MySQL: the mode stored in the
 * existing `domain_settings` columns (accept_all ⇄ none, allow_list ⇄ list,
 * reject/monitor ⇄ reject_unknown_recipients), the 422 for unimplemented modes, the 409 for an
 * empty enforced list, the allow-list (normalization, idempotent bulk add, prefix listing,
 * remove, per-domain cap) and the audit rows (counts only).
 */
// ---- Route coverage (step 6.1 §3.8, test/route-coverage/legacy.ts) ----
// @covers get /api/v1/domains/:id/recipient-validation
// @covers get /api/v1/domains/:id/recipients
// @covers post /api/v1/domains/:id/recipients
// @covers post /api/v1/domains/:id/recipients/remove
// @covers put /api/v1/domains/:id/recipient-validation
// ---- end of route coverage ----
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { TestDnsServer } from '../test/support/dns/test-dns-server';
import type { IntegrationApp } from './support/app';
import { createDomainApp, DomainApi, domainAudit, uniqueDomainName } from './support/domains';
import { createFixtures, type FixtureOrganization, type Fixtures } from './support/fixtures';
import { apiKeyHeader, bearer, loginWithMfa } from './support/http';
import { RecipientApi } from './support/smtp';

const MAX_RECIPIENTS = 5;
const POLL = { timeout: 10_000, interval: 200 };

let dns: TestDnsServer;
let ctx: IntegrationApp;
let fx: Fixtures;
let org: FixtureOrganization;
let domains: DomainApi;
let api: RecipientApi;

const settings = async (publicId: string) => {
  const domain = await ctx.prisma.domain.findUniqueOrThrow({
    where: { publicId },
    include: { settings: true },
  });
  return domain.settings;
};
const listed = async (id: string, query = ''): Promise<string[]> => {
  const res = await api.list(id, query).expect(200);
  return (res.body.data as Array<{ localPart: string }>).map((r) => r.localPart);
};

beforeAll(async () => {
  dns = await TestDnsServer.start({ defaultTtl: 60 });
  ctx = await createDomainApp(dns, { DOMAIN_RECIPIENTS_MAX_PER_DOMAIN: String(MAX_RECIPIENTS) });
  fx = createFixtures(ctx);
  org = await fx.createOrganization();
  const user = await fx.createUser(org, { roles: ['domain_admin'] });
  const headers = bearer((await loginWithMfa(ctx, fx, user)).accessToken);
  domains = new DomainApi(ctx, headers);
  api = new RecipientApi(ctx, headers);
});

afterAll(async () => {
  await fx?.cleanup();
  await ctx?.close();
  await dns?.close();
});

describe('recipient validation mode', () => {
  it('starts as accept_all and maps every mode onto domain_settings', async () => {
    const domain = await domains.okCreate(uniqueDomainName('rv'));
    expect((await api.getValidation(domain.id).expect(200)).body).toEqual({
      domainId: domain.id,
      mode: 'accept_all',
      enforcement: 'monitor',
      implemented: true,
      addressCount: 0,
    });

    // Monitor mode works with an empty list (onboarding shadow mode).
    const monitor = await api
      .setValidation(domain.id, { mode: 'allow_list', enforcement: 'monitor' })
      .expect(200);
    expect(monitor.body).toMatchObject({ mode: 'allow_list', enforcement: 'monitor' });
    expect(await settings(domain.id)).toMatchObject({
      recipientValidation: 'list',
      rejectUnknownRecipients: false,
    });

    // Enforcing an empty list would reject everyone.
    const empty = await api
      .setValidation(domain.id, { mode: 'allow_list', enforcement: 'reject' })
      .expect(409);
    expect(empty.body.message).toBe('Add recipients before enforcing the allow-list');

    await api.add(domain.id, ['postmaster']).expect(200);
    const reject = await api
      .setValidation(domain.id, { mode: 'allow_list', enforcement: 'reject' })
      .expect(200);
    expect(reject.body).toMatchObject({
      mode: 'allow_list',
      enforcement: 'reject',
      implemented: true,
      addressCount: 1,
    });
    expect(await settings(domain.id)).toMatchObject({
      recipientValidation: 'list',
      rejectUnknownRecipients: true,
    });

    await api.setValidation(domain.id, { mode: 'accept_all' }).expect(200);
    expect(await settings(domain.id)).toMatchObject({
      recipientValidation: 'none',
      rejectUnknownRecipients: false,
    });

    const audits = await domainAudit(ctx, domain.id, 'domain.recipient_validation_changed');
    const withoutName = (m: unknown) => {
      // Step 6.1 D11: every audit row also carries the X-Request-Id of its request.
      const { name, requestId, ...rest } = m as { name: string; requestId: unknown };
      expect(name).toBe(domain.name);
      expect(typeof requestId).toBe('string');
      return rest;
    };
    expect(audits.map((a) => withoutName(a.metadata))).toEqual([
      {
        from: { mode: 'accept_all', enforcement: 'monitor' },
        to: { mode: 'allow_list', enforcement: 'monitor' },
      },
      {
        from: { mode: 'allow_list', enforcement: 'monitor' },
        to: { mode: 'allow_list', enforcement: 'reject' },
      },
      {
        from: { mode: 'allow_list', enforcement: 'reject' },
        to: { mode: 'accept_all', enforcement: 'monitor' },
      },
    ]);
  });

  it('refuses smtp_callout and ldap with 422 Not implemented', async () => {
    const domain = await domains.okCreate(uniqueDomainName('rv-422'));
    for (const mode of ['smtp_callout', 'ldap']) {
      const res = await api.setValidation(domain.id, { mode, enforcement: 'reject' }).expect(422);
      expect(res.body).toMatchObject({ error: 'UNPROCESSABLE_ENTITY', message: 'Not implemented' });
    }
    expect(await settings(domain.id)).toMatchObject({ recipientValidation: 'none' });
  });

  it('reports modes set outside the API as not implemented', async () => {
    const domain = await domains.okCreate(uniqueDomainName('rv-ldap'));
    const { id } = await ctx.prisma.domain.findUniqueOrThrow({ where: { publicId: domain.id } });
    await ctx.prisma.domainSetting.update({
      where: { domainId: id },
      data: { recipientValidation: 'ldap', rejectUnknownRecipients: true },
    });
    expect((await api.getValidation(domain.id).expect(200)).body).toMatchObject({
      mode: 'ldap',
      enforcement: 'reject',
      implemented: false,
    });
  });

  it('creates the settings row when a domain has none', async () => {
    const domain = await domains.okCreate(uniqueDomainName('rv-nosettings'));
    const { id } = await ctx.prisma.domain.findUniqueOrThrow({ where: { publicId: domain.id } });
    await ctx.prisma.domainSetting.delete({ where: { domainId: id } });
    await api.setValidation(domain.id, { mode: 'allow_list', enforcement: 'monitor' }).expect(200);
    expect(await settings(domain.id)).toMatchObject({
      organizationId: org.id,
      recipientValidation: 'list',
    });
  });
});

describe('recipient allow-list', () => {
  it('adds normalized local parts idempotently and lists them by prefix', async () => {
    const domain = await domains.okCreate(uniqueDomainName('rl'));
    const first = await api.add(domain.id, ['Sales', 'sales', 'SUPPORT', 'a_b']).expect(200);
    expect(first.body).toEqual({ added: 3, existing: 0 });
    const again = await api.add(domain.id, ['support', 'axb']).expect(200);
    expect(again.body).toEqual({ added: 1, existing: 1 });

    const rows = await ctx.prisma.domainRecipientAddress.findMany({
      where: { domain: { publicId: domain.id } },
      orderBy: { id: 'asc' },
    });
    expect(rows.map((r) => r.localPart)).toEqual(['sales', 'support', 'a_b', 'axb']);
    expect(rows.every((r) => r.organizationId === org.id && r.createdByUserId !== null)).toBe(true);

    await expect.poll(() => listed(domain.id), POLL).toHaveLength(4);
    expect(await listed(domain.id, '?q=S')).toEqual(['support', 'sales']);
    // `_` is literal in the prefix, not a LIKE wildcard.
    expect(await listed(domain.id, '?q=a_')).toEqual(['a_b']);
    const page = await api.list(domain.id, '?limit=3').expect(200);
    expect(page.body.data).toHaveLength(3);
    const rest = await api.list(domain.id, `?limit=3&cursor=${page.body.nextCursor}`).expect(200);
    expect(rest.body.data).toHaveLength(1);
    expect(rest.body.nextCursor).toBeNull();

    const audits = await domainAudit(ctx, domain.id, 'domain.recipients_added');
    expect(audits.map((a) => a.metadata)).toEqual([
      { name: domain.name, added: 3, existing: 0, requestId: expect.any(String) },
      { name: domain.name, added: 1, existing: 1, requestId: expect.any(String) },
    ]);
  });

  it(`enforces DOMAIN_RECIPIENTS_MAX_PER_DOMAIN (${MAX_RECIPIENTS} in this suite) atomically`, async () => {
    const domain = await domains.okCreate(uniqueDomainName('rl-cap'));
    await api.add(domain.id, ['a', 'b', 'c', 'd']).expect(200);
    const res = await api.add(domain.id, ['e', 'f']).expect(409);
    expect(res.body.message).toBe(`Recipient limit reached: at most ${MAX_RECIPIENTS} per domain`);
    expect(
      await ctx.prisma.domainRecipientAddress.count({ where: { domain: { publicId: domain.id } } }),
    ).toBe(4);
    await api.add(domain.id, ['e', 'a']).expect(200);
  });

  it('removes local parts and reports the count', async () => {
    const domain = await domains.okCreate(uniqueDomainName('rl-rm'));
    await api.add(domain.id, ['x', 'y', 'z']).expect(200);
    expect((await api.remove(domain.id, ['X', 'y', 'nobody']).expect(200)).body).toEqual({
      removed: 2,
    });
    expect((await api.remove(domain.id, ['x']).expect(200)).body).toEqual({ removed: 0 });
    const [audit] = await domainAudit(ctx, domain.id, 'domain.recipients_removed');
    expect(audit!.metadata).toEqual({
      name: domain.name,
      removed: 2,
      requested: 3,
      requestId: expect.any(String),
    });
    expect((await api.getValidation(domain.id).expect(200)).body.addressCount).toBe(1);
  });

  it('validates input (400) and refuses deleted domains (404)', async () => {
    const domain = await domains.okCreate(uniqueDomainName('rl-400'));
    const bad = await api.add(domain.id, ['ok', 'a@b.test', ' ', 'x'.repeat(65), 5]).expect(400);
    expect(bad.body.message).toEqual([
      'localParts.1: must be a local part without "@" or domain',
      'localParts.2: must not contain whitespace or control characters',
      'localParts.3: must be at most 64 bytes (UTF-8)',
      'localParts.4: Invalid input: expected string, received number',
    ]);
    await domains.remove(domain.id).expect(204);
    await api.getValidation(domain.id).expect(404);
    await api.add(domain.id, ['ok']).expect(404);
  });

  it('read-only API keys can read but not change', async () => {
    const domain = await domains.okCreate(uniqueDomainName('rl-ro'));
    const ro = new RecipientApi(ctx, apiKeyHeader(await fx.createApiKey(org, ['domain:read'])));
    await ro.getValidation(domain.id).expect(200);
    await ro.list(domain.id).expect(200);
    await ro.setValidation(domain.id, { mode: 'accept_all' }).expect(403);
    await ro.add(domain.id, ['a']).expect(403);
    await ro.remove(domain.id, ['a']).expect(403);
  });
});
