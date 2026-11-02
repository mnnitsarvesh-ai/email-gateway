import { BadRequestException, ConflictException, NotFoundException } from '@nestjs/common';
import { describe, expect, it, vi } from 'vitest';
import { systemScope } from '../../../auth-contracts/tenant-scope';
import {
  apiKeyPrincipal,
  client,
  createDomainTestbed,
  ORG_A,
  ORG_B,
  userPrincipal,
} from '../../../../test/support/domains/domain-testbed';
import type * as DkimEngine from '../engine/dkim';
import { generateDkimKeyPair } from '../engine/dkim';
import { dkimKeyAad } from './domain-configuration.service';
import { maxDomainNameLength } from './domains.service';

vi.mock('../engine/dkim', async (importOriginal) => {
  const actual = await importOriginal<typeof DkimEngine>();
  return { ...actual, generateDkimKeyPair: vi.fn(actual.generateDkimKeyPair) };
});

/** A valid name of exactly `length` characters under `example.com`. */
function nameOfLength(length: number): string {
  const suffix = 'example.com';
  let rest = length - suffix.length;
  const labels: string[] = [];
  while (rest > 0) {
    // Each label costs its length plus one dot; keep labels within 63 characters.
    const take = Math.min(63, rest - 1);
    labels.push('a'.repeat(Math.max(1, take)));
    rest -= Math.max(1, take) + 1;
  }
  const name = [...labels, suffix].join('.');
  if (name.length !== length) throw new Error(`cannot build a name of ${length}`);
  return name;
}

const scopeA = systemScope(ORG_A);
const scopeB = systemScope(ORG_B);
const DAY = 86_400_000;

async function createIn(
  bed: ReturnType<typeof createDomainTestbed>,
  name: string,
  scope = scopeA,
  extra: { ed25519?: boolean } = {},
) {
  return bed.service.create(
    userPrincipal(scope.organizationId),
    scope,
    { name, inboundEnabled: true, ...(extra.ed25519 && { dkim: { ed25519: true } }) },
    client,
  );
}

const messageOf = (err: unknown): string[] => {
  const response = (err as BadRequestException).getResponse() as { message: string[] };
  return response.message;
};

describe('DomainsService.create', () => {
  it('creates a pending domain with its challenge, an encrypted RSA key and the records', async () => {
    const bed = createDomainTestbed();
    const before = Date.now();
    const created = await createIn(bed, '  Münich-Mail.Example.COM. ');
    expect(created).toMatchObject({
      name: 'xn--mnich-mail-9db.example.com',
      unicodeName: 'münich-mail.example.com',
      status: 'pending_verification',
      inboundEnabled: true,
      outboundEnabled: false,
    });
    const row = bed.store.domains[0]!;
    expect(row.nextCheckAt!.getTime() - before).toBeGreaterThanOrEqual(59_000);
    expect(row.nextCheckAt!.getTime() - before).toBeLessThan(65_000);

    const verification = created.verification!;
    expect(verification).toMatchObject({ method: 'dns_txt', status: 'pending', attempts: 0 });
    expect(verification.host).toBe('_emailgateway-verify.xn--mnich-mail-9db.example.com');
    expect(verification.value).toMatch(/^emailgateway-verification=[0-9a-f]{40}$/);
    expect(new Date(verification.expiresAt).getTime() - before).toBeGreaterThanOrEqual(
      7 * DAY - 1000,
    );

    expect(created.dkimKeys).toHaveLength(1);
    const [key] = bed.store.keys;
    expect(key).toMatchObject({ algorithm: 'rsa_2048', status: 'pending' });
    expect(key!.selector).toMatch(/^egr\d{8}[a-z0-9]{4}$/);
    const decrypted = bed.secretBox.decrypt(
      key!.privateKeyCiphertext!,
      dkimKeyAad(created.id, key!.selector),
    );
    expect(decrypted.plaintext).toContain('BEGIN PRIVATE KEY');
    // Bound to its row: another selector's AAD does not decrypt it.
    expect(() =>
      bed.secretBox.decrypt(key!.privateKeyCiphertext!, dkimKeyAad(created.id, 'x')),
    ).toThrow();

    expect(created.dnsRecords.map((r) => r.key)).toEqual([
      'verification',
      'mx:mx1.mail-gateway.test',
      'mx:mx2.mail-gateway.test',
      'spf',
      `dkim:${key!.selector}`,
      'dmarc',
    ]);
    const mx = created.dnsRecords.find((r) => r.key === 'mx:mx1.mail-gateway.test')!;
    expect(mx).toMatchObject({
      type: 'MX',
      name: '@',
      value: 'mx1.mail-gateway.test',
      priority: 10,
    });
    expect(created.dnsRecords.every((r) => r.status === 'pending')).toBe(true);

    const serialized = JSON.stringify(created);
    expect(serialized).not.toContain('PRIVATE KEY');
    expect(serialized).not.toContain(key!.privateKeyCiphertext!);

    expect(bed.store.audits).toEqual([
      expect.objectContaining({
        organizationId: ORG_A,
        action: 'domain.created',
        resourceType: 'domain',
        resourceId: created.id,
        sourceIp: client.ip,
        actor: expect.objectContaining({ type: 'user' }),
        metadata: { name: created.name, inboundEnabled: true, algorithms: ['rsa_2048'] },
      }),
    ]);
    expect(bed.store.outbox).toEqual([]); // events are for transitions only
  });

  it('adds an Ed25519 key on request', async () => {
    const bed = createDomainTestbed();
    const created = await createIn(bed, 'ed.example.com', scopeA, { ed25519: true });
    expect(created.dkimKeys.map((k) => k.algorithm).sort()).toEqual(['ed25519', 'rsa_2048']);
    expect(created.dkimKeys.find((k) => k.algorithm === 'ed25519')!.selector).toMatch(/^ege/);
  });

  it('audits API-key callers as api_key actors', async () => {
    const bed = createDomainTestbed();
    await bed.service.create(
      apiKeyPrincipal(),
      scopeA,
      { name: 'k.example.com', inboundEnabled: false },
      client,
    );
    expect(bed.store.audits[0]!.actor.type).toBe('api_key');
    expect(bed.store.domains[0]!.inboundEnabled).toBe(false);
  });

  it.each([
    ['not a domain', 'name: Domain name contains a character that is not allowed (invalid)'],
    ['localhost', 'name: Domain name is reserved (localhost) (reserved)'],
    ['x.onion', 'name: Domain name is reserved (onion) (reserved)'],
    ['mx1.mail-gateway.test', 'name: Domain name is reserved (mx1.mail-gateway.test) (reserved)'],
    [
      'a._spf.mail-gateway.test',
      'name: Domain name contains a character that is not allowed (invalid)',
    ],
    ['blocked.example.net', 'name: Domain name is reserved (example.net) (reserved)'],
  ])('rejects %j with 400', async (name, message) => {
    const bed = createDomainTestbed({ DOMAIN_RESERVED_SUFFIXES: 'example.net' });
    const err = await createIn(bed, name).catch((e: unknown) => e);
    expect(err).toBeInstanceOf(BadRequestException);
    expect(messageOf(err)).toEqual([message]);
    expect(bed.store.domains).toEqual([]);
  });

  it('rejects the gateway SPF include host and names under it', () => {
    const bed = createDomainTestbed({ GATEWAY_SPF_INCLUDE: 'spf.mail-gateway.test' });
    expect(() => bed.service.normalizeName('spf.mail-gateway.test')).toThrow(BadRequestException);
    expect(() => bed.service.normalizeName('a.spf.mail-gateway.test')).toThrow(BadRequestException);
    expect(bed.service.normalizeName('mail-gateway.test')).toBe('mail-gateway.test');
  });

  it('accepts test names only in local and ci', () => {
    const local = createDomainTestbed({ APP_ENV: 'local' });
    expect(local.service.normalizeName('acme.test')).toBe('acme.test');
    const staging = createDomainTestbed({
      APP_ENV: 'staging',
      PORTAL_PUBLIC_URL: 'https://portal.example.com',
    });
    const reasons = ['acme.test', 'www.example.com'].map((name) => {
      try {
        staging.service.normalizeName(name);
        return null;
      } catch (err) {
        return messageOf(err);
      }
    });
    expect(reasons).toEqual([
      ['name: Domain name is reserved for testing (test) (reserved)'],
      ['name: Domain name is reserved for testing (example.com) (reserved)'],
    ]);
    expect(staging.service.normalizeName('acme.com')).toBe('acme.com');
  });

  it('limits names so every derived record host fits in 253 characters (D2, D6)', async () => {
    expect(maxDomainNameLength('_emailgateway-verify')).toBe(226); // DKIM host is the longest
    expect(maxDomainNameLength(`_${'v'.repeat(40)}`)).toBe(211); // verification host is
    const bed = createDomainTestbed();
    const longest = nameOfLength(226);
    const created = await createIn(bed, longest);
    const hosts = created.dnsRecords.map((r) => r.host);
    expect(Math.max(...hosts.map((h) => h.length))).toBe(253);
    for (const length of [227, 240, 253]) {
      const err = await createIn(bed, nameOfLength(length)).catch((e: unknown) => e);
      expect(err).toBeInstanceOf(BadRequestException);
      expect(messageOf(err)).toEqual([
        'name: Domain name is too long for its DNS records (at most 226 characters) (too_long)',
      ]);
    }
    const custom = createDomainTestbed({ DOMAIN_VERIFICATION_LABEL: `_${'v'.repeat(40)}` });
    expect(custom.service.normalizeName(nameOfLength(211))).toBe(nameOfLength(211));
    expect(() => custom.service.normalizeName(nameOfLength(212))).toThrow(BadRequestException);
    expect(bed.store.domains).toHaveLength(1);
  });

  it('refuses before generating keys (limit, duplicate, owned elsewhere)', async () => {
    const bed = createDomainTestbed();
    bed.store.addDomain(ORG_B, 'owned.example.com', { status: 'active' });
    await createIn(bed, 'dup.example.com');
    bed.store.maxDomains.set(ORG_B, 1);
    const generate = vi.mocked(generateDkimKeyPair);
    generate.mockClear();
    await expect(createIn(bed, 'dup.example.com')).rejects.toThrow(ConflictException);
    await expect(createIn(bed, 'owned.example.com')).rejects.toThrow(ConflictException);
    await expect(createIn(bed, 'two.example.com', scopeB)).rejects.toThrow(
      'Organization limit reached: max_domains',
    );
    expect(generate).not.toHaveBeenCalled();
  });

  it('enforces max_domains on non-deleted domains', async () => {
    const bed = createDomainTestbed();
    bed.store.maxDomains.set(ORG_A, 1);
    bed.store.addDomain(ORG_A, 'old.example.com', { status: 'deleted' });
    await createIn(bed, 'one.example.com');
    await expect(createIn(bed, 'two.example.com')).rejects.toThrow(
      new ConflictException('Organization limit reached: max_domains'),
    );
  });

  it('refuses a duplicate in the same organization', async () => {
    const bed = createDomainTestbed();
    await createIn(bed, 'dup.example.com');
    await expect(createIn(bed, 'DUP.example.com.')).rejects.toThrow('Domain already exists');
  });

  it('maps a concurrent create (live_name unique key) to 409', async () => {
    const bed = createDomainTestbed();
    bed.store.addDomain(ORG_A, 'race.example.com');
    vi.spyOn(bed.repos.domains, 'existsLive').mockResolvedValue(false);
    await expect(createIn(bed, 'race.example.com')).rejects.toThrow('Domain already exists');
  });

  it('refuses a name owned by another organization without naming it', async () => {
    const bed = createDomainTestbed();
    bed.store.addDomain(ORG_B, 'owned.example.com', { status: 'active' });
    const err = (await createIn(bed, 'owned.example.com').catch((e: unknown) => e)) as Error;
    expect(err).toBeInstanceOf(ConflictException);
    expect(err.message).toBe('Domain is already registered with another organization');
  });

  it('allows a name another organization merely claims, or deleted', async () => {
    const bed = createDomainTestbed();
    bed.store.addDomain(ORG_B, 'claimed.example.com');
    bed.store.addDomain(ORG_B, 'freed.example.com', { status: 'deleted' });
    await expect(createIn(bed, 'claimed.example.com')).resolves.toBeDefined();
    await expect(createIn(bed, 'freed.example.com')).resolves.toBeDefined();
  });
});

describe('DomainsService reads', () => {
  it('lists non-deleted domains of the scope, newest first, with filters', async () => {
    const bed = createDomainTestbed();
    const a = bed.store.addDomain(ORG_A, 'alpha.example.com');
    const b = bed.store.addDomain(ORG_A, 'beta.example.com', { status: 'active' });
    bed.store.addDomain(ORG_A, 'gone.example.com', { status: 'deleted' });
    bed.store.addDomain(ORG_B, 'alpha-b.example.com');
    const page = await bed.service.list(scopeA, { limit: 25 });
    expect(page.data.map((d) => d.id)).toEqual([b.publicId, a.publicId]);
    expect((await bed.service.list(scopeA, { limit: 25, status: 'active' })).data).toHaveLength(1);
    expect(
      (await bed.service.list(scopeA, { limit: 25, q: 'alp' })).data.map((d) => d.name),
    ).toEqual(['alpha.example.com']);
    const first = await bed.service.list(scopeA, { limit: 1 });
    expect(first.nextCursor).not.toBeNull();
    const second = await bed.service.list(scopeA, { limit: 1, cursor: first.nextCursor! });
    expect(second.data.map((d) => d.id)).toEqual([a.publicId]);
  });

  it('answers 404 for another tenant’s, deleted and unknown domains', async () => {
    const bed = createDomainTestbed();
    const other = bed.store.addDomain(ORG_B, 'b.example.com');
    const deleted = bed.store.addDomain(ORG_A, 'd.example.com', { status: 'deleted' });
    for (const id of [other.publicId, deleted.publicId, '0190a0b0-0000-7000-8000-000000000000']) {
      await expect(bed.service.get(scopeA, id)).rejects.toThrow(NotFoundException);
      await expect(bed.service.dnsRecords(scopeA, id)).rejects.toThrow(NotFoundException);
      await expect(bed.verification.statusView(scopeA, id)).rejects.toThrow(NotFoundException);
    }
  });

  it('lists retired DKIM selectors of the last 30 days under cleanup', async () => {
    const bed = createDomainTestbed();
    const domain = bed.store.addDomain(ORG_A, 'c.example.com', { status: 'active' });
    const now = new Date();
    bed.store.addKey(domain, 'recent', {
      status: 'retired',
      retiredAt: new Date(now.getTime() - DAY),
    });
    bed.store.addKey(domain, 'ancient', {
      status: 'retired',
      retiredAt: new Date(now.getTime() - 31 * DAY),
    });
    bed.store.addKey(domain, 'live', { status: 'active' });
    const view = await bed.service.dnsRecords(scopeA, domain.publicId);
    expect(view.cleanup).toEqual([
      expect.objectContaining({
        type: 'TXT',
        host: 'recent._domainkey.c.example.com',
        reason: 'retired_dkim_selector',
      }),
    ]);
    const detail = await bed.service.get(scopeA, domain.publicId);
    expect(detail.dkimKeys.map((k) => k.selector)).toEqual(['recent', 'live']);
  });
});

describe('DomainsService.changeStatus', () => {
  it('activates a verified domain, suspends and resumes it', async () => {
    const bed = createDomainTestbed();
    const d = bed.store.addDomain(ORG_A, 's.example.com', { status: 'verified' });
    const principal = userPrincipal();
    const active = await bed.service.changeStatus(
      principal,
      scopeA,
      d.publicId,
      { status: 'active' },
      client,
    );
    expect(active.status).toBe('active');
    const activatedAt = active.activatedAt;
    expect(activatedAt).not.toBeNull();

    const suspended = await bed.service.changeStatus(
      principal,
      scopeA,
      d.publicId,
      { status: 'suspended', reason: 'Billing hold' },
      client,
    );
    expect(suspended).toMatchObject({ status: 'suspended', statusReason: 'Billing hold' });

    const resumed = await bed.service.changeStatus(
      principal,
      scopeA,
      d.publicId,
      { status: 'active' },
      client,
    );
    expect(resumed).toMatchObject({ status: 'active', statusReason: null, activatedAt });

    expect(bed.store.audits.map((a) => [a.action, a.metadata])).toEqual([
      ['domain.status_changed', { name: d.name, from: 'verified', to: 'active', reason: null }],
      [
        'domain.status_changed',
        { name: d.name, from: 'active', to: 'suspended', reason: 'Billing hold' },
      ],
      ['domain.status_changed', { name: d.name, from: 'suspended', to: 'active', reason: null }],
    ]);
    expect(bed.store.outbox.map((e) => [e.payload.previousStatus, e.payload.status])).toEqual([
      ['verified', 'active'],
      ['active', 'suspended'],
      ['suspended', 'active'],
    ]);
    expect(bed.store.outbox[0]).toMatchObject({
      organizationId: ORG_A,
      payload: { domainId: d.id.toString(), domainPublicId: d.publicId, name: d.name },
    });
  });

  it.each([
    ['pending_verification', 'active', 'Domain is pending_verification'],
    ['failed', 'active', 'Domain is failed'],
    ['active', 'active', 'Domain is active'],
    ['verified', 'suspended', 'Domain is verified'],
    ['suspended', 'suspended', 'Domain is suspended'],
  ] as const)('refuses %s → %s with 409', async (from, to, message) => {
    const bed = createDomainTestbed();
    const d = bed.store.addDomain(ORG_A, 'x.example.com', { status: from });
    await expect(
      bed.service.changeStatus(
        userPrincipal(),
        scopeA,
        d.publicId,
        { status: to, reason: 'r' },
        client,
      ),
    ).rejects.toThrow(new ConflictException(message));
    expect(bed.store.outbox).toEqual([]);
  });

  it('cannot change another tenant’s domain', async () => {
    const bed = createDomainTestbed();
    const d = bed.store.addDomain(ORG_A, 'x.example.com', { status: 'verified' });
    await expect(
      bed.service.changeStatus(
        userPrincipal(ORG_B),
        scopeB,
        d.publicId,
        { status: 'active' },
        client,
      ),
    ).rejects.toThrow(NotFoundException);
    expect(bed.store.domain(d.id).status).toBe('verified');
  });
});

describe('DomainsService.remove', () => {
  it('refuses to delete an active domain', async () => {
    const bed = createDomainTestbed();
    const d = bed.store.addDomain(ORG_A, 'a.example.com', { status: 'active' });
    await expect(bed.service.remove(userPrincipal(), scopeA, d.publicId, client)).rejects.toThrow(
      'Suspend the domain before deleting it',
    );
  });

  it('soft-deletes: name freed, checks stopped, keys revoked, pending verification expired', async () => {
    const bed = createDomainTestbed();
    const created = await createIn(bed, 'del.example.com', scopeA, { ed25519: true });
    const row = bed.store.domains[0]!;
    bed.store.addKey(row, 'old', { status: 'retired', privateKeyCiphertext: null });
    await bed.service.remove(userPrincipal(), scopeA, created.id, client);

    expect(bed.store.domain(row.id)).toMatchObject({ status: 'deleted', nextCheckAt: null });
    expect(bed.store.domain(row.id).deletedAt).toBeInstanceOf(Date);
    const keys = bed.store.keysOf(row.id);
    expect(keys.filter((k) => k.selector !== 'old').every((k) => k.status === 'revoked')).toBe(
      true,
    );
    expect(keys.every((k) => k.privateKeyCiphertext === null)).toBe(true);
    expect(keys.find((k) => k.selector === 'old')!.status).toBe('retired');
    expect(bed.store.verificationsOf(row.id).map((v) => v.status)).toEqual(['expired']);

    const audit = bed.store.audits.at(-1)!;
    expect(audit.action).toBe('domain.deleted');
    expect(audit.metadata).toMatchObject({ from: 'pending_verification', to: 'deleted' });
    expect((audit.metadata!.revokedSelectors as string[]).sort()).toEqual(
      created.dkimKeys.map((k) => k.selector).sort(),
    );
    expect(bed.store.outbox.at(-1)!.payload).toMatchObject({
      previousStatus: 'pending_verification',
      status: 'deleted',
    });

    await expect(bed.service.get(scopeA, created.id)).rejects.toThrow(NotFoundException);
    await expect(bed.service.remove(userPrincipal(), scopeA, created.id, client)).rejects.toThrow(
      NotFoundException,
    );
    // The organization can add the name again (a new row).
    const again = await createIn(bed, 'del.example.com');
    expect(again.id).not.toBe(created.id);
  });
});
