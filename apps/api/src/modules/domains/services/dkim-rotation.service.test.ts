import { ConflictException, NotFoundException, ServiceUnavailableException } from '@nestjs/common';
import { describe, expect, it, vi } from 'vitest';
import { systemScope } from '../../../auth-contracts/tenant-scope';
import {
  client,
  createDomainTestbed,
  type DomainTestbed,
  ORG_A,
  ORG_B,
  userPrincipal,
} from '../../../../test/support/domains/domain-testbed';
import { TooManyRotationsException } from '../domains.errors';
import type * as DkimEngine from '../engine/dkim';
import { generateDkimKeyPair } from '../engine/dkim';
import { dkimKeyAad } from './domain-configuration.service';

vi.mock('../engine/dkim', async (importOriginal) => {
  const actual = await importOriginal<typeof DkimEngine>();
  return { ...actual, generateDkimKeyPair: vi.fn(actual.generateDkimKeyPair) };
});

const scopeA = systemScope(ORG_A);
const DAY = 86_400_000;

async function verifiedDomain(bed: DomainTestbed, name = 'rot.example.com') {
  const created = await bed.service.create(
    userPrincipal(),
    scopeA,
    { name, inboundEnabled: true },
    client,
  );
  bed.script(() => 'valid');
  await bed.verification.verifyNow(userPrincipal(), scopeA, created.id, client);
  return { created, row: bed.store.domains.find((d) => d.publicId === created.id)! };
}

const rotate = (bed: DomainTestbed, id: string, algorithm: 'rsa_2048' | 'ed25519' = 'rsa_2048') =>
  bed.rotation.rotate(userPrincipal(), scopeA, id, { algorithm }, client);

describe('DkimRotationService.rotate (D9)', () => {
  it('adds a pending key next to the active one and returns the record to publish', async () => {
    const bed = createDomainTestbed();
    const { created, row } = await verifiedDomain(bed);
    const [active] = bed.store.keysOf(row.id);
    const result = await rotate(bed, created.id);
    expect(result).toMatchObject({
      domainId: created.id,
      key: { algorithm: 'rsa_2048', status: 'pending' },
      previous: { selector: active!.selector, status: 'active' },
      dnsRecord: {
        key: `dkim:${result.key.selector}`,
        type: 'TXT',
        host: `${result.key.selector}._domainkey.rot.example.com`,
        name: `${result.key.selector}._domainkey`,
        status: 'pending',
      },
      overlapDays: 7,
    });
    expect(result.dnsRecord.value).toMatch(/^v=DKIM1; k=rsa; p=/);
    const stored = bed.store.keysOf(row.id).find((k) => k.selector === result.key.selector)!;
    expect(
      bed.secretBox.decrypt(stored.privateKeyCiphertext!, dkimKeyAad(created.id, stored.selector))
        .plaintext,
    ).toContain('PRIVATE KEY');
    expect(bed.store.audits.at(-1)).toMatchObject({
      action: 'domain.dkim_rotation_started',
      metadata: {
        algorithm: 'rsa_2048',
        selector: result.key.selector,
        previousSelector: active!.selector,
        replacedPending: false,
      },
    });
    expect(JSON.stringify(result)).not.toContain('PRIVATE');
  });

  it('refuses a second rotation while the new key waits for its record', async () => {
    const bed = createDomainTestbed();
    const { created } = await verifiedDomain(bed);
    await rotate(bed, created.id);
    await expect(rotate(bed, created.id)).rejects.toThrow(
      new ConflictException('A DKIM rotation is already in progress'),
    );
  });

  it('replaces a never-published pending key instead of stacking keys', async () => {
    const bed = createDomainTestbed();
    const created = await bed.service.create(
      userPrincipal(),
      scopeA,
      { name: 'p.example.com', inboundEnabled: true },
      client,
    );
    const row = bed.store.domains[0]!;
    const [old] = bed.store.keysOf(row.id);
    const result = await rotate(bed, created.id);
    expect(result.previous).toMatchObject({ selector: old!.selector, status: 'revoked' });
    const keys = bed.store.keysOf(row.id);
    expect(keys.find((k) => k.id === old!.id)).toMatchObject({
      status: 'revoked',
      privateKeyCiphertext: null,
    });
    const recordKeys = bed.store.recordsOf(row.id).map((r) => r.recordKey);
    expect(recordKeys).not.toContain(`dkim:${old!.selector}`);
    expect(recordKeys).toContain(`dkim:${result.key.selector}`);
    expect(bed.store.audits.at(-1)!.metadata).toMatchObject({ replacedPending: true });
  });

  it('runs through activation, overlap and retirement', async () => {
    const bed = createDomainTestbed();
    const { created, row } = await verifiedDomain(bed);
    const [old] = bed.store.keysOf(row.id);
    const { key } = await rotate(bed, created.id);
    // The customer publishes the new record; the next check activates it.
    await bed.verification.verifyNow(userPrincipal(), scopeA, created.id, client);
    const afterActivation = bed.store.keysOf(row.id);
    const rotating = afterActivation.find((k) => k.id === old!.id)!;
    expect(rotating.status).toBe('rotating');
    expect(rotating.retireAfter!.getTime() - Date.now()).toBeGreaterThan(7 * DAY - 60_000);
    expect(afterActivation.find((k) => k.selector === key.selector)!.status).toBe('active');
    // Still published during the overlap.
    expect(bed.store.recordsOf(row.id).map((r) => r.recordKey)).toContain(`dkim:${old!.selector}`);

    expect(await bed.rotation.retireDue(new Date())).toBe(0);
    const retired = await bed.rotation.retireDue(new Date(Date.now() + 8 * DAY));
    expect(retired).toBe(1);
    expect(bed.store.keysOf(row.id).find((k) => k.id === old!.id)).toMatchObject({
      status: 'retired',
      privateKeyCiphertext: null,
    });
    expect(bed.store.recordsOf(row.id).map((r) => r.recordKey)).not.toContain(
      `dkim:${old!.selector}`,
    );
    expect(bed.store.audits.at(-1)).toMatchObject({
      organizationId: ORG_A,
      action: 'domain.dkim_key_retired',
      actor: { type: 'system', id: null },
      metadata: { selector: old!.selector, algorithm: 'rsa_2048' },
    });
    // Retiring again is a no-op.
    expect(await bed.rotation.retireDue(new Date(Date.now() + 9 * DAY))).toBe(0);
    // A configuration pass does not resurrect the retired record.
    await bed.configuration.ensure(scopeA, row.id);
    expect(bed.store.recordsOf(row.id).map((r) => r.recordKey)).not.toContain(
      `dkim:${old!.selector}`,
    );
  });

  it('rotates the Ed25519 family independently', async () => {
    const bed = createDomainTestbed();
    const { created } = await verifiedDomain(bed);
    const result = await rotate(bed, created.id, 'ed25519');
    expect(result).toMatchObject({ key: { algorithm: 'ed25519' }, previous: null });
    expect(result.dnsRecord.value).toMatch(/^v=DKIM1; k=ed25519; p=/);
  });

  it('refuses failed domains, other tenants and in-progress rotations before generating a key', async () => {
    const bed = createDomainTestbed();
    const { created } = await verifiedDomain(bed);
    await rotate(bed, created.id);
    const generate = vi.mocked(generateDkimKeyPair);
    generate.mockClear();
    const failed = bed.store.addDomain(ORG_A, 'f.example.com', { status: 'failed' });
    await expect(rotate(bed, failed.publicId)).rejects.toThrow('Domain is failed');
    const other = bed.store.addDomain(ORG_B, 'b.example.com', { status: 'active' });
    await expect(rotate(bed, other.publicId)).rejects.toThrow(NotFoundException);
    await expect(rotate(bed, created.id)).rejects.toThrow('A DKIM rotation is already in progress');
    expect(generate).not.toHaveBeenCalled();
  });

  it('limits rotations per domain (10 per 24 h → 429 with the wait), bounding revoked rows', async () => {
    const bed = createDomainTestbed();
    const created = await bed.service.create(
      userPrincipal(),
      scopeA,
      { name: 'many.example.com', inboundEnabled: true },
      client,
    );
    const row = bed.store.domains.find((d) => d.publicId === created.id)!;
    // Only key pending: each call replaces it (the replace_pending path has no 409).
    for (let i = 0; i < 10; i++) await rotate(bed, created.id);
    const generate = vi.mocked(generateDkimKeyPair);
    generate.mockClear();
    const err = (await rotate(bed, created.id).catch(
      (e: unknown) => e,
    )) as TooManyRotationsException;
    expect(err).toBeInstanceOf(TooManyRotationsException);
    expect(err.getStatus()).toBe(429);
    expect(err.retryAfterSeconds).toBeGreaterThan(86_000);
    expect(generate).not.toHaveBeenCalled();
    expect(bed.store.keysOf(row.id)).toHaveLength(11);
    // Another domain has its own counter.
    const { created: second } = await verifiedDomain(bed, 'other.example.com');
    await expect(rotate(bed, second.id)).resolves.toBeDefined();
  });

  it('fails closed with 503 when the rotation counter store is unavailable', async () => {
    const bed = createDomainTestbed();
    const { created } = await verifiedDomain(bed);
    bed.kv.failing = true;
    await expect(rotate(bed, created.id)).rejects.toThrow(ServiceUnavailableException);
  });
});
