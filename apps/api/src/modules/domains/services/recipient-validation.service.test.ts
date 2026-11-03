import { randomUUID } from 'node:crypto';
import { ConflictException, NotFoundException, UnprocessableEntityException } from '@nestjs/common';
import { describe, expect, it } from 'vitest';
import type { AuditService } from '../../../audit/audit.service';
import type { ApiKeyPrincipal } from '../../../auth-contracts/principal';
import { systemScope, type TenantScope } from '../../../auth-contracts/tenant-scope';
import type { TransactionRunner } from '../../../database/transaction-runner';
import type { RecipientValidationSettings } from '../domain/recipient-validation';
import { RecipientsBodySchema } from '../dto/recipients.schemas';
import type { DomainRow, DomainsRepository } from '../repositories/domains.repository';
import type { RecipientsRepository } from '../repositories/recipients.repository';
import type { DomainAuditRecord, DomainEventsService } from './domain-events.service';
import { RecipientValidationService } from './recipient-validation.service';

const ORG_A = systemScope(1n);
const ORG_B = systemScope(2n);
const principal: ApiKeyPrincipal = {
  kind: 'api_key',
  apiKeyId: 3n,
  apiKeyPublicId: randomUUID(),
  organizationId: 1n,
  organizationPublicId: randomUUID(),
  permissions: new Set(['domain:manage']),
};
const client = { ip: '203.0.113.9', userAgent: null } as never;

function setup(max = 100_000) {
  const domains = new Map<string, DomainRow>();
  const settings = new Map<bigint, RecipientValidationSettings>();
  let rows: Array<{ id: bigint; domainId: bigint; localPart: string; createdAt: Date }> = [];
  let nextId = 1n;
  const audits: DomainAuditRecord[] = [];

  const addDomain = (scope: TenantScope) => {
    const domain = {
      id: BigInt(domains.size + 1),
      publicId: randomUUID(),
      organizationId: scope.organizationId,
      name: `d${domains.size + 1}.test`,
    } as DomainRow;
    domains.set(domain.publicId, domain);
    return domain;
  };
  const find = (scope: TenantScope, publicId: string) => {
    const d = domains.get(publicId);
    return Promise.resolve(d && d.organizationId === scope.organizationId ? d : null);
  };
  const domainsRepo = {
    findByPublicId: find,
    lockByPublicId: (_tx: unknown, scope: TenantScope, id: string) => find(scope, id),
  } as unknown as DomainsRepository;
  const recipientsRepo = {
    findSettings: (_s: TenantScope, domainId: bigint) =>
      Promise.resolve(settings.get(domainId) ?? null),
    upsertSettings: (
      _tx: unknown,
      _s: TenantScope,
      domainId: bigint,
      data: RecipientValidationSettings,
    ) => {
      settings.set(domainId, data);
      return Promise.resolve();
    },
    count: (_s: TenantScope, domainId: bigint) =>
      Promise.resolve(rows.filter((r) => r.domainId === domainId).length),
    list: (_s: TenantScope, domainId: bigint, f: { q?: string }, page: { take: number }) =>
      Promise.resolve(
        rows
          .filter((r) => r.domainId === domainId && (!f.q || r.localPart.startsWith(f.q)))
          .reverse()
          .slice(0, page.take),
      ),
    addMany: (_tx: unknown, _s: TenantScope, domainId: bigint, parts: string[]) => {
      let added = 0;
      for (const localPart of parts) {
        if (rows.some((r) => r.domainId === domainId && r.localPart === localPart)) continue;
        rows.push({ id: nextId++, domainId, localPart, createdAt: new Date() });
        added++;
      }
      return Promise.resolve(added);
    },
    removeMany: (_tx: unknown, _s: TenantScope, domainId: bigint, parts: string[]) => {
      const before = rows.length;
      rows = rows.filter((r) => !(r.domainId === domainId && parts.includes(r.localPart)));
      return Promise.resolve(before - rows.length);
    },
  } as unknown as RecipientsRepository;
  const transactions = {
    run: async <T>(fn: (tx: never) => Promise<T>) => {
      const snapshot = { rows: [...rows], settings: new Map(settings), audits: audits.length };
      try {
        return await fn({} as never);
      } catch (err) {
        rows = snapshot.rows;
        settings.clear();
        for (const [k, v] of snapshot.settings) settings.set(k, v);
        audits.length = snapshot.audits;
        throw err;
      }
    },
  } as unknown as TransactionRunner;
  const events = {
    record: (_tx: unknown, record: DomainAuditRecord) => {
      audits.push(record);
      return Promise.resolve();
    },
  } as unknown as DomainEventsService;
  const audit = {
    actorFrom: () => ({ type: 'api_key', id: principal.apiKeyPublicId }),
  } as unknown as AuditService;
  const service = new RecipientValidationService(
    { DOMAIN_RECIPIENTS_MAX_PER_DOMAIN: max },
    transactions,
    audit,
    domainsRepo,
    recipientsRepo,
    events,
  );
  const add = (scope: TenantScope, id: string, localParts: string[]) =>
    service.add(principal, scope, id, RecipientsBodySchema.parse({ localParts }), client);
  const remove = (scope: TenantScope, id: string, localParts: string[]) =>
    service.remove(principal, scope, id, RecipientsBodySchema.parse({ localParts }), client);
  return { service, addDomain, settings, audits, add, remove, rows: () => rows };
}

describe('RecipientValidationService (D3, §4.1)', () => {
  it('defaults to accept_all without a settings row', async () => {
    const { service, addDomain } = setup();
    const d = addDomain(ORG_A);
    expect(await service.get(ORG_A, d.publicId)).toEqual({
      domainId: d.publicId,
      mode: 'accept_all',
      enforcement: 'monitor',
      implemented: true,
      addressCount: 0,
    });
  });

  it('refuses smtp_callout and ldap with 422 Not implemented, changing nothing', async () => {
    const { service, addDomain, settings, audits } = setup();
    const d = addDomain(ORG_A);
    for (const mode of ['smtp_callout', 'ldap'] as const) {
      const err = await service
        .set(principal, ORG_A, d.publicId, { mode, enforcement: 'reject' }, client)
        .catch((e: unknown) => e);
      expect(err).toBeInstanceOf(UnprocessableEntityException);
      expect((err as Error).message).toBe('Not implemented');
    }
    expect(settings.size).toBe(0);
    expect(audits).toHaveLength(0);
  });

  it('refuses to enforce an empty allow-list (409) but allows monitoring it', async () => {
    const { service, addDomain, settings, add } = setup();
    const d = addDomain(ORG_A);
    const err = await service
      .set(principal, ORG_A, d.publicId, { mode: 'allow_list', enforcement: 'reject' }, client)
      .catch((e: unknown) => e);
    expect(err).toBeInstanceOf(ConflictException);
    expect((err as Error).message).toBe('Add recipients before enforcing the allow-list');
    const monitored = await service.set(
      principal,
      ORG_A,
      d.publicId,
      { mode: 'allow_list', enforcement: 'monitor' },
      client,
    );
    expect(monitored).toMatchObject({ mode: 'allow_list', enforcement: 'monitor' });
    expect(settings.get(d.id)).toEqual({
      recipientValidation: 'list',
      rejectUnknownRecipients: false,
    });
    await add(ORG_A, d.publicId, ['Alice']);
    const enforced = await service.set(
      principal,
      ORG_A,
      d.publicId,
      { mode: 'allow_list', enforcement: 'reject' },
      client,
    );
    expect(enforced).toMatchObject({ mode: 'allow_list', enforcement: 'reject', addressCount: 1 });
    expect(settings.get(d.id)).toEqual({
      recipientValidation: 'list',
      rejectUnknownRecipients: true,
    });
  });

  it('audits mode changes once (from → to) and not repeated identical PUTs', async () => {
    const { service, addDomain, audits } = setup();
    const d = addDomain(ORG_A);
    const body = { mode: 'allow_list', enforcement: 'monitor' } as const;
    await service.set(principal, ORG_A, d.publicId, body, client);
    await service.set(principal, ORG_A, d.publicId, body, client);
    await service.set(principal, ORG_A, d.publicId, { mode: 'accept_all' }, client);
    expect(audits.map((a) => [a.action, a.metadata])).toEqual([
      [
        'domain.recipient_validation_changed',
        {
          from: { mode: 'accept_all', enforcement: 'monitor' },
          to: { mode: 'allow_list', enforcement: 'monitor' },
        },
      ],
      [
        'domain.recipient_validation_changed',
        {
          from: { mode: 'allow_list', enforcement: 'monitor' },
          to: { mode: 'accept_all', enforcement: 'monitor' },
        },
      ],
    ]);
  });

  it('adds idempotently with normalized local parts and audits counts only', async () => {
    const { addDomain, add, audits, rows } = setup();
    const d = addDomain(ORG_A);
    expect(await add(ORG_A, d.publicId, ['Alice', 'alice', 'BOB', 'José'])).toEqual({
      added: 3,
      existing: 0,
    });
    expect(await add(ORG_A, d.publicId, ['ALICE', 'carol'])).toEqual({ added: 1, existing: 1 });
    expect(await add(ORG_A, d.publicId, ['bob'])).toEqual({ added: 0, existing: 1 });
    expect(rows().map((r) => r.localPart)).toEqual(['alice', 'bob', 'josé', 'carol']);
    expect(audits.map((a) => [a.action, a.metadata])).toEqual([
      ['domain.recipients_added', { added: 3, existing: 0 }],
      ['domain.recipients_added', { added: 1, existing: 1 }],
    ]);
    expect(JSON.stringify(audits.map((a) => a.metadata))).not.toContain('alice');
  });

  it('enforces the per-domain cap atomically (409, nothing added)', async () => {
    const { addDomain, add, rows } = setup(3);
    const d = addDomain(ORG_A);
    await add(ORG_A, d.publicId, ['a', 'b']);
    await expect(add(ORG_A, d.publicId, ['c', 'd'])).rejects.toThrow(
      'Recipient limit reached: at most 3 per domain',
    );
    expect(rows()).toHaveLength(2);
    // Re-adding existing ones never trips the cap.
    await add(ORG_A, d.publicId, ['c']);
    expect(await add(ORG_A, d.publicId, ['a', 'b', 'c'])).toEqual({ added: 0, existing: 3 });
  });

  it('removes and reports the count; unknown ones are ignored', async () => {
    const { addDomain, add, remove, audits } = setup();
    const d = addDomain(ORG_A);
    await add(ORG_A, d.publicId, ['a', 'b', 'c']);
    expect(await remove(ORG_A, d.publicId, ['A', 'b', 'zzz'])).toEqual({ removed: 2 });
    expect(await remove(ORG_A, d.publicId, ['a'])).toEqual({ removed: 0 });
    expect(audits.at(-1)).toMatchObject({
      action: 'domain.recipients_removed',
      metadata: { removed: 2, requested: 3 },
    });
  });

  it('lists with a prefix filter, newest first', async () => {
    const { service, addDomain, add } = setup();
    const d = addDomain(ORG_A);
    await add(ORG_A, d.publicId, ['sales', 'support', 'billing']);
    const page = await service.list(ORG_A, d.publicId, { limit: 25, q: 's' });
    expect(page.data.map((r) => r.localPart)).toEqual(['support', 'sales']);
    expect(page.nextCursor).toBeNull();
  });

  it('answers 404 for another tenant’s domain on every method', async () => {
    const { service, addDomain, add, remove } = setup();
    const b = addDomain(ORG_B);
    const calls = [
      () => service.get(ORG_A, b.publicId),
      () => service.set(principal, ORG_A, b.publicId, { mode: 'accept_all' }, client),
      () => service.list(ORG_A, b.publicId, { limit: 25 }),
      () => add(ORG_A, b.publicId, ['x']),
      () => remove(ORG_A, b.publicId, ['x']),
    ];
    for (const call of calls) await expect(call()).rejects.toBeInstanceOf(NotFoundException);
    // Even an unimplemented mode answers 404 first for a foreign domain.
    await expect(
      service.set(principal, ORG_A, b.publicId, { mode: 'ldap', enforcement: 'reject' }, client),
    ).rejects.toBeInstanceOf(NotFoundException);
  });
});
