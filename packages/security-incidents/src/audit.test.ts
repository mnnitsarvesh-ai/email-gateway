import type { Prisma } from '@email-gateway/database';
import { runWithContext } from '@email-gateway/logger';
import { describe, expect, it } from 'vitest';
import { scrubMetadata, writeAuditRow } from './audit';

describe('scrubMetadata (mirrors AuditService)', () => {
  it('drops credential-shaped keys at any depth and keeps safe identifiers', () => {
    expect(
      scrubMetadata({
        password: 'x',
        nested: { apiToken: 'y', ok: 1, list: [{ secretValue: 'z', n: 2n }] },
        resolutionCode: 'remediated',
        reasonCodes: ['ato.auth.bruteforce'],
        resultCode: 'restriction_applied',
        statusCode: 200,
        at: new Date('2026-11-18T00:00:00.000Z'),
        skip: undefined,
      }),
    ).toEqual({
      nested: { ok: 1, list: [{ n: '2' }] },
      resolutionCode: 'remediated',
      reasonCodes: ['ato.auth.bruteforce'],
      resultCode: 'restriction_applied',
      statusCode: 200,
      at: '2026-11-18T00:00:00.000Z',
    });
  });

  it('maps non-finite numbers to null', () => {
    expect(scrubMetadata({ n: Number.NaN })).toEqual({ n: null });
  });
});

describe('writeAuditRow (mirrors AuditService.record)', () => {
  function stubClient() {
    const rows: Array<Record<string, unknown>> = [];
    const tx = {
      auditLog: {
        create: (args: { data: Record<string, unknown> }) => {
          rows.push(args.data);
          return Promise.resolve({ id: 1n });
        },
      },
    } as unknown as Prisma.TransactionClient;
    return { rows, tx };
  }

  it('copies the platform override and the request id, takes the correlation id, clips columns', async () => {
    const { rows, tx } = stubClient();
    await runWithContext({ correlationId: 'corr-0001-abcdef', requestId: 'req-0001' }, () =>
      writeAuditRow(tx, {
        organizationId: 7n,
        actor: {
          type: 'user',
          id: 'u'.repeat(80),
          override: { id: 'ovr-1', reason: 'support case' },
        },
        action: 'security_incident.status_changed',
        resourceType: 'security_incident',
        resourceId: 'r'.repeat(80),
        sourceIp: '203.0.113.9',
        metadata: { from: 'open', to: 'resolved', refreshToken: 'never-stored' },
      }),
    );
    expect(rows).toHaveLength(1);
    const row = rows[0]!;
    expect(row.actorId).toHaveLength(64);
    expect(row.resourceId).toHaveLength(64);
    expect(row.correlationId).toBe('corr-0001-abcdef');
    expect(row.metadata).toEqual({
      from: 'open',
      to: 'resolved',
      override: { id: 'ovr-1', reason: 'support case' },
      requestId: 'req-0001',
    });
  });

  it('writes a null correlation id and no request id outside a request (system actor)', async () => {
    const { rows, tx } = stubClient();
    await writeAuditRow(tx, {
      organizationId: 7n,
      actor: { type: 'system', id: null },
      action: 'security_incident.created',
      resourceType: 'security_incident',
      metadata: { severity: 'high' },
    });
    expect(rows[0]!.correlationId).toBeNull();
    expect(rows[0]!.actorId).toBeNull();
    expect(rows[0]!.metadata).toEqual({ severity: 'high' });
  });
});
