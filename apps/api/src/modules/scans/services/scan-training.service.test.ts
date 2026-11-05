import { Readable } from 'node:stream';
import { HttpException } from '@nestjs/common';
import { RspamdHttpError, RspamdTimeoutError, RspamdUnavailableError } from '@email-gateway/rspamd';
import { describe, expect, it, vi } from 'vitest';
import { AuditService } from '../../../audit/audit.service';
import type { UserPrincipal } from '../../../auth-contracts/principal';
import type { TransactionRunner } from '../../../database/transaction-runner';
import type { ScanTrainingBody } from '../dto/scan-training.schemas';
import type { ScanTrainingRepository } from '../repositories/scan-training.repository';
import { type EmlStore, EmlUnavailableError } from './eml-store';
import type { RspamdController } from './rspamd-controller';
import { FUZZY_FLAG_NUMBERS, ScanTrainingService, trainingFailure } from './scan-training.service';

const ORG = '0190f0f0-0000-7000-8000-00000000000a';
const MSG = '0190f0f0-0000-7000-8000-00000000000b';
const client = { ip: '203.0.113.5', userAgent: null };
const platformUser: UserPrincipal = {
  kind: 'user',
  userId: 1n,
  userPublicId: '0190f0f0-0000-7000-8000-000000000001',
  organizationId: 1n,
  organizationPublicId: '0190f0f0-0000-7000-8000-000000000099',
  organizationKind: 'platform',
  sessionId: 's',
  mfaAuthenticated: true,
  mfaEnrollmentRequired: false,
  permissions: new Set(['platform:scan_training']),
};
const message = {
  id: 77n,
  publicId: MSG,
  receivedAt: new Date('2026-11-05T08:00:00Z'),
  organizationId: 9n,
  emlObjectKey: 'org/9/eml/2026/11/05/x.eml',
};

function setup(
  options: { rspamd?: Partial<Record<'learn' | 'fuzzy' | 'version', unknown>> | null } = {},
) {
  const TX = { tx: true };
  const repository = {
    findOrganization: vi.fn((publicId: string) =>
      Promise.resolve(publicId === ORG ? { id: 9n, publicId: ORG } : null),
    ),
    findMessage: vi.fn((_org: unknown, publicId: string) =>
      Promise.resolve(publicId === MSG ? message : null),
    ),
    insertTrainingEvent: vi.fn(() => Promise.resolve()),
  };
  const streams: Readable[] = [];
  const eml = {
    open: vi.fn(() => {
      const body = Readable.from([Buffer.from('Subject: x\r\n\r\nbody\r\n')]);
      streams.push(body);
      return Promise.resolve({ body, sizeBytes: 21 });
    }),
  };
  const rspamdClient =
    options.rspamd === null
      ? null
      : {
          learn: vi.fn(() => Promise.resolve('learned')),
          fuzzy: vi.fn((op: string) =>
            Promise.resolve({ result: op === 'add' ? 'added' : 'deleted', hashes: 2 }),
          ),
          version: vi.fn(() => Promise.resolve('3.12.1')),
          lastServerVersion: null,
          ...options.rspamd,
        };
  const controller = { client: rspamdClient, fuzzyWeight: 10 };
  const audits: Record<string, unknown>[] = [];
  const audit = {
    actorFrom: (p: UserPrincipal) => new AuditService({} as never).actorFrom(p),
    record: vi.fn((entry: Record<string, unknown>, tx: unknown) => {
      expect(tx).toBe(TX);
      audits.push(entry);
      return Promise.resolve();
    }),
  };
  const transactions = { run: vi.fn((fn: (tx: unknown) => Promise<unknown>) => fn(TX)) };
  const service = new ScanTrainingService(
    repository as unknown as ScanTrainingRepository,
    transactions as unknown as TransactionRunner,
    eml as unknown as EmlStore,
    controller as unknown as RspamdController,
    audit as unknown as AuditService,
  );
  return { service, repository, eml, rspamdClient, audits, streams };
}

const body = (operation: ScanTrainingBody['operation'], fuzzyFlag?: 'spam' | 'phishing') => ({
  operation,
  reason: 'confirmed campaign',
  ...(fuzzyFlag && { fuzzyFlag }),
});

const failure = async (promise: Promise<unknown>) => {
  const error = await promise.then(
    () => null,
    (e: unknown) => e,
  );
  expect(error).toBeInstanceOf(HttpException);
  return {
    status: (error as HttpException).getStatus(),
    code: ((error as HttpException).getResponse() as { code?: string }).code,
  };
};

describe('ScanTrainingService (step 4.1 S13)', () => {
  it('learns spam from the stored EML, audits the outcome and adds the timeline event', async () => {
    const { service, eml, rspamdClient, audits, repository, streams } = setup();
    const result = await service.train(platformUser, ORG, MSG, body('learn_spam'), client);
    expect(result).toEqual({ operation: 'learn_spam', result: 'learned', engineVersion: '3.12.1' });
    expect(eml.open).toHaveBeenCalledWith(9n, message.emlObjectKey);
    expect(rspamdClient!.learn).toHaveBeenCalledWith('spam', expect.any(Readable), 21);
    expect(audits).toEqual([
      {
        organizationId: 9n,
        actor: { type: 'user', id: platformUser.userPublicId },
        action: 'scan_training.learn_spam',
        resourceType: 'message',
        resourceId: MSG,
        sourceIp: '203.0.113.5',
        metadata: {
          operation: 'learn_spam',
          outcome: 'learned',
          engineVersion: '3.12.1',
          reason: 'confirmed campaign',
        },
      },
    ]);
    expect(repository.insertTrainingEvent).toHaveBeenCalledWith({ tx: true }, message, {
      occurredAt: expect.any(Date),
      actorId: platformUser.userPublicId,
      details: { operation: 'learn_spam', result: 'learned' },
    });
    expect(streams[0]!.destroyed).toBe(true);
  });

  it.each([
    ['learn_ham', undefined, 'learn', ['ham', expect.any(Readable), 21], 'already_learned'],
    ['fuzzy_add', 'spam', 'fuzzy', ['add', 11, 10, expect.any(Readable), 21], 'added'],
    ['fuzzy_delete', 'phishing', 'fuzzy', ['delete', 12, 10, expect.any(Readable), 21], 'deleted'],
  ] as const)(
    '%s (%s) calls %s and maps the result',
    async (operation, flag, method, args, expected) => {
      const { service, rspamdClient, audits } = setup(
        operation === 'learn_ham'
          ? { rspamd: { learn: vi.fn(() => Promise.resolve('already_learned')) } }
          : {},
      );
      const result = await service.train(platformUser, ORG, MSG, body(operation, flag), client);
      expect(result.result).toBe(expected);
      expect(
        (rspamdClient as unknown as Record<string, ReturnType<typeof vi.fn>>)[method],
      ).toHaveBeenCalledWith(...args);
      if (flag) {
        expect(audits[0]!.metadata).toMatchObject({
          fuzzyFlag: flag,
          fuzzyFlagNumber: FUZZY_FLAG_NUMBERS[flag],
        });
      }
    },
  );

  it('404s an unknown organization or a message outside that organization (nothing audited)', async () => {
    const { service, audits, eml } = setup();
    expect(
      await failure(service.train(platformUser, MSG, MSG, body('learn_spam'), client)),
    ).toEqual({ status: 404, code: 'organization_not_found' });
    expect(
      await failure(service.train(platformUser, ORG, ORG, body('learn_spam'), client)),
    ).toEqual({ status: 404, code: 'message_not_found' });
    expect(audits).toHaveLength(0);
    expect(eml.open).not.toHaveBeenCalled();
  });

  it('refuses a non-platform or override principal even with the permission', async () => {
    const { service } = setup();
    expect(
      await failure(
        service.train(
          { ...platformUser, organizationKind: 'customer' },
          ORG,
          MSG,
          body('learn_spam'),
          client,
        ),
      ),
    ).toEqual({ status: 403, code: undefined });
  });

  it('409 content_unavailable when the EML is missing or outside the prefix (audited)', async () => {
    for (const why of ['not_found', 'foreign_key'] as const) {
      const { service, eml, audits, repository, rspamdClient } = setup();
      eml.open.mockRejectedValueOnce(new EmlUnavailableError(why));
      expect(
        await failure(service.train(platformUser, ORG, MSG, body('learn_spam'), client)),
      ).toEqual({ status: 409, code: 'content_unavailable' });
      expect(audits[0]!.metadata).toMatchObject({
        outcome: 'content_unavailable',
        engineVersion: null,
      });
      expect(repository.insertTrainingEvent).not.toHaveBeenCalled();
      expect(rspamdClient!.learn).not.toHaveBeenCalled();
    }
  });

  it('503 rspamd_unavailable without a controller, on outages and timeouts (audited)', async () => {
    const none = setup({ rspamd: null });
    expect(
      await failure(none.service.train(platformUser, ORG, MSG, body('learn_spam'), client)),
    ).toEqual({ status: 503, code: 'rspamd_unavailable' });
    expect(none.audits[0]!.metadata).toMatchObject({ outcome: 'rspamd_unavailable' });
    expect(none.eml.open).not.toHaveBeenCalled();
    for (const error of [
      new RspamdUnavailableError('learnspam', 'ECONNREFUSED'),
      new RspamdTimeoutError('learnspam', 30_000),
      new RspamdHttpError('learnspam', 401),
      new Error('socket hang up'),
    ]) {
      const { service, audits, repository } = setup({
        rspamd: { learn: vi.fn(() => Promise.reject(error)) },
      });
      expect(
        await failure(service.train(platformUser, ORG, MSG, body('learn_spam'), client)),
      ).toEqual({ status: 503, code: 'rspamd_unavailable' });
      expect(audits[0]!.metadata).toMatchObject({ outcome: 'rspamd_unavailable' });
      expect(repository.insertTrainingEvent).not.toHaveBeenCalled();
    }
  });

  it('422 when Rspamd has nothing to hash (fuzzy 404); the version falls back to unknown', async () => {
    expect(trainingFailure('fuzzy_add', new RspamdHttpError('fuzzyadd', 404)).outcome).toBe(
      'not_applicable',
    );
    expect(trainingFailure('learn_spam', new RspamdHttpError('learnspam', 404)).outcome).toBe(
      'rspamd_unavailable',
    );
    const { service } = setup({
      rspamd: {
        fuzzy: vi.fn(() => Promise.reject(new RspamdHttpError('fuzzyadd', 404))),
      },
    });
    expect(
      await failure(service.train(platformUser, ORG, MSG, body('fuzzy_add', 'spam'), client)),
    ).toEqual({ status: 422, code: 'scan_training_not_applicable' });
    const unknownVersion = setup({
      rspamd: { version: vi.fn(() => Promise.reject(new Error('x'))) },
    });
    expect(
      (await unknownVersion.service.train(platformUser, ORG, MSG, body('learn_spam'), client))
        .engineVersion,
    ).toBe('unknown');
  });
});
