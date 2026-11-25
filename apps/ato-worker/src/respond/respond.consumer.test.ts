/* eslint-disable @typescript-eslint/require-await -- the fakes implement async interfaces */
import { ProviderAdapterError } from '@email-gateway/ato-detection';
import { defaultClassify } from '@email-gateway/common';
import { Prisma } from '@email-gateway/database';
import type { EventEnvelope } from '@email-gateway/event-contracts';
import { describe, expect, it } from 'vitest';
import { ProviderRetryError, RespondConsumer } from './respond.consumer';

// Step AI-4 D14: a transient database error during a provider action is redelivered by the
// queue as transient (attempts unchanged) and never recorded on the action as a failure.

const ORG = 910_002n;
const ACTION_PUBLIC_ID = '01890a5d-ac96-774b-bcce-000000000a01';

function harness(execute: () => Promise<unknown>) {
  const completions: unknown[] = [];
  const action = {
    id: 41n,
    publicId: ACTION_PUBLIC_ID,
    organizationId: ORG,
    accountId: 42n,
    provider: 'fake',
    actionType: 'revoke_sessions',
    status: 'approved',
    attempts: 0,
    integrationId: null,
    params: {},
    providerReference: null,
  };
  const consumer = new RespondConsumer({
    db: {
      transaction: async (fn: (tx: unknown) => Promise<unknown>) => fn({}),
      once: async () => ({ status: 'processed', result: { status: 'succeeded' } }),
    },
    prisma: {
      atoResponseAction: { findUnique: async () => action },
      atoProviderIntegration: { findFirst: async () => ({ id: 1n, organizationId: ORG }) },
      atoAccountIdentity: {
        findFirst: async () => ({
          organizationId: ORG,
          externalId: 'synthetic-identity',
          userPrincipalName: null,
        }),
      },
    },
    store: {
      completeProviderAction: async (_tx: unknown, input: unknown) => {
        completions.push(input);
        return { id: action.id, status: 'approved', rowVersion: 1 };
      },
    },
    registry: {
      get: () => ({
        kind: 'fake',
        capabilities: () => ({ actions: { revoke_sessions: { supported: true } } }),
        execute,
      }),
    },
    metrics: null,
    logger: { warn: () => undefined, debug: () => undefined },
    idp: null,
  } as unknown as ConstructorParameters<typeof RespondConsumer>[0]);
  const event = {
    eventId: '01890a5d-ac96-774b-bcce-000000000e01',
    eventType: 'ato.response.requested.v1',
    organizationId: ORG.toString(),
    payload: {
      actionId: action.id.toString(),
      actionPublicId: ACTION_PUBLIC_ID,
      phase: 'execute',
      actionType: 'revoke_sessions',
      provider: 'fake',
      incidentId: null,
      accountId: action.accountId.toString(),
      requestedAt: '2026-11-24T08:00:00.000Z',
    },
  } as unknown as EventEnvelope<unknown>;
  return { consumer, event, completions };
}

describe('RespondConsumer: transient database errors (D14)', () => {
  it('rethrows a P2024 of the adapter’s state store as transient; nothing recorded on the action', async () => {
    const h = harness(async () => {
      throw new Prisma.PrismaClientKnownRequestError('synthetic', {
        code: 'P2024',
        clientVersion: 'test',
      });
    });
    const error = await h.consumer.handle(h.event).catch((e: unknown) => e);
    expect(error).toMatchObject({ code: 'P2024' });
    expect(defaultClassify(error)).toBe('transient');
    expect(h.completions).toEqual([]);
  });

  it('still records a retryable provider failure as an attempt (unchanged)', async () => {
    const h = harness(async () => {
      throw new ProviderAdapterError('server_error', true);
    });
    const error = await h.consumer.handle(h.event).catch((e: unknown) => e);
    expect(error).toBeInstanceOf(ProviderRetryError);
    expect(defaultClassify(error)).toBe('retryable');
    expect(h.completions).toHaveLength(1);
    expect(h.completions[0]).toMatchObject({
      final: false,
      result: { status: 'failed', code: 'server_error' },
    });
  });
});
