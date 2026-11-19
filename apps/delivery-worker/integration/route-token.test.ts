import { GetObjectCommand, type S3Client } from '@aws-sdk/client-s3';
import { randomUUID } from 'node:crypto';
import { Readable } from 'node:stream';
import { deriveRouteToken } from '@email-gateway/mail-routing';
import { afterAll, afterEach, beforeAll, describe, expect, it } from 'vitest';
import { FakePostfix } from './support/fake-postfix';
import { DEFAULT_EML, Fixtures, type MessageFixture, workerConfig } from './support/fixtures';
import { buildWorker, FAST, type TestWorker } from './support/worker';

/**
 * Step 8.2 D9 (ADR-0081, §10.2): `X-EG-Route-Token` on internal reinjections to a domain of a
 * Microsoft 365 connection with internal routing and outbound `active`, after `X-Gateway-Trace`;
 * nothing for any other delivery; a lookup failure retries the row. Real MySQL writer and Redis;
 * EMLs are served by an in-memory S3 double (no object storage is written); fake postfix-outbound.
 */

const fx = new Fixtures();
const postfix = new FakePostfix();
const emls = new Map<string, string>();
const s3: Pick<S3Client, 'send'> = {
  send: ((command: unknown) => {
    if (command instanceof GetObjectCommand) {
      const eml = emls.get(command.input.Key ?? '');
      if (eml === undefined) {
        return Promise.reject(Object.assign(new Error('NoSuchKey'), { name: 'NoSuchKey' }));
      }
      return Promise.resolve({
        Body: Readable.from([Buffer.from(eml)]),
        ContentLength: eml.length,
      });
    }
    return Promise.reject(new Error('unexpected S3 command'));
  }) as S3Client['send'],
};

let worker: TestWorker;
let key: string;
let org: bigint;
const domains: Record<'m365' | 'google' | 'off', { id: bigint; name: string; connection: string }> =
  {} as never;

async function linked(
  label: 'm365' | 'google' | 'off',
  provider: 'microsoft_365' | 'google_workspace',
  internalRouting: boolean,
): Promise<void> {
  const name = fx.name(label);
  const id = await fx.domain(org, name, { destination: `mail.${label}.customer.example` });
  const tenant = provider === 'microsoft_365' ? randomUUID() : `C0${fx.suffix}`;
  const connection = await fx.prisma.providerConnection.create({
    data: {
      organizationId: org,
      provider,
      displayName: `it-${fx.suffix}-${label}`,
      status: 'active',
      externalTenantId: tenant,
      activeTenantKey: `${provider}:${tenant}:${label}`.slice(0, 100),
      outboundMode: 'active',
      internalRouting,
    },
  });
  await fx.prisma.providerConnectionDomain.create({
    data: { organizationId: org, connectionId: connection.id, domainId: id },
  });
  domains[label] = { id, name, connection: connection.publicId };
}

beforeAll(async () => {
  await postfix.start();
  const config = workerConfig({ ...FAST, ...postfix.configOverrides });
  if (!config.PROVIDER_ROUTE_TOKEN_KEY)
    throw new Error('PROVIDER_ROUTE_TOKEN_KEY must be set (.env)');
  key = config.PROVIDER_ROUTE_TOKEN_KEY;
  worker = buildWorker(fx, config, { s3 });
  org = await fx.organization('route');
  await linked('m365', 'microsoft_365', true);
  await linked('google', 'google_workspace', true);
  await linked('off', 'microsoft_365', false);
});
afterEach(() => postfix.reset());
afterAll(async () => {
  await worker?.close();
  await postfix.stop();
  try {
    await fx.prisma.providerConnection.deleteMany({
      where: { organizationId: { in: fx.organizationIds } },
    });
  } finally {
    await fx.cleanup();
  }
});

async function planned(
  direction: 'internal' | 'outbound',
  from: string,
  to: string,
): Promise<MessageFixture> {
  const message = await fx.message(org, {
    direction,
    envelopeFrom: from,
    recipients: [{ address: to, direction }],
    upload: false,
  });
  emls.set(message.emlObjectKey, DEFAULT_EML);
  expect(await worker.plan(fx.approval(message))).toMatchObject({ status: 'planned' });
  return message;
}

const headerLines = (data: Buffer): string[] => {
  const text = data.toString('utf8');
  return text.slice(0, text.indexOf('\r\n\r\n')).split('\r\n');
};

describe('route token on reinjection (D9)', () => {
  it('prepends X-EG-Route-Token after X-Gateway-Trace for internal mail to a Microsoft 365 domain with internal routing', async () => {
    const before = (await worker.metrics.routeTokenHeaders.get()).values[0]?.value ?? 0;
    await planned('internal', `alice@${domains.m365.name}`, `bob@${domains.m365.name}`);
    expect(await worker.reinjectOnce()).toBe(1);
    expect(postfix.transactions).toHaveLength(1);
    const tx = postfix.transactions[0]!;
    expect(tx.listener).toBe('inbound');
    const lines = headerLines(tx.data);
    expect(lines[0]).toMatch(/^X-Gateway-Trace: v=1; /);
    expect(lines[1]).toBe(`X-EG-Route-Token: ${deriveRouteToken(key, domains.m365.connection, 1)}`);
    expect(tx.data.toString('utf8').match(/X-Gateway-Trace/g)).toHaveLength(1);
    expect(tx.data.toString('utf8').match(/X-EG-Route-Token/g)).toHaveLength(1);
    // The EML itself is unchanged after the two prepended lines.
    expect(tx.data.toString('utf8').split('\r\n').slice(2).join('\r\n')).toBe(
      DEFAULT_EML.replace(/\n/g, '\r\n'),
    );
    expect((await worker.metrics.routeTokenHeaders.get()).values[0]?.value).toBe(before + 1);
  });

  it.each<[string, () => [string, string, 'internal' | 'outbound']]>([
    [
      'a Google Workspace domain',
      () => [`alice@${domains.google.name}`, `bob@${domains.google.name}`, 'internal'],
    ],
    [
      'internal routing off',
      () => [`alice@${domains.off.name}`, `bob@${domains.off.name}`, 'internal'],
    ],
    [
      'outbound mail from the linked domain',
      () => [`alice@${domains.m365.name}`, 'carol@external.example', 'outbound'],
    ],
  ])('adds exactly one trace header and no route token for %s', async (_, input) => {
    const [from, to, direction] = input();
    await planned(direction, from, to);
    expect(await worker.reinjectOnce()).toBe(1);
    const text = postfix.transactions[0]!.data.toString('utf8');
    expect(text.match(/X-Gateway-Trace/g)).toHaveLength(1);
    expect(text).not.toMatch(/X-EG-Route-Token/i);
  });

  it('retries the reinjection when the route token lookup fails (never sent without it)', async () => {
    const failing = buildWorker(fx, workerConfig({ ...FAST, ...postfix.configOverrides }), {
      s3,
      routeTokens: { headerFor: () => Promise.reject(new Error('db down')) },
    });
    try {
      const message = await planned(
        'internal',
        `alice@${domains.m365.name}`,
        `dave@${domains.m365.name}`,
      );
      expect(await failing.reinjectOnce()).toBe(1);
      expect(postfix.transactions).toHaveLength(0);
      const [row] = await fx.reinjections(message);
      expect(row).toMatchObject({ status: 'pending', lastErrorClass: 'reinjection_error' });
    } finally {
      await failing.close();
    }
  });
});
