import { randomUUID } from 'node:crypto';
import { createConnection } from 'node:net';
import { PrismaService, RedisService } from '@email-gateway/common';
import { runWithContext } from '@email-gateway/logger';
import { ConflictException, Logger } from '@nestjs/common';
import { afterAll, beforeAll, describe, expect, it, vi } from 'vitest';
import { describeKeyValueStoreContract } from '../test/support/key-value-store-contract';
import { AuditService, SYSTEM_ACTOR } from '../src/audit/audit.service';
import { TransactionRunner } from '../src/database/transaction-runner';
import { EmailDeliveryError, SmtpEmailSender } from '../src/email/smtp-email-sender';
import { KV_KEY_PREFIX, RedisKeyValueStore } from '../src/kv/redis-key-value-store';
import { OrganizationFeaturesService } from '../src/tenancy/organization-features.service';
import { OrganizationLimitsService } from '../src/tenancy/organization-limits.service';

function required(key: string): string {
  const value = process.env[key];
  if (!value)
    throw new Error(`${key} is not set. Run \`pnpm env:init\` and start the stack first.`);
  return value;
}

const HOST = '127.0.0.1';
const smtpPort = Number(process.env.SMTP_HOST_PORT ?? 2525);
const relayDomain = (process.env.POSTFIX_RELAY_DOMAINS ?? 'gateway.test').split(',')[0]!.trim();
const policyPort = Number(process.env.SMTP_ADAPTER_HOST_PORT ?? 3010);

function reachable(port: number): Promise<boolean> {
  return new Promise((resolve) => {
    const socket = createConnection({ host: HOST, port });
    socket.setTimeout(1_000);
    socket.once('connect', () => {
      socket.destroy();
      resolve(true);
    });
    socket.once('timeout', () => {
      socket.destroy();
      resolve(false);
    });
    socket.once('error', () => resolve(false));
  });
}

async function policyServiceUp(): Promise<boolean> {
  try {
    return (
      await fetch(`http://${HOST}:${policyPort}/health/live`, {
        signal: AbortSignal.timeout(1_000),
      })
    ).ok;
  } catch {
    return false;
  }
}

let redis: RedisService;
let prisma: PrismaService;

beforeAll(async () => {
  redis = new RedisService({ url: required('REDIS_URL') });
  prisma = new PrismaService({ url: required('DATABASE_URL') });
  await prisma.$connect();
});

afterAll(async () => {
  await redis?.onModuleDestroy();
  await prisma?.$disconnect();
});

describe('RedisKeyValueStore against Redis', () => {
  describeKeyValueStoreContract('RedisKeyValueStore', () => new RedisKeyValueStore(redis));

  it('stores keys under the eg: prefix', async () => {
    const kv = new RedisKeyValueStore(redis);
    const key = `test:prefix:${randomUUID()}`;
    try {
      await kv.set(key, 'v', 60);
      expect(await redis.client.get(`${KV_KEY_PREFIX}${key}`)).toBe('v');
      expect(await redis.client.exists(key)).toBe(0);
    } finally {
      await kv.del(key);
    }
  });

  it('incrWithTtl is atomic under concurrency', async () => {
    const kv = new RedisKeyValueStore(redis);
    const key = `test:concurrent:${randomUUID()}`;
    try {
      const results = await Promise.all(Array.from({ length: 50 }, () => kv.incrWithTtl(key, 60)));
      expect([...results].sort((a, b) => a - b)).toEqual(
        Array.from({ length: 50 }, (_, i) => i + 1),
      );
      expect(await kv.ttl(key)).toBeGreaterThan(0);
    } finally {
      await kv.del(key);
    }
  });
});

describe('AuditService against MySQL (partitioned audit_logs)', () => {
  it('writes a row and reads it back', async () => {
    const audit = new AuditService(prisma);
    const correlationId = `it-audit-${randomUUID()}`;
    await runWithContext({ correlationId }, () =>
      audit.record({
        organizationId: null,
        actor: SYSTEM_ACTOR,
        action: 'test.audit_probe',
        resourceType: 'test',
        resourceId: correlationId.slice(0, 64),
        sourceIp: '203.0.113.10',
        metadata: { probe: true, big: 12345678901234567890n, password: 'never-stored' },
      }),
    );
    const rows = await prisma.auditLog.findMany({ where: { correlationId } });
    expect(rows).toHaveLength(1);
    expect(rows[0]).toMatchObject({
      organizationId: null,
      actorType: 'system',
      actorId: null,
      action: 'test.audit_probe',
      resourceType: 'test',
      sourceIp: '203.0.113.10',
      metadata: { probe: true, big: '12345678901234567890' },
    });
    // audit_logs is append-only: the probe row stays, like every other audit row.
  });
});

describe('OrganizationLimitsService against MySQL', () => {
  const limits = new OrganizationLimitsService();
  let runner: TransactionRunner;
  let organizationId: bigint | undefined;
  let skipReason: string | undefined;

  beforeAll(async () => {
    runner = new TransactionRunner(prisma);
    const plan = await prisma.organizationPlan.findUnique({ where: { code: 'standard' } });
    if (!plan) {
      skipReason = 'organization plan "standard" is not seeded (run pnpm db:seed)';
      return;
    }
    const slug = `it-limits-${randomUUID().slice(0, 8)}`;
    const org = await prisma.organization.create({
      data: { slug, name: 'Integration limits probe', planId: plan.id, dataRegion: 'ap-south-1' },
    });
    organizationId = org.id;
    await prisma.organizationLimit.create({
      data: { organizationId: org.id, limitKey: 'max_users', limitValue: 2n, source: 'override' },
    });
    await prisma.organizationFeature.create({
      data: { organizationId: org.id, featureKey: 'api_access', enabled: true, source: 'override' },
    });
  });

  afterAll(async () => {
    if (organizationId === undefined) return;
    await prisma.organizationLimit.deleteMany({ where: { organizationId } });
    await prisma.organizationFeature.deleteMany({ where: { organizationId } });
    await prisma.organization.delete({ where: { id: organizationId } });
  });

  it('reads limits and enforces them inside a transaction', async (ctx) => {
    if (skipReason) ctx.skip(skipReason);
    const orgId = organizationId!;
    await runner.run(async (tx) => {
      await limits.lockOrganization(tx, orgId);
      expect(await limits.getLimit(tx, orgId, 'max_users')).toBe(2n);
      expect(await limits.getLimit(tx, orgId, 'not_a_limit')).toBeNull();
      await limits.assertWithinLimit(tx, orgId, 'max_users', 1);
      await expect(limits.assertWithinLimit(tx, orgId, 'max_users', 2)).rejects.toThrow(
        new ConflictException('Organization limit reached: max_users'),
      );
    });
  });

  it('serializes concurrent transactions on the organization row lock', async (ctx) => {
    if (skipReason) ctx.skip(skipReason);
    const orgId = organizationId!;
    const events: string[] = [];
    let releaseFirst!: () => void;
    const firstHoldsLock = new Promise<void>((resolve) => {
      const first = runner.run(async (tx) => {
        await limits.lockOrganization(tx, orgId);
        events.push('first locked');
        resolve();
        await new Promise<void>((r) => (releaseFirst = r));
        events.push('first commits');
      });
      void first;
    });
    await firstHoldsLock;
    const second = runner.run(async (tx) => {
      await limits.lockOrganization(tx, orgId);
      events.push('second locked');
    });
    await new Promise((r) => setTimeout(r, 300));
    expect(events).toEqual(['first locked']);
    releaseFirst();
    await second;
    expect(events).toEqual(['first locked', 'first commits', 'second locked']);
  });

  it('reads feature flags on the writer', async (ctx) => {
    if (skipReason) ctx.skip(skipReason);
    const features = new OrganizationFeaturesService(prisma);
    expect(await features.isEnabled(organizationId!, 'api_access')).toBe(true);
    expect(await features.isEnabled(organizationId!, 'sso')).toBe(false);
  });
});

describe('SmtpEmailSender against the Compose Postfix (never NOTIFY_SMTP_HOST)', () => {
  let postfixUp = false;
  let policyUp = false;
  let sender: SmtpEmailSender;
  const email = {
    kind: 'email_verification' as const,
    to: `probe@${relayDomain}`,
    subject: 'Integration probe',
    text: 'SmtpEmailSender integration probe. No token.',
  };

  beforeAll(async () => {
    postfixUp = await reachable(smtpPort);
    policyUp = await policyServiceUp();
    vi.spyOn(Logger.prototype, 'log').mockImplementation(() => undefined);
    vi.spyOn(Logger.prototype, 'error').mockImplementation(() => undefined);
    sender = new SmtpEmailSender({
      NOTIFY_SMTP_HOST: HOST,
      NOTIFY_SMTP_PORT: smtpPort,
      NOTIFY_SMTP_SECURE: 'none',
      NOTIFY_SMTP_FROM: 'no-reply@gateway.local',
    });
  });

  afterAll(() => {
    sender?.close();
    vi.restoreAllMocks();
  });

  it('delivers to the local MX when the mail-plane policy service is running', async (ctx) => {
    if (!postfixUp) ctx.skip(`Postfix is not reachable on ${HOST}:${smtpPort}`);
    if (!policyUp) {
      ctx.skip('smtp-adapter (Postfix policy service) is not running; Postfix tempfails all RCPTs');
    }
    await expect(sender.send(email)).resolves.toBeUndefined();
  });

  it('reports the SMTP tempfail code when the policy service is down (Postfix fails closed)', async (ctx) => {
    if (!postfixUp) ctx.skip(`Postfix is not reachable on ${HOST}:${smtpPort}`);
    if (policyUp) ctx.skip('smtp-adapter is running; delivery is covered by the previous test');
    const error = await sender.send(email).catch((e: unknown) => e);
    expect(error).toBeInstanceOf(EmailDeliveryError);
    expect((error as EmailDeliveryError).responseCode).toBeGreaterThanOrEqual(400);
    expect((error as EmailDeliveryError).responseCode).toBeLessThan(500);
  });
});
