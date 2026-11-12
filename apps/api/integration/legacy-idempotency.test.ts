/**
 * Step 6.1 WP4 (docs/plan/steps/18-rest-api.md D9, §3.5, §9): the reservation interceptor of the
 * legacy sensitive mutations against the real writer (MySQL), Redis and the real services, on a
 * representative subset: DKIM rotation (with the public-field envelope of @LegacyIdempotent),
 * user invitation (envelope; concurrent duplicates), the platform attachment rescan request and
 * the DLP evidence purge. For each: two identical requests have one effect (one row, one audit
 * row, one email), the second answers the stored status and body with `Idempotency-Replayed`,
 * the `api_idempotency_keys` row is `completed` with that status, scoped to the caller's
 * organization and principal; a failing request releases its `pending` reservation (no row, a
 * retry with the same key runs again); a keyless request is refused under `enforce`.
 */
import { randomUUID } from 'node:crypto';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { Prisma } from '@email-gateway/database';
import { type TransactionOptions, TransactionRunner } from '../src/database/transaction-runner';
import { IdempotencyInProgressException } from '../src/http/idempotency/idempotency-key';
import { IdempotencyReservationRepository } from '../src/http/idempotency/idempotency-reservation.repository';
import { IdempotencyReservationService } from '../src/http/idempotency/idempotency-reservation.service';
import { IdempotencyRepository } from '../src/http/idempotency/idempotency.repository';
import { IdempotencyService } from '../src/http/idempotency/idempotency.service';
import { TestDnsServer } from '../test/support/dns/test-dns-server';
import type { IntegrationApp } from './support/app';
import {
  createDomainApp,
  DomainApi,
  domainAudit,
  publishFromApi,
  publishGatewaySpf,
  uniqueDomainName,
} from './support/domains';
import {
  createFixtures,
  type FixtureOrganization,
  type FixtureUser,
  type Fixtures,
} from './support/fixtures';
import { bearer, idem, loginWithMfa, uniqueIp } from './support/http';

let dns: TestDnsServer;
let ctx: IntegrationApp;
let fx: Fixtures;
let org: FixtureOrganization;
let admin: FixtureUser;
let adminAuth: Record<string, string>;
let platformAdmin: FixtureUser;
let platformAuth: Record<string, string>;
/** Keys used under the platform organization (not removed by the fixture cleanup). */
const platformKeys: string[] = [];
const rescanJobs: string[] = [];

const headers = (auth: Record<string, string>) => ({ ...auth, 'X-Forwarded-For': uniqueIp() });
const keyRow = (organizationId: bigint, key: string) =>
  ctx.prisma.apiIdempotencyKey.findUnique({
    where: { organizationId_idempotencyKey: { organizationId, idempotencyKey: key } },
  });

beforeAll(async () => {
  dns = await TestDnsServer.start({ defaultTtl: 60 });
  publishGatewaySpf(dns);
  ctx = await createDomainApp(dns);
  fx = createFixtures(ctx);
  org = await fx.createOrganization();
  admin = await fx.createUser(org, { roles: ['organization_admin'], mfa: true });
  adminAuth = bearer((await loginWithMfa(ctx, fx, admin)).accessToken);
  platformAdmin = await fx.createPlatformUser(['platform_admin']);
  platformAuth = bearer((await loginWithMfa(ctx, fx, platformAdmin)).accessToken);
});

afterAll(async () => {
  if (ctx) {
    const platform = await fx.platformOrg();
    await ctx.prisma.apiIdempotencyKey.deleteMany({
      where: { organizationId: platform.id, idempotencyKey: { in: platformKeys } },
    });
    await ctx.prisma.attachmentRescanJob.deleteMany({ where: { publicId: { in: rescanJobs } } });
  }
  await fx?.cleanup();
  await ctx?.close();
  await dns?.close();
});

describe('POST /domains/{id}/dkim/rotate (domain.dkim_rotate)', () => {
  it('rotates once for two identical requests; the stored row is completed (201)', async () => {
    const api = new DomainApi(ctx, adminAuth);
    const domain = await api.okCreate(uniqueDomainName('idem'));
    await publishFromApi(api, dns, domain.id, ['verification', 'dkim']);
    await api.okVerify(domain.id);
    const key = `wp4-dkim-${randomUUID()}`;

    // @covers post /api/v1/domains/:id/dkim/rotate
    const first = await api.rotate(domain.id, undefined, key).expect(201);
    // The response DTO is unchanged (its `key` / `dnsRecord.key` fields are public).
    expect(first.body).toMatchObject({
      domainId: domain.id,
      key: { algorithm: 'rsa_2048', status: 'pending' },
      dnsRecord: { purpose: 'dkim' },
    });
    expect(first.headers['idempotency-replayed']).toBeUndefined();
    const replay = await api.rotate(domain.id, undefined, key).expect(201);
    expect(replay.headers['idempotency-replayed']).toBe('true');
    expect(replay.body).toEqual(first.body);

    // One effect: one pending key and one audit row (a second run would answer 409).
    const keys = await ctx.prisma.domainDkimKey.count({
      where: { domain: { publicId: domain.id }, status: 'pending' },
    });
    expect(keys).toBe(1);
    expect(await domainAudit(ctx, domain.id, 'domain.dkim_rotation_started')).toHaveLength(1);
    const row = await keyRow(org.id, key);
    expect(row).toMatchObject({
      operation: 'domain.dkim_rotate',
      state: 'completed',
      statusCode: 201,
      resourceId: domain.id,
      principal: `user:${admin.publicId}`,
    });
    expect(row!.expiresAt.getTime()).toBeGreaterThan(Date.now() + 23 * 3_600_000);

    // Another body under the same key: 422, nothing runs.
    const reused = await api.rotate(domain.id, { algorithm: 'ed25519' }, key).expect(422);
    expect(reused.body.code).toBe('idempotency_key_reused');
  });

  it('releases the reservation when the request fails: no row, a retry runs again', async () => {
    const api = new DomainApi(ctx, adminAuth);
    const key = `wp4-dkim-missing-${randomUUID()}`;
    const missing = randomUUID();
    await api.rotate(missing, undefined, key).expect(404);
    expect(await keyRow(org.id, key)).toBeNull();
    const retry = await api.rotate(missing, undefined, key).expect(404);
    expect(retry.headers['idempotency-replayed']).toBeUndefined();
    expect(await keyRow(org.id, key)).toBeNull();
  });

  it('refuses a keyless request (API_IDEMPOTENCY_LEGACY_MODE=enforce)', async () => {
    expect(ctx.config.API_IDEMPOTENCY_LEGACY_MODE).toBe('enforce');
    const res = await ctx.http
      .post(`/api/v1/domains/${randomUUID()}/dkim/rotate`)
      .set(headers(adminAuth))
      .expect(400);
    expect(res.body.code).toBe('idempotency_key_required');
  });
});

describe('POST /users/invitations (user.invite)', () => {
  const invite = (email: string, key: string) =>
    ctx.http
      .post('/api/v1/users/invitations')
      .set(headers(adminAuth))
      .set(idem(key))
      .send({ email, displayName: 'Invited', roleKeys: ['read_only_user'] });

  it('invites once (one user, one email) for two identical requests', async () => {
    const email = `wp4-invite-${randomUUID()}@example.test`;
    fx.registerCleanup(() => ctx.prisma.user.deleteMany({ where: { email } }));
    const key = `wp4-invite-${randomUUID()}`;
    const before = ctx.emails.sent.length;
    // @covers post /api/v1/users/invitations
    const first = await invite(email, key).expect(201);
    expect(first.body.roles).toEqual([{ key: 'read_only_user', name: expect.any(String) }]);
    const replay = await invite(email, key).expect(201);
    expect(replay.headers['idempotency-replayed']).toBe('true');
    expect(replay.body).toEqual(first.body);
    expect(await ctx.prisma.user.count({ where: { email } })).toBe(1);
    expect(ctx.emails.sent.length - before).toBe(1);
    expect(await keyRow(org.id, key)).toMatchObject({
      operation: 'user.invite',
      state: 'completed',
      statusCode: 201,
    });
  });

  it('runs two concurrent identical requests at most once', async () => {
    const email = `wp4-race-${randomUUID()}@example.test`;
    fx.registerCleanup(() => ctx.prisma.user.deleteMany({ where: { email } }));
    const key = `wp4-race-${randomUUID()}`;
    const results = await Promise.all([invite(email, key), invite(email, key)]);
    const statuses = results.map((r) => r.status).sort();
    // The loser either waited for the winner's row (replay) or saw its reservation (409).
    expect([
      [201, 201],
      [201, 409],
    ]).toContainEqual(statuses);
    for (const res of results.filter((r) => r.status === 409)) {
      expect(res.body.code).toBe('idempotency_request_in_progress');
      expect(Number(res.headers['retry-after'])).toBeGreaterThan(0);
    }
    expect(await ctx.prisma.user.count({ where: { email } })).toBe(1);
  });

  it('keeps keys per organization: the same key in another organization is another request', async () => {
    const other = await fx.createOrganization();
    const otherAdmin = await fx.createUser(other, { roles: ['organization_admin'], mfa: true });
    const otherAuth = bearer((await loginWithMfa(ctx, fx, otherAdmin)).accessToken);
    const key = `wp4-shared-${randomUUID()}`;
    const emailA = `wp4-a-${randomUUID()}@example.test`;
    const emailB = `wp4-b-${randomUUID()}@example.test`;
    fx.registerCleanup(() =>
      ctx.prisma.user.deleteMany({ where: { email: { in: [emailA, emailB] } } }),
    );
    await invite(emailA, key).expect(201);
    const inB = await ctx.http
      .post('/api/v1/users/invitations')
      .set(headers(otherAuth))
      .set(idem(key))
      .send({ email: emailB, displayName: 'Invited', roleKeys: ['read_only_user'] })
      .expect(201);
    // Never org A's stored response.
    expect(inB.headers['idempotency-replayed']).toBeUndefined();
    expect(inB.body.email).toBe(emailB);
    expect(await keyRow(other.id, key)).toMatchObject({ state: 'completed' });
  });
});

describe('POST /platform/attachment-rescans (platform.attachment_rescan)', () => {
  it('creates one job for two identical requests; the row is the platform organization’s', async () => {
    const target = await fx.createOrganization();
    const key = `wp4-rescan-${randomUUID()}`;
    platformKeys.push(key);
    const send = () =>
      ctx.http
        .post('/api/v1/platform/attachment-rescans')
        .set(headers(platformAuth))
        .set(idem(key))
        .send({ windowHours: 1, organizationId: target.publicId, reason: 'wp4 idempotency' });
    // @covers post /api/v1/platform/attachment-rescans
    const first = await send().expect(202);
    const jobId = first.body.jobId as string;
    rescanJobs.push(jobId);
    const replay = await send().expect(202);
    expect(replay.headers['idempotency-replayed']).toBe('true');
    expect(replay.body).toEqual(first.body);
    expect(
      await ctx.prisma.attachmentRescanJob.count({ where: { organizationId: target.id } }),
    ).toBe(1);
    const requested = await ctx.prisma.auditLog.count({
      where: { resourceType: 'attachment_rescan_job', resourceId: jobId },
    });
    expect(requested).toBe(1);
    const platform = await fx.platformOrg();
    expect(await keyRow(platform.id, key)).toMatchObject({
      operation: 'platform.attachment_rescan',
      state: 'completed',
      statusCode: 202,
      principal: `user:${platformAdmin.publicId}`,
    });
    await ctx.http
      .post(`/api/v1/platform/attachment-rescans/${jobId}/cancel`)
      .set(headers(platformAuth))
      .send({ reason: 'wp4 cleanup' })
      .expect(200);
  });

  it('stores the dry run’s own 200 and replays it as 200', async () => {
    const key = `wp4-rescan-dry-${randomUUID()}`;
    platformKeys.push(key);
    const send = () =>
      ctx.http
        .post('/api/v1/platform/attachment-rescans')
        .set(headers(platformAuth))
        .set(idem(key))
        .send({ windowHours: 1, reason: 'wp4 estimate', dryRun: true });
    const first = await send().expect(200);
    const replay = await send().expect(200);
    expect(replay.headers['idempotency-replayed']).toBe('true');
    expect(replay.body).toEqual(first.body);
    const platform = await fx.platformOrg();
    expect(await keyRow(platform.id, key)).toMatchObject({ state: 'completed', statusCode: 200 });
  });
});

describe('DELETE /dlp/evidence (dlp.evidence_purge_all)', () => {
  it('purges (one audit row) for two identical requests', async () => {
    const key = `wp4-dlp-${randomUUID()}`;
    const send = () =>
      ctx.http.delete('/api/v1/dlp/evidence').set(headers(adminAuth)).set(idem(key));
    // @covers delete /api/v1/dlp/evidence
    const first = await send().expect(202);
    const replay = await send().expect(202);
    expect(replay.headers['idempotency-replayed']).toBe('true');
    expect(replay.body).toEqual(first.body);
    const audits = await ctx.prisma.auditLog.count({
      where: { organizationId: org.id, action: 'dlp_evidence.purged' },
    });
    expect(audits).toBe(1);
    expect(await keyRow(org.id, key)).toMatchObject({
      operation: 'dlp.evidence_purge_all',
      state: 'completed',
      statusCode: 202,
      resourceId: '-',
    });
  });
});

describe('IdempotencyReservationService against InnoDB (step 6.1 D9)', () => {
  /**
   * The writer runs READ-COMMITTED (ADR-0004), but a writer left at the MySQL default
   * (REPEATABLE READ, e.g. a managed instance without the parameter group) gap-locks the absent
   * key on `SELECT … FOR UPDATE`: two reservations then deadlock on insert (1213 / P2034). The
   * service is built over the app's own repositories with a runner pinned to REPEATABLE READ;
   * every loser must still answer 409 in progress, never a 500. Run at both levels.
   */
  const reservationService = (isolationLevel?: Prisma.TransactionIsolationLevel) => {
    const runner = ctx.get(TransactionRunner);
    const pinned = {
      run: <T>(
        fn: (tx: Prisma.TransactionClient) => Promise<T>,
        options: TransactionOptions = {},
      ) => runner.run(fn, { ...options, ...(isolationLevel && { isolationLevel }) }),
    } as TransactionRunner;
    return new IdempotencyReservationService(
      pinned,
      ctx.get(IdempotencyRepository),
      ctx.get(IdempotencyReservationRepository),
      ctx.get(IdempotencyService),
      ctx.config,
    );
  };

  it.each([
    ['the configured level (READ COMMITTED)', undefined],
    ['REPEATABLE READ (gap locks)', Prisma.TransactionIsolationLevel.RepeatableRead],
  ] as const)(
    'answers concurrent reservations of one new key with one winner and 409s at %s',
    async (_label, isolationLevel) => {
      const service = reservationService(isolationLevel);
      for (let round = 0; round < 5; round += 1) {
        const key = `wp4-gap-${randomUUID()}`;
        const request = {
          organizationId: org.id,
          principal: `user:${admin.publicId}`,
          operation: 'user.invite',
          key,
          resourceId: '-',
          fingerprint: 'a'.repeat(64),
        };
        const outcomes = await Promise.allSettled(
          Array.from({ length: 6 }, () => service.reserve(request)),
        );
        const reserved = outcomes.filter(
          (o) => o.status === 'fulfilled' && o.value.kind === 'reserved',
        );
        const failures: unknown[] = outcomes.flatMap((o) =>
          o.status === 'rejected' ? [o.reason as unknown] : [],
        );
        expect(reserved).toHaveLength(1);
        expect(failures).toHaveLength(5);
        for (const reason of failures) {
          expect(reason).toBeInstanceOf(IdempotencyInProgressException);
        }
        expect(await keyRow(org.id, key)).toMatchObject({ state: 'pending' });
        await ctx.prisma.apiIdempotencyKey.deleteMany({
          where: { organizationId: org.id, idempotencyKey: key },
        });
      }
    },
  );
});
