import { randomUUID } from 'node:crypto';
import {
  type DomainStatus,
  normalizeDomainName,
  type OrganizationStatus,
  PrismaClient,
  resolveActiveDomain,
  resolveDomainOwner,
} from '@email-gateway/database';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { stack } from './support/env';

/**
 * Mail-path tenant resolution (docs/plan/steps/03-domain-onboarding.md D13) against MySQL, with
 * the writer account the data plane uses: only an `active` domain of an `active` organization
 * resolves, through the generated `verified_name` unique key. Post-queue owner resolution
 * (docs/plan/steps/04-smtp-gateway.md D7) also resolves `suspended` domains and organizations.
 * Fixture rows are removed afterwards.
 */
const prisma = new PrismaClient({ datasourceUrl: stack.databaseUrl() });

const suffix = randomUUID().slice(0, 8);
const name = (label: string) => `it-${suffix}-${label}.test`;

let planId: bigint | undefined;
const organizationIds: bigint[] = [];
const domains = new Map<string, { id: bigint; publicId: string; organizationId: bigint }>();

async function organization(label: string, status: OrganizationStatus) {
  const org = await prisma.organization.create({
    data: {
      slug: `it-${suffix}-${label}`,
      name: `Resolution ${label}`,
      planId: planId!,
      dataRegion: 'ap-south-1',
      status,
    },
  });
  organizationIds.push(org.id);
  return org.id;
}

async function domain(
  key: string,
  organizationId: bigint,
  domainName: string,
  status: DomainStatus,
  extra: { outboundEnabled?: boolean } = {},
) {
  const row = await prisma.domain.create({
    data: { organizationId, name: domainName, status, ...extra },
    select: { id: true, publicId: true, organizationId: true },
  });
  domains.set(key, row);
  return row;
}

beforeAll(async () => {
  const plan = await prisma.organizationPlan.create({
    data: { code: `it-${suffix}`, name: 'Resolution test', defaultLimits: {}, defaultFeatures: {} },
  });
  planId = plan.id;
  const active = await organization('active', 'active');
  const other = await organization('other', 'active');
  const suspended = await organization('suspended', 'suspended');
  const pendingDeletion = await organization('pending-deletion', 'pending_deletion');
  const deletedOrg = await organization('deleted-org', 'deleted');

  await domain('active', active, name('active'), 'active', { outboundEnabled: true });
  await domain('verified', active, name('verified'), 'verified');
  await domain('suspended', active, name('suspended'), 'suspended');
  await domain('disabled', active, name('disabled'), 'disabled');
  await domain('failed', active, name('failed'), 'failed');
  await domain('pending', active, name('pending'), 'pending_verification');
  await domain('deleted', active, name('deleted'), 'deleted');
  await domain('org-suspended', suspended, name('org-suspended'), 'active');
  await domain('org-pending-deletion', pendingDeletion, name('org-pending-deletion'), 'active');
  await domain('org-deleted', deletedOrg, name('org-deleted'), 'active');
  await domain('both-suspended', suspended, name('both-suspended'), 'suspended');
  // A pending claim by another organization on the active name never affects resolution.
  await domain('claim', other, name('active'), 'pending_verification');
  // IDN name, stored in its normalized ASCII form.
  const idn = normalizeDomainName(`bücher-${suffix}.test`, { allowTestNames: true }).ascii;
  await domain('idn', active, idn, 'active');
});

afterAll(async () => {
  try {
    if (organizationIds.length > 0) {
      await prisma.domain.deleteMany({ where: { organizationId: { in: organizationIds } } });
      await prisma.organization.deleteMany({ where: { id: { in: organizationIds } } });
    }
    if (planId !== undefined) {
      await prisma.organizationPlan.deleteMany({ where: { id: planId } });
    }
  } finally {
    await prisma.$disconnect();
  }
});

describe('resolveActiveDomain (MySQL)', () => {
  it('resolves an active domain of an active organization to its owner', async () => {
    const owner = domains.get('active')!;
    await expect(resolveActiveDomain(prisma, name('active'))).resolves.toEqual({
      domainId: owner.id,
      domainPublicId: owner.publicId,
      organizationId: owner.organizationId,
      name: name('active'),
      inboundEnabled: true,
      outboundEnabled: true,
    });
  });

  it('normalizes the input: mixed case, trailing dot, surrounding whitespace, IDN', async () => {
    const owner = domains.get('active')!;
    for (const input of [
      name('active').toUpperCase(),
      `${name('active')}.`,
      ` ${name('active')} `,
    ]) {
      expect((await resolveActiveDomain(prisma, input))?.domainId, input).toBe(owner.id);
    }
    expect((await resolveActiveDomain(prisma, `BÜCHER-${suffix}.test.`))?.domainId).toBe(
      domains.get('idn')!.id,
    );
  });

  it.each(['verified', 'suspended', 'disabled', 'failed', 'pending', 'deleted'])(
    'does not resolve a %s domain',
    async (key) => {
      await expect(resolveActiveDomain(prisma, name(key))).resolves.toBeNull();
    },
  );

  it.each(['org-suspended', 'org-pending-deletion'])(
    'does not resolve an active domain of an organization that is not active (%s)',
    async (key) => {
      await expect(resolveActiveDomain(prisma, name(key))).resolves.toBeNull();
    },
  );

  it('returns null for unknown names and for input that is not a domain name', async () => {
    for (const input of [name('unknown'), '', 'localhost', '127.0.0.1', '*.gateway.test']) {
      await expect(resolveActiveDomain(prisma, input), input).resolves.toBeNull();
    }
  });

  it('follows status changes immediately on the writer (suspend, resume, delete)', async () => {
    const id = domains.get('active')!.id;
    try {
      await prisma.domain.update({ where: { id }, data: { status: 'suspended' } });
      await expect(resolveActiveDomain(prisma, name('active'))).resolves.toBeNull();
      await prisma.domain.update({ where: { id }, data: { status: 'active' } });
      expect((await resolveActiveDomain(prisma, name('active')))?.domainId).toBe(id);
      await prisma.domain.update({ where: { id }, data: { status: 'deleted' } });
      await expect(resolveActiveDomain(prisma, name('active'))).resolves.toBeNull();
    } finally {
      await prisma.domain.update({ where: { id }, data: { status: 'active' } });
    }
  });
});

describe('resolveDomainOwner (MySQL)', () => {
  it('resolves an active domain of an active organization with both statuses', async () => {
    const owner = domains.get('active')!;
    await expect(resolveDomainOwner(prisma, name('active'))).resolves.toEqual({
      domainId: owner.id,
      domainPublicId: owner.publicId,
      organizationId: owner.organizationId,
      name: name('active'),
      inboundEnabled: true,
      outboundEnabled: true,
      status: 'active',
      organizationStatus: 'active',
    });
  });

  it.each([
    ['suspended', 'suspended', 'active'],
    ['org-suspended', 'active', 'suspended'],
    ['both-suspended', 'suspended', 'suspended'],
  ] as const)(
    'resolves %s (domain %s, organization %s) to its owner',
    async (key, status, organizationStatus) => {
      const owner = domains.get(key)!;
      await expect(resolveDomainOwner(prisma, name(key))).resolves.toMatchObject({
        domainId: owner.id,
        organizationId: owner.organizationId,
        status,
        organizationStatus,
      });
    },
  );

  it('normalizes the input like resolveActiveDomain (case, trailing dot, IDN)', async () => {
    expect((await resolveDomainOwner(prisma, ` ${name('active').toUpperCase()}. `))?.domainId).toBe(
      domains.get('active')!.id,
    );
    expect((await resolveDomainOwner(prisma, `BÜCHER-${suffix}.test.`))?.domainId).toBe(
      domains.get('idn')!.id,
    );
  });

  it.each(['verified', 'disabled', 'failed', 'pending', 'deleted'])(
    'does not resolve a %s domain',
    async (key) => {
      await expect(resolveDomainOwner(prisma, name(key))).resolves.toBeNull();
    },
  );

  it.each(['org-pending-deletion', 'org-deleted'])(
    'does not resolve a domain of an organization in status %s',
    async (key) => {
      await expect(resolveDomainOwner(prisma, name(key))).resolves.toBeNull();
    },
  );

  it('returns null for unknown names and for input that is not a domain name', async () => {
    for (const input of [name('unknown'), '', 'localhost', '127.0.0.1', '*.gateway.test']) {
      await expect(resolveDomainOwner(prisma, input), input).resolves.toBeNull();
    }
  });

  it('follows status changes immediately on the writer (suspend, delete)', async () => {
    const id = domains.get('active')!.id;
    try {
      await prisma.domain.update({ where: { id }, data: { status: 'suspended' } });
      await expect(resolveDomainOwner(prisma, name('active'))).resolves.toMatchObject({
        domainId: id,
        status: 'suspended',
      });
      await prisma.domain.update({ where: { id }, data: { status: 'deleted' } });
      await expect(resolveDomainOwner(prisma, name('active'))).resolves.toBeNull();
    } finally {
      await prisma.domain.update({ where: { id }, data: { status: 'active' } });
    }
  });
});
