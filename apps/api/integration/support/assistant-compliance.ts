/**
 * Compliance and integrations fixtures of the step AI-5 assistant suites (docs/plan/steps/33-ai-
 * chat-compliance-integrations.md §9 item 3): a synthetic `it-*` organization with the plan
 * features `archiving` and `journal_intake`, the archive set up the way an administrator leaves
 * it (a default retention policy and an archive settings row, written on the writer as the
 * module suites do), a TXT-verified domain, the assistant enabled through the documented path by
 * an owner holding every tenant permission, and the chat users of the design: a compliance user
 * (archive, eDiscovery, legal hold, export, search) and a journaling administrator (journal
 * management), both with MFA sessions. Intake sources are created through the api (the portal's
 * path; never through chat: creation returns the intake address, D7/I23), and the address the
 * api returned once is kept in memory only so a suite can prove it never reached a stored
 * assistant row. `cleanup` order: the journal intake and provider rows (organization purge of
 * the owning modules), then every archive row and object of `ArchiveFixtures`. Nothing here is
 * used by production code; tests never reach an LLM, a provider or the internet.
 */
import { randomUUID } from 'node:crypto';
import { systemScope } from '../../src/auth-contracts/tenant-scope';
import { JournalIntakeTenantDataRepository } from '../../src/modules/tenant-data/journal-intake-tenant-data.repository';
import { ProviderTenantDataRepository } from '../../src/modules/tenant-data/provider-tenant-data.repository';
import type { IntegrationApp } from './app';
import { ArchiveFixtures } from './archive';
import {
  ALL_TENANT_PERMISSIONS,
  call,
  enableAssistant,
  type Member,
  memberWith,
} from './assistant';
import type { FixtureOrganization, Fixtures } from './fixtures';
import { idem } from './http';
import { insertDomain, type InsertedDomain, randomV4Network } from './smtp';

export const ARCHIVE = '/api/v1/archive';
export const JOURNALING = '/api/v1/journaling';
export const INTAKE = `${JOURNALING}/intake-sources`;
export const CASES = '/api/v1/ediscovery/cases';
export const HOLDS = '/api/v1/legal-holds';
export const PROVIDERS = '/api/v1/provider-connections';

/**
 * The compliance user's grant (design 33 §9 item 3): archive management, eDiscovery, legal holds,
 * exports and archive search, plus the reads their precondition reads need (`archive:read` for
 * retention policies, `journal:read` for the capture issues) and `message:reveal` (case
 * custodian addresses need it, step 8.1 A17).
 */
export const COMPLIANCE_PERMISSIONS = [
  'archive:manage',
  'archive:read',
  'archive:search',
  'archive:export',
  'archive:legal_hold',
  'ediscovery:manage',
  'message:reveal',
  'journal:read',
] as const;

/**
 * The journaling administrator's grant: journal management (intake sources, journaling settings
 * and the `enabled` / capture-section paths of the shared archive settings row, step 8.6 D11).
 */
export const JOURNALING_PERMISSIONS = ['journal:manage', 'journal:read', 'archive:read'] as const;

/**
 * The integration administrator's grant: provider connections, plus the change permissions of
 * the mail-flow wizard (`domain:routing_manage` for `inbound`, `connector:manage` for the other
 * kinds and the disconnect, step 8.2).
 */
export const INTEGRATION_PERMISSIONS = [
  'integration:manage',
  'integration:read',
  'connector:manage',
  'domain:routing_manage',
] as const;

export interface ComplianceTenant {
  org: FixtureOrganization;
  ax: ArchiveFixtures;
  /** Holds every tenant permission; enabled the assistant (never used for chat writes). */
  owner: Member;
  /** A TXT-verified (active) domain of the organization (intake sources need one). */
  domain: InsertedDomain;
  /** The default retention policy (the archive settings' `defaultRetentionPolicyId`). */
  defaultPolicy: { id: bigint; publicId: string };
}

/**
 * An `it-*` organization (enterprise plan, `archiving` and `journal_intake` on) with its archive
 * configured: a default retention policy of 2555 days (`review` on expiry), an archive settings
 * row naming it (`enabled` as given; the archive-worker is not involved), a verified domain, and
 * the assistant enabled by an owner with every tenant permission. Registers the cleanup of the
 * journal intake, provider and archive rows (and the archive objects and test indices).
 */
export async function complianceTenant(
  ctx: IntegrationApp,
  fx: Fixtures,
  operator: Member,
  options: { archiveEnabled?: boolean; features?: Record<string, boolean> } = {},
): Promise<ComplianceTenant> {
  const org = await fx.createOrganization({
    planCode: 'enterprise',
    features: { archiving: true, journal_intake: true, ...options.features },
  });
  const ax = new ArchiveFixtures(ctx, ctx.config.ARCHIVE_SEARCH_INDEX_PREFIX);
  // Cleanups run in reverse registration order: intake and provider rows first, then archive.
  fx.registerCleanup(() => ax.cleanup());
  fx.registerCleanup(async () => {
    await ctx.get(JournalIntakeTenantDataRepository).purgeOrganization(systemScope(org.id));
    await ctx.get(ProviderTenantDataRepository).purgeOrganization(systemScope(org.id));
  });
  const defaultPolicy = await ctx.prisma.archiveRetentionPolicy.create({
    data: {
      organizationId: org.id,
      name: 'Seven years (default)',
      retentionDays: 2555,
      onExpiry: 'review',
      priority: 100,
    },
    select: { id: true, publicId: true },
  });
  await ax.settings(org, {
    enabled: options.archiveEnabled ?? true,
    defaultRetentionPolicyId: defaultPolicy.id,
    ...((options.archiveEnabled ?? true) && { journalEnabledAt: new Date() }),
  });
  const domain = await insertDomain(ctx, org, { label: 'compliance' });
  const owner = await memberWith(ctx, fx, org, { permissions: [...ALL_TENANT_PERMISSIONS] });
  await enableAssistant(ctx, operator, org, owner);
  return { org, ax, owner, domain, defaultPolicy };
}

/** A chat user of `org` holding exactly these permissions (plus `assistant:use`), with MFA. */
export function chatUser(
  ctx: IntegrationApp,
  fx: Fixtures,
  org: FixtureOrganization,
  permissions: readonly string[],
  displayName: string,
): Promise<Member> {
  return memberWith(ctx, fx, org, { permissions }, { displayName });
}

export interface CreatedIntakeSource {
  id: string;
  /**
   * The clear intake address the api returned once (in memory only: a suite asserts it never
   * reached a stored assistant row, an envelope or an audit row).
   */
  address: string;
}

/**
 * An on-premises Exchange journal intake source created through the api (the portal's path) by
 * a `journal:manage` holder: one public network, TLS required.
 */
export async function createIntakeSource(
  ctx: IntegrationApp,
  who: Member,
  displayName = `On-prem journal ${randomUUID().slice(0, 8)}`,
): Promise<CreatedIntakeSource> {
  const res = await call(ctx, who.headers, 'post', INTAKE, {
    kind: 'exchange_onprem_journal',
    displayName,
    networks: [randomV4Network(28)],
  }).set(idem());
  if (res.status !== 201) {
    throw new Error(`intake source create failed: ${res.status} ${JSON.stringify(res.body)}`);
  }
  return { id: res.body.source.id as string, address: res.body.address as string };
}

/** An eDiscovery case created through the api (the portal's path). */
export async function createCase(
  ctx: IntegrationApp,
  who: Member,
  body: Record<string, unknown> = {},
): Promise<string> {
  const res = await call(ctx, who.headers, 'post', CASES, {
    name: `Matter ${randomUUID().slice(0, 8)}`,
    ...body,
  }).set(idem());
  if (res.status !== 201) {
    throw new Error(`case create failed: ${res.status} ${JSON.stringify(res.body)}`);
  }
  return res.body.id as string;
}

/** A legal hold placed through the api in a case (the portal's path; needs an MFA user). */
export async function createHold(
  ctx: IntegrationApp,
  who: Member,
  caseId: string,
  body: Record<string, unknown> = {},
): Promise<string> {
  const res = await call(ctx, who.headers, 'post', `${CASES}/${caseId}/holds`, {
    name: `Hold ${randomUUID().slice(0, 8)}`,
    reason: 'Litigation notice received',
    ...body,
  }).set(idem());
  if (res.status !== 201) {
    throw new Error(`hold create failed: ${res.status} ${JSON.stringify(res.body)}`);
  }
  return res.body.id as string;
}

/**
 * The archive-worker's completion of a queued case search (simulated on the writer exactly as
 * `archive-ediscovery.test.ts` does): status `completed`, the hit count and completeness flags,
 * and one verified hit per record.
 */
export async function completeSearch(
  ctx: IntegrationApp,
  org: FixtureOrganization,
  searchPublicId: string,
  records: ReadonlyArray<{
    row: { messageId: bigint; receivedAt: Date; messagePublicId: string };
  }>,
): Promise<void> {
  const search = await ctx.prisma.ediscoverySearch.findUniqueOrThrow({
    where: { publicId: searchPublicId },
  });
  await ctx.prisma.ediscoverySearch.update({
    where: { id: search.id },
    data: {
      status: 'completed',
      hitCount: records.length,
      indexComplete: true,
      startedAt: new Date(),
      completedAt: new Date(),
    },
  });
  for (const r of records) {
    await ctx.prisma.ediscoverySearchHit.create({
      data: {
        searchId: search.id,
        organizationId: org.id,
        messageId: r.row.messageId,
        messageReceivedAt: r.row.receivedAt,
        messagePublicId: r.row.messagePublicId,
      },
    });
  }
}
