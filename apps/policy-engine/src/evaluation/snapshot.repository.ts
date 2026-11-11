import type { Prisma } from '@email-gateway/database';
import {
  compileSnapshot,
  type CompiledSnapshot,
  type PolicySnapshotSource,
} from '@email-gateway/policy-dsl';
import { type InconsistencySink, wrongRead } from './errors';
import { type SnapshotCache } from './snapshot-cache';

/** The compiled snapshot of one (organization, generation) and its internal version ids. */
export interface LoadedSnapshot {
  compiled: CompiledSnapshot;
  /** `policy_versions.id` (decimal) by `<policyPublicId>#<versionNo>` (P10 row mapping). */
  policyVersionIds: Readonly<Record<string, string>>;
}

export interface SnapshotLookup extends LoadedSnapshot {
  cache: 'hit' | 'miss';
  /** Versions excluded by this compilation (0 on a hit: counted once per compilation). */
  invalidVersions: number;
}

/**
 * The organization's policy snapshot for one evaluation (P12), read on the writer inside the
 * evaluation transaction:
 *
 * 1. `policy_settings.generation` (+ settings) of the organization, echo-checked; no row = 0.
 * 2. Cache `(organizationId, generation)` hit → the compiled snapshot. Every api change that
 *    alters what evaluation sees increments the generation in the same transaction, so a
 *    snapshot compiled for a generation is valid for every transaction that reads it.
 * 3. Miss → the active policies (`status = active`, not deleted, pointer set) and their published
 *    versions in the same transaction (consistent snapshot: the generation and the policies come
 *    from the same read view), echo-checked (organization, policy, status), then `compileSnapshot`
 *    (never throws; invalid stored definitions are excluded and counted).
 *
 * Non-locking consistent reads: the read view of this transaction was established after the
 * message lock; a change committed before it applies to this message, a later one to the next
 * (next-evaluation-only).
 */
export class SnapshotRepository {
  constructor(
    private readonly cache: SnapshotCache<LoadedSnapshot>,
    private readonly platformDefaultId: string,
    private readonly sink: InconsistencySink,
    private readonly onMissingVersion: (details: { policyPublicId: string }) => void = () =>
      undefined,
  ) {}

  async get(tx: Prisma.TransactionClient, organizationId: bigint): Promise<SnapshotLookup> {
    const settings = await tx.policySettings.findFirst({
      where: { organizationId },
      select: { organizationId: true, generation: true, settings: true },
    });
    if (settings !== null && settings.organizationId !== organizationId) {
      wrongRead(this.sink, 'settings', 'organization echo');
    }
    const generation = settings === null ? '0' : settings.generation.toString();
    const key = `${organizationId.toString()}:${generation}`;
    const cached = this.cache.get(key);
    if (cached !== undefined) return { ...cached, cache: 'hit', invalidVersions: 0 };

    const loaded = await this.load(tx, organizationId, generation, settings?.settings ?? null);
    this.cache.set(key, loaded);
    return { ...loaded, cache: 'miss', invalidVersions: loaded.compiled.invalid.length };
  }

  private async load(
    tx: Prisma.TransactionClient,
    organizationId: bigint,
    generation: string,
    settings: unknown,
  ): Promise<LoadedSnapshot> {
    const policies = await tx.emailPolicy.findMany({
      where: { organizationId, status: 'active', deletedAt: null, activeVersionId: { not: null } },
      select: {
        id: true,
        publicId: true,
        organizationId: true,
        status: true,
        deletedAt: true,
        activeVersionId: true,
      },
      orderBy: { id: 'asc' },
    });
    for (const p of policies) {
      if (p.organizationId !== organizationId)
        wrongRead(this.sink, 'policies', 'organization echo');
      if (p.status !== 'active' || p.deletedAt !== null || p.activeVersionId === null) {
        wrongRead(this.sink, 'policies', 'status echo');
      }
    }
    const versionIds = policies.map((p) => p.activeVersionId!);
    const versions =
      versionIds.length === 0
        ? []
        : await tx.policyVersion.findMany({
            where: { id: { in: versionIds }, organizationId, status: 'published' },
            select: {
              id: true,
              organizationId: true,
              policyId: true,
              version: true,
              status: true,
              definition: true,
              definitionSha256: true,
            },
          });
    const byId = new Map(versions.map((v) => [v.id, v]));
    for (const v of versions) {
      if (v.organizationId !== organizationId)
        wrongRead(this.sink, 'versions', 'organization echo');
      if (v.status !== 'published') wrongRead(this.sink, 'versions', 'status echo');
      if (!versionIds.includes(v.id)) wrongRead(this.sink, 'versions', 'id echo');
    }
    const sourcePolicies: Array<PolicySnapshotSource['policies'][number]> = [];
    const policyVersionIds: Record<string, string> = {};
    for (const p of policies) {
      const v = byId.get(p.activeVersionId!);
      if (v === undefined) {
        // The pointer names a version that is not published (never written by the api): the
        // policy contributes no rule; reported, never guessed.
        this.onMissingVersion({ policyPublicId: p.publicId });
        continue;
      }
      if (v.policyId !== p.id) wrongRead(this.sink, 'versions', 'policy echo');
      sourcePolicies.push({
        publicId: p.publicId,
        versionNo: v.version,
        definition: v.definition,
        definitionSha256: v.definitionSha256,
      });
      policyVersionIds[`${p.publicId}#${v.version}`] = v.id.toString();
    }
    const compiled = compileSnapshot({
      generation,
      settings,
      platformDefaultId: this.platformDefaultId,
      policies: sourcePolicies,
    });
    return { compiled, policyVersionIds };
  }
}
