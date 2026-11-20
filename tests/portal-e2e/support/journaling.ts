/**
 * Step 8.6 helpers of the journaling, archive-split and archive-only specs: alpha's journaling is
 * enabled on the writer when a spec runs on its own (the same columns the api writes; the
 * archive spec enables it through the page), and audit rows are read through the writer.
 */
import { writerDb } from './messages';
import { readState } from './state';

async function orgId(which: 'alpha' | 'beta' | 'gamma'): Promise<bigint> {
  const org = await writerDb().organization.findUniqueOrThrow({
    where: { publicId: readState().orgs[which].id },
    select: { id: true },
  });
  return org.id;
}

/** Enables alpha's journaling (archiving) when it is off; needs the seeded default policy. */
export async function ensureAlphaJournaling(): Promise<void> {
  const p = writerDb();
  const organizationId = await orgId('alpha');
  const row = await p.archiveSetting.findUnique({
    where: { organizationId },
    select: { enabled: true, defaultRetentionPolicyId: true },
  });
  if (!row?.defaultRetentionPolicyId) throw new Error('alpha has no default retention policy');
  if (row.enabled) return;
  await p.archiveSetting.update({
    where: { organizationId },
    data: {
      enabled: true,
      journalEnabledAt: new Date(),
      generation: { increment: 1 },
      rowVersion: { increment: 1 },
    },
  });
}

/** `audit_logs` rows of an organization for an action since an instant (writer). */
export async function auditRows(
  which: 'alpha' | 'beta' | 'gamma',
  action: string,
  since: Date,
): Promise<Array<{ resourceType: string | null; resourceId: string | null; metadata: unknown }>> {
  return writerDb().auditLog.findMany({
    where: { organizationId: await orgId(which), action, createdAt: { gte: since } },
    select: { resourceType: true, resourceId: true, metadata: true },
  });
}

/** Journal intake sources of alpha (writer; ids and statuses only). */
export async function alphaIntakeSources(): Promise<Array<{ publicId: string; status: string }>> {
  return writerDb().journalIntakeSource.findMany({
    where: { organizationId: await orgId('alpha') },
    select: { publicId: true, status: true },
  });
}
