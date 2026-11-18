/**
 * Step 8.1 helpers of the archive and eDiscovery specs: the alpha archive messages are inserted
 * after archiving was enabled and captured by the **real archive-worker** (journal sweep after
 * its safety lag, capture, encryption into the archive bucket, index sync into OpenSearch). The
 * archive spec enables archiving through the Settings page first; a spec run on its own enables
 * it on the writer instead (same columns the api writes) so each spec stays self-sufficient.
 */
import { expect } from '@playwright/test';
import {
  ARCHIVE_SUBJECTS,
  alphaArchivePlans,
  capturedCount,
  insertArchiveMessages,
} from '../seed/archive';
import { writerDb } from './messages';
import { readState } from './state';

/** Journal sweep safety lag (120 s) + sweep interval + capture + index sync, with margin. */
export const CAPTURE_TIMEOUT_MS = 330_000;

export type ArchiveKey = 'invoice' | 'outbound' | 'phish';

async function orgId(which: 'alpha' | 'beta'): Promise<bigint> {
  const org = await writerDb().organization.findUniqueOrThrow({
    where: { publicId: readState().orgs[which].id },
    select: { id: true },
  });
  return org.id;
}

/** Whether alpha's archiving is enabled (writer). */
export async function alphaArchivingEnabled(): Promise<boolean> {
  const row = await writerDb().archiveSetting.findUnique({
    where: { organizationId: await orgId('alpha') },
    select: { enabled: true },
  });
  return row?.enabled === true;
}

async function poll(what: string, check: () => Promise<boolean>, timeoutMs: number): Promise<void> {
  const deadline = Date.now() + timeoutMs;
  for (;;) {
    if (await check()) return;
    if (Date.now() > deadline) throw new Error(`timed out waiting for ${what}`);
    await new Promise((r) => setTimeout(r, 2_000));
  }
}

/** Waits until the given messages are captured and the organization's index queue is empty. */
export async function waitForCapture(which: 'alpha' | 'beta', messageIds: bigint[]): Promise<void> {
  const p = writerDb();
  const org = await orgId(which);
  await poll(
    `${messageIds.length} archive captures of ${which}`,
    async () => (await capturedCount(p, messageIds)) === messageIds.length,
    CAPTURE_TIMEOUT_MS,
  );
  await poll(
    `the ${which} archive index queue`,
    async () => (await p.archiveIndexQueue.count({ where: { organizationId: org } })) === 0,
    120_000,
  );
}

/**
 * The alpha archive messages, inserted once per run after archiving is enabled, captured and
 * indexed. Returns their public ids by key.
 */
export async function ensureAlphaArchive(): Promise<Record<ArchiveKey, string>> {
  const p = writerDb();
  const org = await orgId('alpha');
  if (!(await alphaArchivingEnabled())) {
    const now = new Date();
    await p.archiveSetting.update({
      where: { organizationId: org },
      data: {
        enabled: true,
        journalEnabledAt: now,
        generation: { increment: 1 },
        rowVersion: { increment: 1 },
      },
    });
    // The worker reads settings through a cache (ARCHIVE_SETTINGS_CACHE_TTL_MS, 30 s); the
    // sweep reaches new messages only after its 120 s safety lag, long after the cache expired.
  }
  let rows = await p.emailMessage.findMany({
    where: { organizationId: org, subject: { in: Object.values(ARCHIVE_SUBJECTS) } },
    select: { id: true, subject: true },
  });
  if (rows.length === 0) {
    await insertArchiveMessages(p, org, alphaArchivePlans());
    rows = await p.emailMessage.findMany({
      where: { organizationId: org, subject: { in: Object.values(ARCHIVE_SUBJECTS) } },
      select: { id: true, subject: true },
    });
  }
  expect(rows).toHaveLength(3);
  await waitForCapture(
    'alpha',
    rows.map((r) => r.id),
  );
  const identities = await p.messageIdentity.findMany({
    where: { id: { in: rows.map((r) => r.id) } },
    select: { id: true, publicId: true },
  });
  const publicOf = (subject: string) => {
    const row = rows.find((r) => r.subject === subject)!;
    return identities.find((i) => i.id === row.id)!.publicId;
  };
  return {
    invoice: publicOf(ARCHIVE_SUBJECTS.invoice),
    outbound: publicOf(ARCHIVE_SUBJECTS.outbound),
    phish: publicOf(ARCHIVE_SUBJECTS.phish),
  };
}

/** Beta's archive message (seeded at seed time), captured and indexed. */
export async function ensureBetaArchive(): Promise<string> {
  const p = writerDb();
  const publicId = readState().archive.betaMessageId;
  const identity = await p.messageIdentity.findUniqueOrThrow({
    where: { publicId },
    select: { id: true },
  });
  await waitForCapture('beta', [identity.id]);
  return publicId;
}

/** `audit_logs` rows of an organization for an action since an instant (writer). */
export async function archiveAuditRows(
  which: 'alpha' | 'beta',
  action: string,
  since: Date,
): Promise<Array<{ resourceType: string | null; resourceId: string | null; metadata: unknown }>> {
  return writerDb().auditLog.findMany({
    where: { organizationId: await orgId(which), action, createdAt: { gte: since } },
    select: { resourceType: true, resourceId: true, metadata: true },
  });
}
