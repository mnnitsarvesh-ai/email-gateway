/**
 * Helpers of the step 7.2 specs (Email Explorer and Email Details): the explorer list waiting
 * for its own api response, a network spy, BFF calls made from the page (same origin, with the
 * double-submit CSRF token, as the portal's client sends them), the 14 sections of design §1.4
 * with their gates evaluated from the OpenAPI snapshot (independent of the portal's code), and
 * read-only database checks of audit rows and saved views on the writer.
 */
import { expect, type Locator, type Page, type Request } from '@playwright/test';
import { PrismaClient } from '@email-gateway/database';
import { mayCall } from './contract';
import { requireEnv } from './env';
import { readState } from './state';

/** The explorer's list request (`GET /messages` through the BFF). */
export function isListRequest(url: string): boolean {
  const { pathname } = new URL(url);
  return pathname === '/bff/api/v1/messages';
}

/** Records every request whose URL matches `predicate` (method and URL) from now on. */
export function spy(page: Page, predicate: (request: Request) => boolean) {
  const seen: Array<{
    method: string;
    url: string;
    headers: Record<string, string>;
    body: string | null;
  }> = [];
  const listener = (request: Request) => {
    if (predicate(request)) {
      seen.push({
        method: request.method(),
        url: request.url(),
        headers: request.headers(),
        body: request.postData(),
      });
    }
  };
  page.on('request', listener);
  return {
    seen,
    stop: () => page.off('request', listener),
  };
}

export function pager(page: Page): Locator {
  return page.getByRole('navigation', { name: /pagination$/ }).first();
}

/**
 * Runs `action`, waits for the explorer's list response whose query contains `fragment` (or
 * any list response) and for the table to settle, then expects `rows` rows on page 1.
 */
export async function expectListAfter(
  page: Page,
  action: () => Promise<unknown>,
  rows: number,
  fragment?: string,
): Promise<void> {
  const response = page.waitForResponse(
    (res) =>
      isListRequest(res.url()) &&
      res.request().method() === 'GET' &&
      (fragment === undefined || decodeURIComponent(res.url()).includes(fragment)),
  );
  await action();
  expect((await response).status()).toBe(200);
  await expectRows(page, rows);
}

export async function expectRows(page: Page, rows: number): Promise<void> {
  await expect(page.locator('main [aria-busy="true"]')).toHaveCount(0, { timeout: 20_000 });
  if (rows === 0) {
    await expect(page.getByText('No results match these filters')).toBeVisible();
    return;
  }
  await expect(pager(page)).toContainText(`Page 1 · ${rows} ${rows === 1 ? 'row' : 'rows'}`);
}

/** A BFF request made from the page (Origin and the CSRF header as the portal's client sends). */
export async function bff(
  page: Page,
  method: 'GET' | 'POST' | 'PUT' | 'DELETE',
  path: string,
  body?: unknown,
): Promise<{ status: number; body: Record<string, unknown> | null }> {
  return page.evaluate(
    async ({ method, path, body }) => {
      const csrf =
        document.cookie
          .split(';')
          .map((part) => part.trim().split('='))
          .find(([name]) => name === '__Host-eg_csrf' || name === 'eg_csrf')?.[1] ?? '';
      const res = await fetch(`/bff/api/v1${path}`, {
        method,
        headers: {
          accept: 'application/json',
          ...(body === undefined ? {} : { 'content-type': 'application/json' }),
          ...(method === 'GET' ? {} : { 'x-csrf-token': csrf }),
        },
        body: body === undefined ? undefined : JSON.stringify(body),
      });
      const text = await res.text();
      let parsed: Record<string, unknown> | null = null;
      try {
        parsed = text ? (JSON.parse(text) as Record<string, unknown>) : null;
      } catch {
        parsed = null;
      }
      return { status: res.status, body: parsed };
    },
    { method, path, body },
  );
}

/** Design §1.4: the 14 sections, their operations and extra permissions (gates). */
export const SECTION_TABLE: ReadonlyArray<{
  id: string;
  label: string;
  operations: string[];
  permissions?: string[];
}> = [
  {
    id: 'summary',
    label: 'Message summary',
    operations: ['MessagesController_detail_v1', 'MessageLifecycleController_lifecycle_v1'],
  },
  {
    id: 'people',
    label: 'Sender and recipients',
    operations: ['MessagesController_recipients_v1'],
  },
  { id: 'headers', label: 'Email headers', operations: ['MessageHeadersController_headers_v1'] },
  {
    id: 'authentication',
    label: 'Authentication results',
    operations: ['MessageScansController_scansOf_v1'],
  },
  { id: 'spam', label: 'Spam score', operations: ['MessageScansController_scansOf_v1'] },
  { id: 'phishing', label: 'Phishing analysis', operations: ['MessageScansController_scansOf_v1'] },
  {
    id: 'urls',
    label: 'URL analysis',
    operations: ['UrlProtectionController_ofMessage_v1', 'MessageScansController_scansOf_v1'],
  },
  {
    id: 'attachments',
    label: 'Attachment analysis',
    operations: ['AttachmentsController_ofMessage_v1', 'MessageScansController_scansOf_v1'],
  },
  {
    id: 'dlp',
    label: 'DLP results',
    operations: ['MessageScansController_scansOf_v1'],
    permissions: ['dlp:read'],
  },
  { id: 'risk', label: 'Risk score', operations: ['MessageScansController_scansOf_v1'] },
  {
    id: 'policy',
    label: 'Policy decisions',
    operations: ['PolicyMessagesController_evaluations_v1'],
  },
  {
    id: 'delivery',
    label: 'Delivery timeline',
    operations: ['DeliveriesController_forMessage_v1'],
  },
  {
    id: 'quarantine',
    label: 'Quarantine actions',
    operations: ['QuarantineEntriesController_search_v1'],
  },
  { id: 'audit', label: 'Audit history', operations: ['AuditLogsController_search_v1'] },
];

/** The sections a user with `permissions` may open (in §1.4 order). */
export function expectedSections(permissions: readonly string[]): string[] {
  const granted = new Set(permissions);
  return SECTION_TABLE.filter(
    (section) =>
      section.operations.every((op) => mayCall(op, granted)) &&
      (section.permissions ?? []).every((permission) => granted.has(permission)),
  ).map((section) => section.id);
}

/** Public id of a step 7.2 message of the seed plan (seed/plan.ts `planExplorerAlpha`). */
export function messageOf(key: string): string {
  const id = readState().alpha.explorer[key];
  if (!id) throw new Error(`No seeded message ${key}`);
  return id;
}

let db: PrismaClient | undefined;

/** Read-only checks on the writer (the api writes audit rows there before it answers). */
export function writerDb(): PrismaClient {
  db ??= new PrismaClient({ datasourceUrl: requireEnv('DATABASE_URL') });
  return db;
}

/** `audit_logs` rows of the alpha organization for `action` on the message resources. */
export async function messageAuditRows(
  action: string,
  messageIds: readonly string[],
  since: Date,
): Promise<Array<{ resourceId: string | null; actorId: string | null; metadata: unknown }>> {
  const org = await writerDb().organization.findUniqueOrThrow({
    where: { publicId: readState().orgs.alpha.id },
    select: { id: true },
  });
  return writerDb().auditLog.findMany({
    where: {
      organizationId: org.id,
      action,
      resourceType: 'message',
      resourceId: { in: [...messageIds] },
      createdAt: { gte: since },
    },
    select: { resourceId: true, actorId: true, metadata: true },
  });
}

/** The public id of a seeded user (audit rows name the actor by public id). */
export async function userPublicId(email: string): Promise<string> {
  const row = await writerDb().user.findFirstOrThrow({
    where: { email },
    select: { publicId: true },
  });
  return row.publicId;
}
