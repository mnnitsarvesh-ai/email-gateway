import { createHash, randomBytes } from 'node:crypto';
import type { PrismaClient } from '@email-gateway/database';
import { composeOk, compose, waitFor } from './compose';
import { stack } from './env';
import { providerStackGate } from './providers';
import type { SmtpStackGate } from './smtp-stack';

/**
 * Pieces of the step API-1 stack suite `api-mode.test.ts`
 * (docs/plan/steps/35-api-mode-protection.md §9.6, ADR-0098–0100): the TEST-ONLY idp-simulator's
 * admin API (dataset, mailbox deliveries that push Graph change notifications to the api, scripted
 * throttling, the call log), the Compose overrides of the run (short mailbox-worker intervals, the
 * adapter's 1 s intake source cache), the dedupe hash of contracts §36, synthetic GTUBE/EICAR
 * copies and the removal of every API-mode row of the suite's organizations. Synthetic data only;
 * nothing reaches Microsoft, Google or the Internet; no credential is printed.
 */

const simAdminBase = () =>
  `http://${stack.host}:${process.env.IDP_SIMULATOR_ADMIN_HOST_PORT ?? 18097}`;
const mailboxWorkerPort = () => Number(process.env.MAILBOX_WORKER_HOST_PORT || 3087);
export const mailboxWorkerUrl = () => `http://${stack.host}:${mailboxWorkerPort()}`;

async function reachable(url: string): Promise<boolean> {
  try {
    return (await fetch(url, { signal: AbortSignal.timeout(3_000) })).ok;
  } catch {
    return false;
  }
}

let cached: Promise<SmtpStackGate> | undefined;

/**
 * Gate of the API-mode suite: the provider stack gate (Postfix reaching the adapter, engines,
 * relay, api, webhook-worker and receiver, integration-worker, provider-fake, provider senders)
 * plus a ready mailbox-worker and the idp-simulator's admin API. Missing pieces FAIL the suite;
 * `SMTP_STACK_TESTS=skip` skips it like every stack suite.
 */
export function apiModeStackGate(): Promise<SmtpStackGate> {
  cached ??= (async () => {
    const base = await providerStackGate();
    if (base.skip) return base;
    const problems: string[] = base.problem ? [base.problem] : [];
    if (!(await reachable(`${mailboxWorkerUrl()}/health/ready`))) {
      problems.push(
        `mailbox-worker is not ready on ${stack.host}:${mailboxWorkerPort()} ` +
          '(docker compose --profile apps up -d --wait mailbox-worker)',
      );
    }
    if (!(await reachable(`${simAdminBase()}/admin/calls`))) {
      problems.push(
        'idp-simulator is not running (pnpm --filter @email-gateway/idp-adapters build; ' +
          'docker compose --profile smtp-test up -d --wait idp-simulator)',
      );
    }
    if (!process.env.API_MODE_GRAPH_NOTIFICATION_URL) {
      problems.push('API_MODE_GRAPH_NOTIFICATION_URL is not set in .env (step API-1 keys)');
    }
    return { ...base, problem: problems.length > 0 ? problems.join('\n') : undefined };
  })();
  return cached;
}

// --- idp-simulator admin API ----------------------------------------------------------------------

async function simRequest(path: string, method: string, body?: unknown): Promise<Response> {
  return fetch(`${simAdminBase()}${path}`, {
    method,
    headers: body === undefined ? {} : { 'content-type': 'application/json' },
    ...(body === undefined ? {} : { body: JSON.stringify(body) }),
  });
}

export interface SimCall {
  simulator: string;
  method: string;
  path: string;
  query?: string;
  status: number;
}

export interface SimNotification {
  kind: 'validation' | 'change' | 'lifecycle';
  subscriptionId: string | null;
  event?: string;
  status: number;
  ok: boolean;
  at: string;
}

export interface SimDelivery {
  provider: 'microsoft' | 'google';
  userId: string;
  messageId: string;
  internetMessageId: string | null;
  receivedAt: string;
  historyId: string;
  notifications: SimNotification[];
}

export interface SimSubscription {
  id: string;
  userId: string;
  notificationUrl: string;
  lifecycleNotificationUrl: string | null;
  hasClientState: boolean;
}

export const sim = {
  async ok(path: string, body: unknown): Promise<void> {
    const res = await simRequest(path, 'POST', body);
    if (res.status !== 204) throw new Error(`idp-simulator ${path} answered ${res.status}`);
  },
  reset: () => sim.ok('/admin/reset', {}),
  dataset: (dataset: unknown) => sim.ok('/admin/dataset', dataset),
  /** Scripted failure of an API family (`graph`, `gmail`, `google_directory`). */
  inject: (injection: {
    family: string;
    status: number;
    retryAfter?: string;
    times?: number;
    path?: string;
    method?: string;
  }) => sim.ok('/admin/inject', injection),
  /** Delivers a synthetic EML into a simulated mailbox (Graph pushes change notifications). */
  async deliver(user: string, eml: string | Buffer): Promise<SimDelivery> {
    const body =
      typeof eml === 'string' ? { eml } : { emlBase64: Buffer.from(eml).toString('base64') };
    const res = await simRequest(
      `/admin/mailboxes/${encodeURIComponent(user)}/messages`,
      'POST',
      body,
    );
    if (res.status !== 201) throw new Error(`idp-simulator delivery answered ${res.status}`);
    return (await res.json()) as SimDelivery;
  },
  async calls(filter: { simulator?: string; path?: string; method?: string } = {}) {
    const query = new URLSearchParams(filter as Record<string, string>).toString();
    const res = await simRequest(`/admin/calls${query ? `?${query}` : ''}`, 'GET');
    return ((await res.json()) as { calls: SimCall[] }).calls;
  },
  async subscriptions(): Promise<SimSubscription[]> {
    const res = await simRequest('/admin/subscriptions', 'GET');
    return ((await res.json()) as { subscriptions: SimSubscription[] }).subscriptions;
  },
  async notifications(): Promise<SimNotification[]> {
    const res = await simRequest('/admin/notifications', 'GET');
    return ((await res.json()) as { notifications: SimNotification[] }).notifications;
  },
};

/** A Microsoft directory of the simulators with mailbox users only (no ATO telemetry). */
export function simMicrosoftDirectory(
  tenantId: string,
  domains: readonly string[],
  users: readonly { id: string; address: string; aliases?: string[]; enabled?: boolean }[],
) {
  return {
    tenantId,
    domains: [...domains],
    licenses: { entraP1: false, entraP2: false, unifiedAudit: false },
    users: users.map((u) => ({
      id: u.id,
      userPrincipalName: u.address,
      mail: u.address,
      displayName: `EXAMPLE ${u.address.split('@')[0]}`,
      accountEnabled: u.enabled ?? true,
      onPremisesSyncEnabled: null,
      proxyAddresses: [`SMTP:${u.address}`, ...(u.aliases ?? []).map((a) => `smtp:${a}`)],
    })),
    signIns: [],
    riskDetections: [],
    directoryAudits: [],
    exchange: { subscribed: false, blobs: [] },
    messageRules: {},
    groups: [],
    oauth2PermissionGrants: [],
    servicePrincipals: [],
  };
}

/** A Google customer of the simulators with Directory users (the first one an administrator). */
export function simGoogleCustomer(
  customerId: string,
  domains: readonly string[],
  users: readonly { id: string; address: string; admin?: boolean; suspended?: boolean }[],
) {
  return {
    customerId,
    domains: [...domains],
    users: users.map((u) => ({
      id: u.id,
      primaryEmail: u.address,
      aliases: [],
      suspended: u.suspended ?? false,
      orgUnitPath: '/',
      changePasswordAtNextLogin: false,
      isAdmin: u.admin ?? false,
    })),
    orgUnits: [{ orgUnitId: 'id:root', orgUnitPath: '/', name: 'root' }],
    activities: [],
    tokens: {},
    gmail: {},
  };
}

// --- Compose overrides of the run ----------------------------------------------------------------

/**
 * mailbox-worker overrides of the run (shell environment over `.env`, LOCAL ONLY): health every
 * 3 s, counters flushed every 2 s, feed claims every second and a 10 s poll interval (the Gmail
 * history path); the notify-mode safety poll stays at its default (3 600 s), so a Graph sync in
 * the suite is caused by a change notification, never by the safety poll.
 */
export const MAILBOX_WORKER_SUITE_ENV: Record<string, string> = {
  API_MODE_HEALTH_INTERVAL_MS: '3000',
  API_MODE_COUNTER_FLUSH_SECONDS: '2',
  API_MODE_FEED_TICK_MS: '1000',
  API_MODE_FEED_POLL_SECONDS: '10',
};

/** The adapter's intake source snapshot (incl. `apiDetect`, D6) is cached for 1 s. */
export const ADAPTER_SUITE_ENV: Record<string, string> = {
  JOURNAL_INTAKE_SOURCE_CACHE_SECONDS: '1',
  JOURNAL_INTAKE_COUNTER_FLUSH_SECONDS: '2',
};

export async function recreateService(service: string, env: Record<string, string> = {}) {
  await composeOk(['up', '-d', '--no-deps', '--force-recreate', '--wait', service], {
    timeoutMs: 300_000,
    env,
  });
}

/** Recreates a service from `.env` again (the developer's own values). */
export async function restoreService(service: string): Promise<void> {
  await compose(['up', '-d', '--no-deps', '--force-recreate', '--wait', service], {
    timeoutMs: 300_000,
  });
}

// --- identifiers (contracts §36) -----------------------------------------------------------------

/**
 * `api_message_copies.message_id_hash` / dedupe key (D7 step 6): SHA-256 of
 * `api-copy/1 \0 <organizationId> \0 <Message-ID without angle brackets and surrounding blanks>`.
 */
export function copyMessageIdHash(organizationId: bigint, messageId: string): string {
  const bare = messageId.trim().replace(/^</, '').replace(/>$/, '').trim();
  return createHash('sha256')
    .update(`api-copy/1\0${organizationId.toString()}\0${bare}`)
    .digest('hex');
}

/** A fresh synthetic Message-ID (no angle brackets) under a reserved test domain. */
export const apiModeMessageId = (label: string) =>
  `it-apimode-${label}-${randomBytes(6).toString('hex')}@sender.example.test`;

const CRLF = '\r\n';
const rfc5322 = (d: Date) => d.toUTCString().replace('GMT', '+0000');

/** A synthetic RFC 5322 message (CRLF) with an optional top `Received:` hop. */
export function copyEml(o: {
  messageId: string;
  from: string;
  to: readonly string[];
  subject: string;
  body?: string;
  receivedAt?: Date;
}): string {
  return [
    ...(o.receivedAt
      ? [
          'Received: from mx.sender.example.test (mx.sender.example.test [192.0.2.25])',
          `\tby mailbox.provider.example.test with ESMTPS id EXAMPLE1; ${rfc5322(o.receivedAt)}`,
        ]
      : []),
    `Message-ID: <${o.messageId}>`,
    `Date: ${rfc5322(new Date())}`,
    `From: ${o.from}`,
    `To: ${o.to.join(', ')}`,
    `Subject: ${o.subject}`,
    'MIME-Version: 1.0',
    'Content-Type: text/plain; charset=utf-8',
    'Content-Transfer-Encoding: 7bit',
    '',
    o.body ?? 'Synthetic API-mode copy body.',
    '',
  ].join(CRLF);
}

/** A message with one attachment (base64), e.g. the EICAR test file from the attachment corpus. */
export function attachmentEml(o: {
  messageId: string;
  from: string;
  to: readonly string[];
  subject: string;
  filename: string;
  content: Buffer;
}): string {
  const boundary = `b_${randomBytes(6).toString('hex')}`;
  const base64 = o.content.toString('base64').replace(/.{1,76}/g, (line) => `${line}${CRLF}`);
  return [
    `Message-ID: <${o.messageId}>`,
    `Date: ${rfc5322(new Date())}`,
    `From: ${o.from}`,
    `To: ${o.to.join(', ')}`,
    `Subject: ${o.subject}`,
    'MIME-Version: 1.0',
    `Content-Type: multipart/mixed; boundary="${boundary}"`,
    '',
    `--${boundary}`,
    'Content-Type: text/plain; charset=utf-8',
    '',
    'Synthetic attachment copy.',
    `--${boundary}`,
    `Content-Type: application/octet-stream; name="${o.filename}"`,
    `Content-Disposition: attachment; filename="${o.filename}"`,
    'Content-Transfer-Encoding: base64',
    '',
    base64,
    `--${boundary}--`,
    '',
  ].join(CRLF);
}

// --- rows ----------------------------------------------------------------------------------------

/** Copy rows of a mailbox (writer), newest first. */
export function copiesOf(prisma: PrismaClient, organizationId: bigint, mailboxId: bigint) {
  return prisma.apiMessageCopy.findMany({
    where: { organizationId, mailboxId },
    orderBy: [{ receivedAt: 'desc' }, { id: 'desc' }],
  });
}

/** Waits for the copy row of a Message-ID in a mailbox that satisfies `predicate`. */
export function waitForCopy(
  prisma: PrismaClient,
  organizationId: bigint,
  mailboxId: () => Promise<bigint | undefined>,
  messageId: string,
  predicate: (copy: Awaited<ReturnType<typeof copiesOf>>[number]) => boolean,
  timeoutMs = 240_000,
) {
  const hash = copyMessageIdHash(organizationId, messageId);
  return waitFor(
    `API-mode copy of ${messageId}`,
    async () => {
      const id = await mailboxId();
      if (id === undefined) return undefined;
      const rows = await prisma.apiMessageCopy.findMany({
        where: { organizationId, mailboxId: id, messageIdHash: hash },
      });
      return rows.find(predicate);
    },
    { timeoutMs, intervalMs: 1_500 },
  );
}

/** The `api_mailboxes` row that owns an address (through `api_mailbox_addresses`). */
export async function mailboxByAddress(
  prisma: PrismaClient,
  organizationId: bigint,
  address: string,
) {
  const owner = await prisma.apiMailboxAddress.findFirst({
    where: { organizationId, address: address.toLowerCase() },
    select: { mailboxId: true },
  });
  if (!owner) return undefined;
  return (await prisma.apiMailbox.findUnique({ where: { id: owner.mailboxId } })) ?? undefined;
}

/**
 * Removes every step API-1 row of the organizations (the api purge's order: since step API-3 the
 * clawback targets, clawbacks and user reports first, then (step API-2) the remediation actions and
 * policies, the organization settings, then copies, dedupe keys, addresses, mailboxes, counters,
 * connections) and the mailbox-worker's Redis keys of their
 * API-mode connections (budgets, throttle pauses, counter hashes).
 */
export async function purgeApiModeRows(
  prisma: PrismaClient,
  redis: {
    keys: (pattern: string) => Promise<string[]>;
    del: (...keys: string[]) => Promise<number>;
  },
  organizationIds: readonly bigint[],
): Promise<void> {
  if (organizationIds.length === 0) return;
  const where = { organizationId: { in: [...organizationIds] } };
  const connections = await prisma.apiModeConnection.findMany({
    where,
    select: { id: true, publicId: true },
  });
  // Step API-3 (note 37 §3.4): clawback targets, clawbacks and user reports go before the
  // remediation actions (reports reference mailboxes and connections, RESTRICT); since API-3 the
  // live workers may claw back or record reports for the suite's copies.
  await prisma.apiClawbackTarget.deleteMany({ where });
  await prisma.apiClawback.deleteMany({ where });
  await prisma.apiUserReport.deleteMany({ where });
  // Step API-2 (§3.4): remediation actions reference mailboxes and connections (RESTRICT) and
  // policies reference domains (RESTRICT); the remediation decided on the suite's copies goes first.
  await prisma.apiRemediationAction.deleteMany({ where });
  await prisma.apiRemediationPolicy.deleteMany({ where });
  // Step API-3: the organization settings row (RESTRICT to the organization).
  await prisma.apiModeOrgSetting.deleteMany({ where });
  await prisma.apiMessageCopy.deleteMany({ where });
  await prisma.apiCopyDedupeKey.deleteMany({ where });
  await prisma.apiMailboxAddress.deleteMany({ where });
  await prisma.apiMailbox.deleteMany({ where });
  await prisma.apiModeCounter.deleteMany({ where });
  await prisma.apiModeConnection.deleteMany({ where });
  for (const c of connections) {
    const keys = [
      ...(await redis.keys(`mbx:rb:${c.publicId}:*`)),
      ...(await redis.keys(`mbx:throttle:${c.publicId}:*`)),
      ...(await redis.keys(`mbx:cnt:${c.id.toString()}:*`)),
    ];
    if (keys.length > 0) await redis.del(...keys);
  }
}

/** Rows of the API-mode tables still referencing the organizations (all zero after cleanup). */
export async function apiModeRowCounts(prisma: PrismaClient, organizationIds: readonly bigint[]) {
  const where = { organizationId: { in: [...organizationIds] } };
  return {
    connections: await prisma.apiModeConnection.count({ where }),
    mailboxes: await prisma.apiMailbox.count({ where }),
    addresses: await prisma.apiMailboxAddress.count({ where }),
    copies: await prisma.apiMessageCopy.count({ where }),
    dedupeKeys: await prisma.apiCopyDedupeKey.count({ where }),
    counters: await prisma.apiModeCounter.count({ where }),
  };
}

/** A Prometheus metric family's samples from the mailbox-worker (`/metrics`). */
export async function mailboxWorkerMetric(name: string): Promise<string[]> {
  const res = await fetch(`${mailboxWorkerUrl()}/metrics`, { signal: AbortSignal.timeout(5_000) });
  const text = await res.text();
  return text.split('\n').filter((line) => line.startsWith(name));
}

/**
 * The decoded text of a stored notification e-mail (single-part or the first text part):
 * nodemailer writes long lines quoted-printable (or base64), so raw bytes cannot be matched.
 */
export function decodedMailText(raw: Buffer): string {
  const text = raw.toString('latin1').replace(/\r\n/g, '\n');
  const parts = text.split(/\n--[^\n]+\n/);
  const decoded: string[] = [];
  for (const part of parts) {
    const split = part.indexOf('\n\n');
    if (split < 0) continue;
    const headers = part.slice(0, split).toLowerCase();
    const body = part.slice(split + 2);
    if (/content-transfer-encoding:\s*base64/.test(headers)) {
      decoded.push(Buffer.from(body.replace(/\s+/g, ''), 'base64').toString('utf8'));
    } else if (/content-transfer-encoding:\s*quoted-printable/.test(headers)) {
      const bytes = body
        .replace(/=\n/g, '')
        .replace(/=([0-9A-Fa-f]{2})/g, (_m, hex: string) => String.fromCharCode(parseInt(hex, 16)));
      decoded.push(Buffer.from(bytes, 'latin1').toString('utf8'));
    } else {
      decoded.push(body);
    }
  }
  // Unfolded top-level headers (a long Subject is folded) followed by the decoded text parts.
  const head = text.slice(0, Math.max(0, text.indexOf('\n\n'))).replace(/\n[ \t]+/g, ' ');
  return `${head}\n\n${decoded.join('\n')}`;
}
