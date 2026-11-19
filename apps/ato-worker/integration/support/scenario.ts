import { createHash } from 'node:crypto';
import {
  atoSubjectHash,
  utcDayStart,
  type AccountSubject,
  type AtoSettingsInput,
} from '@email-gateway/ato-detection';
import type { AtoAccount } from '@email-gateway/database';
import type { EventEnvelope } from '@email-gateway/event-contracts';
import type { Fixtures } from './fixtures';
import type { Harness } from './harness';

/**
 * Stores tenant settings through the ATO store (normalized, versioned, audited). Suites run with no
 * learning period by default so baseline-relative rules fire.
 */
export async function configure(
  h: Harness,
  organizationId: bigint,
  settings: AtoSettingsInput = {},
): Promise<void> {
  await h.comps.db.transaction(async (tx) => {
    const current = await h.comps.store.ensureSettings(tx, organizationId);
    await h.comps.store.saveSettings(tx, {
      organizationId,
      settings: { learningDays: 0, ...settings },
      expectedRowVersion: current.rowVersion,
      actor: { type: 'system', id: null },
    });
  });
  h.comps.orgs.invalidate(organizationId);
}

export async function accountOf(
  fx: Fixtures,
  organizationId: bigint,
  kind: 'mailbox' | 'gateway_user' | 'smtp_connector',
  subject: string | bigint,
): Promise<AtoAccount | null> {
  const hashKind = kind === 'mailbox' ? 'mailbox' : kind === 'gateway_user' ? 'user' : 'connector';
  return fx.prisma.atoAccount.findUnique({
    where: {
      organizationId_kind_subjectHash: {
        organizationId,
        kind,
        subjectHash: atoSubjectHash(
          hashKind,
          typeof subject === 'string' ? subject.toLowerCase() : subject,
        ),
      },
    },
  });
}

export async function codes(
  fx: Fixtures,
  organizationId: bigint,
  accountId?: bigint,
): Promise<string[]> {
  const rows = await fx.prisma.atoRiskSignal.findMany({
    where: { organizationId, ...(accountId !== undefined && { accountId }) },
    select: { ruleCode: true },
    orderBy: { id: 'asc' },
  });
  return rows.map((r) => r.ruleCode);
}

/** Runs one envelope through the `ato.events` consumer handler (as the queue would). */
export function deliver(h: Harness, event: EventEnvelope): Promise<'handled' | 'duplicate'> {
  return h.comps.eventsConsumer.handle(event);
}

export function deliverMail(h: Harness, event: EventEnvelope): Promise<'handled' | 'duplicate'> {
  return h.comps.mailConsumer.handle(event);
}

const hex16 = (v: string) => createHash('sha256').update(v).digest('hex').slice(0, 16);

/**
 * A mature baseline for an account (D9): ten active days of activity rows and successful
 * authentications from the given prefixes, countries, ASNs and devices, then the maintenance
 * rebuild (the same code path as the daily job).
 */
export async function matureAccount(
  h: Harness,
  fx: Fixtures,
  organizationId: bigint,
  subject: AccountSubject,
  options: {
    prefix?: string;
    country?: string;
    asn?: number;
    deviceUserAgent?: string;
    days?: number;
    messagesPerDay?: number;
    externalDomains?: readonly string[];
    clientPrefixes?: readonly string[];
  } = {},
): Promise<AtoAccount> {
  const now = h.clock.now();
  const account = await h.comps.db.transaction((tx) =>
    h.comps.store.ensureAccount(tx, { organizationId, subject, at: now }),
  );
  const days = options.days ?? 10;
  const device = options.deviceUserAgent ? h.comps.enricher.device(options.deviceUserAgent) : null;
  for (let d = 1; d <= days; d++) {
    const dayStart = new Date(utcDayStart(now).getTime() - d * 86_400_000);
    const messages = options.messagesPerDay ?? 0;
    await fx.prisma.atoAccountActivityDaily.create({
      data: {
        dayStart,
        organizationId,
        accountId: account.id,
        authSuccess: 5,
        messages,
        recipients: messages,
        externalRecipients: messages,
        maxHourMessages: Math.ceil(messages / 8),
        hourCounts: Array.from({ length: 24 }, (_, hour) => ({
          m: hour >= 9 && hour < 17 ? Math.floor(messages / 8) : 0,
          a: hour >= 9 && hour < 17 ? 1 : 0,
        })),
        ipPrefixes: options.prefix
          ? [{ p: options.prefix, n: 5, cc: options.country, asn: options.asn }]
          : [],
        recipientDomains: (options.externalDomains ?? []).map((x) => ({ d: x, n: 1 })),
        attachmentTypes: [],
        peers: [],
        content: {
          maxHourExternalDomains: Math.min(3, options.externalDomains?.length ?? 0),
          ...(options.clientPrefixes ? { clientPrefixes: [...options.clientPrefixes] } : {}),
        },
      },
    });
    for (let i = 0; i < 4; i++) {
      const at = new Date(dayStart.getTime() + (10 + i) * 3_600_000);
      await fx.prisma.atoAuthEvent.create({
        data: {
          occurredAt: at,
          organizationId,
          accountId: account.id,
          source: account.kind === 'smtp_connector' ? 'smtp_auth' : 'portal_login',
          channel: account.kind === 'smtp_connector' ? 'smtp' : 'portal',
          outcome: 'success',
          ipPrefix: options.prefix ?? null,
          countryCode: options.country ?? null,
          geoStatus: options.country ? 'located' : 'unavailable',
          asn: options.asn ?? null,
          deviceHash: device?.hash ?? null,
          deviceLabel: device?.label ?? null,
          lastOccurredAt: at,
          dedupeKey: createHash('sha256').update(`mature|${account.id}|${d}|${i}`).digest('hex'),
          sourceRef: `it:${hex16(`${account.id}|${d}|${i}`)}`,
        },
      });
    }
  }
  await h.comps.maintenance.rebuildOne(organizationId, account.id, now);
  return account;
}
