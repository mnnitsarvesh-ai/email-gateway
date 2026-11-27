import { randomUUID } from 'node:crypto';
import { uuidv7 } from '@email-gateway/common';
import type { ApiClawback } from '@email-gateway/database';
import {
  EventTypes,
  type EventEnvelope,
  type ThreatLateSignalV1,
} from '@email-gateway/event-contracts';
import type { RunningSimulators } from '@email-gateway/idp-adapters/testing';
import {
  canonicalCriteriaSha256,
  decidePurgeApproval,
  normalizeClawbackCriteria,
  requiresPurgeApproval,
  signalFacts,
  type ClawbackCriteria,
  type ClawbackChosenVerdict,
} from '@email-gateway/mailbox-api';
import type { MailboxComponents } from '../../src/components';
import type { WorkerConfig } from '../../src/config';
import type { Clock, Fixtures } from './harness';
import { remediationConfig } from './remediation';

/**
 * Step API-3 helpers of the clawback, report and internal-mail suites (synthetic `it-apiclaw-*`
 * organizations only): registry rows the scanner writes (attachments, URLs), late-signal
 * envelopes, threat indicators, and the api's clawback writes (create, submit, approve, cancel,
 * restore request; owned by WP4 and mimicked here as the rows the api commits, using the same
 * pure rules of `@email-gateway/mailbox-api`).
 */

const DAY_MS = 86_400_000;

/** Worker configuration with every role incl. `remediate`, `clawback` and `reports`. */
export function clawbackConfig(
  fx: Fixtures,
  sims: RunningSimulators,
  overrides: Record<string, string> = {},
): Readonly<WorkerConfig> {
  return remediationConfig(fx, sims, {
    MAILBOX_WORKER_ROLES: 'copies,feeds,inventory,health,remediate,clawback,reports',
    ...overrides,
  });
}

/** An `email_attachments` row (the parser's), content-free. */
export async function attachment(
  fx: Fixtures,
  organizationId: bigint,
  message: { id: bigint; receivedAt: Date },
  sha256: string,
  partIndex = 1,
): Promise<void> {
  await fx.prisma.emailAttachment.create({
    data: {
      receivedAt: message.receivedAt,
      messageId: message.id,
      organizationId,
      partIndex,
      filename: 'invoice.pdf',
      sizeBytes: 1024,
      sha256,
    },
  });
}

/** A `message_urls` row (the URL extractor's): identity hash and registrable domain. */
export async function messageUrl(
  fx: Fixtures,
  organizationId: bigint,
  message: { id: bigint; receivedAt: Date },
  urlSha256: string,
  host = 'phish.example',
  urlSeq = 0,
): Promise<void> {
  await fx.prisma.messageUrl.create({
    data: {
      receivedAt: message.receivedAt,
      messageId: message.id,
      organizationId,
      urlSeq,
      url: `https://${host}/login`,
      urlSha256,
      scheme: 'https',
      host,
      registrableDomain: host,
      hostKind: 'domain',
      sources: ['text'],
      occurrences: 1,
      firstLifecycleRound: 0,
      extractorVersion: 'url/1',
    },
  });
}

/** A `mail.threat.late_signal.v1` envelope as the email-worker's outbox row is relayed. */
export function lateSignal(
  fx: Fixtures,
  organizationId: bigint,
  payload: Partial<Omit<ThreatLateSignalV1, 'signalAt'>> & {
    messageId: string;
    receivedAt: string;
    signalAt: Date;
  },
): EventEnvelope<ThreatLateSignalV1> {
  const eventId = uuidv7();
  fx.eventIds.push(eventId);
  const kind = payload.kind ?? 'sandbox_revision';
  return {
    eventId,
    eventType: EventTypes.ThreatLateSignal,
    occurredAt: payload.signalAt.toISOString(),
    correlationId: `it-apiclaw-${fx.suffix}`,
    organizationId: organizationId.toString(),
    payload: {
      kind,
      messageId: payload.messageId,
      receivedAt: payload.receivedAt,
      scanId: payload.scanId ?? '1',
      revision: kind === 'sandbox_revision' ? (payload.revision ?? 1) : null,
      verdict: payload.verdict ?? 'malware',
      level: payload.level ?? 'critical',
      hardBlocks: payload.hardBlocks ?? ['hb.malware_sandbox'],
      attachmentSha256: payload.attachmentSha256 ?? [],
      urlSha256: payload.urlSha256 ?? [],
      signalAt: payload.signalAt.toISOString(),
    },
  };
}

/** An active organization user (requester, approver, restoring user, reporter). */
export async function user(
  fx: Fixtures,
  organizationId: bigint,
  email: string,
): Promise<{ id: bigint; publicId: string }> {
  return fx.prisma.user.create({
    data: { organizationId, email, displayName: email.split('@')[0]!, status: 'active' },
    select: { id: true, publicId: true },
  });
}

/** The api's admin/campaign/report clawback create (C2.3, C14 #1): status `searching`. */
export async function adminClawback(
  fx: Fixtures,
  organizationId: bigint,
  input: {
    keys: ClawbackCriteria['keys'];
    now: Date;
    windowDays?: number;
    requestedBy: bigint;
    trigger?: 'admin' | 'campaign' | 'report';
    directions?: ClawbackCriteria['directions'];
  },
): Promise<ApiClawback> {
  const criteria = normalizeClawbackCriteria({
    v: 1,
    window: {
      from: new Date(input.now.getTime() - (input.windowDays ?? 7) * DAY_MS).toISOString(),
      to: new Date(input.now.getTime() + 60_000).toISOString(),
    },
    keys: input.keys,
    directions: input.directions ?? ['inbound', 'internal'],
    includeReportMailboxes: false,
  });
  return fx.prisma.apiClawback.create({
    data: {
      publicId: uuidv7(),
      organizationId,
      trigger: input.trigger ?? 'admin',
      signal: {
        v: 1,
        kind: input.trigger ?? 'admin',
        refs: {},
        facts: null,
        signalAt: input.now.toISOString(),
      },
      criteria: JSON.parse(JSON.stringify(criteria)) as never,
      criteriaSha256: canonicalCriteriaSha256(criteria),
      status: 'searching',
      requestedByType: 'user',
      requestedByUserId: input.requestedBy,
      requestReason: 'it: phishing campaign',
      signalAt: input.now,
      nextStepAt: input.now,
    },
  });
}

/**
 * The api's submit (C6, C14 #5) as rows: `requiresPurgeApproval` over the materialized counts →
 * `pending_approval` (TTL) or `queued`; policy mode stores the analyst facts (C3.1).
 */
export async function submit(
  fx: Fixtures,
  clawbackId: bigint,
  input: {
    mode: 'policy' | 'explicit';
    action?: 'move_quarantine' | 'move_junk' | 'soft_delete' | 'hard_delete';
    verdict?: ClawbackChosenVerdict;
    submittedBy: bigint;
    threshold: number;
    now: Date;
    ttlHours?: number;
  },
): Promise<ApiClawback> {
  const row = await fx.prisma.apiClawback.findUniqueOrThrow({ where: { id: clawbackId } });
  const need = requiresPurgeApproval({
    mailboxesEligible: row.mailboxesEligible,
    threshold: input.threshold,
    action: input.mode === 'explicit' ? (input.action ?? null) : null,
    autoCap: Array.isArray(row.approvalReasons) && row.approvalReasons.includes('auto_cap'),
  });
  const facts =
    input.mode === 'policy'
      ? signalFacts({ kind: 'admin', verdict: input.verdict ?? 'phishing' })
      : null;
  return fx.prisma.apiClawback.update({
    where: { id: clawbackId },
    data: {
      decisionMode: input.mode,
      action: input.mode === 'explicit' ? (input.action ?? null) : null,
      signalVerdict: facts?.verdict ?? null,
      signalLevel: facts?.level ?? null,
      signalHardBlocks: facts ? facts.hardBlocks : undefined,
      status: need.required ? 'pending_approval' : 'queued',
      requiresApproval: need.required,
      approvalReasons: need.required ? need.reasons : undefined,
      approvalStatus: need.required ? 'pending' : null,
      approvalRequestedAt: need.required ? input.now : null,
      approvalExpiresAt: need.required
        ? new Date(input.now.getTime() + (input.ttlHours ?? 72) * 3_600_000)
        : null,
      submittedByUserId: input.submittedBy,
      submittedAt: input.now,
      nextStepAt: input.now,
      rowVersion: { increment: 1 },
    },
  });
}

/** The api's approve (C6, C14 #7): `decidePurgeApproval`, then `queued`. Returns the decision. */
export async function approve(
  fx: Fixtures,
  clawbackId: bigint,
  approver: { userId: bigint; type?: 'user' | 'api_key'; permissions?: string[] },
  now: Date,
): Promise<ReturnType<typeof decidePurgeApproval>> {
  const row = await fx.prisma.apiClawback.findUniqueOrThrow({ where: { id: clawbackId } });
  const decision = decidePurgeApproval({
    approver: {
      type: approver.type ?? 'user',
      userId: approver.userId.toString(),
      permissions: approver.permissions ?? ['remediation:read', 'remediation:purge'],
    },
    request: {
      status: row.approvalStatus,
      expiresAt: row.approvalExpiresAt,
      requestedByUserId: row.requestedByUserId?.toString() ?? null,
      submittedByUserId: row.submittedByUserId?.toString() ?? null,
    },
    now,
  });
  if (decision.allowed) {
    await fx.prisma.apiClawback.update({
      where: { id: clawbackId },
      data: {
        approvalStatus: 'approved',
        approvalDecidedAt: now,
        approvedByUserId: approver.userId,
        approverPermissionsHash: 'd'.repeat(64),
        status: 'queued',
        nextStepAt: now,
        rowVersion: { increment: 1 },
      },
    });
  }
  return decision;
}

/** The api's cancel (C5.6): `cancel_requested_at`. */
export async function requestCancel(fx: Fixtures, clawbackId: bigint, now: Date): Promise<void> {
  await fx.prisma.apiClawback.update({
    where: { id: clawbackId },
    data: { cancelRequestedAt: now, rowVersion: { increment: 1 } },
  });
}

/** The api's restore request (C7, C14 #10): `restore_status = requested` and its audit row. */
export async function requestRestore(
  fx: Fixtures,
  clawback: { id: bigint; publicId: string; organizationId: bigint },
  restoringUser: { publicId: string },
  now: Date,
): Promise<void> {
  await fx.prisma.$transaction([
    fx.prisma.apiClawback.update({
      where: { id: clawback.id },
      data: { restoreStatus: 'requested', nextStepAt: now, rowVersion: { increment: 1 } },
    }),
    fx.prisma.auditLog.create({
      data: {
        organizationId: clawback.organizationId,
        actorType: 'user',
        actorId: restoringUser.publicId,
        action: 'api_mode.clawback_restore_requested',
        resourceType: 'api_clawback',
        resourceId: clawback.publicId,
        correlationId: `it-${randomUUID()}`,
        metadata: { clawbackId: clawback.publicId },
      },
    }),
  ]);
}

/**
 * Drives the `clawback` and `remediate` roles until nothing is due (the injected clock advances
 * past each `next_step_at`); returns the passes run.
 */
export async function settle(comps: MailboxComponents, clock: Clock, max = 30): Promise<number> {
  for (let pass = 1; pass <= max; pass++) {
    clock.advance(comps.config.API_MODE_CLAWBACK_TICK_MS + 1);
    const moreClawback = await comps.clawback.tick();
    const moreRemediation = comps.remediation ? await comps.remediation.tick() : false;
    const open = await comps.deps.prisma.apiClawback.count({
      where: {
        organizationId: { in: [...(comps.deps.organizationIds ?? [])] },
        OR: [
          { status: { in: ['searching', 'queued', 'running'] } },
          { restoreStatus: { in: ['requested', 'running'] } },
        ],
      },
    });
    const pending = await comps.deps.prisma.apiRemediationAction.count({
      where: {
        organizationId: { in: [...(comps.deps.organizationIds ?? [])] },
        status: { in: ['pending', 'in_progress'] },
        nextAttemptAt: { lte: clock.now() },
      },
    });
    if (!moreClawback && !moreRemediation && open === 0 && pending === 0) return pass;
  }
  return max;
}

export const hex = (seed: string): string =>
  Buffer.from(seed.padEnd(32, '0').slice(0, 32)).toString('hex');
