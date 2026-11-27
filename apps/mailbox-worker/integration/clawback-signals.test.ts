import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';
import {
  messageLocation,
  microsoftDirectory,
  MS_DOMAIN,
  MS_TENANT_ID,
  startSimulators,
  syntheticEml,
  type RunningSimulators,
} from '@email-gateway/idp-adapters/testing';
import { clawbackSignalKey, DEFAULT_REMEDIATION_POLICY } from '@email-gateway/mailbox-api';
import { M365_MAILBOX_REMEDIATION_PROFILE } from '@email-gateway/provider-integrations';
import type { MailboxComponents } from '../src/components';
import { COPIES_CONSUMER } from '../src/copies/copies.handler';
import { TiSweep } from '../src/clawback/ti-sweep';
import {
  attachment,
  clawbackConfig,
  hex,
  lateSignal,
  messageUrl,
  settle,
} from './support/clawback';
import {
  Clock,
  Fixtures,
  SimAccessTokens,
  silent,
  type TestConnection,
  type TestOrg,
} from './support/harness';
import { actionsOfCopy, cancelOpenActions, copiesOf, policy, riskRow } from './support/remediation';

/**
 * Design note 37 §9.3 (mailbox-worker, automatic clawback; C2, C3, C5, ADR-0103): a late sandbox
 * signal → clawback (signal key, policy mode, signal facts, Message-ID + attachment criteria) →
 * targets → P1 decisions → actions executed by the `remediate` role on the Graph simulator →
 * mailbox entries with the clawback reason/explanation → reconcile `completed` (audit, counters);
 * the signal's own copies raised to the late verdict (`verdict_revision`); a duplicate signal
 * creates nothing; an organization without API mode or with automatic clawback off is acked; a
 * detect-only policy simulates; a paused connection waits (and `clawback.stalled` warns); hybrid
 * inline copies are acted on with copy authority; the threat-intelligence sweep (platform
 * indicator fans out only to organizations with matches, an organization indicator only to its
 * organization, below-confidence ignored, malware signatures, cursor resume after a restart).
 * Real MySQL writer, Redis and MinIO; injected clock; synthetic `it-apiclaw-*` organizations.
 */
const fx = new Fixtures('it-apiclaw');
const clock = new Clock();
const S = fx.suffix;
let sims: RunningSimulators;
let tokens: SimAccessTokens;
let comps: MailboxComponents;
let org: TestOrg;
let conn: TestConnection;
let sourceId: bigint;
const ALEX = `alex@${MS_DOMAIN}`;
const BLAKE = `blake@${MS_DOMAIN}`;
const CASEY = `casey@${MS_DOMAIN}`;
const DREW = `drew@${MS_DOMAIN}`;
const FOLDER = 'Email Gateway Quarantine';
const TI_SOURCE = `it-apiclaw-${S}`;
let scan = 40_000n;

/** A clean journal copy (delivered to the simulator mailboxes) and its revision-0 risk row. */
async function cleanCopy(
  recipients: string[],
  input: {
    organization?: TestOrg;
    source?: bigint;
    deliver?: boolean;
    messageId?: string;
    from?: string;
    attachmentSha256?: string;
    urlSha256?: string;
  } = {},
) {
  const o = input.organization ?? org;
  const messageId = input.messageId ?? `${crypto.randomUUID()}@sender.example`;
  const eml = syntheticEml({ messageId, to: recipients });
  const delivered = new Map<string, string>();
  if (input.deliver !== false) {
    for (const to of recipients)
      delivered.set(to, (await sims.deliver({ user: to, eml })).messageId);
  }
  const message = await fx.journalCopy(o, input.source ?? sourceId, {
    eml,
    recipients,
    messageId,
    from: input.from ?? 'sender@sender.example',
    receivedAt: clock.now(),
  });
  if (input.attachmentSha256) await attachment(fx, o.id, message, input.attachmentSha256);
  if (input.urlSha256) await messageUrl(fx, o.id, message, input.urlSha256);
  scan += 1n;
  await riskRow(fx, o.id, message, { scanId: scan, level: 'none', verdict: 'clean', score: 10 });
  expect(
    await comps.copies.handle(
      fx.copyScanned(o.id, message, {
        completedAt: clock.now(),
        verdict: 'clean',
        riskScore: 10,
        scanId: scan.toString(),
      }),
    ),
  ).toBe('handled');
  return { message, messageId, delivered, scanId: scan, copies: await copiesOf(fx, message.id) };
}

const clawbacksOf = (organizationId: bigint) =>
  fx.prisma.apiClawback.findMany({ where: { organizationId }, orderBy: { id: 'asc' } });
const targetsOf = (clawbackId: bigint) =>
  fx.prisma.apiClawbackTarget.findMany({ where: { clawbackId }, orderBy: { id: 'asc' } });

beforeAll(async () => {
  sims = await startSimulators({
    dataset: { microsoft: { directories: [microsoftDirectory(clock.now())] } },
    now: clock.ms,
  });
  sims.tokens.setGrant(
    MS_TENANT_ID,
    M365_MAILBOX_REMEDIATION_PROFILE.key,
    M365_MAILBOX_REMEDIATION_PROFILE.permissions,
  );
  tokens = new SimAccessTokens(() => sims, clock);
  comps = fx.components(clawbackConfig(fx, sims), { clock, tokens });
  org = await fx.organization('signals');
  await fx.domain(org, MS_DOMAIN, 'api');
  conn = await fx.connection(org, 'microsoft_365', {
    tenantId: MS_TENANT_ID,
    domains: [MS_DOMAIN],
  });
  tokens.directories.set(conn.providerConnectionPublicId, MS_TENANT_ID);
  sourceId = await fx.journalSource(org, conn);
  expect((await comps.inventory!.run(conn.apiConnectionId)).result).toBe('ok');
});

beforeEach(async () => {
  await cancelOpenActions(fx, fx.organizationIds);
  comps.policies.invalidate();
});

afterAll(async () => {
  await fx.prisma.threatIndicator.deleteMany({ where: { source: TI_SOURCE } });
  await fx.prisma.malwareSignature.deleteMany({ where: { source: TI_SOURCE } });
  await sims?.stop();
  await fx.cleanup();
});

describe('late verdict → clawback (C2.1, C3, C5)', () => {
  it('a sandbox revision claws back every copy by Message-ID and attachment through P1', async () => {
    const fileHash = hex(`sbx-${S}`);
    const seed = await cleanCopy([ALEX, BLAKE, CASEY], { attachmentSha256: fileHash });
    const other = await cleanCopy([DREW], { attachmentSha256: fileHash });
    expect(seed.copies).toHaveLength(3);
    // The sandbox revision 1 of the seed's round (what the email-worker writes, C2.1).
    await riskRow(fx, org.id, seed.message, {
      scanId: seed.scanId,
      revision: 1,
      level: 'critical',
      verdict: 'malware',
      score: 990,
      hardBlocks: ['hb.malware_sandbox'],
    });
    const signalAt = clock.now();
    const event = lateSignal(fx, org.id, {
      messageId: seed.message.id.toString(),
      receivedAt: seed.message.receivedAt.toISOString(),
      scanId: seed.scanId.toString(),
      attachmentSha256: [fileHash],
      signalAt,
    });
    expect(await comps.copies.handle(event)).toBe('handled');
    const [clawback] = await clawbacksOf(org.id);
    expect(clawback).toMatchObject({
      trigger: 'late_verdict',
      status: 'searching',
      decisionMode: 'policy',
      signalVerdict: 'malware',
      signalLevel: 'critical',
      requestedByType: 'system',
      signalKey: clawbackSignalKey(org.id, {
        source: 'late',
        messageId: seed.message.id,
        receivedAt: seed.message.receivedAt,
        kind: 'sandbox_revision',
        revision: 1,
        urlSha256: null,
      }),
    });
    expect(clawback!.signalHardBlocks).toEqual(['hb.malware_sandbox']);
    expect(clawback!.criteria).toMatchObject({
      keys: { messageIdHashes: [seed.copies[0]!.messageIdHash], attachmentSha256: [fileHash] },
      directions: ['inbound', 'internal'],
    });
    // C3.3: the signal's own copies show the late verdict.
    for (const copy of await copiesOf(fx, seed.message.id)) {
      expect(copy).toMatchObject({ verdict: 'malware', verdictRevision: 1 });
    }
    expect((await copiesOf(fx, other.message.id))[0]).toMatchObject({
      verdict: 'clean',
      verdictRevision: 0,
    });
    // The ledger row of the copies consumer (reconciled queue).
    expect(
      await fx.prisma.messageIdempotency.count({
        where: { consumer: COPIES_CONSUMER, eventId: event.eventId },
      }),
    ).toBe(1);
    // Redelivery: one effect.
    expect(await comps.copies.handle(event)).toBe('duplicate');
    // A replay with another event id but the same signal: no second clawback.
    expect(
      await comps.copies.handle(
        lateSignal(fx, org.id, {
          messageId: seed.message.id.toString(),
          receivedAt: seed.message.receivedAt.toISOString(),
          scanId: seed.scanId.toString(),
          attachmentSha256: [fileHash],
          signalAt,
        }),
      ),
    ).toBe('handled');
    expect(await clawbacksOf(org.id)).toHaveLength(1);

    // Materialization: 4 targets (3 by Message-ID + attachment, 1 by attachment), planned move.
    clock.advance(1);
    await comps.clawback.tick();
    const materialized = await fx.prisma.apiClawback.findUniqueOrThrow({
      where: { id: clawback!.id },
    });
    expect(materialized).toMatchObject({
      status: 'queued',
      targetsTotal: 4,
      mailboxesTotal: 4,
      targetsEligible: 4,
      mailboxesEligible: 4,
    });
    const targets = await targetsOf(clawback!.id);
    expect(targets.map((t) => t.status)).toEqual(['matched', 'matched', 'matched', 'matched']);
    expect(targets.map((t) => t.plannedAction)).toEqual(Array(4).fill('move_quarantine'));
    expect(targets.filter((t) => (t.matchKeys as string[]).includes('message_id'))).toHaveLength(3);
    expect(targets.find((t) => t.copyId === other.copies[0]!.id)!.matchKeys).toEqual([
      'attachment',
    ]);

    // Queue → remediate → reconcile.
    await settle(comps, clock);
    const done = await fx.prisma.apiClawback.findUniqueOrThrow({ where: { id: clawback!.id } });
    expect(done).toMatchObject({
      status: 'completed',
      targetsSucceeded: 4,
      targetsFailed: 0,
      targetsQueued: 0,
    });
    expect(done.startedAt).not.toBeNull();
    expect(done.completedAt).not.toBeNull();
    for (const t of await targetsOf(clawback!.id)) {
      expect(t.status).toBe('succeeded');
      const action = await fx.prisma.apiRemediationAction.findUniqueOrThrow({
        where: { id: t.actionId! },
      });
      expect(action).toMatchObject({
        trigger: 'clawback',
        clawbackId: clawback!.id,
        status: 'succeeded',
        action: 'move_quarantine',
        requestedByType: 'system',
      });
      expect((action.decision as { notes: string[] }).notes).toEqual(
        expect.arrayContaining(['source:clawback', `clawback:${clawback!.publicId}`]),
      );
      const entry = await fx.prisma.quarantineMessage.findFirstOrThrow({
        where: { apiRemediationActionId: action.id },
      });
      expect(entry).toMatchObject({ location: 'mailbox', status: 'held', reason: 'malware' });
      expect(entry.explanationText).toBe(
        `Removed from the mailbox by clawback ${clawback!.publicId} (late_verdict)`,
      );
    }
    for (const [to, id] of seed.delivered) {
      expect(messageLocation(sims.script, to, id)?.folder?.displayName).toBe(FOLDER);
    }
    const audit = await fx.prisma.auditLog.findFirstOrThrow({
      where: { organizationId: org.id, action: 'api_mode.clawback_completed' },
    });
    expect(audit).toMatchObject({ actorType: 'system', resourceId: clawback!.publicId });
    await comps.counters.flush(fx.organizationIds);
    const counters = await fx.prisma.apiModeCounter.findMany({
      where: { apiConnectionId: conn.apiConnectionId },
    });
    expect(counters.reduce((n, c) => n + c.clawbackTargetsQueued, 0)).toBe(4);
    expect(counters.reduce((n, c) => n + c.clawbackTargetsSucceeded, 0)).toBe(4);
  });

  it('an organization without API mode is acked; automatic clawback off creates nothing', async () => {
    const inline = await fx.organization('inline');
    await fx.domain(inline, `in-${S}.it-apiclaw.example`, 'inline');
    const inlineMessage = await fx.gatewayMessage(inline, {
      messageId: `${crypto.randomUUID()}@sender.example`,
      recipient: `jo@in-${S}.it-apiclaw.example`,
      receivedAt: clock.now(),
      finalVerdict: 'clean',
    });
    const acked = lateSignal(fx, inline.id, {
      messageId: inlineMessage.toString(),
      receivedAt: clock.now().toISOString(),
      signalAt: clock.now(),
    });
    expect(await comps.copies.handle(acked)).toBe('handled');
    expect(await clawbacksOf(inline.id)).toHaveLength(0);
    expect(
      await fx.prisma.messageIdempotency.count({
        where: { consumer: COPIES_CONSUMER, eventId: acked.eventId },
      }),
    ).toBe(1);

    await fx.prisma.apiModeOrgSetting.create({
      data: { organizationId: org.id, autoClawback: 'off' },
    });
    try {
      const seed = await cleanCopy([BLAKE], { deliver: false });
      const before = (await clawbacksOf(org.id)).length;
      expect(
        await comps.copies.handle(
          lateSignal(fx, org.id, {
            messageId: seed.message.id.toString(),
            receivedAt: seed.message.receivedAt.toISOString(),
            signalAt: clock.now(),
          }),
        ),
      ).toBe('handled');
      expect(await clawbacksOf(org.id)).toHaveLength(before);
    } finally {
      await fx.prisma.apiModeOrgSetting.delete({ where: { organizationId: org.id } });
    }
  });

  it('detect-only simulates every target; a paused connection waits and clawback.stalled warns', async () => {
    await policy(fx, org.id, 'detect_only', DEFAULT_REMEDIATION_POLICY.document);
    comps.policies.invalidate();
    const simulated = await cleanCopy([CASEY], { deliver: false });
    await comps.copies.handle(
      lateSignal(fx, org.id, {
        messageId: simulated.message.id.toString(),
        receivedAt: simulated.message.receivedAt.toISOString(),
        signalAt: clock.now(),
      }),
    );
    const simClawback = (await clawbacksOf(org.id)).at(-1)!;
    await settle(comps, clock);
    expect(await targetsOf(simClawback.id)).toMatchObject([
      { status: 'simulated', reasonCode: 'simulated', plannedAction: 'move_quarantine' },
    ]);
    expect(await actionsOfCopy(fx, simulated.copies[0]!.id)).toHaveLength(0);
    expect(
      await fx.prisma.apiClawback.findUniqueOrThrow({ where: { id: simClawback.id } }),
    ).toMatchObject({ status: 'completed', targetsSimulated: 1 });
    await fx.prisma.apiRemediationPolicy.deleteMany({ where: { organizationId: org.id } });
    comps.policies.invalidate();

    await fx.prisma.apiModeConnection.update({
      where: { id: conn.apiConnectionId },
      data: { remediationPaused: true },
    });
    try {
      const paused = await cleanCopy([DREW]);
      await comps.copies.handle(
        lateSignal(fx, org.id, {
          messageId: paused.message.id.toString(),
          receivedAt: paused.message.receivedAt.toISOString(),
          signalAt: clock.now(),
        }),
      );
      const pausedClawback = (await clawbacksOf(org.id)).at(-1)!;
      for (let i = 0; i < 4; i++) {
        clock.advance(6_000);
        await comps.clawback.tick();
        await comps.remediation!.tick();
      }
      const [target] = await targetsOf(pausedClawback.id);
      expect(target).toMatchObject({ status: 'queued', plannedAction: 'move_quarantine' });
      const action = await fx.prisma.apiRemediationAction.findUniqueOrThrow({
        where: { id: target!.actionId! },
      });
      expect(action).toMatchObject({ status: 'pending', trigger: 'clawback', attempts: 0 });
      expect(action.nextAttemptAt!.getTime()).toBeGreaterThan(clock.ms());
      expect(
        await fx.prisma.apiClawback.findUniqueOrThrow({ where: { id: pausedClawback.id } }),
      ).toMatchObject({ status: 'running' });
      // C13: the clawback waits for more than the warn threshold.
      clock.advance(61 * 60_000);
      await comps.health.runOnce();
      const health = await fx.prisma.apiModeConnection.findUniqueOrThrow({
        where: { id: conn.apiConnectionId },
      });
      const checks = (health.healthChecks as { checks: { code: string; status: string }[] }).checks;
      expect(checks.find((c) => c.code === 'clawback.stalled')?.status).toBe('warn');
      expect(checks.find((c) => c.code === 'reports.backlog')?.status).toBe('pass');
    } finally {
      await fx.prisma.apiModeConnection.update({
        where: { id: conn.apiConnectionId },
        data: { remediationPaused: false },
      });
    }
    clock.advance(6 * 60_000);
    await settle(comps, clock);
    const last = (await clawbacksOf(org.id)).at(-1)!;
    expect(last.status).toBe('completed');
  });

  it('review_required above the automatic cap or with auto_clawback = review, with the approval alert', async () => {
    await fx.prisma.apiModeOrgSetting.create({
      data: { organizationId: org.id, autoMaxMailboxes: 1 },
    });
    try {
      const capped = await cleanCopy([ALEX, BLAKE], { deliver: false });
      await comps.copies.handle(
        lateSignal(fx, org.id, {
          messageId: capped.message.id.toString(),
          receivedAt: capped.message.receivedAt.toISOString(),
          signalAt: clock.now(),
        }),
      );
      const cap = (await clawbacksOf(org.id)).at(-1)!;
      clock.advance(1);
      await comps.clawback.tick();
      const review = await fx.prisma.apiClawback.findUniqueOrThrow({ where: { id: cap.id } });
      expect(review).toMatchObject({ status: 'review_required', mailboxesEligible: 2 });
      expect(review.approvalReasons).toEqual(['auto_cap']);
      // Nothing is queued before an administrator submits and a second user approves.
      clock.advance(6_000);
      await comps.clawback.tick();
      expect(await fx.prisma.apiRemediationAction.count({ where: { clawbackId: cap.id } })).toBe(0);
      const alerts = await fx.prisma.messageOutbox.findMany({
        where: { organizationId: org.id, eventType: 'notification.alert_requested.v1' },
      });
      const approval = alerts.filter(
        (a) => (a.payload as { kind: string }).kind === 'api_mode_purge_approval',
      );
      expect(approval).toHaveLength(1);
      expect(approval[0]!.payload).toMatchObject({
        severity: 'medium',
        refs: { clawbackId: cap.publicId },
      });

      await fx.prisma.apiModeOrgSetting.update({
        where: { organizationId: org.id },
        data: { autoMaxMailboxes: 500, autoClawback: 'review' },
      });
      const reviewed = await cleanCopy([CASEY], { deliver: false });
      await comps.copies.handle(
        lateSignal(fx, org.id, {
          messageId: reviewed.message.id.toString(),
          receivedAt: reviewed.message.receivedAt.toISOString(),
          signalAt: clock.now(),
        }),
      );
      const always = (await clawbacksOf(org.id)).at(-1)!;
      clock.advance(1);
      await comps.clawback.tick();
      const second = await fx.prisma.apiClawback.findUniqueOrThrow({ where: { id: always.id } });
      expect(second).toMatchObject({ status: 'review_required', approvalReasons: null });
    } finally {
      await fx.prisma.apiModeOrgSetting.delete({ where: { organizationId: org.id } });
    }
  });

  it('hybrid copies linked to their inline message are acted on with copy authority', async () => {
    const hybrid = await fx.organization('hybrid');
    const domain = `hy-${S}.it-apiclaw.example`;
    await fx.domain(hybrid, domain, 'hybrid');
    const hconn = await fx.connection(hybrid, 'microsoft_365', {
      tenantId: `tenant-hybrid-${S}`,
      domains: [domain],
    });
    const hsource = await fx.journalSource(hybrid, hconn);
    const to = `jo@${domain}`;
    const messageId = `${crypto.randomUUID()}@sender.example`;
    await fx.gatewayMessage(hybrid, {
      messageId,
      recipient: to,
      receivedAt: clock.now(),
      finalVerdict: 'clean',
    });
    const seed = await cleanCopy([to], {
      organization: hybrid,
      source: hsource,
      deliver: false,
      messageId,
    });
    expect(seed.copies[0]).toMatchObject({ verdictAuthority: 'inline' });
    await comps.copies.handle(
      lateSignal(fx, hybrid.id, {
        messageId: seed.message.id.toString(),
        receivedAt: seed.message.receivedAt.toISOString(),
        signalAt: clock.now(),
      }),
    );
    const [clawback] = await clawbacksOf(hybrid.id);
    clock.advance(1);
    await comps.clawback.tick();
    clock.advance(6_000);
    await comps.clawback.tick();
    const [target] = await targetsOf(clawback!.id);
    expect(target).toMatchObject({ status: 'queued', plannedAction: 'move_quarantine' });
    const action = await fx.prisma.apiRemediationAction.findUniqueOrThrow({
      where: { id: target!.actionId! },
    });
    expect(action).toMatchObject({ trigger: 'clawback', status: 'pending' });
    expect((action.decision as { inputs: { verdictAuthority: string } }).inputs).toMatchObject({
      verdictAuthority: 'copy',
    });
  });
});

describe('threat-intelligence sweep (C2.2)', () => {
  it('platform and organization indicators, confidence floor, signatures, cursor resume', async () => {
    // A second API-active organization without the URL.
    const quiet = await fx.organization('quiet');
    const quietDomain = `qt-${S}.it-apiclaw.example`;
    await fx.domain(quiet, quietDomain, 'api');
    const qconn = await fx.connection(quiet, 'microsoft_365', {
      tenantId: `tenant-quiet-${S}`,
      domains: [quietDomain],
    });
    const qsource = await fx.journalSource(quiet, qconn);
    const urlHash = hex(`url-${S}`);
    const fileHash = hex(`ti-file-${S}`);
    const sigHash = hex(`sig-${S}`);
    const withUrl = await cleanCopy([ALEX], { urlSha256: urlHash });
    const withFile = await cleanCopy([BLAKE], { attachmentSha256: fileHash });
    const withSig = await cleanCopy([CASEY], { attachmentSha256: sigHash });
    // The quiet organization has the file hash too (an org indicator of `org` must not reach it).
    await cleanCopy([`kim@${quietDomain}`], {
      organization: quiet,
      source: qsource,
      deliver: false,
      attachmentSha256: fileHash,
    });
    const sweep = () =>
      new TiSweep({
        prisma: fx.prisma,
        metrics: null,
        logger: silent,
        now: clock.now,
        config: { batch: 2, maxTargets: 20_000 },
        cursorPrefix: `it-${S}:`,
        organizationIds: fx.organizationIds,
      });
    // The first run starts at the default lookback: older rows are never swept.
    const old = new Date(clock.ms() - 30 * 86_400_000);
    const created = new Date(clock.ms() - 1000);
    const indicator = (input: {
      organizationId: bigint | null;
      type: 'url' | 'file_sha256';
      value: string;
      valueSha256: string;
      confidence: number;
      createdAt?: Date;
    }) =>
      fx.prisma.threatIndicator.create({
        data: {
          organizationId: input.organizationId,
          indicatorType: input.type,
          value: input.value,
          valueSha256: input.valueSha256,
          source: TI_SOURCE,
          severity: 'high',
          confidence: input.confidence,
          category: 'phishing',
          firstSeenAt: created,
          lastSeenAt: created,
          createdAt: input.createdAt ?? created,
        },
      });
    await indicator({
      organizationId: null,
      type: 'url',
      value: 'https://phish.example/old',
      valueSha256: hex(`old-${S}`),
      confidence: 95,
      createdAt: old,
    });
    const platform = await indicator({
      organizationId: null,
      type: 'url',
      value: 'https://phish.example/login',
      valueSha256: urlHash,
      confidence: 90,
    });
    await indicator({
      organizationId: null,
      type: 'url',
      value: 'https://phish.example/weak',
      valueSha256: hex(`weak-${S}`),
      confidence: 60,
    });
    const own = await indicator({
      organizationId: org.id,
      type: 'file_sha256',
      value: fileHash,
      valueSha256: hex(`own-${S}`),
      confidence: 85,
    });
    const before = (await clawbacksOf(org.id)).length;
    const first = await sweep().runOnce();
    expect(first.created).toBe(2);
    const created1 = (await clawbacksOf(org.id)).slice(before);
    expect(created1.map((c) => c.trigger)).toEqual(['threat_intel', 'threat_intel']);
    expect(created1.map((c) => c.signalKey).sort()).toEqual(
      [
        clawbackSignalKey(org.id, { source: 'ti', table: 'threat_indicators', rowId: platform.id }),
        clawbackSignalKey(org.id, { source: 'ti', table: 'threat_indicators', rowId: own.id }),
      ].sort(),
    );
    expect(await clawbacksOf(quiet.id)).toHaveLength(0);
    // Confidence 90 → hb.clawback.threat_intel (C3.1), category phishing → phishing.
    const urlClawback = created1.find(
      (c) =>
        c.signalKey ===
        clawbackSignalKey(org.id, { source: 'ti', table: 'threat_indicators', rowId: platform.id }),
    )!;
    expect(urlClawback.signalVerdict).toBe('phishing');
    expect(urlClawback.signalLevel).toBe('high');

    // Restart: a new sweep resumes after the stored cursor (nothing replayed).
    const cursor = await fx.prisma.apiModeCursor.findUniqueOrThrow({
      where: { name: `it-${S}:ti:threat_indicators` },
    });
    expect(cursor.position).toMatchObject({ id: expect.any(String) as string });
    expect((await sweep().runOnce()).created).toBe(0);
    await fx.prisma.malwareSignature.create({
      data: {
        sha256: sigHash,
        severity: 'high',
        source: TI_SOURCE,
        firstSeenAt: clock.now(),
        lastSeenAt: clock.now(),
      },
    });
    const third = await sweep().runOnce();
    expect(third.created).toBe(1);
    const sig = (await clawbacksOf(org.id)).at(-1)!;
    expect(sig).toMatchObject({ trigger: 'threat_intel', signalVerdict: 'malware' });
    // The clawbacks then run like any other: materialized and executed.
    await settle(comps, clock);
    for (const c of await clawbacksOf(org.id)) {
      if (c.trigger !== 'threat_intel') continue;
      expect(['completed', 'completed_with_errors']).toContain(c.status);
    }
    expect((await copiesOf(fx, withUrl.message.id))[0]!.remediationState).not.toBe('none');
    expect((await copiesOf(fx, withFile.message.id))[0]!.remediationState).not.toBe('none');
    expect((await copiesOf(fx, withSig.message.id))[0]!.remediationState).not.toBe('none');
  });
});
