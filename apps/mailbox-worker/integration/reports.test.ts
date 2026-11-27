import { GetObjectCommand } from '@aws-sdk/client-s3';
import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';
import {
  microsoftDirectory,
  MS_DOMAIN,
  MS_TENANT_ID,
  rfc5322Date,
  startSimulators,
  syntheticEml,
  type RunningSimulators,
} from '@email-gateway/idp-adapters/testing';
import { copyMessageIdHash } from '@email-gateway/mailbox-api';
import { M365_MAILBOX_REMEDIATION_PROFILE } from '@email-gateway/provider-integrations';
import type { MailboxComponents } from '../src/components';
import { reportIngestKey } from '../src/reports/report-original.repository';
import { adminClawback, clawbackConfig, user } from './support/clawback';
import {
  Clock,
  Fixtures,
  SimAccessTokens,
  type TestConnection,
  type TestOrg,
} from './support/harness';
import { actionsOfCopy, cancelOpenActions, copiesOf, riskRow } from './support/remediation';

/**
 * Design note 37 §9.3 (mailbox-worker, reported phishing; C9–C11, ADR-0104): report intake by the
 * copies role (an internal journal copy to the report mailbox → a report row, no remediation;
 * also with internal mail off; duplicates create nothing), the `reports` role (forward-as-
 * attachment original found by Message-ID → `pending_triage` with the original's scan and the
 * assessment; an original not in the tenant ingested as a `mailbox_api` registry message → its
 * `copy_scanned` → `pending_triage`; an inline forward matched by sender + subject; no original →
 * the report copy's own scan; an external reporter rejected without feedback; the per-reporter
 * rate limit), the acknowledgement outbox row and the throttled `api_mode_report_received` alert,
 * the `reports.backlog` health check, retention of terminal reports and clawbacks, counters.
 * Synthetic `it-apiclaw-*` organizations only.
 */
const fx = new Fixtures('it-apiclaw');
const clock = new Clock();
const S = fx.suffix;
let sims: RunningSimulators;
let comps: MailboxComponents;
let limited: MailboxComponents;
let org: TestOrg;
let conn: TestConnection;
let sourceId: bigint;
const ALEX = `alex@${MS_DOMAIN}`;
const BLAKE = `blake@${MS_DOMAIN}`;
const CASEY = `casey@${MS_DOMAIN}`;
const REPORT = `drew@${MS_DOMAIN}`;
let scan = 70_000n;

/** A journal copy of `eml` to `recipients`, scanned with `verdict`, handled by the copies role. */
async function journal(
  eml: string,
  input: {
    recipients: string[];
    from: string;
    messageId: string;
    verdict?: 'clean' | 'malware' | 'phishing';
    subject?: string;
  },
) {
  const message = await fx.journalCopy(org, sourceId, {
    eml,
    recipients: input.recipients,
    messageId: input.messageId,
    from: input.from,
    receivedAt: clock.now(),
  });
  if (input.subject) {
    await fx.prisma.emailMessage.updateMany({
      where: { id: message.id },
      data: { subject: input.subject },
    });
  }
  const verdict = input.verdict ?? 'clean';
  const threat = verdict !== 'clean';
  scan += 1n;
  await riskRow(fx, org.id, message, {
    scanId: scan,
    level: threat ? 'critical' : 'none',
    verdict,
    score: threat ? 990 : 10,
    hardBlocks: threat ? ['hb.known_phishing'] : [],
  });
  const event = fx.copyScanned(org.id, message, {
    completedAt: clock.now(),
    verdict,
    riskScore: threat ? 990 : 10,
    scanId: scan.toString(),
  });
  expect(await comps.copies.handle(event)).toBe('handled');
  return { message, event, copies: await copiesOf(fx, message.id) };
}

/** A report e-mail forwarding `original` as a `message/rfc822` attachment. */
function forwardAsAttachment(original: string, input: { from: string; messageId: string }) {
  return [
    `From: Reporter <${input.from}>`,
    `To: ${REPORT}`,
    'Subject: Fwd: suspicious message',
    `Message-ID: <${input.messageId}>`,
    `Date: ${rfc5322Date(clock.now())}`,
    'MIME-Version: 1.0',
    'Content-Type: multipart/mixed; boundary="it-report-boundary"',
    '',
    '--it-report-boundary',
    'Content-Type: text/plain; charset=utf-8',
    '',
    'Please have a look at the attached message.',
    '--it-report-boundary',
    'Content-Type: message/rfc822',
    'Content-Disposition: attachment; filename="original.eml"',
    '',
    original.replace(/\r\n$/, ''),
    '--it-report-boundary--',
    '',
  ].join('\r\n');
}

/** A report e-mail with an inline (Gmail style) forward. */
function inlineForward(input: {
  from: string;
  messageId: string;
  sender: string;
  subject: string;
  date: Date;
}) {
  return [
    `From: Reporter <${input.from}>`,
    `To: ${REPORT}`,
    `Subject: Fwd: ${input.subject}`,
    `Message-ID: <${input.messageId}>`,
    'MIME-Version: 1.0',
    'Content-Type: text/plain; charset=utf-8',
    '',
    'This looks wrong.',
    '',
    '---------- Forwarded message ---------',
    `From: Billing Team <${input.sender}>`,
    `Date: ${rfc5322Date(input.date)}`,
    `Subject: ${input.subject}`,
    `To: <${input.from}>`,
    '',
    'Please pay the attached invoice today.',
    '',
  ].join('\r\n');
}

async function report(eml: string, from: string, messageId: string) {
  const sent = await journal(eml, { recipients: [REPORT], from, messageId });
  const reportCopy = sent.copies[0]!;
  const row = await fx.prisma.apiUserReport.findFirstOrThrow({
    where: { reportCopyId: reportCopy.id },
  });
  return { ...sent, reportCopy, row };
}

const reportOf = (id: bigint) => fx.prisma.apiUserReport.findUniqueOrThrow({ where: { id } });
const feedbackRows = (reportPublicId: string) =>
  fx.prisma.messageOutbox.findMany({
    where: {
      organizationId: org.id,
      eventType: 'mail.report.feedback_requested.v1',
      correlationId: `rpt:${reportPublicId}`,
    },
  });

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
  const tokens = new SimAccessTokens(() => sims, clock);
  comps = fx.components(clawbackConfig(fx, sims), { clock, tokens });
  limited = fx.components(
    clawbackConfig(fx, sims, { API_MODE_REPORTS_PER_REPORTER_PER_HOUR: '2' }),
    { clock, tokens },
  );
  org = await fx.organization('reports');
  await fx.domain(org, MS_DOMAIN, 'api');
  conn = await fx.connection(org, 'microsoft_365', {
    tenantId: MS_TENANT_ID,
    domains: [MS_DOMAIN],
  });
  tokens.directories.set(conn.providerConnectionPublicId, MS_TENANT_ID);
  sourceId = await fx.journalSource(org, conn);
  expect((await comps.inventory!.run(conn.apiConnectionId)).result).toBe('ok');
  await fx.prisma.apiMailbox.updateMany({
    where: { organizationId: org.id, primaryAddress: REPORT },
    data: { reportMailbox: true, reportMailboxAt: clock.now() },
  });
  await user(fx, org.id, ALEX);
});

beforeEach(async () => {
  await cancelOpenActions(fx, fx.organizationIds);
});

afterAll(async () => {
  await sims?.stop();
  await fx.cleanup();
});

describe('report intake by the copies role (C9.2)', () => {
  it('an internal journal copy to the report mailbox becomes a report and is never remediated', async () => {
    const original = syntheticEml({ messageId: `${crypto.randomUUID()}@evil.example`, to: [ALEX] });
    const id = `${crypto.randomUUID()}@${MS_DOMAIN}`;
    // The report copy itself scans as phishing (it contains the forwarded message).
    const sent = await journal(forwardAsAttachment(original, { from: ALEX, messageId: id }), {
      recipients: [REPORT],
      from: ALEX,
      messageId: id,
      verdict: 'phishing',
    });
    expect(sent.copies).toHaveLength(1);
    expect(sent.copies[0]).toMatchObject({ direction: 'internal', remediationState: 'none' });
    expect(await actionsOfCopy(fx, sent.copies[0]!.id)).toHaveLength(0);
    const row = await fx.prisma.apiUserReport.findFirstOrThrow({
      where: { reportCopyId: sent.copies[0]!.id },
    });
    expect(row).toMatchObject({
      status: 'received',
      reporterAddress: ALEX,
      apiConnectionId: conn.apiConnectionId,
      reportMessageId: sent.message.id,
      ackFeedback: 'none',
    });
    expect(row.reportedAt.getTime()).toBe(sent.message.receivedAt.getTime());
    // Redelivery creates nothing.
    expect(await comps.copies.handle(sent.event)).toBe('duplicate');
    expect(
      await fx.prisma.apiUserReport.count({ where: { reportCopyId: sent.copies[0]!.id } }),
    ).toBe(1);
    // With internal mail off, a report mailbox still records internal reports.
    await fx.prisma.apiModeOrgSetting.create({
      data: { organizationId: org.id, internalMailEnabled: false },
    });
    try {
      const id2 = `${crypto.randomUUID()}@${MS_DOMAIN}`;
      const second = await journal(forwardAsAttachment(original, { from: CASEY, messageId: id2 }), {
        recipients: [REPORT, BLAKE],
        from: CASEY,
        messageId: id2,
      });
      expect(second.copies).toHaveLength(1);
      expect(
        await fx.prisma.apiUserReport.count({ where: { reportCopyId: second.copies[0]!.id } }),
      ).toBe(1);
    } finally {
      await fx.prisma.apiModeOrgSetting.delete({ where: { organizationId: org.id } });
    }
    await comps.counters.flush(fx.organizationIds);
    const counters = await fx.prisma.apiModeCounter.findMany({
      where: { apiConnectionId: conn.apiConnectionId },
    });
    expect(counters.reduce((n, c) => n + c.reportsReceived, 0)).toBeGreaterThanOrEqual(2);
    // Leave the received reports processed (they are not part of later assertions).
    await comps.reports.tick();
  });
});

describe('the reports role (C10)', () => {
  it('a forward-as-attachment original found by Message-ID → pending_triage, ack and alert', async () => {
    const originalId = `${crypto.randomUUID()}@evil.example`;
    const originalEml = syntheticEml({
      messageId: originalId,
      from: 'phisher@evil.example',
      to: [ALEX],
    });
    const original = await journal(originalEml, {
      recipients: [ALEX],
      from: 'phisher@evil.example',
      messageId: originalId,
      verdict: 'phishing',
    });
    const id = `${crypto.randomUUID()}@${MS_DOMAIN}`;
    const sent = await report(
      forwardAsAttachment(originalEml, { from: ALEX, messageId: id }),
      ALEX,
      id,
    );
    await comps.reports.tick();
    const done = await reportOf(sent.row.id);
    const hash = copyMessageIdHash(org.id, `<${originalId}>`);
    expect(done).toMatchObject({
      status: 'pending_triage',
      identification: 'attachment',
      originalMessageIdHash: hash,
      groupKey: hash,
      originalCopyId: original.copies[0]!.id,
      originalMessageId: original.message.id,
      originalIngested: false,
      scanVerdict: 'phishing',
      scanLevel: 'critical',
      assessment: 'malicious',
      ackFeedback: 'queued',
    });
    expect(done.reporterMailboxId).not.toBeNull();
    expect(done.reporterUserId).not.toBeNull();
    expect(done.original).toMatchObject({ v: 1, sender: 'phisher@evil.example' });
    const feedback = await feedbackRows(done.publicId);
    expect(feedback).toHaveLength(1);
    expect(feedback[0]!.payload).toMatchObject({ reportId: done.publicId, kind: 'received' });
    const alerts = await fx.prisma.messageOutbox.findMany({
      where: { organizationId: org.id, eventType: 'notification.alert_requested.v1' },
    });
    expect(
      alerts.filter((a) => (a.payload as { kind: string }).kind === 'api_mode_report_received'),
    ).toHaveLength(1);
  });

  it('an original not in the tenant is ingested, scanned (copy_scanned) and reaches triage', async () => {
    const originalId = `${crypto.randomUUID()}@evil.example`;
    const originalEml = syntheticEml({
      messageId: originalId,
      from: 'unknown-sender@evil.example',
      to: [ALEX],
    });
    const id = `${crypto.randomUUID()}@${MS_DOMAIN}`;
    const sent = await report(
      forwardAsAttachment(originalEml, { from: ALEX, messageId: id }),
      ALEX,
      id,
    );
    await comps.reports.tick();
    const scanning = await reportOf(sent.row.id);
    expect(scanning).toMatchObject({
      status: 'scanning',
      identification: 'attachment',
      originalIngested: true,
      ackFeedback: 'queued',
    });
    const message = await fx.prisma.emailMessage.findFirstOrThrow({
      where: { id: scanning.originalMessageId!, receivedAt: scanning.originalReceivedAt! },
    });
    expect(message).toMatchObject({
      organizationId: org.id,
      ingestSource: 'mailbox_api',
      internetMessageId: `<${originalId}>`,
      headerFrom: 'unknown-sender@evil.example',
      status: 'persisted',
    });
    const identity = await fx.prisma.messageIdentity.findFirstOrThrow({
      where: { id: message.id },
    });
    expect(identity.ingestKey).toBe(reportIngestKey(scanning.publicId));
    expect(
      await fx.prisma.emailRecipient.findMany({ where: { messageId: message.id } }),
    ).toMatchObject([{ address: ALEX, status: 'journaled' }]);
    const received = await fx.prisma.emailEvent.findFirstOrThrow({
      where: { messageId: message.id, eventType: 'received' },
    });
    expect(received.details).toMatchObject({ userReport: { reportId: scanning.publicId } });
    const outbox = await fx.prisma.messageOutbox.findFirstOrThrow({
      where: { aggregateId: message.id.toString(), eventType: 'mail.message.received.v1' },
    });
    expect(outbox.payload).toMatchObject({ ingestSource: 'mailbox_api', recipientCount: 1 });
    const object = await fx.s3.send(
      new GetObjectCommand({ Bucket: fx.bucket, Key: message.emlObjectKey }),
    );
    expect(await object.Body!.transformToString()).toContain(originalId);
    // No copy row was written for the original (C10.4).
    expect(await copiesOf(fx, message.id)).toHaveLength(0);

    // The email-worker's detect-mode scan of the original.
    scan += 1n;
    await riskRow(fx, org.id, message, {
      scanId: scan,
      level: 'high',
      verdict: 'phishing',
      score: 800,
    });
    await comps.copies.handle(
      fx.copyScanned(
        org.id,
        { id: message.id, publicId: identity.publicId, receivedAt: message.receivedAt },
        {
          completedAt: clock.now(),
          ingestSource: 'mailbox_api',
          verdict: 'phishing',
          riskScore: 800,
          scanId: scan.toString(),
        },
      ),
    );
    expect(await reportOf(sent.row.id)).toMatchObject({
      status: 'pending_triage',
      scanVerdict: 'phishing',
      scanRiskScore: 800,
      scanLevel: 'high',
      assessment: 'suspicious',
    });
  });

  it('an ingested original whose scan never arrives reaches triage after the scan timeout', async () => {
    const originalId = `${crypto.randomUUID()}@evil.example`;
    const originalEml = syntheticEml({
      messageId: originalId,
      from: 'lost-scan@evil.example',
      to: [ALEX],
    });
    const id = `${crypto.randomUUID()}@${MS_DOMAIN}`;
    const sent = await report(
      forwardAsAttachment(originalEml, { from: ALEX, messageId: id }),
      ALEX,
      id,
    );
    await comps.reports.tick();
    const scanning = await reportOf(sent.row.id);
    const timeoutMs = comps.config.API_MODE_REPORT_SCAN_TIMEOUT_MINUTES * 60_000;
    expect(scanning).toMatchObject({ status: 'scanning', originalIngested: true });
    expect(scanning.nextAttemptAt!.getTime()).toBe(clock.ms() + timeoutMs);

    // Before the deadline nothing changes.
    clock.advance(timeoutMs - 1_000);
    await comps.reports.tick();
    expect(await reportOf(sent.row.id)).toMatchObject({ status: 'scanning' });

    // The copy_scanned event of the original is lost: past the deadline the report copy's own
    // scan (clean) is used and the report can be triaged.
    clock.advance(2_000);
    await comps.reports.tick();
    const overdue = await reportOf(sent.row.id);
    expect(overdue).toMatchObject({
      status: 'pending_triage',
      lastErrorCode: 'original_scan_timeout',
      scanVerdict: 'clean',
      nextAttemptAt: null,
    });
    expect(overdue.rowVersion).toBeGreaterThan(scanning.rowVersion);

    // A scan that still arrives later updates the facts; the report stays open for triage.
    const message = await fx.prisma.emailMessage.findFirstOrThrow({
      where: { id: overdue.originalMessageId!, receivedAt: overdue.originalReceivedAt! },
    });
    const identity = await fx.prisma.messageIdentity.findFirstOrThrow({
      where: { id: message.id },
    });
    scan += 1n;
    await riskRow(fx, org.id, message, {
      scanId: scan,
      level: 'critical',
      verdict: 'phishing',
      score: 950,
      hardBlocks: ['hb.known_phishing'],
    });
    await comps.copies.handle(
      fx.copyScanned(
        org.id,
        { id: message.id, publicId: identity.publicId, receivedAt: message.receivedAt },
        {
          completedAt: clock.now(),
          ingestSource: 'mailbox_api',
          verdict: 'phishing',
          riskScore: 950,
          scanId: scan.toString(),
        },
      ),
    );
    expect(await reportOf(sent.row.id)).toMatchObject({
      status: 'pending_triage',
      lastErrorCode: null,
      scanVerdict: 'phishing',
      scanRiskScore: 950,
      scanLevel: 'critical',
    });
  });

  it('an inline forward is matched by sender and subject; no original uses the report copy scan', async () => {
    const sender = `billing-${S}@evil.example`;
    const subject = `Invoice ${S}`;
    const originalId = `${crypto.randomUUID()}@evil.example`;
    const original = await journal(
      syntheticEml({ messageId: originalId, from: sender, to: [CASEY] }),
      {
        recipients: [CASEY],
        from: sender,
        messageId: originalId,
        subject,
        verdict: 'phishing',
      },
    );
    const id = `${crypto.randomUUID()}@${MS_DOMAIN}`;
    const inline = await report(
      inlineForward({ from: CASEY, messageId: id, sender, subject, date: clock.now() }),
      CASEY,
      id,
    );
    const plainId = `${crypto.randomUUID()}@${MS_DOMAIN}`;
    const plain = await report(
      syntheticEml({ messageId: plainId, from: CASEY, to: [REPORT], body: 'Is this spam?' }),
      CASEY,
      plainId,
    );
    await comps.reports.tick();
    expect(await reportOf(inline.row.id)).toMatchObject({
      status: 'pending_triage',
      identification: 'inline',
      originalCopyId: original.copies[0]!.id,
      scanVerdict: 'phishing',
      assessment: 'malicious',
    });
    expect(await reportOf(plain.row.id)).toMatchObject({
      status: 'pending_triage',
      identification: 'none',
      originalCopyId: null,
      scanVerdict: 'clean',
      assessment: 'clean',
    });
  });

  it('an external reporter is rejected without feedback; the per-reporter rate limit applies', async () => {
    const id = `${crypto.randomUUID()}@partner-org.example`;
    const external = await report(
      syntheticEml({ messageId: id, from: 'outsider@partner-org.example', to: [REPORT] }),
      'outsider@partner-org.example',
      id,
    );
    expect(external.reportCopy.direction).toBe('inbound');
    await comps.reports.tick();
    const rejected = await reportOf(external.row.id);
    expect(rejected).toMatchObject({
      status: 'rejected',
      rejectReason: 'external_reporter',
      ackFeedback: 'skipped',
    });
    expect(await feedbackRows(rejected.publicId)).toHaveLength(0);

    const rows = [];
    for (let i = 0; i < 3; i++) {
      const rid = `${crypto.randomUUID()}@${MS_DOMAIN}`;
      rows.push(
        await report(
          syntheticEml({ messageId: rid, from: BLAKE, to: [REPORT], body: `report ${i}` }),
          BLAKE,
          rid,
        ),
      );
    }
    await limited.reports.tick();
    const statuses = await Promise.all(rows.map((r) => reportOf(r.row.id)));
    expect(statuses.map((r) => r.status)).toEqual(['pending_triage', 'pending_triage', 'rejected']);
    expect(statuses[2]).toMatchObject({ rejectReason: 'rate_limited', ackFeedback: 'skipped' });
  });
});

describe('reports health and retention (C13, §3.4)', () => {
  it('reports.backlog warns for an old pending report; terminal reports and clawbacks are pruned', async () => {
    const pending = await fx.prisma.apiUserReport.findFirstOrThrow({
      where: { organizationId: org.id, status: 'pending_triage' },
      orderBy: { id: 'asc' },
    });
    await fx.prisma.$executeRaw`
      UPDATE api_user_reports SET reported_at = ${new Date(clock.ms() - 25 * 3_600_000)}
      WHERE id = ${pending.id}`;
    await comps.health.runOnce();
    const health = await fx.prisma.apiModeConnection.findUniqueOrThrow({
      where: { id: conn.apiConnectionId },
    });
    const checks = (health.healthChecks as { checks: { code: string; status: string }[] }).checks;
    expect(checks.find((c) => c.code === 'reports.backlog')?.status).toBe('warn');

    // Retention: a resolved report and a completed clawback older than 400 days.
    const old = new Date(clock.ms() - 401 * 86_400_000);
    await fx.prisma.$executeRaw`
      UPDATE api_user_reports SET status = 'resolved', updated_at = ${old}
      WHERE id = ${pending.id}`;
    const requester = await user(fx, org.id, `it-req-${S}@${MS_DOMAIN}`);
    const clawback = await adminClawback(fx, org.id, {
      keys: { messageIdHashes: ['e'.repeat(64)] },
      now: clock.now(),
      requestedBy: requester.id,
    });
    await fx.prisma.$executeRaw`
      UPDATE api_clawbacks SET status = 'completed', completed_at = ${old}, updated_at = ${old}
      WHERE id = ${clawback.id}`;
    const report = await comps.maintenance.runOnce();
    expect(report.reports).toBeGreaterThanOrEqual(1);
    expect(report.clawbacks).toBeGreaterThanOrEqual(1);
    expect(await fx.prisma.apiUserReport.findUnique({ where: { id: pending.id } })).toBeNull();
    expect(await fx.prisma.apiClawback.findUnique({ where: { id: clawback.id } })).toBeNull();
  });
});
