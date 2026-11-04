import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { waitFor } from './support/compose';
import { involving, listQueue, waitForQueueDrained } from './support/postfix';
import { SmtpFixtures, type FixtureDomain } from './support/smtp-fixtures';
import { assertStackReady, smtpStackGate } from './support/smtp-stack';
import { smtpSource } from './support/smtp-tools';

/**
 * Concurrency and zero loss (docs/plan/steps/04-smtp-gateway.md §9 stack suite 9): Postfix's
 * smtp-source opens SMTP_LOAD_SESSIONS parallel sessions (default 40) against the inbound MX and
 * sends SMTP_LOAD_MESSAGES messages (default 1 000) in total. Zero loss = the inbound queue is
 * empty for the fixture domain AND there are exactly as many email_messages rows and S3 objects
 * as messages sent. Duration and throughput are printed for the step's verification record.
 */
const gate = await smtpStackGate();
const fx = new SmtpFixtures();
const SESSIONS = Number(process.env.SMTP_LOAD_SESSIONS ?? 40);
const MESSAGES = Number(process.env.SMTP_LOAD_MESSAGES ?? 1_000);
let org = 0n;
let domain: FixtureDomain;

beforeAll(async () => {
  assertStackReady(gate);
  org = await fx.organization('load');
  domain = await fx.domain(org, 'load');
}, 60_000);

afterAll(async () => {
  if (gate.skip) return;
  await waitForQueueDrained('postfix', [domain.name], 300_000).catch(() => undefined);
  await fx.cleanup();
}, 600_000);

describe.skipIf(gate.skip)('SMTP stack: concurrency (suite 9)', { timeout: 900_000 }, () => {
  it(`ingests ${MESSAGES} messages over ${SESSIONS} parallel sessions with zero loss`, async () => {
    const started = Date.now();
    const result = await smtpSource({
      target: 'postfix:25',
      sessions: SESSIONS,
      messages: MESSAGES,
      from: 'load@example.org',
      to: `load@${domain.name}`,
      length: 2048,
      subject: `load ${fx.suffix}`,
    });
    const acceptedAfterMs = Date.now() - started;
    expect(result.exitCode, `${result.stdout}${result.stderr}`).toBe(0);
    expect(result.stderr).not.toMatch(/fatal|error/i);

    await waitFor(
      `${MESSAGES} stored messages`,
      async () => (await fx.messageCount(org)) >= MESSAGES,
      { timeoutMs: 480_000, intervalMs: 2_000 },
    );
    const storedAfterMs = Date.now() - started;
    await waitForQueueDrained('postfix', [domain.name], 120_000);

    expect(involving(await listQueue('postfix'), [domain.name])).toEqual([]);
    expect(await fx.messageCount(org)).toBe(MESSAGES);
    expect(await fx.prisma.messageIdentity.count({ where: { organizationId: org } })).toBe(
      MESSAGES,
    );
    expect(await fx.prisma.emailRecipient.count({ where: { organizationId: org } })).toBe(MESSAGES);
    // Step 2.3 (docs/plan/steps/05-routing.md R5, R9.1): the delivery-worker's dev pass-through
    // and recorder add `mail.delivery.*` outbox rows; ingestion's own rows are counted here.
    expect(
      await fx.prisma.messageOutbox.count({
        where: { organizationId: org, eventType: 'mail.message.received.v1' },
      }),
    ).toBe(MESSAGES);
    // Step 3.1: the email-worker adds the parsed parts under org/{id}/part/; EMLs are counted.
    expect(await fx.emlObjectKeys(org)).toHaveLength(MESSAGES);
    // Postfix queue ids are case-sensitive (base 52), but `mta_queue_id` uses the table's
    // case-insensitive collation, so a SQL GROUP BY can merge two ids that differ only in case
    // (seen: 4jKFxV5fmHz12JnW / 4jKFxV5fMHz12Jnw). Distinct ids are counted case-sensitively.
    const queueIds = await fx.prisma.emailMessage.findMany({
      where: { organizationId: org },
      select: { mtaQueueId: true },
    });
    expect(queueIds.every((m) => m.mtaQueueId !== null)).toBe(true);
    expect(new Set(queueIds.map((m) => m.mtaQueueId))).toHaveProperty('size', MESSAGES);

    const seconds = (ms: number) => (ms / 1000).toFixed(1);
    process.stdout.write(
      `[smtp-concurrency] sessions=${SESSIONS} messages=${MESSAGES} ` +
        `smtp_accept=${seconds(acceptedAfterMs)}s (${(MESSAGES / (acceptedAfterMs / 1000)).toFixed(1)} msg/s) ` +
        `stored=${seconds(storedAfterMs)}s (${(MESSAGES / (storedAfterMs / 1000)).toFixed(1)} msg/s end to end) loss=0\n`,
    );
  });
});
