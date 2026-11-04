import { expect } from 'vitest';
import { waitFor } from './compose';
import { clearSinkDomain, sinkFiles } from './mail-sink';
import {
  exactlyOnceProblems,
  LiveBroker,
  metricLines,
  MIME_LEDGER,
  pipelineCounts,
  QUEUES,
  record,
  waitForPipeline,
  type PipelineCounts,
} from './messaging-stack';
import { MAIL_SINK_HOST } from './routing';
import type { FixtureDomain, SmtpFixtures } from './smtp-fixtures';
import { smtpSource } from './smtp-tools';

/**
 * One chaos scenario of the step 3.2 stack suites (docs/plan/steps/07-rabbitmq.md §10): `n`
 * single-recipient messages sent through the gateway MX with Postfix's smtp-source while `chaos`
 * disturbs one component, then the exactly-once assertions for every stage, an unchanged
 * dead-letter queue and `n` files in the sink mailbox.
 */
export interface ScenarioProgress {
  /** Resolves once at least `k` messages of the run are stored (`email_messages`). */
  stored(k: number): Promise<void>;
  /** Resolves once at least `k` messages are parsed (MIME ledger rows). */
  parsed(k: number): Promise<void>;
  /** Resolves once at least `k` approvals are planned (planner ledger rows). */
  planned(k: number): Promise<void>;
  counts(): Promise<PipelineCounts>;
}

export class MessagingScenario {
  org = 0n;
  domain!: FixtureDomain;
  broker!: LiveBroker;

  constructor(
    readonly suite: string,
    readonly fx: SmtpFixtures,
  ) {}

  get recipient(): string {
    return `load@${this.domain.name}`;
  }

  /** Fixture organization and domain (destination: mail-sink) and the admin connection. */
  async setup(label: string): Promise<void> {
    this.org = await this.fx.organization(label);
    this.domain = await this.fx.domain(this.org, label);
    await this.fx.destinations(this.domain, [{ host: MAIL_SINK_HOST, tlsMode: 'opportunistic' }]);
    this.broker = await LiveBroker.connect();
  }

  async teardown(): Promise<void> {
    if (this.domain) await clearSinkDomain(this.domain.name).catch(() => undefined);
    await this.broker?.close().catch(() => undefined);
    await this.fx.cleanup();
  }

  progress(): ScenarioProgress {
    const prisma = this.fx.prisma;
    const org = this.org;
    const ledgerOf = async (consumer: string, eventType: string) => {
      const events = await prisma.messageOutbox.findMany({
        where: { organizationId: org, eventType },
        select: { eventId: true },
      });
      return prisma.messageIdempotency.count({
        where: { consumer, eventId: { in: events.map((e) => e.eventId) } },
      });
    };
    const until = async (what: string, check: () => Promise<boolean>, timeoutMs: number) => {
      await waitFor(what, async () => (await check()) || undefined, { timeoutMs, intervalMs: 250 });
    };
    return {
      stored: (k) =>
        until(
          `${k} stored messages`,
          async () => (await prisma.emailMessage.count({ where: { organizationId: org } })) >= k,
          300_000,
        ),
      parsed: (k) =>
        until(
          `${k} parsed messages`,
          async () => (await ledgerOf(MIME_LEDGER, 'mail.message.received.v1')) >= k,
          300_000,
        ),
      planned: (k) =>
        until(
          `${k} planned approvals`,
          async () => (await ledgerOf('delivery-worker.planner', 'mail.delivery.approved.v1')) >= k,
          600_000,
        ),
      counts: () => pipelineCounts(prisma, [org]),
    };
  }

  /**
   * Sends `n` messages over `sessions` SMTP sessions, runs `chaos` concurrently, waits for the
   * whole pipeline and asserts exactly-once effects. Returns the final counts.
   */
  async run(options: {
    n: number;
    sessions?: number;
    chaos: (progress: ScenarioProgress) => Promise<void>;
    timeoutMs?: number;
  }): Promise<PipelineCounts> {
    const { n } = options;
    const deadLettersBefore = await this.broker.depth(QUEUES.deadLetter);
    const redeliveredBefore = await redelivered();
    const started = Date.now();
    const sending = smtpSource({
      target: 'postfix:25',
      sessions: options.sessions ?? 10,
      messages: n,
      from: 'load@example.org',
      to: this.recipient,
      length: 1024,
      subject: `${this.suite} ${this.fx.suffix}`,
    });
    const progress = this.progress();
    const chaos = options.chaos(progress);
    const [sent] = await Promise.all([sending, chaos]);
    expect(sent.exitCode, `${sent.stdout}${sent.stderr}`).toBe(0);
    const sentAfterMs = Date.now() - started;

    const counts = await waitForPipeline(
      this.fx.prisma,
      [this.org],
      n,
      options.timeoutMs ?? 900_000,
    );
    const doneAfterMs = Date.now() - started;
    // Settle: nothing late may add a second effect (a redelivery still in flight, a re-drive).
    await new Promise((r) => setTimeout(r, 5_000));
    const settled = await pipelineCounts(this.fx.prisma, [this.org]);
    expect(exactlyOnceProblems(settled, n)).toEqual([]);
    expect(await this.broker.depth(QUEUES.deadLetter)).toBe(deadLettersBefore);
    // Delivered exactly once to the destination mailbox.
    expect(await sinkFiles(this.recipient)).toHaveLength(n);
    const redeliveredAfter = await redelivered();
    record(this.suite, {
      messages: n,
      smtp_accepted_s: (sentAfterMs / 1000).toFixed(1),
      delivered_all_s: (doneAfterMs / 1000).toFixed(1),
      parses: settled.parses,
      mime_ledger: settled.mimeLedger,
      approvals: settled.approvals,
      planner_ledger: settled.plannerLedger,
      deliveries: settled.deliveries,
      reinjections: settled.reinjections,
      unpublished: settled.unpublished,
      dead_letters_added: 0,
      // The counter restarts with the worker process (consumer-crash suite) and cannot be read
      // while the worker is paused (backlog suite): then the process total is reported.
      email_received_redelivered:
        redeliveredAfter === undefined
          ? 'n/a'
          : redeliveredBefore !== undefined && redeliveredAfter >= redeliveredBefore
            ? redeliveredAfter - redeliveredBefore
            : `${redeliveredAfter} (process total)`,
    });
    return counts;
  }
}

/** `amqp_consumer_deliveries_total{queue="email.received",redelivered="true"}` of the worker. */
async function redelivered(): Promise<number | undefined> {
  try {
    const lines = await metricLines('email-worker', 'amqp_consumer_deliveries_total');
    return lines
      .filter((l) => l.includes('queue="email.received"') && l.includes('redelivered="true"'))
      .reduce((sum, l) => sum + Number(l.split(' ').at(-1)), 0);
  } catch {
    return undefined;
  }
}
