import { randomUUID } from 'node:crypto';
import type { AddressInfo } from 'node:net';
import type { INestApplication } from '@nestjs/common';
import { NestFactory } from '@nestjs/core';
import { encodeEvent, uuidv7 } from '@email-gateway/common';
import {
  EventTypes,
  sandboxTaskRequestedV1,
  type EventEnvelope,
  type SandboxTaskCompletedV1,
  type SandboxTaskRequestedV1,
} from '@email-gateway/event-contracts';
import { createLogger } from '@email-gateway/logger';
import { sampleObjectKey, sealResultToken } from '@email-gateway/sandbox';
import {
  connect,
  type Channel,
  type ChannelModel,
  type ConfirmChannel,
  type GetMessage,
} from 'amqplib';
import { AppModule } from '../../src/app.module';
import { createBackend } from '../../src/backends/factory';
import { compiledAnalyzerChild } from '../../src/backends/static/child.test-support';
import { type ControllerConfig, loadControllerConfig } from '../../src/config';
import { ScratchArea } from '../../src/scratch/scratch';
import { controllerEnv, required, vhostUrl } from './env';

/**
 * The controller in-process against the Compose broker and MinIO (host run): the same startup
 * order as `main.ts` (config → factory → self-test → Nest: startup reap → consumer), listening on
 * an ephemeral port for health and metrics. The static backend spawns the real analyzer child
 * (compiled from source by swc for the run).
 */

export interface RunningController {
  app: INestApplication;
  config: Readonly<ControllerConfig>;
  url: string;
  close(): Promise<void>;
}

export async function startController(
  overrides: Record<string, string> = {},
): Promise<RunningController> {
  const config = loadControllerConfig(controllerEnv(overrides));
  const logger = createLogger({ service: 'sandbox-controller-it', level: config.LOG_LEVEL });
  const scratch = new ScratchArea(config.SANDBOX_SCRATCH_DIR);
  await scratch.init();
  const backend = createBackend(config, {
    scratch,
    logger,
    analyzerChildEntry: compiledAnalyzerChild(),
  });
  const selfTest = await backend.selfTest(AbortSignal.timeout(60_000));
  const app = await NestFactory.create(AppModule.forRoot(config, { backend, scratch, selfTest }), {
    logger: false,
  });
  app.enableShutdownHooks();
  await app.listen(0, '127.0.0.1');
  const port = (app.getHttpServer().address() as AddressInfo).port;
  return {
    app,
    config,
    url: `http://127.0.0.1:${String(port)}`,
    close: () => app.close(),
  };
}

/** Polls `/health/ready` until it answers 200 (broker connected, backend ready, bucket reachable). */
export async function waitReady(url: string, timeoutMs = 30_000): Promise<Record<string, unknown>> {
  const deadline = Date.now() + timeoutMs;
  let last: unknown = null;
  while (Date.now() < deadline) {
    const res = await fetch(`${url}/health/ready`).catch(() => null);
    if (res?.ok) return (await res.json()) as Record<string, unknown>;
    last = res ? await res.json().catch(() => null) : null;
    await new Promise((r) => setTimeout(r, 250));
  }
  throw new Error(`controller not ready: ${JSON.stringify(last)}`);
}

/** Polls a series until `predicate` holds (metrics are updated right after the confirm). */
export async function eventuallyMetric(
  url: string,
  name: string,
  labels: string,
  predicate: (value: number) => boolean,
  timeoutMs = 5_000,
): Promise<number> {
  const deadline = Date.now() + timeoutMs;
  let value = await metric(url, name, labels);
  while (!predicate(value) && Date.now() < deadline) {
    await new Promise((r) => setTimeout(r, 100));
    value = await metric(url, name, labels);
  }
  return value;
}

/** The value of one series of `/metrics` (0 when absent). */
export async function metric(url: string, name: string, labels = ''): Promise<number> {
  const text = await (await fetch(`${url}/metrics`)).text();
  const line = text.split('\n').find((l) => l.startsWith(`${name}{`) && l.includes(labels));
  return line ? Number(line.split(' ').pop()) : 0;
}

/**
 * The test's broker side: publishes tasks to `email.security` as the admin user with the org
 * routing key, receives results on an exclusive queue bound to the test organization's result
 * key, and removes this run's copies from the durable `scan.sandbox.results` (other messages are
 * returned untouched).
 */
export class BrokerProbe {
  private readonly results = new Map<string, EventEnvelope<SandboxTaskCompletedV1>>();
  private readonly waiters = new Map<string, (r: EventEnvelope<SandboxTaskCompletedV1>) => void>();
  private readonly taskIds = new Set<string>();
  private readonly tokenHashes = new Map<string, string>();

  private constructor(
    private readonly model: ChannelModel,
    private readonly publishChannel: ConfirmChannel,
    private readonly resultChannel: Channel,
    readonly organizationId: string,
  ) {}

  static async open(organizationId: string): Promise<BrokerProbe> {
    const model = await connect(vhostUrl(required('RABBITMQ_URL')));
    const publishChannel = await model.createConfirmChannel();
    const resultChannel = await model.createChannel();
    const probe = new BrokerProbe(model, publishChannel, resultChannel, organizationId);
    const { queue } = await resultChannel.assertQueue('', {
      exclusive: true,
      autoDelete: true,
      durable: false,
    });
    await resultChannel.bindQueue(
      queue,
      'email.security',
      `org.${organizationId}.mail.sandbox.task_completed.v1`,
    );
    await resultChannel.consume(
      queue,
      (msg) => {
        if (!msg) return;
        const envelope = JSON.parse(
          msg.content.toString('utf8'),
        ) as EventEnvelope<SandboxTaskCompletedV1>;
        resultChannel.ack(msg);
        const taskId = envelope.payload.taskId;
        const waiter = probe.waiters.get(taskId);
        if (waiter) waiter(envelope);
        else probe.results.set(taskId, envelope);
      },
      { noAck: false },
    );
    return probe;
  }

  /** A valid task for `sha256`/`detectedType`; the caller stages the sample when needed. */
  task(input: {
    sha256: string;
    sizeBytes: number;
    detectedType: string;
    deadlineMs?: number;
    taskId?: string;
  }): SandboxTaskRequestedV1 {
    const taskId = input.taskId ?? uuidv7();
    const now = Date.now();
    // The one-time result token the dispatcher would seal (X11); its hash verifies the result.
    const token = sealResultToken(required('SANDBOX_RESULT_KEY'), taskId);
    this.tokenHashes.set(taskId, token.tokenSha256);
    return sandboxTaskRequestedV1.parse({
      taskId,
      analysisId: String(BigInt(now) * 1000n + BigInt(Math.floor(Math.random() * 1000))),
      sample: {
        key: sampleObjectKey(taskId, new Date(now)),
        sha256: input.sha256,
        sizeBytes: input.sizeBytes,
        detectedType: input.detectedType,
      },
      profile: 'static',
      limits: {
        wallTimeoutMs: 60_000,
        memoryMb: 512,
        cpuMillis: 1000,
        pids: 128,
        scratchMb: 64,
        maxArtifacts: 16,
        maxArtifactBytes: 2_097_152,
        maxTotalArtifactBytes: 8_388_608,
      },
      requestedAt: new Date(now - 1000).toISOString(),
      deadlineAt: new Date(now + (input.deadlineMs ?? 600_000)).toISOString(),
      resultToken: token.sealed,
    });
  }

  /** SHA-256 of the result token sealed into `task(...)` for this task id. */
  tokenSha256(taskId: string): string {
    const hash = this.tokenHashes.get(taskId);
    if (!hash) throw new Error(`no result token for task ${taskId}`);
    return hash;
  }

  async publish(payload: SandboxTaskRequestedV1): Promise<void> {
    this.taskIds.add(payload.taskId);
    const encoded = encodeEvent(
      {
        eventId: uuidv7(),
        eventType: EventTypes.SandboxTaskRequested,
        occurredAt: new Date().toISOString(),
        correlationId: `wp2-it-${randomUUID()}`,
        organizationId: this.organizationId,
        payload,
      },
      'wp2-integration-suite',
    );
    await new Promise<void>((resolve, reject) => {
      this.publishChannel.publish(
        encoded.exchange,
        encoded.routingKey,
        encoded.content,
        encoded.options,
        (err: unknown) => (err ? reject(new Error('publish not confirmed')) : resolve()),
      );
    });
  }

  result(taskId: string, timeoutMs = 120_000): Promise<EventEnvelope<SandboxTaskCompletedV1>> {
    const ready = this.results.get(taskId);
    if (ready) return Promise.resolve(ready);
    return new Promise((resolve, reject) => {
      const timer = setTimeout(() => {
        this.waiters.delete(taskId);
        reject(new Error(`no result for task ${taskId} within ${String(timeoutMs)} ms`));
      }, timeoutMs);
      this.waiters.set(taskId, (r) => {
        clearTimeout(timer);
        this.waiters.delete(taskId);
        resolve(r);
      });
    });
  }

  /**
   * Removes this run's results from `scan.sandbox.results` (and any of its tasks still queued in
   * `scan.sandbox`): every message is fetched once; ours are acked, others returned (nack
   * requeue). Returns the number removed.
   */
  async cleanup(): Promise<number> {
    let removed = 0;
    const channel = await this.model.createChannel();
    try {
      for (const queue of ['scan.sandbox.results', 'scan.sandbox']) {
        const { messageCount } = await channel.checkQueue(queue);
        const held: GetMessage[] = [];
        for (let i = 0; i < messageCount + 5; i += 1) {
          const msg = await channel.get(queue, { noAck: false });
          if (!msg) break;
          let ours = false;
          try {
            const envelope = JSON.parse(msg.content.toString('utf8')) as EventEnvelope<{
              taskId?: string;
            }>;
            ours =
              envelope.organizationId === this.organizationId ||
              this.taskIds.has(envelope.payload?.taskId ?? '');
          } catch {
            ours = false;
          }
          if (ours) {
            channel.ack(msg);
            removed += 1;
          } else {
            held.push(msg);
          }
        }
        for (const msg of held) channel.nack(msg, false, true);
      }
    } finally {
      await channel.close().catch(() => undefined);
    }
    return removed;
  }

  /** Consumers of `scan.sandbox.results` (the email-worker's results consumer, apps profile). */
  async resultsConsumers(): Promise<number> {
    const channel = await this.model.createChannel();
    try {
      return (await channel.checkQueue('scan.sandbox.results')).consumerCount;
    } finally {
      await channel.close().catch(() => undefined);
    }
  }

  async close(): Promise<void> {
    await this.model.close().catch(() => undefined);
  }
}
