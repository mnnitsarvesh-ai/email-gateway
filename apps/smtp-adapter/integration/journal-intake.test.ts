import { createHash, randomBytes, randomUUID } from 'node:crypto';
import { Test, type TestingModule } from '@nestjs/testing';
import { DatabaseModule, MetricsModule, RedisModule, S3Module } from '@email-gateway/common';
import { journalEnvelopeSchema, journalIntakeProofSchema } from '@email-gateway/archive';
import { messageReceivedV1 } from '@email-gateway/event-contracts';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { AdapterCoreModule } from '../src/app.module';
import { loadSmtpAdapterConfig } from '../src/config';
import { JournalIntakeCountersService } from '../src/journal-intake/journal-intake-counters.service';
import {
  JournalIntakeListener,
  JournalIntakeModule,
} from '../src/journal-intake/journal-intake.module';
import {
  googleWorkspaceCopy,
  m365JournalReport,
  onPremJournalReport,
  originalMessage,
} from '../src/journal-intake/testing/fixtures';
import { PolicyModule } from '../src/policy/policy.module';
import { PolicyServerService } from '../src/policy/policy-server.service';
import { ProviderRelayModule } from '../src/provider-relay/provider-relay.module';
import { SmtpSharedModule } from '../src/shared/shared.module';
import { policy } from './in-session-support/harness';
import { JournalFixtures } from './journal-intake-support/fixtures';
import { s3Config } from './support/stack';
import { deliver } from './support/lmtp-client';

/**
 * Step 8.6 §9.2 (WP3): journal intake inside the adapter end to end — policy delegation (RCPT,
 * END-OF-MESSAGE marker) → journal LMTP (re-check, unwrap, proof, S3 upload, writer commit) →
 * counter flush — against the real MySQL writer, Redis and MinIO of the .env. Synthetic
 * `it-jrnl-*` organizations and documentation addresses only; the provider egress ranges are the
 * TEST-ONLY extra ranges (APP_ENV ci). Every row, object and key is removed afterwards.
 */

const M365_CLIENT = '198.51.100.70';
const GOOGLE_CLIENT = '198.51.100.71';
const ONPREM_CLIENT = '203.0.113.25';
const DOMAIN = 'journal.gateway.test';
const sha = (b: Buffer) => createHash('sha256').update(b).digest('hex');

const fx = new JournalFixtures();
let moduleRef: TestingModule;
let policyPort: number;
let lmtpPort: number;
let org: bigint;
let orgDomain: string;
let tenantId: string;
let m365: Awaited<ReturnType<JournalFixtures['source']>>;
let google: Awaited<ReturnType<JournalFixtures['source']>>;
let onprem: Awaited<ReturnType<JournalFixtures['source']>>;
let m365b: Awaited<ReturnType<JournalFixtures['source']>>;
let tenantDomain: string;
let queueSeq = 0;

const queueId = (): string => `J${fx.suffix}${(queueSeq += 1).toString().padStart(4, '0')}`;

beforeAll(async () => {
  tenantId = randomUUID();
  org = await fx.organization('m365');
  orgDomain = `it-jrnl-${fx.suffix}.example.com`;
  const domainId = await fx.domain(org, orgDomain);
  const m365Connection = await fx.connection(org, 'microsoft_365', tenantId, domainId);
  const googleConnection = await fx.connection(
    org,
    'google_workspace',
    `C0${randomBytes(4).toString('hex')}`,
    // Google needs its own linked domain (one link per domain).
    await fx.domain(org, `g-${orgDomain}`),
  );
  m365 = await fx.source({
    organizationId: org,
    kind: 'microsoft_365_journal',
    domain: DOMAIN,
    providerConnectionId: m365Connection,
  });
  google = await fx.source({
    organizationId: org,
    kind: 'google_workspace_copy',
    domain: DOMAIN,
    providerConnectionId: googleConnection,
    status: 'active',
  });
  m365b = await fx.source({
    organizationId: org,
    kind: 'microsoft_365_journal',
    domain: DOMAIN,
    providerConnectionId: m365Connection,
    status: 'active',
  });
  // A gateway (tenant) domain of the same organization, for the mixing rule.
  tenantDomain = `t-${orgDomain}`;
  await fx.domain(org, tenantDomain, { inboundEnabled: true });
  onprem = await fx.source({
    organizationId: org,
    kind: 'exchange_onprem_journal',
    domain: DOMAIN,
    networks: ['203.0.113.0/24'],
    status: 'active',
  });

  const loaded = loadSmtpAdapterConfig({
    ...process.env,
    LOG_LEVEL: 'fatal',
    APP_ENV: 'ci',
    POLICY_HOST: '127.0.0.1',
    POLICY_PORT: String(45_000 + Math.floor(Math.random() * 2000)),
    MAIL_LISTEN_HOST: '127.0.0.1',
    JOURNAL_INTAKE_ENABLED: 'true',
    JOURNAL_INTAKE_DOMAIN: DOMAIN,
    JOURNAL_INTAKE_COUNTER_FLUSH_SECONDS: '3600',
    PROVIDER_EGRESS_EXTRA_RANGES: JSON.stringify({
      microsoft_365: [`${M365_CLIENT}/32`],
      google_workspace: [`${GOOGLE_CLIENT}/32`],
    }),
  });
  const config = { ...loaded, LMTP_JOURNAL_PORT: 0 };
  moduleRef = await Test.createTestingModule({
    imports: [
      AdapterCoreModule.forRoot(config),
      DatabaseModule.forRoot({ url: config.DATABASE_URL }),
      RedisModule.forRoot({ url: config.REDIS_URL }),
      S3Module.forRoot(s3Config()),
      MetricsModule.forRoot({ service: 'smtp-adapter-it' }),
      SmtpSharedModule,
      ProviderRelayModule,
      JournalIntakeModule.forRoot({
        config,
        listenHost: '127.0.0.1',
        internalNetworks: '127.0.0.0/8,::1/128',
        logLevel: 'silent',
      }),
      PolicyModule,
    ],
  }).compile();
  await moduleRef.init();
  policyPort = moduleRef.get(PolicyServerService).address();
  lmtpPort = moduleRef.get(JournalIntakeListener).port();
});

afterAll(async () => {
  await moduleRef?.close();
  await fx.cleanup();
});

/** The intake path as Postfix drives it: RCPT, END-OF-MESSAGE, then LMTP to :10053. */
async function journal(input: {
  client: string;
  to: string[];
  message: Buffer;
  queue?: string;
  tls?: boolean;
  instance?: string;
  /** false: policy only (a tenant recipient would go to the gateway LMTP, not tested here). */
  deliver?: boolean;
}): Promise<{ rcpt: string[]; eom: string | null; lmtp: string[]; queue: string }> {
  const queue = input.queue ?? queueId();
  const base = {
    policy_context: 'inbound',
    client_address: input.client,
    sender: 'journal-agent@example.com',
    instance: input.instance ?? `it.${randomBytes(6).toString('hex')}`,
    ...(input.tls === false ? {} : { encryption_protocol: 'TLSv1.3' }),
  };
  const rcpt: string[] = [];
  for (const recipient of input.to) {
    rcpt.push(await policy(policyPort, { ...base, recipient, size: String(input.message.length) }));
  }
  const accepted = input.to.filter((_, i) => rcpt[i] === 'DUNNO');
  if (accepted.length === 0 || input.deliver === false) return { rcpt, eom: null, lmtp: [], queue };
  const eom = await policy(policyPort, {
    ...base,
    protocol_state: 'END-OF-MESSAGE',
    queue_id: queue,
    size: String(input.message.length),
  });
  if (eom !== 'DUNNO') return { rcpt, eom, lmtp: [], queue };
  const delivery = await lmtp(queue, input.client, accepted, input.message);
  return { rcpt, eom, lmtp: delivery, queue };
}

async function lmtp(queue: string, client: string, to: string[], message: Buffer) {
  const delivery = await deliver({
    port: lmtpPort,
    lhlo: 'mx.gateway.local',
    xforward: {
      ADDR: client,
      HELO: 'mail.example.com',
      NAME: '[UNAVAILABLE]',
      PROTO: 'ESMTP',
      IDENT: queue,
      SOURCE: 'REMOTE',
    },
    from: 'journal-agent@example.com',
    to,
    message,
  });
  return [...delivery.rcpt.filter((r) => r.code !== 250), ...delivery.data].map((r) => r.text);
}

const messagesOf = (queue: string) =>
  fx.prisma.emailMessage.findMany({ where: { organizationId: org, mtaQueueId: queue } });

describe('journal intake: Microsoft 365 report end to end (D2)', () => {
  it('commits the unwrapped original with the journal envelope, BCC included', async () => {
    const original = originalMessage({
      messageId: `<m-${fx.suffix}@${orgDomain}>`,
      from: `Alice <alice@${orgDomain}>`,
      to: ['bob@example.org'],
    });
    const report = m365JournalReport({
      intakeAddress: m365.credentials.address,
      tenantId,
      original,
      encoding: 'base64',
      envelope: {
        sender: `alice@${orgDomain}`,
        messageId: `<m-${fx.suffix}@${orgDomain}>`,
        to: ['bob@example.org'],
        bcc: [`dave@${orgDomain}`],
      },
    });
    const result = await journal({
      client: M365_CLIENT,
      to: [m365.credentials.address],
      message: report,
    });
    expect(result).toMatchObject({ rcpt: ['DUNNO'], eom: 'DUNNO', lmtp: ['250 2.0.0 Ok'] });

    const [message] = await messagesOf(result.queue);
    expect(message).toMatchObject({
      ingestSource: 'journal_intake',
      status: 'persisted',
      direction: 'outbound',
      internetMessageId: `<m-${fx.suffix}@${orgDomain}>`,
      headerFrom: `alice@${orgDomain}`,
      envelopeFrom: 'journal-agent@example.com',
      recipientCount: 2,
      emlSha256: sha(original),
      sizeBytes: original.length,
      clientIp: M365_CLIENT,
    });
    expect(message!.emlObjectKey).toMatch(
      new RegExp(`^org/${org}/eml/\\d{4}/\\d{2}/\\d{2}/[0-9a-f]{32}\\.eml$`),
    );
    expect((await fx.object(message!.emlObjectKey)).equals(original)).toBe(true);

    const recipients = await fx.prisma.emailRecipient.findMany({
      where: { organizationId: org, messageId: message!.id },
      orderBy: { rcptSeq: 'asc' },
    });
    expect(recipients.map((r) => [r.address, r.status, r.direction])).toEqual([
      ['bob@example.org', 'journaled', 'outbound'],
      [`dave@${orgDomain}`, 'journaled', 'internal'],
    ]);
    const intake = await fx.prisma.journalIntakeMessage.findFirst({
      where: { organizationId: org, messageId: message!.id },
    });
    expect(intake).toMatchObject({
      sourceId: m365.id,
      kind: 'microsoft_365_journal',
      format: 'journal_report',
      reportSha256: sha(report),
      reportSizeBytes: report.length,
      scanRequested: false,
    });
    const envelope = journalEnvelopeSchema.parse(intake!.envelope);
    expect(envelope.recipients).toEqual([
      { address: 'bob@example.org', field: 'to' },
      { address: `dave@${orgDomain}`, field: 'bcc' },
    ]);
    expect(journalIntakeProofSchema.parse(intake!.proof)).toMatchObject({
      network: 'provider_egress',
      tls: true,
      tenantHeader: 'match',
    });
    const history = await fx.prisma.emailMessageStatusHistory.findMany({
      where: { organizationId: org, messageId: message!.id },
      orderBy: { version: 'asc' },
    });
    expect(history.map((h) => h.toStatus)).toEqual(['received', 'persisted']);
    const event = await fx.prisma.emailEvent.findFirst({
      where: { organizationId: org, messageId: message!.id, eventType: 'received' },
    });
    expect((event!.details as Record<string, unknown>).intake).toEqual({
      sourceId: m365.publicId,
      kind: 'microsoft_365_journal',
      format: 'journal_report',
    });
    const outbox = await fx.prisma.messageOutbox.findFirst({
      where: { organizationId: org, aggregateId: message!.id.toString() },
    });
    expect(messageReceivedV1.parse(outbox!.payload)).toMatchObject({
      ingestSource: 'journal_intake',
      direction: 'outbound',
      recipientCount: 2,
    });
  });

  it('a redelivery of the same queue file is a duplicate (one message, one object)', async () => {
    const report = m365JournalReport({ intakeAddress: m365.credentials.address, tenantId });
    const first = await journal({
      client: M365_CLIENT,
      to: [m365.credentials.address],
      message: report,
    });
    expect(first.lmtp).toEqual(['250 2.0.0 Ok']);
    // Postfix retries the LMTP delivery of the same queue file (the marker is still there).
    expect(await lmtp(first.queue, M365_CLIENT, [m365.credentials.address], report)).toEqual([
      '250 2.0.0 Ok',
    ]);
    const messages = await messagesOf(first.queue);
    expect(messages).toHaveLength(1);
    const keys = (await fx.objectKeys(org)).filter((k) => k === messages[0]!.emlObjectKey);
    expect(keys).toHaveLength(1);
  });

  it('a wrong tenant header is accepted and dropped: nothing stored', async () => {
    const before = await fx.prisma.messageIdentity.count({ where: { organizationId: org } });
    const objectsBefore = (await fx.objectKeys(org)).length;
    const report = m365JournalReport({
      intakeAddress: m365.credentials.address,
      tenantId: randomUUID(),
    });
    const result = await journal({
      client: M365_CLIENT,
      to: [m365.credentials.address],
      message: report,
    });
    expect(result.lmtp).toEqual(['250 2.0.0 Ok: dropped']);
    expect(await fx.prisma.messageIdentity.count({ where: { organizationId: org } })).toBe(before);
    expect(await messagesOf(result.queue)).toHaveLength(0);
    expect((await fx.objectKeys(org)).length).toBe(objectsBefore);
  });

  it('refuses in-session: non-egress client, plaintext, unknown address, mixed transaction', async () => {
    const report = m365JournalReport({ intakeAddress: m365.credentials.address, tenantId });
    expect(
      (await journal({ client: '192.0.2.77', to: [m365.credentials.address], message: report }))
        .rcpt,
    ).toEqual(['550 5.7.1 Journal intake sender not authorized']);
    expect(
      (
        await journal({
          client: M365_CLIENT,
          to: [m365.credentials.address],
          message: report,
          tls: false,
        })
      ).rcpt,
    ).toEqual(['550 5.7.1 Must issue a STARTTLS command first']);
    expect(
      (
        await journal({
          client: M365_CLIENT,
          to: [`journal-${'a'.repeat(26)}@${DOMAIN}`],
          message: report,
        })
      ).rcpt,
    ).toEqual(['550 5.1.1 User unknown']);
    // D2.2.5: another source, or a tenant domain, in the same transaction: 452 (both orders).
    const mixed = await journal({
      client: M365_CLIENT,
      to: [m365.credentials.address, m365b.credentials.address, `bob@${tenantDomain}`],
      message: report,
    });
    expect(mixed.rcpt).toEqual([
      'DUNNO',
      '452 4.5.3 Error: too many recipients',
      '452 4.5.3 Error: too many recipients',
    ]);
    expect(mixed.lmtp).toEqual(['250 2.0.0 Ok']);
    const tenantFirst = await journal({
      client: M365_CLIENT,
      to: [`bob@${tenantDomain}`, m365.credentials.address],
      message: report,
      deliver: false,
    });
    expect(tenantFirst.rcpt).toEqual(['DUNNO', '452 4.5.3 Error: too many recipients']);
  });

  it('the LMTP answers 451 (never 5xx) without the END-OF-MESSAGE marker', async () => {
    const report = m365JournalReport({ intakeAddress: m365.credentials.address, tenantId });
    expect(await lmtp(queueId(), M365_CLIENT, [m365.credentials.address], report)).toEqual([
      '451 4.3.0 Temporary failure, please retry',
    ]);
  });
});

describe('journal intake: Google copy and on-premises report', () => {
  it('Google: the header token proves the source and never reaches the archive copy', async () => {
    const original = originalMessage({ to: [`bob@${orgDomain}`], from: 'carol@example.org' });
    const copy = googleWorkspaceCopy({
      tokens: [google.credentials.headerToken],
      originalTo: [`bob@${orgDomain}`],
      original,
    });
    const result = await journal({
      client: GOOGLE_CLIENT,
      to: [google.credentials.address],
      message: copy,
    });
    expect(result.lmtp).toEqual(['250 2.0.0 Ok']);
    const [message] = await messagesOf(result.queue);
    const stored = await fx.object(message!.emlObjectKey);
    expect(stored.toString('latin1')).not.toContain(google.credentials.headerToken);
    expect(stored.toString('latin1')).not.toMatch(/X-EG-Journal-Token/i);
    expect(message!.emlSha256).toBe(sha(stored));
    expect(message!.direction).toBe('inbound');
  });

  it('on-premises: accepted from its networks, refused from a provider range', async () => {
    const report = onPremJournalReport({
      intakeAddress: onprem.credentials.address,
      envelope: { sender: 'x@example.org', to: [`bob@${orgDomain}`] },
    });
    expect(
      (await journal({ client: ONPREM_CLIENT, to: [onprem.credentials.address], message: report }))
        .lmtp,
    ).toEqual(['250 2.0.0 Ok']);
    expect(
      (await journal({ client: M365_CLIENT, to: [onprem.credentials.address], message: report }))
        .rcpt,
    ).toEqual(['550 5.7.1 Journal intake sender not authorized']);
  });
});

describe('journal intake counters (D2.8)', () => {
  it('flushes daily counts and verifies the pending source on its first accepted message', async () => {
    const before = await fx.prisma.journalIntakeSource.findUniqueOrThrow({
      where: { id: m365.id },
    });
    expect(before.status).toBe('pending_verification');
    // Counter writes are fire-and-forget: give them a moment, then flush.
    await new Promise((resolve) => setTimeout(resolve, 200));
    await moduleRef.get(JournalIntakeCountersService).flush();
    const counter = await fx.prisma.journalIntakeCounter.findFirst({
      where: { sourceId: m365.id },
    });
    expect(counter).toMatchObject({ organizationId: org });
    expect(counter!.accepted).toBeGreaterThanOrEqual(3);
    expect(counter!.duplicates).toBeGreaterThanOrEqual(1);
    expect(counter!.droppedProof).toBe(1);
    expect(counter!.refusedNetwork).toBe(1);
    expect(counter!.refusedTls).toBe(1);
    expect(Number(counter!.bytes)).toBeGreaterThan(0);
    const after = await fx.prisma.journalIntakeSource.findUniqueOrThrow({ where: { id: m365.id } });
    expect(after.status).toBe('active');
    expect(after.verifiedAt).not.toBeNull();
    expect(after.lastAcceptedAt).not.toBeNull();
    expect(after.rowVersion).toBe(before.rowVersion + 1);
    expect(after.lastRefusalCode).not.toBeNull();
    // A second flush adds nothing (the hashes were taken).
    await moduleRef.get(JournalIntakeCountersService).flush();
    const again = await fx.prisma.journalIntakeCounter.findFirst({ where: { sourceId: m365.id } });
    expect(again!.accepted).toBe(counter!.accepted);
    const onpremCounter = await fx.prisma.journalIntakeCounter.findFirst({
      where: { sourceId: onprem.id },
    });
    expect(onpremCounter!.refusedNetwork).toBe(1);
  });
});
