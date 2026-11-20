import { Readable } from 'node:stream';
import { createHash } from 'node:crypto';
import { journalIntakeProofSchema } from '@email-gateway/archive';
import type { SMTPServerDataStream } from 'smtp-server';
import { describe, expect, it, vi } from 'vitest';
import { metricValue, newMetrics, testConfig } from '../../integration/in-session-support/fakes';
import type { EmlStore, EmlUploadOptions } from '../ingestion/eml-store';
import { LmtpReplyException } from '../lmtp/lmtp-reply';
import type { EgressIndexService } from '../provider-relay/egress-index.service';
import type { DkimRun, ProofVerifier } from '../provider-relay/proof-verifier';
import { LMTP_INTAKE_DROPPED, LMTP_OK, LMTP_TEMPFAIL } from '../shared/replies';
import type { IntakeMarker, IntakeStateStore } from './intake-state.store';
import type { JournalIntakeCountersService } from './journal-intake-counters.service';
import { JournalIntakeMetrics } from './journal-intake.metrics';
import type { JournalIntakeModuleOptions } from './journal-intake.options';
import type { IntakeCommit, JournalIntakeRepository } from './journal-intake.repository';
import { JournalIntakeService } from './journal-intake.service';
import type { IntakeSourceSnapshot, JournalIntakeSourceRepository } from './source-snapshot';
import {
  googleWorkspaceCopy,
  intakeCredentials,
  journalReport,
  m365JournalReport,
  originalMessage,
  smtpBccCopy,
  testIntakeSecret,
} from './testing/fixtures';
import {
  snapshotFixture,
  TEST_GOOGLE_CLIENT,
  TEST_M365_CLIENT,
  TEST_ONPREM_CLIENT,
  TEST_TENANT_ID,
  testEgressIndex,
} from './testing/snapshots';

const DOMAIN = 'journal.gateway.test';
const secret = testIntakeSecret();
const creds = intakeCredentials(secret, '0190a0a0-0000-7000-8000-00000000a042', 1, DOMAIN);
const sha = (b: Buffer) => createHash('sha256').update(b).digest('hex');

class FakeUpload {
  readonly chunks: Buffer[] = [];
  finished = false;
  aborted = false;
  failed = false;
  write(chunk: Buffer): Promise<void> {
    this.chunks.push(Buffer.from(chunk));
    return Promise.resolve();
  }
  finish(): Promise<void> {
    this.finished = true;
    return this.failed ? Promise.reject(new Error('s3 down')) : Promise.resolve();
  }
  abort(): void {
    this.aborted = true;
  }
  get body(): Buffer {
    return Buffer.concat(this.chunks);
  }
}

function harness(snapshot: IntakeSourceSnapshot, marker: Partial<IntakeMarker> = {}) {
  const config = testConfig({ JOURNAL_INTAKE_DOMAIN: DOMAIN, JOURNAL_INTAKE_MAX_RECIPIENTS: '3' });
  const options: JournalIntakeModuleOptions = {
    config,
    listenHost: '127.0.0.1',
    internalNetworks: '127.0.0.0/8',
    logLevel: 'silent',
  };
  const uploads: { key: string; upload: FakeUpload }[] = [];
  const store = {
    startUpload: vi.fn((o: EmlUploadOptions) => {
      const upload = new FakeUpload();
      uploads.push({ key: o.key, upload });
      return upload;
    }),
    delete: vi.fn(() => Promise.resolve()),
  };
  const commits: IntakeCommit[] = [];
  const committed = new Map<
    string,
    { messageId: bigint; receivedAt: Date; emlObjectKey: string }
  >();
  const repository = {
    findCommitted: vi.fn((_org: bigint, key: string) =>
      Promise.resolve(committed.get(key) ?? null),
    ),
    commit: vi.fn((data: IntakeCommit) => {
      commits.push(data);
      committed.set(data.ingestKey, {
        messageId: BigInt(commits.length),
        receivedAt: data.receivedAt,
        emlObjectKey: data.emlObjectKey,
      });
      return Promise.resolve({
        messageId: BigInt(commits.length),
        eventId: 'e',
        scanRequested: false,
      });
    }),
  };
  const state = {
    readMarker: vi.fn(() =>
      Promise.resolve<IntakeMarker | null>({
        v: 1,
        sourceId: snapshot.source.id,
        tls: true,
        tlsProtocol: 'TLSv1.3',
        certFingerprints: [],
        clientAddress: TEST_M365_CLIENT,
        ...marker,
      }),
    ),
  };
  const dkimRun: DkimRun = {
    write: () => Promise.resolve(),
    finish: () => Promise.resolve({ ok: true, signatures: [] }),
    abort: () => undefined,
  };
  const proofs = { startDkim: vi.fn(() => dkimRun) };
  const counters = { record: vi.fn() };
  const metrics = newMetrics();
  const sources = { loadByAddressHash: vi.fn(() => Promise.resolve(snapshot)) };
  const service = new JournalIntakeService(
    options,
    sources as unknown as JournalIntakeSourceRepository,
    repository as unknown as JournalIntakeRepository,
    store as unknown as EmlStore,
    state as unknown as IntakeStateStore,
    { current: testEgressIndex } as unknown as EgressIndexService,
    proofs as unknown as ProofVerifier,
    counters as unknown as JournalIntakeCountersService,
    new JournalIntakeMetrics(metrics),
  );
  return {
    service,
    store,
    uploads,
    repository,
    commits,
    state,
    proofs,
    counters,
    metrics,
    sources,
  };
}

const client = (clientAddress = TEST_M365_CLIENT) => ({
  connectionId: 'c1',
  peerAddress: '127.0.0.1',
  lhloName: 'mx.gateway.local',
  queueId: '4ZQUEUE1',
  clientAddress,
  clientHelo: 'mail.example.com',
  clientName: 'mail.example.com',
});

const stream = (message: Buffer, chunk = 97): SMTPServerDataStream => {
  const parts: Buffer[] = [];
  for (let i = 0; i < message.length; i += chunk) parts.push(message.subarray(i, i + chunk));
  return Readable.from(parts) as unknown as SMTPServerDataStream;
};

async function deliver(
  h: ReturnType<typeof harness>,
  message: Buffer,
  opts: { clientAddress?: string; mailFrom?: string; address?: string } = {},
) {
  const tx = h.service.beginTransaction(
    client(opts.clientAddress),
    opts.mailFrom ?? 'journal-agent@example.com',
  );
  const recipient = await h.service.acceptRecipient(tx, opts.address ?? creds.address);
  return h.service.handleData(tx, [recipient], stream(message));
}

const m365Snapshot = () => snapshotFixture('microsoft_365_journal');

describe('JournalIntakeService (D2.5-D2.7)', () => {
  it('unwraps a Microsoft 365 journal report, stores the original and commits the envelope', async () => {
    const h = harness(m365Snapshot());
    const original = originalMessage({
      messageId: '<m1@example.com>',
      from: 'Alice <alice@example.com>',
      to: ['bob@example.org'],
    });
    const report = m365JournalReport({
      intakeAddress: creds.address,
      tenantId: TEST_TENANT_ID,
      original,
      encoding: 'base64',
      envelope: {
        sender: 'alice@example.com',
        messageId: '<m1@example.com>',
        to: ['bob@example.org', creds.address],
        cc: ['carol@example.net'],
        bcc: ['dave@example.com', 'erin@example.com', 'frank@example.com'],
      },
    });
    expect(await deliver(h, report)).toEqual([LMTP_OK]);
    const { key, upload } = h.uploads[0]!;
    expect(upload.finished).toBe(true);
    expect(upload.body.equals(original)).toBe(true);
    expect(key).toMatch(/^org\/7\/eml\/\d{4}\/\d{2}\/\d{2}\/[0-9a-f]{32}\.eml$/);
    const commit = h.commits[0]!;
    expect(commit).toMatchObject({
      organizationId: 7n,
      domainId: 100n,
      direction: 'outbound',
      envelopeFrom: 'journal-agent@example.com',
      internetMessageId: '<m1@example.com>',
      headerFrom: 'alice@example.com',
      sizeBytes: original.length,
      emlSha256: sha(original),
      reportSha256: sha(report),
      reportSizeBytes: report.length,
      format: 'journal_report',
      source: { id: 42n, kind: 'microsoft_365_journal' },
      queueId: '4ZQUEUE1',
    });
    expect(commit.ingestKey).toMatch(/^v2:[0-9a-f]{64}$/);
    // The intake address is never a party; the cap of 3 recipients truncates.
    expect(commit.envelope.recipients.map((r) => [r.address, r.field])).toEqual([
      ['bob@example.org', 'to'],
      ['carol@example.net', 'cc'],
      ['dave@example.com', 'bcc'],
    ]);
    expect(commit.envelope.truncated).toBe(true);
    expect(commit.recipients).toEqual([
      { address: 'bob@example.org', direction: 'outbound' },
      // example.net is a verified domain of the organization (org side).
      { address: 'carol@example.net', direction: 'internal' },
      { address: 'dave@example.com', direction: 'internal' },
    ]);
    expect(journalIntakeProofSchema.parse(commit.proof)).toEqual({
      v: 1,
      network: 'provider_egress',
      tls: true,
      clientCert: 'n/a',
      tenantHeader: 'match',
      headerToken: 'n/a',
      dkim: { result: 'none', domains: [] },
      result: 'pass',
    });
    expect(h.counters.record).toHaveBeenCalledWith(
      42n,
      expect.objectContaining({ counts: { accepted: 1, bytes: report.length } }),
      expect.any(Date),
    );
    expect(
      await metricValue(h.metrics, 'journal_intake_messages_total', {
        kind: 'microsoft_365_journal',
        outcome: 'accepted',
      }),
    ).toBe(1);
    expect(
      await metricValue(h.metrics, 'journal_intake_unwrap_total', {
        format: 'journal_report',
        result: 'ok',
      }),
    ).toBe(1);
  });

  it('drops a report whose tenant header fails: nothing stored, 250 dropped, counted', async () => {
    const h = harness(m365Snapshot());
    const report = m365JournalReport({
      intakeAddress: creds.address,
      tenantId: '00000000-0000-0000-0000-000000000000',
    });
    expect(await deliver(h, report)).toEqual([LMTP_INTAKE_DROPPED]);
    expect(h.uploads[0]!.upload.aborted).toBe(true);
    expect(h.uploads[0]!.upload.finished).toBe(false);
    expect(h.repository.commit).not.toHaveBeenCalled();
    expect(h.counters.record).toHaveBeenCalledWith(
      42n,
      expect.objectContaining({
        counts: { dropped_proof: 1 },
        refusalCode: 'proof_tenant_header',
      }),
      expect.any(Date),
    );
    expect(
      await metricValue(h.metrics, 'journal_intake_messages_total', {
        kind: 'microsoft_365_journal',
        outcome: 'dropped',
      }),
    ).toBe(1);
  });

  it('answers 451 on a proof temperror (binding gone) and stores nothing', async () => {
    const h = harness(
      snapshotFixture('microsoft_365_journal', { connection: { externalTenantId: null } }),
    );
    // The re-check passes (bound flag), the proof cannot check the tenant.
    const report = m365JournalReport({ intakeAddress: creds.address, tenantId: TEST_TENANT_ID });
    expect(await deliver(h, report)).toEqual([LMTP_TEMPFAIL]);
    expect(h.repository.commit).not.toHaveBeenCalled();
    expect(h.uploads[0]!.upload.aborted).toBe(true);
  });

  it('stores an unrecognizable report as received (journal_report_unparsed) and counts it', async () => {
    const h = harness(m365Snapshot());
    const report = journalReport({
      intakeAddress: creds.address,
      tenantIds: [TEST_TENANT_ID],
      withoutJournalHeader: true,
      original: originalMessage({ to: ['bob@example.org'] }),
    });
    expect(await deliver(h, report)).toEqual([LMTP_OK]);
    expect(h.uploads[0]!.upload.body.equals(report)).toBe(true);
    const commit = h.commits[0]!;
    expect(commit.format).toBe('journal_report_unparsed');
    expect(commit.emlSha256).toBe(sha(report));
    // Header recipients of the report, without the intake address.
    expect(commit.envelope.recipients).toEqual([]);
    expect(h.counters.record).toHaveBeenCalledWith(
      42n,
      expect.objectContaining({ counts: { accepted: 1, bytes: report.length, unwrap_failed: 1 } }),
      expect.any(Date),
    );
    expect(
      await metricValue(h.metrics, 'journal_intake_unwrap_total', {
        format: 'journal_report_unparsed',
        result: 'not_journal_report',
      }),
    ).toBe(1);
  });

  it('answers a redelivery of a committed queue file as a duplicate', async () => {
    const h = harness(m365Snapshot());
    const report = m365JournalReport({ intakeAddress: creds.address, tenantId: TEST_TENANT_ID });
    expect(await deliver(h, report)).toEqual([LMTP_OK]);
    expect(await deliver(h, report)).toEqual([LMTP_OK]);
    expect(h.repository.commit).toHaveBeenCalledTimes(1);
    expect(h.counters.record).toHaveBeenLastCalledWith(
      42n,
      expect.objectContaining({ counts: { duplicates: 1 } }),
      expect.any(Date),
    );
  });

  it('google copy: the token proves the source and is removed from the stored message', async () => {
    const token = creds.headerToken;
    const h = harness(
      snapshotFixture('google_workspace_copy', {
        source: { headerTokenHash: creds.headerTokenHash },
      }),
      { clientAddress: TEST_GOOGLE_CLIENT },
    );
    const original = originalMessage({ to: ['bob@example.com'], from: 'x@example.org' });
    const copy = googleWorkspaceCopy({
      tokens: [token],
      originalTo: ['bob@example.com'],
      original,
    });
    expect(
      await deliver(h, copy, { clientAddress: TEST_GOOGLE_CLIENT, mailFrom: 'x@example.org' }),
    ).toEqual([LMTP_OK]);
    const stored = h.uploads[0]!.upload.body;
    expect(stored.toString('latin1')).not.toContain(token);
    expect(stored.toString('latin1')).not.toMatch(/x-eg-journal-token/i);
    const commit = h.commits[0]!;
    expect(commit.format).toBe('copy');
    expect(commit.emlSha256).toBe(sha(stored));
    expect(commit.reportSha256).toBe(sha(copy));
    expect(commit.direction).toBe('inbound');
    expect(commit.envelope.recipients).toEqual([{ address: 'bob@example.com', field: 'envelope' }]);
    expect(commit.proof.headerToken).toBe('match');
    // A copy without (or with a wrong) token is dropped.
    const bad = harness(
      snapshotFixture('google_workspace_copy', {
        source: { headerTokenHash: creds.headerTokenHash },
      }),
      { clientAddress: TEST_GOOGLE_CLIENT },
    );
    expect(
      await deliver(bad, googleWorkspaceCopy({ tokens: ['a'.repeat(26)], original }), {
        clientAddress: TEST_GOOGLE_CLIENT,
      }),
    ).toEqual([LMTP_INTAKE_DROPPED]);
  });

  it('smtp_bcc copy from the source networks: header recipients, no content proof', async () => {
    const h = harness(snapshotFixture('smtp_bcc'), { clientAddress: TEST_ONPREM_CLIENT });
    const original = originalMessage({ to: ['bob@example.com'], cc: ['eve@elsewhere.example'] });
    expect(await deliver(h, smtpBccCopy(original), { clientAddress: TEST_ONPREM_CLIENT })).toEqual([
      LMTP_OK,
    ]);
    const commit = h.commits[0]!;
    expect(commit.envelope.recipients).toEqual([
      { address: 'bob@example.com', field: 'header' },
      { address: 'eve@elsewhere.example', field: 'header' },
    ]);
    expect(commit.proof).toMatchObject({ network: 'source_networks', tenantHeader: 'n/a' });
    expect(h.proofs.startDkim).not.toHaveBeenCalled();
  });

  it('tempfails when the S3 upload fails, and on a commit error', async () => {
    const h = harness(m365Snapshot());
    h.store.startUpload.mockImplementationOnce((o: EmlUploadOptions) => {
      const upload = new FakeUpload();
      upload.failed = true;
      h.uploads.push({ key: o.key, upload });
      return upload;
    });
    const report = m365JournalReport({ intakeAddress: creds.address, tenantId: TEST_TENANT_ID });
    expect(await deliver(h, report)).toEqual([LMTP_TEMPFAIL]);
    h.repository.commit.mockRejectedValueOnce(new Error('db down'));
    expect(await deliver(h, report)).toEqual([LMTP_TEMPFAIL]);
    expect(await deliver(h, report)).toEqual([LMTP_OK]);
  });
});

describe('JournalIntakeService RCPT re-check (D2.5)', () => {
  const tx = (h: ReturnType<typeof harness>, address = TEST_M365_CLIENT) =>
    h.service.beginTransaction(client(address), 'journal-agent@example.com');

  it('answers 451 (never 5xx) for every refusal', async () => {
    const cases: [IntakeSourceSnapshot | null, Partial<IntakeMarker> | null, string][] = [
      [
        snapshotFixture('microsoft_365_journal', { source: { status: 'paused' } }),
        {},
        TEST_M365_CLIENT,
      ],
      [
        snapshotFixture('microsoft_365_journal', { source: { status: 'disabled' } }),
        {},
        TEST_M365_CLIENT,
      ],
      [m365Snapshot(), {}, '192.0.2.1'],
      [m365Snapshot(), { tls: false }, TEST_M365_CLIENT],
      [m365Snapshot(), { sourceId: '99' }, TEST_M365_CLIENT],
      [m365Snapshot(), null, TEST_M365_CLIENT],
      [null, {}, TEST_M365_CLIENT],
    ];
    for (const [snapshot, marker, address] of cases) {
      const h = harness(snapshot ?? m365Snapshot(), marker ?? {});
      if (snapshot === null) h.sources.loadByAddressHash.mockResolvedValueOnce(null as never);
      if (marker === null) h.state.readMarker.mockResolvedValueOnce(null);
      const error = await h.service
        .acceptRecipient(tx(h, address), creds.address)
        .catch((e: unknown) => e);
      expect(error).toBeInstanceOf(LmtpReplyException);
      expect((error as LmtpReplyException).reply).toEqual(LMTP_TEMPFAIL);
    }
  });

  it('accepts one intake recipient per transaction (a case variant is the same one)', async () => {
    const h = harness(m365Snapshot());
    const t = tx(h);
    const first = await h.service.acceptRecipient(t, creds.address);
    expect(await h.service.acceptRecipient(t, creds.address.toUpperCase())).toBe(first);
    const other = intakeCredentials(secret, '0190a0a0-0000-7000-8000-00000000a099', 1, DOMAIN);
    await expect(h.service.acceptRecipient(t, other.address)).rejects.toBeInstanceOf(
      LmtpReplyException,
    );
    await expect(h.service.acceptRecipient(tx(h), 'bob@example.com')).rejects.toBeInstanceOf(
      LmtpReplyException,
    );
  });

  it('refuses a transaction without XFORWARD IDENT', () => {
    const h = harness(m365Snapshot());
    expect(() =>
      h.service.beginTransaction({ ...client(), queueId: null }, 'journal-agent@example.com'),
    ).toThrow(LmtpReplyException);
  });
});
