import { randomBytes, randomUUID } from 'node:crypto';
import { BadRequestException } from '@nestjs/common';
import { describe, expect, it, vi } from 'vitest';
import type { AuditService } from '../../audit/audit.service';
import type { Principal } from '../../auth-contracts/principal';
import { systemScope } from '../../auth-contracts/tenant-scope';
import { CursorCodec } from '../../http/cursor/cursor-codec';
import type { MessageDataRepository } from '../messages/repositories/message-data.repository';
import type { MessageDataService } from '../messages/services/message-data.service';
import type { MessagesRepository } from '../tenant-data/messages.repository';
import type {
  AttachmentPart,
  AttachmentsRepository,
  LatestResultRow,
} from './attachments.repository';
import { AttachmentSearchQuerySchema, MessageAttachmentsQuerySchema } from './attachments.schemas';
import {
  AttachmentsService,
  latestResults,
  searchHash,
  toAttachmentItem,
} from './attachments.service';

const scope = systemScope(7n);
const principal: Principal = {
  kind: 'api_key',
  apiKeyId: 1n,
  apiKeyPublicId: randomUUID(),
  organizationId: 7n,
  organizationPublicId: randomUUID(),
  permissions: new Set(['message:read']),
};
const HASH = 'AB'.repeat(32);
const ref = {
  id: 5n,
  publicId: 'pub',
  receivedAt: new Date('2026-11-12T08:00:00Z'),
  organizationId: 7n,
};

const part = (id: number, partIndex: number): AttachmentPart => ({
  id: BigInt(id),
  organizationId: 7n,
  messageId: 5n,
  receivedAt: ref.receivedAt,
  partIndex,
  filename: 'report.pdf',
  declaredContentType: 'application/pdf',
  detectedContentType: 'application/pdf',
  sizeBytes: 10,
  sha256: 'ab'.repeat(32),
  disposition: 'attachment',
  depth: 1,
});

const result = (attachmentId: number, scanId: number, verdict: string): LatestResultRow =>
  ({
    scanId: BigInt(scanId),
    attachmentId: BigInt(attachmentId),
    partIndex: 0,
    sha256: 'ab'.repeat(32),
    sizeBytes: 10,
    detectedType: 'pdf',
    typeFamily: 'document',
    typeMismatch: false,
    verdict,
    reasonCodes: ['clean.no_findings', 'not-a-code'],
    clamavSignature: null,
    clamavEngineVersion: '1.4.1',
    clamavDbVersion: 27450,
    yaraBundleId: null,
    yaraMatches: null,
    archive: null,
    knownHashSeverity: null,
    organizationId: 7n,
  }) as unknown as LatestResultRow;

function setup() {
  const codec = new CursorCodec({
    API_CURSOR_KEY: randomBytes(32).toString('hex'),
    API_CURSOR_KEY_PREVIOUS: undefined,
    API_CURSOR_TTL_SECONDS: 86_400,
  });
  const repo = {
    parts: vi.fn<AttachmentsRepository['parts']>(),
    results: vi.fn<AttachmentsRepository['results']>(),
    search: vi.fn<AttachmentsRepository['search']>(),
    latestVerdicts: vi.fn<AttachmentsRepository['latestVerdicts']>(() =>
      Promise.resolve(new Map()),
    ),
  };
  const messages = { messageRef: vi.fn(() => Promise.resolve(ref)) };
  const data = { scanRounds: vi.fn(() => Promise.resolve(new Map([[30n, 2]]))) };
  const identities = {
    publicIdMap: vi.fn((_s: unknown, ids: readonly bigint[]) =>
      Promise.resolve(new Map(ids.map((i) => [i, `m-${i}`]))),
    ),
  };
  const audit = {
    record: vi.fn(() => Promise.resolve()),
    actorFrom: vi.fn(() => ({ type: 'api_key', id: 'k' })),
  };
  const service = new AttachmentsService(
    { API_MESSAGES_MAX_RANGE_DAYS: 31 },
    repo as unknown as AttachmentsRepository,
    messages as unknown as MessageDataService,
    data as unknown as MessageDataRepository,
    identities as unknown as MessagesRepository,
    codec,
    audit as unknown as AuditService,
  );
  service.now = () => new Date('2026-11-12T12:00:00Z');
  return { service, repo, audit, messages };
}

describe('attachments (step 6.1 WP2)', () => {
  it('latestResults keeps the newest round per attachment', () => {
    const latest = latestResults([
      result(1, 10, 'clean'),
      result(1, 30, 'malicious'),
      result(2, 10, 'clean'),
    ]);
    expect(latest.get(1n)?.scanId).toBe(30n);
    expect(latest.get(2n)?.scanId).toBe(10n);
  });

  it('maps a part with its latest round through the scans view mapper', () => {
    const item = toAttachmentItem(part(1, 2), result(1, 30, 'clean'), 2);
    expect(item).toMatchObject({
      partIndex: 2,
      filename: 'report.pdf',
      verdict: 'clean',
      latestScan: {
        round: 2,
        reasonCodes: ['clean.no_findings'],
        clamav: { signature: null, engineVersion: '1.4.1', dbVersion: 27450 },
      },
    });
    expect(item).not.toHaveProperty('objectKey');
    expect(item.latestScan).not.toHaveProperty('cache');
    expect(toAttachmentItem(part(1, 2), undefined, undefined)).toMatchObject({
      verdict: null,
      latestScan: null,
    });
  });

  it('lists the attachments of a message with a part-index cursor bound to the message', async () => {
    const t = setup();
    t.repo.parts.mockResolvedValueOnce([part(1, 0), part(2, 1)]);
    t.repo.results.mockResolvedValueOnce([result(1, 30, 'clean')]);
    const page = await t.service.ofMessage(
      principal,
      scope,
      'pub',
      MessageAttachmentsQuerySchema.parse({ limit: '1' }),
    );
    expect(page.data).toHaveLength(1);
    expect(page.data[0]!.latestScan?.round).toBe(2);
    t.repo.parts.mockResolvedValueOnce([]);
    t.repo.results.mockResolvedValueOnce([]);
    await t.service.ofMessage(
      principal,
      scope,
      'pub',
      MessageAttachmentsQuerySchema.parse({ cursor: page.nextCursor! }),
    );
    expect(t.repo.parts.mock.calls[1]![2]).toMatchObject({ afterPartIndex: 0 });
    await expect(
      t.service.ofMessage(
        principal,
        scope,
        'other',
        MessageAttachmentsQuerySchema.parse({ cursor: page.nextCursor! }),
      ),
    ).rejects.toMatchObject({ code: 'cursor_invalid' });
  });

  it('requires a 64-hex sha256 and lower-cases it', () => {
    expect(searchHash(AttachmentSearchQuerySchema.parse({ sha256: HASH }))).toBe(
      HASH.toLowerCase(),
    );
    expect(() => searchHash(AttachmentSearchQuerySchema.parse({}))).toThrow(BadRequestException);
    expect(() =>
      searchHash(AttachmentSearchQuerySchema.parse({ sha256: 'zz'.repeat(32) })),
    ).toThrow(BadRequestException);
    expect(() => searchHash(AttachmentSearchQuerySchema.parse({ sha256: 'ab' }))).toThrow(
      BadRequestException,
    );
  });

  it('hash search: keyset page, verdicts, audit with the hash hashed, first page only', async () => {
    const t = setup();
    const at = new Date('2026-11-12T10:00:00Z');
    const hit = (id: number) => ({
      id: BigInt(id),
      receivedAt: at,
      organizationId: 7n,
      messageId: BigInt(100 + id),
      partIndex: 0,
      filename: 'a.exe',
      sizeBytes: 1,
      detectedContentType: null,
      sha256: HASH.toLowerCase(),
    });
    t.repo.search.mockResolvedValueOnce([hit(2), hit(1)]);
    t.repo.latestVerdicts.mockResolvedValueOnce(new Map([[2n, 'malicious']]));
    const page = await t.service.search(
      principal,
      scope,
      AttachmentSearchQuerySchema.parse({ sha256: HASH, limit: '1' }),
      '10.1.1.1',
    );
    expect(t.repo.search.mock.calls[0]![1]).toMatchObject({
      sha256: HASH.toLowerCase(),
      take: 2,
      direction: 'desc',
    });
    expect(page.data).toEqual([
      expect.objectContaining({ messageId: 'm-102', verdict: 'malicious' }),
    ]);
    expect(page.nextCursor).toEqual(expect.any(String));
    const entry = (t.audit.record.mock.calls[0] as unknown[])[0] as {
      metadata: Record<string, unknown>;
    };
    expect(entry).toMatchObject({
      action: 'attachment.searched',
      metadata: { resultCount: 1, filters: ['sha256'] },
    });
    expect(JSON.stringify(entry.metadata)).not.toContain(HASH.toLowerCase());
    t.repo.search.mockResolvedValueOnce([]);
    await t.service.search(
      principal,
      scope,
      AttachmentSearchQuerySchema.parse({ sha256: HASH.toLowerCase(), cursor: page.nextCursor! }),
    );
    expect(t.audit.record).toHaveBeenCalledTimes(1);
    expect(t.repo.search.mock.calls[1]![1].after).toEqual({ at, id: 2n });
  });

  it('hash search range is bounded by API_MESSAGES_MAX_RANGE_DAYS', async () => {
    const t = setup();
    await expect(
      t.service.search(
        principal,
        scope,
        AttachmentSearchQuerySchema.parse({
          sha256: HASH,
          from: '2026-09-01T00:00:00Z',
          to: '2026-11-01T00:00:00Z',
        }),
      ),
    ).rejects.toBeInstanceOf(BadRequestException);
    expect(t.repo.search).not.toHaveBeenCalled();
  });
});
