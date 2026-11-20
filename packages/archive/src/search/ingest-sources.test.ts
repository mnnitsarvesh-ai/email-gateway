import { describe, expect, it } from 'vitest';
import { ARCHIVE_PARTIES_EXAMPLE } from '../documents/records';
import { ARCHIVE_INDEX_MAPPING_REVISION } from '../versions';
import { type ArchiveIndexRecord, buildArchiveSearchDocument } from './document';
import { ARCHIVE_SEARCH_SOURCE_FIELDS, buildArchiveSearchQuery } from './query';
import { ARCHIVE_INDEX_MAPPING, buildIndexMappingUpdate, buildIndexTemplate } from './template';

/** Step 8.6 D7: `ingest_sources` in the index and the `source` filter of the archive search. */

const MSG = '0190a5d0-0000-7000-8000-0000000000aa';
const record: ArchiveIndexRecord = {
  organizationId: 42n,
  messagePublicId: MSG,
  receivedAt: new Date('2026-11-16T10:15:00.000Z'),
  archivedAt: new Date('2026-11-16T10:17:00.000Z'),
  direction: 'inbound',
  category: 'delivered',
  capturedByJournal: true,
  capturedByPolicy: false,
  status: 'active',
  envelopeFrom: 'sender@example.org',
  headerFrom: null,
  parties: {
    ...ARCHIVE_PARTIES_EXAMPLE,
    recipients: [
      ...ARCHIVE_PARTIES_EXAMPLE.recipients,
      {
        seq: 1,
        address: 'Bcc@Example.com',
        direction: null,
        status: 'journaled',
        finalAction: null,
        field: 'bcc',
        sources: ['journal_intake'],
      },
    ],
  },
  subject: null,
  internetMessageId: null,
  sizeBytes: 10,
  attachmentCount: 0,
  finalVerdict: null,
  finalAction: null,
  riskScore: null,
  malicious: false,
  retainUntil: null,
  legalHold: false,
  lockMode: 'none',
};
const build = (over: Partial<ArchiveIndexRecord>) =>
  buildArchiveSearchDocument({ ...record, ...over }, { prefix: 'eg-archive', now: new Date(0) })
    .document;

describe('index document ingest_sources', () => {
  it('follows the record source flags (defaults: gateway only)', () => {
    expect(build({}).ingest_sources).toEqual(['gateway']);
    expect(build({ sourceGateway: false, sourceJournalIntake: true }).ingest_sources).toEqual([
      'journal_intake',
    ]);
    expect(build({ sourceGateway: true, sourceJournalIntake: true }).ingest_sources).toEqual([
      'gateway',
      'journal_intake',
    ]);
  });

  it('indexes merged parties (a BCC recipient of the journal envelope)', () => {
    expect(build({}).recipients).toEqual(['user@example.com', 'bcc@example.com']);
  });
});

describe('mapping revision 2', () => {
  it('adds a keyword field; the template names the revision; an additive mapping update exists', () => {
    expect(ARCHIVE_INDEX_MAPPING.properties.ingest_sources).toEqual({ type: 'keyword' });
    const t = buildIndexTemplate({ prefix: 'eg-archive', shards: 1, replicas: 0 }) as {
      index_patterns: string[];
      _meta: Record<string, unknown>;
    };
    // Same index version (names stay -v1-), new mapping revision.
    expect(t.index_patterns).toEqual(['eg-archive-v1-*']);
    expect(t._meta).toMatchObject({ version: 1, mappingRevision: ARCHIVE_INDEX_MAPPING_REVISION });
    expect(buildIndexMappingUpdate()).toEqual({
      properties: { ingest_sources: { type: 'keyword' } },
      _meta: { mappingRevision: 2 },
    });
    expect(ARCHIVE_SEARCH_SOURCE_FIELDS).toContain('ingest_sources');
  });
});

describe('source filter', () => {
  const q = (source?: 'gateway' | 'journal_intake') =>
    buildArchiveSearchQuery({
      organizationId: 42,
      criteria: { from: '2026-11-01', to: '2026-11-30', ...(source ? { source } : {}) },
      limit: 10,
      permissions: { reveal: false, holds: false },
    }) as { query: { bool: { filter: unknown[] } } };

  it('journal_intake matches the keyword', () => {
    expect(q('journal_intake').query.bool.filter).toContainEqual({
      term: { ingest_sources: 'journal_intake' },
    });
  });

  it('gateway also matches documents indexed before the field existed', () => {
    expect(q('gateway').query.bool.filter).toContainEqual({
      bool: {
        should: [
          { term: { ingest_sources: 'gateway' } },
          { bool: { must_not: [{ exists: { field: 'ingest_sources' } }] } },
        ],
        minimum_should_match: 1,
      },
    });
  });

  it('absent adds nothing; an invalid value is refused', () => {
    expect(q().query.bool.filter).toHaveLength(2);
    expect(() =>
      buildArchiveSearchQuery({
        organizationId: 42,
        criteria: { from: '2026-11-01', to: '2026-11-30', source: 'pst' as never },
        limit: 10,
        permissions: { reveal: false, holds: false },
      }),
    ).toThrow(TypeError);
  });
});
