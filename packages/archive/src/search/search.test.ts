import { describe, expect, it } from 'vitest';
import { ARCHIVE_PARTIES_EXAMPLE } from '../documents/records';
import type { ArchiveSearchCriteria } from '../documents/search';
import { holdToSearchCriteria } from '../holds/matcher';
import { type ArchiveIndexRecord, buildArchiveSearchDocument, messageIdKey } from './document';
import {
  aliasesForIndexCreation,
  indexPattern,
  indexTemplateName,
  newIndexAliasActions,
  removeTenantAliasActions,
  tenantAliasActions,
  tenantAliasName,
  yearlyIndexName,
  yearlyIndicesBetween,
} from './names';
import {
  ARCHIVE_SEARCH_SOURCE_FIELDS,
  ArchiveSearchQueryError,
  buildArchiveSearchQuery,
  buildDayCountQuery,
  buildOrganizationPurgeQuery,
  decodeSearchAfter,
  encodeSearchAfter,
  parseSearchAfter,
  searchAfterOfHit,
  searchFilterHash,
  searchFilterNames,
} from './query';
import { ARCHIVE_INDEX_FIELDS, type ARCHIVE_INDEX_MAPPING, buildIndexTemplate } from './template';

const MSG = '0190a5d0-0000-7000-8000-0000000000aa';
const HOLD = '0190a5d0-0000-7000-8000-0000000000ee';
const ALL = { reveal: true, holds: true };
const NONE = { reveal: false, holds: false };

describe('names', () => {
  it('derives every name from the prefix, version and organization id', () => {
    expect(indexTemplateName('eg-archive')).toBe('eg-archive-v1');
    expect(indexPattern('eg-archive')).toBe('eg-archive-v1-*');
    expect(indexPattern('eg-archive', 2)).toBe('eg-archive-v2-*');
    expect(yearlyIndexName('eg-archive', new Date('2026-12-31T23:59:59.999Z'))).toBe(
      'eg-archive-v1-2026',
    );
    expect(yearlyIndexName('eg-archive', new Date('2027-01-01T00:00:00.000Z'))).toBe(
      'eg-archive-v1-2027',
    );
    expect(tenantAliasName('eg-archive', 42n)).toBe('eg-archive-t42');
    expect(
      yearlyIndicesBetween('eg-test', new Date('2024-06-01Z'), new Date('2026-01-01Z')),
    ).toEqual(['eg-test-v1-2024', 'eg-test-v1-2025', 'eg-test-v1-2026']);
  });

  it('refuses invalid prefixes and organization ids', () => {
    for (const bad of ['EG', 'eg', '1abc', 'eg_archive', 'eg-archive/../x', 'a'.repeat(42)]) {
      expect(() => indexTemplateName(bad), bad).toThrow(/prefix/);
    }
    expect(() => tenantAliasName('eg-archive', 'acme')).toThrow(/organization/);
    expect(() => tenantAliasName('eg-archive', -1)).toThrow(/organization/);
    expect(() => yearlyIndexName('eg-archive', new Date(Number.NaN))).toThrow();
  });

  it('builds filtered, routed tenant alias actions', () => {
    expect(tenantAliasActions('eg-archive', 7, ['eg-archive-v1-2026'])).toEqual({
      actions: [
        {
          add: {
            index: 'eg-archive-v1-2026',
            alias: 'eg-archive-t7',
            filter: { term: { org_id: '7' } },
            routing: '7',
          },
        },
      ],
    });
    expect(
      newIndexAliasActions('eg-archive', 'eg-archive-v1-2027', [7, '7', 8n]).actions,
    ).toHaveLength(2);
    expect(removeTenantAliasActions('eg-archive', 7, ['a', 'b']).actions).toEqual([
      { remove: { index: 'a', alias: 'eg-archive-t7' } },
      { remove: { index: 'b', alias: 'eg-archive-t7' } },
    ]);
    expect(aliasesForIndexCreation('eg-archive', [3])).toEqual({
      'eg-archive-t3': { filter: { term: { org_id: '3' } }, routing: '3' },
    });
  });
});

describe('index template (§4.3)', () => {
  it('is strict, lower-case normalized and parameterized', () => {
    const t = buildIndexTemplate({ prefix: 'eg-archive', shards: 1, replicas: 0 }) as {
      index_patterns: string[];
      template: { settings: Record<string, unknown>; mappings: typeof ARCHIVE_INDEX_MAPPING };
    };
    expect(t.index_patterns).toEqual(['eg-archive-v1-*']);
    expect(t.template.settings).toMatchObject({
      number_of_shards: 1,
      number_of_replicas: 0,
      refresh_interval: '1s',
      analysis: { normalizer: { eg_lowercase: { type: 'custom', filter: ['lowercase'] } } },
    });
    expect(t.template.mappings.dynamic).toBe('strict');
    expect(t.template.mappings.properties.subject.fields.raw).toMatchObject({ ignore_above: 256 });
    expect(t.template.mappings.properties.recipients).toEqual({
      type: 'keyword',
      normalizer: 'eg_lowercase',
    });
    expect([...ARCHIVE_INDEX_FIELDS].sort()).toEqual(
      [
        'org_id',
        'message_id',
        'received_at',
        'captured_at',
        'direction',
        'category',
        'sources',
        'status',
        'envelope_from',
        'header_from',
        'sender_domain',
        'recipients',
        'recipient_domains',
        'subject',
        'message_id_key',
        'size_bytes',
        'attachment_count',
        'attachment_names',
        'attachment_sha256',
        'verdict',
        'final_action',
        'risk_score',
        'malicious',
        'dlp_matched',
        'spf',
        'dkim',
        'dmarc',
        'retain_until',
        'legal_hold',
        'lock_mode',
        'indexed_at',
      ].sort(),
    );
    expect(() => buildIndexTemplate({ prefix: 'eg-archive', shards: 0, replicas: 0 })).toThrow(
      RangeError,
    );
    expect(() => buildIndexTemplate({ prefix: 'eg-archive', shards: 1, replicas: -1 })).toThrow(
      RangeError,
    );
  });
});

describe('buildArchiveSearchDocument', () => {
  const record: ArchiveIndexRecord = {
    organizationId: 42n,
    messagePublicId: MSG,
    receivedAt: new Date('2026-11-16T10:15:00.000Z'),
    archivedAt: new Date('2026-11-16T10:17:00.000Z'),
    direction: 'inbound',
    category: 'delivered',
    capturedByJournal: true,
    capturedByPolicy: true,
    status: 'active',
    envelopeFrom: 'Sender@Example.org',
    headerFrom: 'Sender <sender@example.ORG>',
    parties: {
      ...ARCHIVE_PARTIES_EXAMPLE,
      recipients: [
        ...ARCHIVE_PARTIES_EXAMPLE.recipients,
        {
          seq: 1,
          address: 'Bob@Example.com',
          direction: 'inbound',
          status: 'delivered',
          finalAction: null,
        },
      ],
    },
    subject: 'Quarterly report',
    internetMessageId: '<ABC-1@Example.org>',
    sizeBytes: 2048n,
    attachmentCount: 1,
    finalVerdict: 'clean',
    finalAction: 'deliver',
    riskScore: 12,
    malicious: false,
    retainUntil: new Date('2027-11-16T10:15:00.000Z'),
    legalHold: false,
    lockMode: 'governance',
  };

  it('emits exactly the template fields, normalized, with routing and the yearly index', () => {
    const built = buildArchiveSearchDocument(record, {
      prefix: 'eg-archive',
      now: new Date('2026-11-16T10:18:00.000Z'),
      extra: {
        attachmentNames: ['report.pdf', 'report.pdf', null],
        attachmentSha256s: ['B'.repeat(64), 'not-a-hash'],
        dlpMatched: true,
        spf: 'pass',
        dkim: 'fail',
        dmarc: '<script>',
      },
    });
    expect(built).toMatchObject({ index: 'eg-archive-v1-2026', id: MSG, routing: '42' });
    expect(Object.keys(built.document).sort()).toEqual([...ARCHIVE_INDEX_FIELDS].sort());
    expect(built.document).toMatchObject({
      org_id: '42',
      sources: ['journal', 'policy'],
      envelope_from: 'sender@example.org',
      header_from: 'sender@example.org',
      sender_domain: ['example.org'],
      recipients: ['user@example.com', 'bob@example.com'],
      recipient_domains: ['example.com'],
      message_id_key: 'abc-1@example.org',
      size_bytes: 2048,
      attachment_names: ['report.pdf'],
      attachment_sha256: ['b'.repeat(64)],
      dlp_matched: true,
      spf: 'pass',
      dkim: 'fail',
      dmarc: null,
      retain_until: '2027-11-16T10:15:00.000Z',
      indexed_at: '2026-11-16T10:18:00.000Z',
    });
  });

  it('never emits a body or another header value, whatever the input carries', () => {
    const polluted = {
      ...record,
      body: 'secret body',
      headers: [{ name: 'X', value: 'v' }],
    } as ArchiveIndexRecord;
    const doc = buildArchiveSearchDocument(polluted, {
      prefix: 'eg-archive',
      now: new Date(),
    }).document;
    const json = JSON.stringify(doc);
    expect(json).not.toContain('secret body');
    expect(Object.keys(doc)).not.toContain('body');
    expect(Object.keys(doc)).not.toContain('headers');
  });

  it('refuses invalid parties documents', () => {
    expect(() =>
      buildArchiveSearchDocument(
        { ...record, parties: { v: 2 } },
        { prefix: 'eg-archive', now: new Date() },
      ),
    ).toThrow(/archive-parties/);
  });

  it('messageIdKey', () => {
    expect(messageIdKey(' <A@B> ')).toBe('a@b');
    expect(messageIdKey('<>')).toBeNull();
    expect(messageIdKey(null)).toBeNull();
  });
});

describe('buildArchiveSearchQuery', () => {
  const base: ArchiveSearchCriteria = { from: '2026-01-01', to: '2026-01-31' };
  type Q = {
    size: number;
    track_total_hits: boolean;
    query: { bool: { filter: Record<string, unknown>[] } };
    sort: unknown[];
    _source: { includes: string[] };
    search_after?: unknown;
    timeout?: string;
  };
  const build = (criteria: Partial<ArchiveSearchCriteria> & { legalHold?: boolean }, extra = {}) =>
    buildArchiveSearchQuery({
      organizationId: 42,
      criteria: { ...base, ...criteria },
      limit: 50,
      permissions: ALL,
      ...extra,
    }) as unknown as Q;

  it('always carries the organization term and the received_at range', () => {
    const q = build({});
    expect(q.query.bool.filter[0]).toEqual({ term: { org_id: '42' } });
    expect(q.query.bool.filter[1]).toEqual({
      range: {
        received_at: {
          gte: '2026-01-01T00:00:00.000Z',
          lte: '2026-01-31T23:59:59.999Z',
          format: 'strict_date_optional_time',
        },
      },
    });
    expect(q).toMatchObject({ size: 51, track_total_hits: false });
    expect(q.sort).toEqual([{ received_at: { order: 'desc' } }, { message_id: { order: 'desc' } }]);
    expect(q._source.includes).toEqual([...ARCHIVE_SEARCH_SOURCE_FIELDS]);
    expect(q._source.includes).not.toContain('body');
    expect(build({}, { sort: 'receivedAt' }).sort).toEqual([
      { received_at: { order: 'asc' } },
      { message_id: { order: 'asc' } },
    ]);
  });

  it('maps every filter', () => {
    const q = build(
      {
        directions: ['inbound'],
        categories: ['delivered'],
        sources: ['policy'],
        statuses: ['active'],
        senders: ['A@Example.org'],
        senderDomains: ['Example.ORG'],
        recipients: ['Bob@Example.com'],
        recipientDomains: ['example.com'],
        custodians: ['Carol@Example.com'],
        subject: 'Quarterly',
        internetMessageId: '<ID@x>',
        hasAttachments: true,
        attachmentName: 'report',
        attachmentSha256: ['a'.repeat(64)],
        verdicts: ['phishing'],
        finalActions: ['quarantine'],
        riskScoreGte: 500,
        riskScoreLte: 900,
        malicious: true,
        legalHold: true,
        holdId: HOLD,
      },
      {
        hold: holdToSearchCriteria(
          { custodians: ['dave@example.com'], from: '2026-01-10', directions: ['inbound'] },
          'archive-hold/1',
        ),
        timeoutMs: 5000,
        searchAfter: [1767225600000, MSG],
      },
    );
    const f = q.query.bool.filter;
    const has = (clause: unknown) => expect(f).toContainEqual(clause);
    has({ terms: { direction: ['inbound'] } });
    has({ terms: { category: ['delivered'] } });
    has({ terms: { sources: ['policy'] } });
    has({ terms: { status: ['active'] } });
    has({
      bool: {
        should: [
          { terms: { envelope_from: ['a@example.org'] } },
          { terms: { header_from: ['a@example.org'] } },
        ],
        minimum_should_match: 1,
      },
    });
    has({ terms: { sender_domain: ['example.org'] } });
    has({ terms: { recipients: ['bob@example.com'] } });
    has({ terms: { recipient_domains: ['example.com'] } });
    has({
      bool: {
        should: [
          { terms: { envelope_from: ['carol@example.com'] } },
          { terms: { header_from: ['carol@example.com'] } },
          { terms: { recipients: ['carol@example.com'] } },
        ],
        minimum_should_match: 1,
      },
    });
    has({ match_phrase: { subject: { query: 'Quarterly' } } });
    has({ term: { message_id_key: 'id@x' } });
    has({ range: { attachment_count: { gte: 1 } } });
    has({ match_phrase: { attachment_names: { query: 'report' } } });
    has({ terms: { attachment_sha256: ['a'.repeat(64)] } });
    has({ terms: { verdict: ['phishing'] } });
    has({ terms: { final_action: ['quarantine'] } });
    has({ range: { risk_score: { gte: 500, lte: 900 } } });
    has({ term: { malicious: true } });
    has({ term: { legal_hold: true } });
    has({
      range: {
        received_at: { gte: '2026-01-10T00:00:00.000Z', format: 'strict_date_optional_time' },
      },
    });
    expect(q.search_after).toEqual([1767225600000, MSG]);
    expect(q.timeout).toBe('5000ms');
    expect(build({ hasAttachments: false }).query.bool.filter).toContainEqual({
      term: { attachment_count: 0 },
    });
  });

  it.each(['recipients', 'subject', 'custodians'] as const)(
    'refuses the reveal-gated filter %s without message:reveal',
    (filter) => {
      const value = filter === 'subject' ? 'x' : ['a@example.com'];
      try {
        build({ [filter]: value }, { permissions: { reveal: false, holds: true } });
        expect.fail('expected refusal');
      } catch (error) {
        expect(error).toBeInstanceOf(ArchiveSearchQueryError);
        expect(error).toMatchObject({ code: 'archive_filter_forbidden', filter });
        expect((error as Error).message).not.toContain('a@example.com');
      }
    },
  );

  it('refuses holdId without the hold permission, and an unresolved hold', () => {
    expect(() => build({ holdId: HOLD }, { permissions: { reveal: true, holds: false } })).toThrow(
      expect.objectContaining({ code: 'archive_filter_forbidden', filter: 'holdId' }),
    );
    expect(() => build({ holdId: HOLD })).toThrow(
      expect.objectContaining({ code: 'hold_unresolved' }),
    );
    // A match-all hold adds no restriction beyond the tenant and range.
    const q = build({ holdId: HOLD }, { hold: holdToSearchCriteria('broken', null) });
    expect(q.query.bool.filter).toHaveLength(2);
  });

  it('non-gated filters work without any permission flag', () => {
    expect(() =>
      build({ senders: ['a@b.c'], recipientDomains: ['b.c'] }, { permissions: NONE }),
    ).not.toThrow();
  });

  it('custodians "case" uses the case custodians; an empty case matches nothing', () => {
    const q = build({ custodians: 'case' }, { caseCustodians: ['E@x.org'] });
    expect(JSON.stringify(q.query)).toContain('e@x.org');
    expect(build({ custodians: 'case' }, { caseCustodians: [] }).query.bool.filter).toContainEqual({
      bool: { must_not: [{ match_all: {} }] },
    });
    expect(() => build({ custodians: 'case' })).toThrow(
      expect.objectContaining({ code: 'case_custodians_unresolved' }),
    );
  });

  it('refuses an inverted or invalid range, a bad limit and a bad cursor', () => {
    expect(() => build({ from: '2026-02-01', to: '2026-01-01' })).toThrow(
      expect.objectContaining({ code: 'archive_search_range_invalid' }),
    );
    expect(() => build({}, { limit: 0 })).toThrow(RangeError);
    expect(() => build({}, { searchAfter: [1, 'x'] })).toThrow(
      expect.objectContaining({ code: 'cursor_invalid' }),
    );
    expect(() =>
      buildArchiveSearchQuery({
        organizationId: 'acme',
        criteria: base,
        limit: 1,
        permissions: ALL,
      }),
    ).toThrow(/organization/);
  });

  it('search_after cursor helpers round-trip and refuse garbage', () => {
    const v: [number, string] = [1767225600000, MSG];
    expect(decodeSearchAfter(encodeSearchAfter(v))).toEqual(v);
    expect(searchAfterOfHit({ sort: v })).toEqual(v);
    expect(searchAfterOfHit({})).toBeNull();
    expect(parseSearchAfter([1.5, MSG])).toBeNull();
    expect(parseSearchAfter([-1, MSG])).toBeNull();
    for (const bad of ['', '1', 'x.y', `01.${MSG}`, `1.${MSG.toUpperCase()}`]) {
      expect(() => decodeSearchAfter(bad), bad).toThrow(ArchiveSearchQueryError);
    }
  });

  it('filter hash and names are stable and value-free', () => {
    const a = { ...base, senders: ['a@b.c'], directions: ['inbound' as const] };
    const b = { directions: ['inbound' as const], senders: ['a@b.c'], ...base };
    expect(searchFilterHash(a)).toBe(searchFilterHash(b));
    expect(searchFilterHash(a)).toMatch(/^[0-9a-f]{64}$/);
    expect(searchFilterNames({ ...a, subject: undefined })).toEqual([
      'directions',
      'from',
      'senders',
      'to',
    ]);
  });

  it('day count and purge queries are tenant-filtered', () => {
    expect(JSON.stringify(buildDayCountQuery(9, '2026-11-16'))).toContain('"org_id":"9"');
    expect(JSON.stringify(buildDayCountQuery(9, '2026-11-16'))).toContain(
      '2026-11-16T23:59:59.999Z',
    );
    expect(() => buildDayCountQuery(9, 'today')).toThrow(ArchiveSearchQueryError);
    expect(buildOrganizationPurgeQuery(9)).toEqual({
      query: { bool: { filter: [{ term: { org_id: '9' } }] } },
    });
  });
});
