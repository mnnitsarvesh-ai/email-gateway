import { createHash } from 'node:crypto';
import { describe, expect, it } from 'vitest';
import { addrSpecOf, reporterAddressOf } from './report-intake';
import { reportIngestKey, reportOriginalObjectKey } from './report-original.repository';

describe('reporter address (C9.2)', () => {
  it('takes the addr-spec of a header value, lower case', () => {
    expect(addrSpecOf('Alex Example <Alex@Contoso-IT.example>')).toBe('alex@contoso-it.example');
    expect(addrSpecOf(' blake@contoso-it.example ')).toBe('blake@contoso-it.example');
    expect(addrSpecOf('no address')).toBeNull();
    expect(addrSpecOf('broken@')).toBeNull();
    expect(addrSpecOf(null)).toBeNull();
  });

  it('prefers the header From, else the envelope sender, else empty', () => {
    expect(reporterAddressOf('A <a@x.example>', 'bounce@x.example')).toBe('a@x.example');
    expect(reporterAddressOf(null, 'Bounce@X.example')).toBe('bounce@x.example');
    expect(reporterAddressOf('', '')).toBe('');
  });
});

describe('report original identifiers (C10.4, §5)', () => {
  const reportId = '0193b000-0000-7000-8000-0000000000aa';

  it('ingest key: v2:rpt: + SHA-256 of the report public id', () => {
    const key = reportIngestKey(reportId);
    expect(key).toBe(`v2:rpt:${createHash('sha256').update(reportId).digest('hex')}`);
    expect(key.length).toBeLessThanOrEqual(128);
  });

  it('object key: the organization EML layout with a deterministic reference', () => {
    const at = new Date('2026-11-27T08:00:00.000Z');
    const key = reportOriginalObjectKey(41n, reportId, at);
    expect(key).toMatch(/^org\/41\/eml\/2026\/11\/27\/[0-9a-f]{32}\.eml$/);
    expect(reportOriginalObjectKey(41n, reportId, at)).toBe(key);
    expect(reportOriginalObjectKey(42n, reportId, at)).not.toBe(key.replace('org/41', 'org/42'));
  });
});
