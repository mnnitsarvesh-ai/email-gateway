import fc from 'fast-check';
import { describe, expect, it } from 'vitest';
import { decodeRows, decodeTagged, encodeRows, encodeTagged, SnapshotCodecError } from './codec';
import { buildScanSnapshot, parseScanSnapshot, type ScanSnapshotRows } from './scan-snapshot';

class Decimal {
  constructor(readonly value: string) {}
}

function emptyRows(): ScanSnapshotRows {
  return {
    scan: null,
    policy: null,
    engines: [],
    auth: [],
    attachments: [],
    attachmentParts: [],
    sandboxSubmissions: [],
    sandboxAnalyses: [],
    sandboxArtifacts: [],
    urls: [],
    urlResults: [],
    urlRewrites: [],
    urlInspections: [],
    bec: [],
    dlp: [],
    risk: [],
  };
}

describe('tagged codec', () => {
  it('round-trips BigInt and Date losslessly and passes plain JSON', () => {
    const row = {
      id: 18446744073709551615n,
      negative: -5n,
      at: new Date('2026-11-16T10:15:00.123Z'),
      nested: { list: [1n, new Date(0), 'x', 2.5, null, true], empty: {} },
      skipped: undefined,
    };
    const tagged = encodeTagged(row);
    expect(tagged).toEqual({
      id: { $b: '18446744073709551615' },
      negative: { $b: '-5' },
      at: { $d: '2026-11-16T10:15:00.123Z' },
      nested: {
        list: [{ $b: '1' }, { $d: '1970-01-01T00:00:00.000Z' }, 'x', 2.5, null, true],
        empty: {},
      },
    });
    const { skipped: _skipped, ...expected } = row;
    expect(decodeTagged(tagged)).toEqual(expected);
    expect(decodeRows(encodeRows([row]))).toEqual([expected]);
    expect(decodeRows(Buffer.from(encodeRows({ a: 1 })))).toEqual({ a: 1 });
  });

  it('is lossless for arbitrary BigInt / Date / JSON trees (property)', () => {
    const leaf = fc.oneof(
      fc.bigInt(),
      fc.date({ min: new Date('1970-01-01Z'), max: new Date('9999-12-31Z'), noInvalidDate: true }),
      fc.string(),
      fc.double({ noNaN: true, noDefaultInfinity: true }).filter((n) => !Object.is(n, -0)),
      fc.boolean(),
      fc.constant(null),
    );
    const tree = fc.letrec((tie) => ({
      node: fc.oneof(
        { depthSize: 'small' },
        leaf,
        fc.array(tie('node'), { maxLength: 4 }),
        fc.dictionary(
          fc.string().filter((k) => k !== '$b' && k !== '$d' && k !== '__proto__'),
          tie('node'),
          {
            maxKeys: 4,
          },
        ),
      ),
    })).node;
    fc.assert(
      fc.property(tree, (value) => {
        expect(decodeRows(encodeRows(value))).toEqual(value);
      }),
      { numRuns: 200 },
    );
  });

  it.each([
    ['a Buffer', { b: Buffer.from('x') }, 'b'],
    ['a Uint8Array', { b: new Uint8Array(2) }, 'b'],
    ['a Decimal', { amount: new Decimal('1.5') }, 'amount'],
    ['a function', { f: () => 1 }, 'f'],
    ['a symbol', { s: Symbol('x') }, 's'],
    ['undefined in an array', { list: [1, undefined] }, 'list[1]'],
    ['NaN', { n: Number.NaN }, 'n'],
    ['Infinity', { n: Number.POSITIVE_INFINITY }, 'n'],
    ['an invalid Date', { d: new Date(Number.NaN) }, 'd'],
    ['a Map', { m: new Map() }, 'm'],
    ['an object that looks like a tag', { t: { $b: '1' } }, 't'],
  ])('refuses %s, naming the path only', (_name, value, path) => {
    try {
      encodeTagged(value);
      expect.fail('expected SnapshotCodecError');
    } catch (error) {
      expect(error).toBeInstanceOf(SnapshotCodecError);
      expect((error as SnapshotCodecError).path).toBe(path);
    }
  });

  it('refuses cycles and malformed tags', () => {
    const a: Record<string, unknown> = {};
    a.self = a;
    expect(() => encodeTagged(a)).toThrow(SnapshotCodecError);
    for (const bad of [
      { $b: 'x' },
      { $b: 1 },
      { $b: '01' },
      { $d: '2026-11-16' },
      { $d: '2026-02-30T00:00:00.000Z' },
      { $d: 5 },
    ]) {
      expect(() => decodeTagged(bad), JSON.stringify(bad)).toThrow(SnapshotCodecError);
    }
    expect(() => decodeRows('{not json')).toThrow(SnapshotCodecError);
    // Objects with a tag key plus other keys are plain objects.
    expect(decodeTagged({ $b: '1', other: 2 })).toEqual({ $b: '1', other: 2 });
  });
});

describe('archive-scan/1 snapshots', () => {
  it('builds and parses back the read-model rows (BigInt and Date preserved)', () => {
    const rows = emptyRows();
    rows.scan = {
      id: 99n,
      round: 1,
      startedAt: new Date('2026-11-16T10:00:00.000Z'),
      status: 'completed',
    };
    rows.engines = [{ id: 1n, engine: 'clamav', outcome: 'timeout', durationMs: 30000 }];
    rows.risk = [{ revision: 0, score: 120, computedAt: new Date('2026-11-16T10:00:05.000Z') }];
    rows.policy = { id: 5n, actions: [{ type: 'ARCHIVE', status: 'requested' }] };
    const frozenAt = new Date('2026-11-16T10:17:00.000Z');
    const { document, bytes } = buildScanSnapshot({
      organizationId: '42',
      messageId: '0190a5d0-0000-7000-8000-0000000000aa',
      round: 1,
      revision: 0,
      frozenAt,
      rows,
    });
    expect(document.version).toBe('archive-scan/1');
    expect(document.rows.scan).toMatchObject({ id: { $b: '99' } });
    const parsed = parseScanSnapshot(bytes);
    expect(parsed.frozenAt).toEqual(frozenAt);
    expect(parsed.rows).toEqual(rows);
    // A scanner failure is copied verbatim, never turned into a clean result.
    expect(parsed.rows.engines[0]).toMatchObject({ outcome: 'timeout' });
  });

  it('refuses invalid rows and documents', () => {
    const rows = emptyRows();
    rows.engines = [{ blob: Buffer.from('x') }];
    expect(() =>
      buildScanSnapshot({
        organizationId: '42',
        messageId: '0190a5d0-0000-7000-8000-0000000000aa',
        round: 1,
        revision: 0,
        frozenAt: new Date(),
        rows,
      }),
    ).toThrow(SnapshotCodecError);
    expect(() =>
      buildScanSnapshot({
        organizationId: 'org',
        messageId: 'x',
        round: 1,
        revision: 0,
        frozenAt: new Date(),
        rows: emptyRows(),
      }),
    ).toThrow(/archive-scan\/1/);
    expect(() => parseScanSnapshot('{}')).toThrow(/archive-scan\/1/);
    expect(() => parseScanSnapshot('not json')).toThrow(/archive-scan\/1/);
    const ok = buildScanSnapshot({
      organizationId: '42',
      messageId: '0190a5d0-0000-7000-8000-0000000000aa',
      round: 1,
      revision: 0,
      frozenAt: new Date(),
      rows: emptyRows(),
    }).document;
    const broken = { ...ok, rows: { ...ok.rows, engines: [{ id: { $b: 'nope' } }] } };
    expect(() => parseScanSnapshot(JSON.stringify(broken))).toThrow(/archive-scan\/1/);
    expect(() =>
      parseScanSnapshot(JSON.stringify({ ...ok, rows: { ...ok.rows, body: [] } })),
    ).toThrow();
  });
});
