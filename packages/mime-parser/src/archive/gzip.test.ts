import { describe, expect, it } from 'vitest';
import { buildGzip } from '../../test/zip-builders';
import { DEFAULT_MIME_LIMITS } from '../limits';
import { inspectGzip } from './gzip';

const inspect = (gzip: Buffer, limits = DEFAULT_MIME_LIMITS) =>
  inspectGzip(gzip.subarray(0, 4096), gzip.subarray(-8), gzip.length, limits);

describe('inspectGzip', () => {
  it('reads ISIZE and the ratio of an ordinary member', () => {
    const gzip = buildGzip(Buffer.from('hello world '.repeat(10)), { name: 'notes.txt' });
    expect(inspect(gzip)).toEqual({
      type: 'gzip',
      inspected: true,
      entries: 1,
      declaredUncompressedBytes: 120,
      maxRatio: Math.round((120 / gzip.length) * 100) / 100,
      encryptedEntries: 0,
      nestedArchives: 0,
      flags: [],
    });
  });

  it('flags a large ISIZE (ratio and total), as a hint only', () => {
    const gzip = buildGzip(Buffer.from('tiny'), { isize: 0xfffffff0 });
    const info = inspect(gzip);
    expect(info.flags).toEqual(['archive_compression_ratio', 'archive_total_size']);
    expect(info.declaredUncompressedBytes).toBe(0xfffffff0);
  });

  it('flags the ratio only above the limit', () => {
    const gzip = buildGzip(Buffer.alloc(100_000));
    const ratio = 100_000 / gzip.length;
    expect(
      inspect(gzip, { ...DEFAULT_MIME_LIMITS, archiveMaxRatio: Math.ceil(ratio) }).flags,
    ).toEqual([]);
    expect(
      inspect(gzip, { ...DEFAULT_MIME_LIMITS, archiveMaxRatio: Math.floor(ratio) }).flags,
    ).toEqual(['archive_compression_ratio']);
  });

  it('flags a nested archive named in FNAME, also behind FEXTRA', () => {
    expect(inspect(buildGzip(Buffer.from('t'), { name: 'backup.tar' })).flags).toEqual([
      'archive_nested',
    ]);
    expect(
      inspect(buildGzip(Buffer.from('t'), { name: 'x.zip', extra: Buffer.alloc(10) }))
        .nestedArchives,
    ).toBe(1);
    expect(
      inspect(buildGzip(Buffer.from('t'), { name: 'x.txt', extra: Buffer.alloc(10) })).flags,
    ).toEqual([]);
  });

  it('marks a truncated or foreign stream malformed', () => {
    expect(inspect(Buffer.from([0x1f, 0x8b, 0x08])).flags).toEqual(['archive_malformed']);
    expect(inspect(Buffer.alloc(40)).flags).toEqual(['archive_malformed']);
  });
});
