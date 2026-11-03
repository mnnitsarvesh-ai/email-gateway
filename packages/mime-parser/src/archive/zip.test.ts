import { describe, expect, it } from 'vitest';
import { buildZip, markEncrypted, overlapEntries, renameEntry } from '../../test/zip-builders';
import { DEFAULT_MIME_LIMITS, type MimeLimits } from '../limits';
import type { StoredPart } from '../types';
import { inspectZip, ZIP_TAIL_BYTES } from './zip';

interface Recorded extends StoredPart {
  ranges: [number, number][];
}

function stored(data: Buffer, failWith?: Error): Recorded {
  const ranges: [number, number][] = [];
  return {
    key: 'zip',
    ranges,
    readRange(start: number, end: number): Promise<Buffer> {
      ranges.push([start, end]);
      if (failWith) return Promise.reject(failWith);
      return Promise.resolve(data.subarray(start, end + 1));
    },
  };
}

const signal = new AbortController().signal;
const inspect = (data: Buffer, limits: Partial<MimeLimits> = {}, part = stored(data)) =>
  inspectZip(part, data.length, { ...DEFAULT_MIME_LIMITS, ...limits }, signal);

describe('inspectZip', () => {
  it('reads the central directory of a clean zip from one tail fetch', async () => {
    const zip = await buildZip([
      { name: 'a.txt', data: Buffer.from('hello hello hello') },
      { name: 'dir/b.pdf', data: Buffer.from('%PDF-1.4') },
    ]);
    const part = stored(zip);
    const info = await inspect(zip, {}, part);
    expect(info).toMatchObject({
      type: 'zip',
      inspected: true,
      entries: 2,
      encryptedEntries: 0,
      nestedArchives: 0,
      flags: [],
    });
    expect(info.declaredUncompressedBytes).toBe(25);
    expect(part.ranges).toEqual([[0, zip.length - 1]]);
  });

  it('flags a deflated 200 MiB of zeros (ratio) with two bounded fetches and no entry data read', async () => {
    const zip = await buildZip([{ name: 'zeros.bin', zeros: 200 * 1024 * 1024 }]);
    expect(zip.length).toBeGreaterThan(ZIP_TAIL_BYTES);
    const part = stored(zip);
    const info = await inspect(zip, {}, part);
    expect(info.flags).toEqual(['archive_compression_ratio']);
    expect(info.maxRatio).toBeGreaterThan(100);
    expect(info.declaredUncompressedBytes).toBe(200 * 1024 * 1024);
    // One bounded fetch of the tail; the compressed data before it is never read.
    expect(part.ranges).toEqual([[zip.length - ZIP_TAIL_BYTES, zip.length - 1]]);
  });

  it('fetches a central directory larger than the tail as a second bounded range', async () => {
    const entries = Array.from({ length: 600 }, (_, index) => ({
      name: `${String(index).padStart(4, '0')}-${'n'.repeat(100)}.txt`,
      data: Buffer.from('x'),
    }));
    const zip = await buildZip(entries);
    const part = stored(zip);
    const info = await inspect(zip, {}, part);
    expect(info).toMatchObject({ inspected: true, entries: 600, flags: [] });
    expect(part.ranges).toHaveLength(2);
    const [tail, directory] = part.ranges;
    expect(tail).toEqual([zip.length - ZIP_TAIL_BYTES, zip.length - 1]);
    const directoryStart = zip.indexOf('PK\x01\x02', 0, 'latin1');
    expect(directory?.[0]).toBe(directoryStart);
    expect((directory?.[1] ?? 0) - directoryStart + 1).toBeLessThan(zip.length - directoryStart);
  });

  it('flags the ratio threshold only above the limit', async () => {
    const zip = await buildZip([{ name: 'zeros.bin', zeros: 100_000 }]);
    const info = await inspect(zip);
    const ratio = info.maxRatio ?? 0;
    expect((await inspect(zip, { archiveMaxRatio: Math.floor(ratio) })).flags).toContain(
      'archive_compression_ratio',
    );
    expect((await inspect(zip, { archiveMaxRatio: Math.ceil(ratio) })).flags).not.toContain(
      'archive_compression_ratio',
    );
  });

  it('flags the declared total above the limit', async () => {
    const zip = await buildZip([
      { name: 'a.bin', data: Buffer.alloc(600), compress: false },
      { name: 'b.bin', data: Buffer.alloc(400), compress: false },
    ]);
    expect((await inspect(zip, { archiveMaxTotalUncompressedBytes: 1000 })).flags).toEqual([]);
    expect((await inspect(zip, { archiveMaxTotalUncompressedBytes: 999 })).flags).toEqual([
      'archive_total_size',
    ]);
  });

  it('stops after max entries + 1 (entry-count bomb)', async () => {
    const entries = Array.from({ length: 1001 }, (_, index) => ({
      name: `f${index}.txt`,
      data: Buffer.from('x'),
    }));
    const bomb = await buildZip(entries);
    const info = await inspect(bomb);
    expect(info.flags).toEqual(['archive_entry_count']);
    expect(info.entries).toBe(1001);
    const atLimit = await buildZip(entries.slice(0, 1000));
    expect((await inspect(atLimit)).flags).toEqual([]);
  });

  it('flags encrypted entries (general-purpose bit 0)', async () => {
    const zip = markEncrypted(await buildZip([{ name: 'secret.txt', data: Buffer.from('s') }]));
    const info = await inspect(zip);
    expect(info.flags).toEqual(['archive_encrypted']);
    expect(info.encryptedEntries).toBe(1);
  });

  it('flags overlapping entries (Fifield non-recursive bomb)', async () => {
    const zip = overlapEntries(
      await buildZip([
        { name: 'a.txt', data: Buffer.from('a'.repeat(100)) },
        { name: 'b.txt', data: Buffer.from('b'.repeat(100)) },
      ]),
    );
    expect((await inspect(zip)).flags).toEqual(['archive_overlapping_entries']);
  });

  it('flags nested archives by entry extension', async () => {
    const inner = await buildZip([{ name: 'x.txt', data: Buffer.from('x') }]);
    const zip = await buildZip([
      { name: 'inner.zip', data: inner },
      { name: 'logs/backup.tar.gz', data: Buffer.from('not really') },
      { name: 'readme.txt', data: Buffer.from('r') },
    ]);
    const info = await inspect(zip);
    expect(info.flags).toEqual(['archive_nested']);
    expect(info.nestedArchives).toBe(2);
  });

  it('flags path traversal names without yauzl rejecting the archive', async () => {
    for (const [from, to] of [
      ['aa/evil.txt', '../evil.txt'],
      ['aetc/passwd', '/etc/passwd'],
      ['aa/x.exe', 'C:\\x.exe'],
    ] as const) {
      const zip = renameEntry(
        await buildZip([
          { name: from, data: Buffer.from('x') },
          { name: 'ok.txt', data: Buffer.from('y') },
        ]),
        from,
        to,
      );
      const info = await inspect(zip);
      expect(info.flags, to).toEqual(['archive_path_traversal']);
      expect(info.inspected).toBe(true);
    }
  });

  it('reads zip64 archives', async () => {
    const zip = await buildZip([{ name: 'a.txt', data: Buffer.from('hello') }], { zip64: true });
    expect(await inspect(zip)).toMatchObject({ inspected: true, entries: 1, flags: [] });
  });

  it('marks garbage and truncated archives malformed', async () => {
    const garbage = Buffer.concat([Buffer.from('PK\x03\x04', 'latin1'), Buffer.alloc(100, 7)]);
    expect((await inspect(garbage)).flags).toEqual(['archive_malformed']);
    expect((await inspect(Buffer.from('PK\x03\x04', 'latin1'))).flags).toEqual([
      'archive_malformed',
    ]);
    const zip = await buildZip([{ name: 'a.txt', data: Buffer.from('a') }]);
    const broken = Buffer.from(zip);
    const directory = broken.indexOf('PK\x01\x02', 0, 'latin1');
    broken.write('XX', directory, 'latin1');
    expect((await inspect(broken)).flags).toEqual(['archive_malformed']);
  });

  it('does not inspect a central directory above the limit', async () => {
    const zip = await buildZip(
      Array.from({ length: 20 }, (_, index) => ({
        name: `entry-${index}.txt`,
        data: Buffer.from('x'),
      })),
    );
    const info = await inspect(zip, { archiveMaxCentralDirectoryBytes: 100 });
    expect(info).toMatchObject({
      inspected: false,
      entries: null,
      flags: ['archive_not_inspected'],
    });
  });

  it('rethrows readRange errors unchanged', async () => {
    const zip = await buildZip([{ name: 'a.txt', data: Buffer.from('a') }]);
    const failure = new Error('S3 unavailable');
    await expect(inspect(zip, {}, stored(zip, failure))).rejects.toBe(failure);
  });

  it('honours an aborted signal', async () => {
    const zip = await buildZip([{ name: 'a.txt', data: Buffer.from('a') }]);
    const controller = new AbortController();
    controller.abort(new Error('timeout'));
    await expect(
      inspectZip(stored(zip), zip.length, DEFAULT_MIME_LIMITS, controller.signal),
    ).rejects.toThrow('timeout');
  });
});
