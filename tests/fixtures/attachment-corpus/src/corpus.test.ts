import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { Readable } from 'node:stream';
import { gunzipSync, inflateRawSync } from 'node:zlib';
import { extract } from 'tar-stream';
import { describe, expect, it } from 'vitest';
import {
  absolutePathZip,
  aesEncryptedZip,
  badTarChecksum,
  docmLike,
  docxLike,
  docxTemplateInjection,
  EICAR_SHA256,
  eicar,
  encryptedZip,
  fake7z,
  fakeBzip2,
  fakeCab,
  fakeRar,
  fakeXz,
  gzip,
  highRatioFile,
  htmlSmuggling,
  largeFile,
  lnkWithCommandTarget,
  malformedZip,
  manyEntriesZip,
  multiMemberGzip,
  mzWithoutPe,
  nestedZip,
  overlappingZip,
  pathTraversalZip,
  pdfLike,
  peStub,
  powershellEncoded,
  tar,
  tgz,
  truncatedGzip,
  truncatedPdf,
  truncatedZip,
  YARA_TEST_MARKERS,
  yaraHigh,
  yaraMedium,
  zip,
  zipBomb,
  zipLayout,
} from './index';

const MiB = 1024 * 1024;

interface CentralEntry {
  name: string;
  flags: number;
  method: number;
  compressedSize: number;
  uncompressedSize: number;
  localHeaderOffset: number;
  extra: Buffer;
}

/** Central directory of a zip (test-only reader; the inspector uses yauzl). */
function centralEntries(buffer: Buffer): CentralEntry[] {
  const { directoryOffset, directorySize } = zipLayout(buffer);
  const entries: CentralEntry[] = [];
  let at = directoryOffset;
  while (at < directoryOffset + directorySize) {
    expect(buffer.readUInt32LE(at)).toBe(0x02014b50);
    const nameLength = buffer.readUInt16LE(at + 28);
    const extraLength = buffer.readUInt16LE(at + 30);
    const commentLength = buffer.readUInt16LE(at + 32);
    entries.push({
      flags: buffer.readUInt16LE(at + 8),
      method: buffer.readUInt16LE(at + 10),
      compressedSize: buffer.readUInt32LE(at + 20),
      uncompressedSize: buffer.readUInt32LE(at + 24),
      localHeaderOffset: buffer.readUInt32LE(at + 42),
      name: buffer.toString('utf8', at + 46, at + 46 + nameLength),
      extra: buffer.subarray(at + 46 + nameLength, at + 46 + nameLength + extraLength),
    });
    at += 46 + nameLength + extraLength + commentLength;
  }
  return entries;
}

/** Data of one entry (stored or deflated). */
function entryData(buffer: Buffer, entry: CentralEntry): Buffer {
  const at = entry.localHeaderOffset;
  const start = at + 30 + buffer.readUInt16LE(at + 26) + buffer.readUInt16LE(at + 28);
  const raw = buffer.subarray(start, start + entry.compressedSize);
  return entry.method === 8 ? inflateRawSync(raw) : Buffer.from(raw);
}

async function tarNames(buffer: Buffer): Promise<string[]> {
  const names: string[] = [];
  const reader = extract();
  const done = new Promise<void>((resolve, reject) => {
    reader.on('entry', (header, stream, next) => {
      names.push(header.name);
      stream.on('end', next);
      stream.resume();
    });
    reader.on('finish', resolve);
    reader.on('error', reject);
  });
  Readable.from([buffer]).pipe(reader);
  await done;
  return names;
}

const sha256 = (data: Buffer) => createHash('sha256').update(data).digest('hex');

describe('eicar', () => {
  it('builds the 68-byte EICAR file with its known SHA-256', () => {
    const file = eicar();
    expect(file).toHaveLength(68);
    expect(sha256(file)).toBe(EICAR_SHA256);
    expect(sha256(file)).toBe('275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f');
  });

  it('never contains the full EICAR string verbatim in its source', () => {
    const source = readFileSync(join(__dirname, 'eicar.ts'), 'latin1');
    expect(source.includes(eicar().toString('latin1'))).toBe(false);
    expect(source.includes(eicar().toString('latin1').slice(0, 40))).toBe(false);
  });
});

describe('zip archives', () => {
  it('zip() lists the entries in order and round-trips the data', async () => {
    const archive = await zip([
      { name: 'eicar.com', data: eicar() },
      { name: 'stored.txt', data: Buffer.from('hello'), compress: false },
    ]);
    const entries = centralEntries(archive);
    expect(entries.map((e) => e.name)).toEqual(['eicar.com', 'stored.txt']);
    expect(entries.map((e) => e.method)).toEqual([8, 0]);
    expect(sha256(entryData(archive, entries[0]!))).toBe(EICAR_SHA256);
    // Deterministic: identical bytes on every call.
    expect(sha256(await zip([{ name: 'eicar.com', data: eicar() }]))).toBe(
      sha256(await zip([{ name: 'eicar.com', data: eicar() }])),
    );
  });

  it('nestedZip(depth) nests exactly depth zips around the inner file', async () => {
    let current = await nestedZip(4, { name: 'eicar.com', data: eicar() });
    for (let level = 1; level < 4; level += 1) {
      const [entry] = centralEntries(current);
      expect(entry?.name).toBe(`level-${level}.zip`);
      current = entryData(current, entry!);
    }
    const [inner] = centralEntries(current);
    expect(inner?.name).toBe('eicar.com');
    expect(sha256(entryData(current, inner!))).toBe(EICAR_SHA256);
    await expect(nestedZip(0, { name: 'x', data: Buffer.alloc(1) })).rejects.toThrow(RangeError);
  });

  it('zipBomb declares >= 50 MiB in well under 1 MiB', async () => {
    const bomb = await zipBomb();
    const [entry] = centralEntries(bomb);
    expect(entry?.uncompressedSize).toBe(64 * MiB);
    expect(bomb.length).toBeLessThan(1 * MiB);
    expect(entry!.uncompressedSize / entry!.compressedSize).toBeGreaterThan(500);
    await expect(zipBomb(10 * MiB)).rejects.toThrow(RangeError);
  });

  it('highRatioFile has a ratio above 100 and a small decompressed size', async () => {
    const [entry] = centralEntries(await highRatioFile());
    expect(entry!.uncompressedSize).toBe(4 * MiB);
    expect(entry!.uncompressedSize / entry!.compressedSize).toBeGreaterThan(100);
  });

  it('encrypted zips carry general purpose bit 0, the AES one also method 99 and 0x9901', () => {
    const [classic] = centralEntries(encryptedZip());
    expect(classic!.flags & 1).toBe(1);
    const [aes] = centralEntries(aesEncryptedZip());
    expect(aes!.flags & 1).toBe(1);
    expect(aes!.method).toBe(99);
    expect(aes!.extra.readUInt16LE(0)).toBe(0x9901);
    expect(aes!.extra.toString('latin1', 6, 8)).toBe('AE');
  });

  it('malformedZip has a central directory shorter than its end record claims', async () => {
    const broken = await malformedZip();
    const { endOffset, directoryOffset, directorySize } = zipLayout(broken);
    expect(directoryOffset + directorySize).toBeGreaterThan(endOffset);
    const truncated = await truncatedZip();
    expect(truncated).toHaveLength(20);
    expect(() => zipLayout(truncated)).toThrow();
  });

  it('pathTraversalZip, absolutePathZip and overlappingZip have the hostile layouts', () => {
    expect(centralEntries(pathTraversalZip()).map((e) => e.name)).toEqual([
      'readme.txt',
      '../../etc/evil.txt',
    ]);
    expect(centralEntries(absolutePathZip())[0]?.name).toBe('/tmp/evil.txt');
    const overlapping = centralEntries(overlappingZip());
    expect(overlapping.map((e) => e.localHeaderOffset)).toEqual([0, 0]);
    expect(overlapping.map((e) => e.name)).toEqual(['one.txt', 'two.txt']);
  });

  it('manyEntriesZip has exactly count entries', async () => {
    expect(centralEntries(await manyEntriesZip(1001))).toHaveLength(1001);
  });

  it('OOXML-like zips have the expected parts', async () => {
    const docx = centralEntries(await docxLike()).map((e) => e.name);
    expect(docx).toEqual(['[Content_Types].xml', '_rels/.rels', 'word/document.xml']);
    const docmZip = await docmLike();
    const docm = centralEntries(docmZip);
    expect(docm.map((e) => e.name)).toContain('word/vbaProject.bin');
    const injection = await docxTemplateInjection();
    const rels = centralEntries(injection).find((e) => e.name === 'word/_rels/settings.xml.rels');
    expect(entryData(injection, rels!).toString()).toContain('TargetMode="External"');
  });
});

describe('gzip and tar', () => {
  it('gzip, multi-member gzip and tgz decompress', async () => {
    expect(gunzipSync(gzip(eicar())).equals(eicar())).toBe(true);
    expect(gunzipSync(multiMemberGzip(Buffer.from('a'), Buffer.from('b'))).toString()).toBe('ab');
    const archive = await tgz([{ name: 'eicar.com', data: eicar() }]);
    expect(archive.subarray(0, 2)).toEqual(Buffer.from([0x1f, 0x8b]));
    expect(await tarNames(gunzipSync(archive))).toEqual(['eicar.com']);
  });

  it('tar() is a ustar archive of the entries', async () => {
    const archive = await tar([
      { name: 'a.txt', data: Buffer.from('a') },
      { name: 'dir/b.txt', data: Buffer.from('b') },
    ]);
    expect(archive.toString('latin1', 257, 262)).toBe('ustar');
    expect(archive.length % 512).toBe(0);
    expect(await tarNames(archive)).toEqual(['a.txt', 'dir/b.txt']);
  });

  it('truncatedGzip and badTarChecksum are malformed', async () => {
    expect(() => gunzipSync(truncatedGzip())).toThrow();
    await expect(tarNames(await badTarChecksum())).rejects.toThrow();
  });
});

describe('single files', () => {
  it('fake archive headers start with their magic', () => {
    expect(fake7z().subarray(0, 6)).toEqual(Buffer.from([0x37, 0x7a, 0xbc, 0xaf, 0x27, 0x1c]));
    expect(fakeRar().toString('latin1', 0, 4)).toBe('Rar!');
    expect(fakeXz().subarray(0, 6)).toEqual(Buffer.from([0xfd, 0x37, 0x7a, 0x58, 0x5a, 0x00]));
    expect(fakeBzip2().toString('latin1', 0, 3)).toBe('BZh');
    expect(fakeCab().toString('latin1', 0, 4)).toBe('MSCF');
    expect(fake7z(2048)).toHaveLength(2048);
  });

  it('peStub has MZ with e_lfanew pointing at PE\\0\\0; mzWithoutPe does not', () => {
    const pe = peStub();
    expect(pe.toString('latin1', 0, 2)).toBe('MZ');
    const lfanew = pe.readUInt32LE(0x3c);
    expect(pe.toString('latin1', lfanew, lfanew + 4)).toBe('PE\0\0');
    const mz = mzWithoutPe();
    const target = mz.readUInt32LE(0x3c);
    expect(mz.toString('latin1', target, target + 4)).not.toBe('PE\0\0');
  });

  it('YARA marker files contain their markers', () => {
    expect(yaraHigh().toString()).toContain(YARA_TEST_MARKERS.high);
    expect(yaraMedium().toString()).toContain(YARA_TEST_MARKERS.medium);
    expect(YARA_TEST_MARKERS.high).toBe('EG-YARA-TEST-HIGH-5f0c2e7a');
    expect(YARA_TEST_MARKERS.medium).toBe('EG-YARA-TEST-MEDIUM-8d41b9c3');
  });

  it('pdfLike and largeFile have exact sizes near the limits', () => {
    const below = 26_214_400 - 1;
    const pdf = pdfLike(below);
    expect(pdf).toHaveLength(below);
    expect(pdf.toString('latin1', 0, 5)).toBe('%PDF-');
    expect(pdf.toString('latin1', pdf.length - 6)).toBe('%%EOF\n');
    expect(largeFile(26_214_401)).toHaveLength(26_214_401);
    expect(sha256(largeFile(1000))).toBe(sha256(largeFile(1000)));
    expect(truncatedPdf(1000)).toHaveLength(500);
  });

  it('heuristic samples carry their indicators', () => {
    expect(htmlSmuggling().toString()).toContain('msSaveOrOpenBlob');
    expect(htmlSmuggling().length).toBeGreaterThan(12 * 1024);
    expect(powershellEncoded().toString()).toMatch(/-EncodedCommand [A-Za-z0-9+/=]{40,}/);
    const lnk = lnkWithCommandTarget();
    expect(lnk.readUInt32LE(0)).toBe(0x4c);
    expect(lnk.includes(Buffer.from('cmd.exe', 'utf16le'))).toBe(true);
  });
});
