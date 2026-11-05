import * as corpus from '@email-gateway/attachment-corpus';
import { beforeAll, describe, expect, it } from 'vitest';
import type { InspectLimits } from '../content';
import { BUNDLED_RULES_DIR } from './bundle';
import { inspectBytes, isTraversalName } from './inspect';
import { type YaraEngine, YaraXScanner } from './yara-scanner';

const LIMITS: InspectLimits = {
  archiveMaxDepth: 3,
  archiveMaxEntries: 1000,
  maxEntryBytes: 26_214_400,
  maxDecompressedBytes: 104_857_600,
  maxCompressionRatio: 100,
  maxEntryFindings: 20,
  yaraTimeoutMs: 10_000,
  cpuSeconds: 10,
  maxRssMb: 384,
};

let yara: YaraEngine;
beforeAll(() => {
  yara = new YaraXScanner(BUNDLED_RULES_DIR, 10_000);
});

const inspect = (bytes: Buffer, limits: Partial<InspectLimits> = {}) =>
  inspectBytes(bytes, { ...LIMITS, ...limits }, yara);

const MiB = 1024 * 1024;

describe('attachment inspection (step 4.2 A4)', () => {
  it('reports the type, the bundle and no finding for plain files', async () => {
    const result = await inspect(corpus.pdfLike());
    expect(result).toMatchObject({
      inspectorVersion: 'att-inspect/1',
      type: { detected: 'pdf', family: 'document', executable: false, textLike: false },
      yara: { bundleId: yara.bundleId, matches: [] },
      archive: null,
      limits: [],
      codes: [],
    });
  });

  it('walks zip, gzip, tar and tgz and hashes every entry by index path', async () => {
    const zip = await inspect(
      await corpus.zip([
        { name: 'a.txt', data: Buffer.from('a\n') },
        { name: 'b/c.pdf', data: corpus.pdfLike(4096) },
      ]),
    );
    expect(zip.type.detected).toBe('zip');
    expect(zip.archive).toMatchObject({
      format: 'zip',
      supported: true,
      entries: 2,
      depthReached: 1,
    });
    expect(zip.archive!.entryHashes.map((e) => [e.path, e.type, e.ext])).toEqual([
      ['0', 'text', 'text'],
      ['1', 'pdf', 'pdf'],
    ]);
    const gz = await inspect(corpus.gzip(corpus.yaraMedium()));
    expect(gz.archive).toMatchObject({ format: 'gzip', entries: 1 });
    expect(gz.yara!.matches).toEqual([
      { rule: 'EG_Test_Marker_Medium', severity: 'medium', scope: '0' },
    ]);
    const multi = await inspect(
      corpus.multiMemberGzip(Buffer.from('first\n'), Buffer.from('second\n')),
    );
    expect(multi.archive!.decompressedBytes).toBe(13);
    const tar = await inspect(await corpus.tar([{ name: 'n.txt', data: corpus.yaraHigh() }]));
    expect(tar.archive).toMatchObject({ format: 'tar', entries: 1 });
    expect(tar.yara!.matches.map((m) => m.scope)).toContain('0');
    const tgz = await inspect(await corpus.tgz([{ name: 'x/m.txt', data: corpus.yaraHigh() }]));
    // gzip → tar counts as two levels (A4).
    expect(tgz.archive).toMatchObject({ format: 'gzip', depthReached: 2, entries: 2 });
    expect(tgz.yara!.matches.map((m) => m.scope)).toContain('0/0');
  });

  it('stops at the depth limit but still inspects the entry that holds the deeper level', async () => {
    const depth2 = await inspect(
      await corpus.nestedZip(2, { name: 'x.txt', data: corpus.yaraHigh() }),
    );
    expect(depth2.limits).toEqual([]);
    expect(depth2.yara!.matches.map((m) => m.scope)).toEqual(['0/0']);
    const depth4 = await inspect(
      await corpus.nestedZip(4, { name: 'x.txt', data: corpus.yaraHigh() }),
    );
    expect(depth4.limits).toContain('limit.archive_depth');
    expect(depth4.archive!.depthReached).toBe(3);
    expect(depth4.archive!.findings).toContainEqual({
      path: '0/0/0',
      type: 'zip',
      codes: ['limit.archive_depth'],
    });
  });

  it('enforces the entry count, entry size, decompressed total and ratio limits while inflating', async () => {
    const many = await inspect(await corpus.manyEntriesZip(1001));
    expect(many.limits).toContain('limit.archive_entries');
    expect(many.archive!.entries).toBe(1000);
    const bomb = await inspect(await corpus.zipBomb());
    expect(bomb.limits).toContain('limit.compression_ratio');
    // Stopped early: the declared ratio refuses the entry before any inflate.
    expect(bomb.archive!.decompressedBytes).toBeLessThan(MiB);
    const ratio = await inspect(await corpus.highRatioFile());
    expect(ratio.limits).toEqual(['limit.compression_ratio']);
    const entry = await inspect(
      await corpus.zip([{ name: 'r.bin', data: corpus.largeFile(2 * MiB) }]),
      { maxEntryBytes: MiB, maxDecompressedBytes: 4 * MiB },
    );
    expect(entry.limits).toContain('limit.entry_size');
    const total = await inspect(
      await corpus.zip([
        { name: 'a.bin', data: corpus.largeFile(600 * 1024, 1) },
        { name: 'b.bin', data: corpus.largeFile(600 * 1024, 2) },
      ]),
      { maxDecompressedBytes: MiB },
    );
    expect(total.limits).toContain('limit.decompressed_size');
    expect(total.archive!.decompressedBytes).toBeLessThanOrEqual(MiB + 70_000);
    // A lying declared size: the counters stop the inflate at the first breach.
    const lying = corpus.buildRawZip([
      { ...corpus.rawEntry('z.bin', Buffer.alloc(8 * MiB)), uncompressedSize: 1000 },
    ]);
    const lied = await inspect(lying, { maxEntryBytes: MiB });
    expect(
      [...lied.limits, ...lied.codes].some(
        (c) =>
          c === 'limit.entry_size' || c === 'limit.compression_ratio' || c === 'archive.malformed',
      ),
    ).toBe(true);
  });

  it('marks encrypted entries by every marker without inflating them', async () => {
    const classic = await inspect(corpus.encryptedZip());
    expect(classic.codes).toContain('archive.encrypted');
    expect(classic.archive!.encrypted).toBe(true);
    const aes = await inspect(corpus.aesEncryptedZip());
    expect(aes.codes).toContain('archive.encrypted');
    const strong = corpus.buildRawZip([
      { ...corpus.rawEntry('s.txt', Buffer.from('x')), flags: 0x0040 },
    ]);
    expect((await inspect(strong)).codes).toContain('archive.encrypted');
  });

  it('reports malformed, truncated, traversing and overlapping archives', async () => {
    expect((await inspect(await corpus.malformedZip())).codes).toContain('archive.malformed');
    expect((await inspect(await corpus.truncatedZip())).codes).toContain('archive.malformed');
    expect((await inspect(corpus.truncatedGzip(corpus.largeFile(64 * 1024)))).codes).toContain(
      'archive.malformed',
    );
    expect((await inspect(await corpus.badTarChecksum())).codes).toContain('archive.malformed');
    const crc = corpus.buildRawZip([
      { ...corpus.rawEntry('c.txt', Buffer.from('content')), crc: 1 },
    ]);
    expect((await inspect(crc)).codes).toContain('archive.malformed');
    const traversal = await inspect(corpus.pathTraversalZip());
    expect(traversal.codes).toContain('archive.path_traversal');
    expect(traversal.archive!.findings).toContainEqual({
      path: '1',
      type: 'text',
      codes: ['archive.path_traversal'],
    });
    expect((await inspect(corpus.absolutePathZip())).codes).toContain('archive.path_traversal');
    expect((await inspect(corpus.overlappingZip())).codes).toContain('archive.overlapping_entries');
    expect(isTraversalName('a/../../b')).toBe(true);
    expect(isTraversalName('C:\\x')).toBe(true);
    expect(isTraversalName('a/b..c/d')).toBe(false);
  });

  it('records 7z, rar, xz, bzip2 and cab as unsupported (rule U1)', async () => {
    for (const bytes of [
      corpus.fake7z(),
      corpus.fakeRar(),
      corpus.fakeXz(),
      corpus.fakeBzip2(),
      corpus.fakeCab(),
    ]) {
      const result = await inspect(bytes);
      expect(result.codes).toEqual(['archive.unsupported_format']);
      expect(result.archive).toMatchObject({ supported: false, entries: 0 });
    }
    const nested = await inspect(await corpus.zip([{ name: 'in.7z', data: corpus.fake7z() }]));
    expect(nested.archive!.findings).toContainEqual({
      path: '0',
      type: '7z',
      codes: ['archive.unsupported_format'],
    });
  });

  it('sub-types OOXML, sets the macro marker and scans decompressed parts with YARA', async () => {
    expect((await inspect(await corpus.docxLike())).type.detected).toBe('ooxml_word');
    const docm = await inspect(await corpus.docmLike());
    expect(docm.type.detected).toBe('ooxml_macro');
    expect(docm.codes).toContain('office.macros');
    const template = await inspect(await corpus.docxTemplateInjection());
    expect(template.yara!.matches).toContainEqual({
      rule: 'EG_Heuristic_OOXML_External_Template',
      severity: 'medium',
      scope: '3',
    });
  });

  it('flags a disguised executable inside an archive by its entry name only', async () => {
    const result = await inspect(
      await corpus.zip([{ name: 'invoice.pdf', data: corpus.peStub() }]),
    );
    expect(result.archive!.findings).toContainEqual({
      path: '0',
      type: 'pe_executable',
      codes: ['type.executable_disguised'],
    });
    expect(result.archive!.entryHashes[0]).toMatchObject({ type: 'pe_executable', ext: 'pdf' });
  });

  it('runs the bundled heuristics on the attachment (YARA, A9)', async () => {
    expect((await inspect(corpus.htmlSmuggling())).yara!.matches[0]).toMatchObject({
      rule: 'EG_Heuristic_HTML_Smuggling',
      scope: 'attachment',
    });
    expect((await inspect(corpus.powershellEncoded())).yara!.matches[0]!.rule).toBe(
      'EG_Heuristic_PowerShell_EncodedCommand',
    );
    expect((await inspect(corpus.lnkWithCommandTarget())).yara!.matches[0]!.rule).toBe(
      'EG_Heuristic_LNK_Command_Interpreter',
    );
    expect((await inspect(corpus.cleanHtml())).yara!.matches).toEqual([]);
  });

  it('scans only the first ATTACHMENT_MAX_ENTRY_BYTES of a larger attachment and says so', async () => {
    const result = await inspect(corpus.largeFile(2 * MiB), { maxEntryBytes: MiB });
    expect(result.limits).toEqual(['limit.entry_size']);
  });

  it('reports a YARA timeout as a limit, never as clean', async () => {
    const slow: YaraEngine = {
      bundleId: yara.bundleId,
      ruleCount: 1,
      yaraXVersion: '0',
      scan: () => ({ matches: [], timedOut: true }),
    };
    const result = await inspectBytes(corpus.pdfLike(), LIMITS, slow);
    expect(result.limits).toEqual(['limit.yara_timeout']);
  });

  it('keeps at most maxEntryFindings findings and counts the rest', async () => {
    const entries = Array.from({ length: 30 }, (_, i) => ({
      name: `../x${String(i)}.txt`,
      data: Buffer.from('x'),
    }));
    const raw = corpus.buildRawZip(entries.map((e) => corpus.rawEntry(e.name, e.data)));
    const result = await inspect(raw, { maxEntryFindings: 5 });
    expect(result.archive!.findings).toHaveLength(5);
    expect(result.archive!.findingCount).toBe(30);
  });

  it('never keeps an entry name in its result', async () => {
    const secret = 'Confidential-Merger-Plan-2026.docx';
    const result = await inspect(await corpus.zip([{ name: secret, data: corpus.peStub() }]));
    expect(JSON.stringify(result)).not.toContain('Confidential');
  });
});
