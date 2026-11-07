import * as corpus from '@email-gateway/attachment-corpus';
import type { FileTypeId } from '@email-gateway/security-contracts';
import { beforeAll, describe, expect, it } from 'vitest';
import type { InspectLimits } from '../content';
import { BUNDLED_RULES_DIR } from './bundle';
import { type EntryVisitor, inspectBytes } from './inspect';
import { NOOP_YARA_ENGINE, type YaraEngine } from './yara-engine';
import { YaraXScanner } from './yara-scanner';

/**
 * The shared walker's entry visitor (step 4.5 D4): it observes every inspected entry and never
 * changes the 4.2 inspection result (INSPECTOR_VERSION and the content version unchanged).
 */
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

interface Visited {
  path: string;
  depth: number;
  type: FileTypeId;
  ext: FileTypeId | null;
  name: string | null;
  bytes: number;
}

function recorder(): { visited: Visited[]; onEntry: EntryVisitor } {
  const visited: Visited[] = [];
  return {
    visited,
    onEntry: async (data, path, depth, type, ext, name) => {
      // An async visitor (the extractor awaits format extraction) must not change the walk.
      await new Promise((resolve) => setImmediate(resolve));
      visited.push({ path, depth, type, ext, name, bytes: data.length });
    },
  };
}

async function fixtures(): Promise<Array<[string, Buffer]>> {
  return [
    ['plain pdf', corpus.pdfLike()],
    ['eicar', corpus.eicar()],
    [
      'zip',
      await corpus.zip([
        { name: 'a.txt', data: Buffer.from('a\n') },
        { name: 'b/c.pdf', data: corpus.pdfLike(4096) },
        { name: 'm.txt', data: corpus.yaraHigh() },
      ]),
    ],
    ['nested zip depth 3', await corpus.nestedZip(3, { name: 'x.txt', data: corpus.yaraMedium() })],
    ['nested zip depth 5', await corpus.nestedZip(5, { name: 'x.txt', data: Buffer.from('x') })],
    ['gzip', corpus.gzip(corpus.yaraMedium())],
    ['multi-member gzip', corpus.multiMemberGzip(Buffer.from('a\n'), Buffer.from('b\n'))],
    ['tar', await corpus.tar([{ name: 'n.txt', data: corpus.yaraHigh() }])],
    ['tgz', await corpus.tgz([{ name: 'x/m.txt', data: Buffer.from('m') }])],
    ['docx', await corpus.docxLike()],
    ['docm', await corpus.docmLike()],
    ['encrypted zip', corpus.encryptedZip()],
    ['aes zip', corpus.aesEncryptedZip()],
    ['malformed zip', await corpus.malformedZip()],
    ['truncated zip', await corpus.truncatedZip()],
    ['path traversal', corpus.pathTraversalZip()],
    ['overlapping', corpus.overlappingZip()],
    ['many entries', await corpus.manyEntriesZip(40)],
    ['zip bomb', await corpus.zipBomb()],
    ['high ratio', await corpus.highRatioFile()],
    ['7z', corpus.fake7z()],
  ];
}

describe('shared walker entry visitor (step 4.5 D4)', () => {
  it('leaves the inspection result byte-identical with and without a visitor', async () => {
    for (const [label, bytes] of await fixtures()) {
      const limits = label === 'many entries' ? { ...LIMITS, archiveMaxEntries: 25 } : LIMITS;
      const plain = await inspectBytes(bytes, limits, yara);
      const { onEntry } = recorder();
      const visited = await inspectBytes(bytes, limits, yara, { onEntry });
      expect(JSON.stringify(visited), label).toBe(JSON.stringify(plain));
    }
  });

  it('visits every inspected entry with its index path, depth, refined type and name', async () => {
    const { visited, onEntry } = recorder();
    const result = await inspectBytes(
      await corpus.zip([
        { name: 'a.txt', data: Buffer.from('a\n') },
        { name: 'b/c.pdf', data: corpus.pdfLike(4096) },
      ]),
      LIMITS,
      yara,
      { onEntry },
    );
    expect(visited).toEqual([
      { path: '0', depth: 1, type: 'text', ext: 'text', name: 'a.txt', bytes: 2 },
      { path: '1', depth: 1, type: 'pdf', ext: 'pdf', name: 'b/c.pdf', bytes: 4096 },
    ]);
    // Exactly the entries the inspector hashed (the same reach as 4.2).
    expect(result.archive!.entryHashes.map((e) => e.path)).toEqual(visited.map((v) => v.path));
  });

  it('visits nested containers post-order, a gzip member without a name, tar names', async () => {
    const nested = recorder();
    await inspectBytes(
      await corpus.zip([
        {
          name: 'inner.zip',
          data: await corpus.zip([{ name: 'deep.csv', data: Buffer.from('h\n1\n') }]),
        },
      ]),
      LIMITS,
      NOOP_YARA_ENGINE,
      { onEntry: nested.onEntry },
    );
    expect(nested.visited.map((v) => [v.path, v.depth, v.type, v.name])).toEqual([
      ['0/0', 2, 'text', 'deep.csv'],
      ['0', 1, 'zip', 'inner.zip'],
    ]);

    const tgz = recorder();
    await inspectBytes(
      await corpus.tgz([{ name: 'x/m.txt', data: Buffer.from('m') }]),
      LIMITS,
      NOOP_YARA_ENGINE,
      { onEntry: tgz.onEntry },
    );
    expect(tgz.visited.map((v) => [v.path, v.depth, v.type, v.name])).toEqual([
      ['0/0', 2, 'text', 'x/m.txt'],
      ['0', 1, 'tar', null],
    ]);
  });

  it('sees the OOXML parts of a document by name and stops at the same limits', async () => {
    const docx = recorder();
    const result = await inspectBytes(await corpus.docxLike(), LIMITS, NOOP_YARA_ENGINE, {
      onEntry: docx.onEntry,
    });
    expect(result.type.detected).toBe('ooxml_word');
    expect(docx.visited.map((v) => v.name)).toContain('word/document.xml');

    const capped = recorder();
    const limited = await inspectBytes(
      await corpus.manyEntriesZip(40),
      { ...LIMITS, archiveMaxEntries: 25 },
      NOOP_YARA_ENGINE,
      { onEntry: capped.onEntry },
    );
    expect(limited.limits).toContain('limit.archive_entries');
    expect(capped.visited).toHaveLength(25);

    // Encrypted entries are never read, so never visited.
    const encrypted = recorder();
    const enc = await inspectBytes(corpus.encryptedZip(), LIMITS, NOOP_YARA_ENGINE, {
      onEntry: encrypted.onEntry,
    });
    expect(enc.archive!.encrypted).toBe(true);
    expect(encrypted.visited).toEqual([]);
  });

  it('runs the walk without YARA through the no-op engine', async () => {
    const result = await inspectBytes(corpus.gzip(corpus.yaraHigh()), LIMITS, NOOP_YARA_ENGINE);
    expect(result.yara).toEqual({ bundleId: 'none', matches: [] });
    expect(result.archive).toMatchObject({ format: 'gzip', entries: 1 });
  });

  it('rejects with the first visitor error over zip, gzip, tar, tgz and nested containers', async () => {
    const cases: Array<[string, Buffer]> = [
      [
        'zip',
        await corpus.zip([
          { name: 'a.txt', data: Buffer.from('a\n') },
          { name: 'b.txt', data: Buffer.from('b\n') },
        ]),
      ],
      ['gzip', corpus.gzip(Buffer.from('a\n'))],
      [
        'tar',
        await corpus.tar([
          { name: 'a.txt', data: Buffer.from('a\n') },
          { name: 'b.txt', data: Buffer.from('b\n') },
        ]),
      ],
      ['tgz', await corpus.tgz([{ name: 'x/m.txt', data: Buffer.from('m') }])],
      [
        'tar in zip',
        await corpus.zip([
          { name: 'in.tar', data: await corpus.tar([{ name: 'n.txt', data: Buffer.from('n') }]) },
        ]),
      ],
    ];
    for (const [label, bytes] of cases) {
      let calls = 0;
      const failure = new Error(`visitor failed (${label})`);
      const onEntry: EntryVisitor = async () => {
        calls += 1;
        await new Promise((resolve) => setImmediate(resolve));
        throw failure;
      };
      await expect(inspectBytes(bytes, LIMITS, NOOP_YARA_ENGINE, { onEntry }), label).rejects.toBe(
        failure,
      );
      // The walk stops at the first failure: the visitor is not called again.
      expect(calls, label).toBe(1);
    }
  });

  it('rejects with a synchronous visitor error inside a tar instead of reporting it malformed', async () => {
    const failure = new Error('sync failure');
    const onEntry: EntryVisitor = () => {
      throw failure;
    };
    await expect(
      inspectBytes(
        await corpus.tar([{ name: 'n.txt', data: Buffer.from('n') }]),
        LIMITS,
        NOOP_YARA_ENGINE,
        { onEntry },
      ),
    ).rejects.toBe(failure);
  });
});
