import { describe, expect, it } from 'vitest';
import { MemorySink, multipart, parse } from './helpers';
import { buildGzip, buildZip, markEncrypted } from './zip-builders';

const attach = (type: string, name: string, data: Buffer) =>
  multipart('mixed', 'a', [
    { headers: ['Content-Type: text/plain'], body: 'see attachment' },
    {
      headers: [
        `Content-Type: ${type}; name="${name}"`,
        'Content-Disposition: attachment',
        'Content-Transfer-Encoding: base64',
      ],
      body: data.toString('base64').replace(/.{76}/g, '$&\r\n'),
    },
  ]);

describe('archives inside messages (design M10)', () => {
  it('flags a zip bomb through ranged reads of the stored part', async () => {
    const bomb = await buildZip([{ name: 'zeros.bin', zeros: 200 * 1024 * 1024 }]);
    const sink = new MemorySink();
    const { result } = await parse(attach('application/zip', 'bomb.zip', bomb), { sink });
    const [attachment] = result.attachments;
    expect(attachment?.flags).toEqual(['archive', 'archive_compression_ratio']);
    expect(attachment?.archiveInfo).toMatchObject({
      type: 'zip',
      inspected: true,
      entries: 1,
      declaredUncompressedBytes: 200 * 1024 * 1024,
    });
    expect(attachment?.archiveInfo).not.toHaveProperty('flags');
    expect(sink.ranges.every((range) => range.key === attachment?.key)).toBe(true);
    expect(result.status).toBe('parsed');
  });

  it('flags a nested archive (a zip with a .zip and a .tar.gz) and encrypted entries', async () => {
    const inner = await buildZip([{ name: 'x.txt', data: Buffer.from('x') }]);
    const tarGz = buildGzip(Buffer.from('tar payload'), { name: 'backup.tar' });
    const zip = markEncrypted(
      await buildZip([
        { name: 'inner.zip', data: inner },
        { name: 'backup.tar.gz', data: tarGz },
      ]),
    );
    const { result } = await parse(attach('application/zip', 'nested.zip', zip));
    expect(result.attachments[0]?.flags).toEqual([
      'archive',
      'archive_encrypted',
      'archive_nested',
    ]);
    expect(result.attachments[0]?.archiveInfo).toMatchObject({
      nestedArchives: 2,
      encryptedEntries: 2,
    });
  });

  it('inspects gzip from the streamed head and trailer (large ISIZE)', async () => {
    const gzip = buildGzip(Buffer.from('payload'), { name: 'big.tar', isize: 0xfffffff0 });
    const sink = new MemorySink();
    const { result } = await parse(attach('application/gzip', 'big.tar.gz', gzip), { sink });
    expect(result.attachments[0]?.flags).toEqual([
      'archive',
      'archive_compression_ratio',
      'archive_total_size',
      'archive_nested',
    ]);
    expect(result.attachments[0]?.archiveInfo).toMatchObject({
      type: 'gzip',
      declaredUncompressedBytes: 0xfffffff0,
    });
    expect(sink.ranges).toHaveLength(0);
  });

  it('does not inspect a zip that was not stored', async () => {
    const zip = await buildZip([{ name: 'a.txt', data: Buffer.alloc(5000, 1) }], {});
    const sink = new MemorySink();
    const { result } = await parse(attach('application/zip', 'a.zip', zip), {
      sink,
      limits: { maxAttachmentBytes: 100 },
    });
    expect(result.attachments[0]?.flags).toEqual([
      'archive',
      'not_stored_size_limit',
      'archive_not_inspected',
    ]);
    expect(result.attachments[0]?.archiveInfo).toMatchObject({ type: 'zip', inspected: false });
    expect(sink.ranges).toHaveLength(0);
  });

  it('identifies other archive types without inspecting them', async () => {
    const rar = Buffer.from('Rar!\x1a\x07\x01\x00rest', 'latin1');
    const { result } = await parse(attach('application/octet-stream', 'x.rar', rar));
    expect(result.attachments[0]?.flags).toEqual([
      'content_type_mismatch',
      'archive',
      'archive_not_inspected',
    ]);
    expect(result.attachments[0]?.archiveInfo).toEqual({
      type: 'rar',
      inspected: false,
      entries: null,
      declaredUncompressedBytes: null,
      maxRatio: null,
      encryptedEntries: null,
      nestedArchives: null,
    });
  });

  it('flags a malformed zip and flags a zip disguised by its extension', async () => {
    const garbage = Buffer.concat([Buffer.from('PK\x03\x04', 'latin1'), Buffer.alloc(200, 3)]);
    const { result } = await parse(attach('application/pdf', 'invoice.pdf', garbage));
    expect(result.attachments[0]?.flags).toEqual([
      'content_type_mismatch',
      'archive',
      'filename_extension_mismatch',
      'archive_malformed',
    ]);
    expect(result.status).toBe('parsed');
  });
});
