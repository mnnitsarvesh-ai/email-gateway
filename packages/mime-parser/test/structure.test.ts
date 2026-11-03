import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import iconv from 'iconv-lite';
import { describe, expect, it } from 'vitest';
import { crlf, MemorySink, multipart, parse, sha256, simpleMessage } from './helpers';

const fixture = (name: string): Buffer => readFileSync(join(__dirname, 'fixtures', name));

describe('structure and bodies', () => {
  it('records a nested rfc822 tree with paths, parents, depths and kinds', async () => {
    const { result } = await parse(fixture('nested-rfc822.eml'));
    expect(
      result.structure.map((node) => [node.index, node.path, node.parent, node.depth, node.kind]),
    ).toEqual([
      [0, '0', null, 0, 'container'],
      [1, '0.1', 0, 1, 'text'],
      [2, '0.2', 0, 1, 'message'],
      [3, '0.2.0', 2, 2, 'container'],
      [4, '0.2.0.1', 3, 3, 'attachment'],
      [5, '0.2.0.2', 3, 3, 'attachment'],
      [6, '0.2.0.3', 3, 3, 'message'],
      [7, '0.2.0.3.0', 6, 4, 'container'],
      [8, '0.2.0.3.0.1', 7, 5, 'attachment'],
      [9, '0.2.0.3.0.2', 7, 5, 'attachment'],
    ]);
    expect(result.stats).toMatchObject({ partCount: 10, maxDepth: 5, attachmentCount: 4 });
    // Every leaf of an embedded message is an attachment, flagged as nested.
    expect(
      result.attachments.every((attachment) => attachment.flags.includes('nested_message_part')),
    ).toBe(true);
    expect(result.attachments.map((attachment) => attachment.filename)).toEqual([
      null,
      'data.csv',
      null,
      'deep.pdf',
    ]);
    expect(result.attachments[3]?.detectedContentType).toBe('application/pdf');
    // Only the top-level headers are stored.
    expect(result.headers.map((header) => header.value)).not.toContain('innermost');
    expect(result.subject).toBe('forwarded twice');
  });

  it('keeps a message/rfc822 attachment (disposition attachment or encoded) as a leaf', async () => {
    const inner = crlf('Subject: inner', '', 'inner body');
    const message = multipart('mixed', 'b', [
      {
        headers: [
          'Content-Type: message/rfc822',
          'Content-Disposition: attachment; filename="fwd.eml"',
        ],
        body: inner,
      },
      {
        headers: ['Content-Type: message/rfc822', 'Content-Transfer-Encoding: base64'],
        body: Buffer.from(inner).toString('base64'),
      },
    ]);
    const { result, sink } = await parse(message);
    expect(result.structure.map((node) => node.kind)).toEqual([
      'container',
      'attachment',
      'attachment',
    ]);
    expect(result.attachments.map((attachment) => attachment.declaredContentType)).toEqual([
      'message/rfc822',
      'message/rfc822',
    ]);
    expect(sink.text(result.attachments[1]?.key)).toBe(inner);
  });

  it('selects the first text/plain and text/html that are not attachments (design M8)', async () => {
    const message = multipart('mixed', 'b', [
      {
        headers: ['Content-Type: text/plain', 'Content-Disposition: attachment'],
        body: 'attached text',
      },
      { headers: ['Content-Type: text/plain; name="named.txt"'], body: 'named text' },
      { headers: ['Content-Type: text/html'], body: '<p>first html</p>' },
      { headers: ['Content-Type: text/plain'], body: 'first plain' },
      { headers: ['Content-Type: text/plain'], body: 'second plain' },
      { headers: ['Content-Type: text/html'], body: '<p>second html</p>' },
    ]);
    const { result, sink } = await parse(message);
    expect(sink.text(result.textBody?.key)).toBe('first plain');
    expect(sink.text(result.htmlBody?.key)).toBe('<p>first html</p>');
    expect(
      result.attachments.map((attachment) => [attachment.partIndex, attachment.disposition]),
    ).toEqual([
      [1, 'attachment'],
      [2, 'attachment'],
      [5, 'inline'],
      [6, 'inline'],
    ]);
    expect(sink.opened.map((info) => info.kind)).toEqual([
      'attachment',
      'attachment',
      'html',
      'text',
      'attachment',
      'attachment',
    ]);
  });

  it('stores multiple attachments with their own hashes, sizes and sniffed types', async () => {
    const { result, sink } = await parse(fixture('multiple-attachments.eml'));
    expect(result.attachments).toHaveLength(6);
    for (const attachment of result.attachments) {
      const object = sink.objects.get(attachment.key ?? '');
      expect(object?.data.length).toBe(attachment.sizeBytes);
      expect(sha256(object?.data ?? Buffer.alloc(0))).toBe(attachment.sha256);
      expect(attachment.encodedSizeBytes).toBeGreaterThan(0);
    }
    expect(result.attachments.map((attachment) => attachment.detectedContentType)).toEqual([
      'application/pdf',
      'image/png',
      'application/octet-stream',
      'application/octet-stream',
      'application/octet-stream',
      'application/octet-stream',
    ]);
  });

  it('treats a bare non-text root as a single attachment', async () => {
    const { result } = await parse(fixture('pdf-root.eml'));
    expect(result.textBody).toBeNull();
    expect(result.attachments).toEqual([
      expect.objectContaining({
        partIndex: 0,
        partPath: '0',
        depth: 0,
        filename: 'bare.pdf',
        detectedContentType: 'application/pdf',
      }),
    ]);
  });

  it('converts bodies to UTF-8 from ISO-8859-1, Shift_JIS and KOI8-R; attachments keep their bytes', async () => {
    const encode = (text: string, charset: string) =>
      Buffer.concat([
        Buffer.from(
          crlf(
            `Content-Type: text/plain; charset=${charset}`,
            'Content-Transfer-Encoding: 8bit',
            '',
            '',
          ),
        ),
        iconv.encode(text, charset),
      ]);
    for (const [text, charset] of [
      ['Grüße', 'iso-8859-1'],
      ['日本語のメール', 'shift_jis'],
      ['Привет мир', 'koi8-r'],
    ] as const) {
      const { result, sink } = await parse(encode(text, charset));
      expect(sink.text(result.textBody?.key), charset).toBe(text);
      expect(result.textBody?.sizeBytes).toBe(Buffer.byteLength(text));
      expect(result.textBody?.charset).toBe(charset);
    }
    const latin = iconv.encode('Grüße', 'iso-8859-1');
    const attachment = Buffer.concat([
      Buffer.from(crlf('Content-Type: text/plain; charset=iso-8859-1; name="g.txt"', '', '')),
      latin,
    ]);
    const { result, sink } = await parse(attachment);
    expect(sink.objects.get(result.attachments[0]?.key ?? '')?.data).toEqual(latin);
  });

  it('decodes quoted-printable and base64, and does not apply format=flowed', async () => {
    const flowed = simpleMessage(
      ['Content-Type: text/plain; format=flowed; delsp=yes'],
      'soft \r\nwrapped line',
    );
    const { result, sink } = await parse(flowed);
    expect(sink.text(result.textBody?.key)).toBe('soft \r\nwrapped line');
    const html = await parse(fixture('alternative.eml'));
    expect(html.sink.text(html.result.htmlBody?.key)).toBe('<p>html ✓ version</p>');
    const latin = await parse(fixture('html-only.eml'));
    expect(latin.sink.text(latin.result.htmlBody?.key)).toBe('<p>café</p>');
  });

  it('awaits every sink write (one write in flight at a time)', async () => {
    const sink = new MemorySink();
    sink.writeDelayMs = 1;
    let maxInFlight = 0;
    const original = sink.open.bind(sink);
    sink.open = async (info) => {
      const writer = await original(info);
      const write = writer.write.bind(writer);
      writer.write = async (chunk) => {
        const pending = write(chunk);
        maxInFlight = Math.max(maxInFlight, sink.inFlight);
        await pending;
      };
      return writer;
    };
    const lines = `${'line of text '.repeat(6)}\r\n`.repeat(2000);
    const message = multipart('mixed', 'b', [
      { headers: ['Content-Type: text/plain'], body: lines },
      { headers: ['Content-Type: application/octet-stream; name="a"'], body: lines },
    ]);
    const { result } = await parse(message, { sink, chunkSize: 4096 });
    expect(result.status).toBe('parsed');
    expect(maxInFlight).toBe(1);
  });
});
