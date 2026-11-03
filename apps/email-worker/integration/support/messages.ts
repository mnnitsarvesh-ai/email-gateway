import { createHash, randomBytes } from 'node:crypto';
import { Readable } from 'node:stream';
import { gzipSync } from 'node:zlib';
import yazl from 'yazl';

const CRLF = '\r\n';

/** RFC 2045 base64 body lines (76 characters). */
export function base64Lines(bytes: Buffer): string {
  return (bytes.toString('base64').match(/.{1,76}/g) ?? []).join(CRLF);
}

export interface AttachmentSpec {
  filename: string;
  contentType: string;
  bytes: Buffer;
  disposition?: 'attachment' | 'inline';
}

/**
 * A multipart/mixed message with an RFC 2047 subject, a text and an HTML body (alternative) and
 * the given attachments (RFC 2231 encoded filenames when they are not ASCII).
 */
export function multipartMessage(
  options: { subject?: string; text?: string; html?: string; attachments?: AttachmentSpec[] } = {},
): string {
  const subject = options.subject ?? '=?UTF-8?B?w5xiZXJ3ZWlzdW5nIOKckw==?=';
  const lines = [
    'Return-Path: <sender@example.org>',
    'Authentication-Results: mx.gateway.local; spf=pass smtp.mailfrom=example.org',
    'From: Sender <sender@example.org>',
    'To: rcpt@example.net',
    `Subject: ${subject}`,
    'Date: Tue, 03 Nov 2026 10:00:00 +0000',
    `Message-ID: <${randomBytes(6).toString('hex')}@example.org>`,
    'MIME-Version: 1.0',
    'Content-Type: multipart/mixed; boundary="mixed-b"',
    '',
    '--mixed-b',
    'Content-Type: multipart/alternative; boundary="alt-b"',
    '',
    '--alt-b',
    'Content-Type: text/plain; charset=utf-8',
    'Content-Transfer-Encoding: quoted-printable',
    '',
    options.text ?? 'Hello =E2=9C=93 integration.',
    '--alt-b',
    'Content-Type: text/html; charset=utf-8',
    '',
    options.html ?? '<p>Hello integration.</p>',
    '--alt-b--',
  ];
  for (const a of options.attachments ?? []) {
    const ascii = /^[\x20-\x7e]*$/.test(a.filename);
    const param = ascii
      ? `filename="${a.filename}"`
      : `filename*=UTF-8''${encodeURIComponent(a.filename)}`;
    lines.push(
      '--mixed-b',
      `Content-Type: ${a.contentType}`,
      `Content-Disposition: ${a.disposition ?? 'attachment'}; ${param}`,
      'Content-Transfer-Encoding: base64',
      '',
      base64Lines(a.bytes),
    );
  }
  lines.push('--mixed-b--', '');
  return lines.join(CRLF);
}

async function zipBuffer(build: (zip: yazl.ZipFile) => void): Promise<Buffer> {
  const zip = new yazl.ZipFile();
  build(zip);
  zip.end();
  const chunks: Buffer[] = [];
  for await (const chunk of zip.outputStream as Readable) chunks.push(chunk as Buffer);
  return Buffer.concat(chunks);
}

/** A deflated 200 MiB of zeros (ratio far above MIME_ARCHIVE_MAX_RATIO), streamed into yazl. */
export function zipBomb(): Promise<Buffer> {
  const total = 200 * 1024 * 1024;
  const block = Buffer.alloc(1024 * 1024);
  return zipBuffer((zip) => {
    let sent = 0;
    const zeros = new Readable({
      read() {
        if (sent >= total) this.push(null);
        else {
          sent += block.length;
          this.push(block);
        }
      },
    });
    zip.addReadStream(zeros, 'zeros.bin');
  });
}

/** A zip that contains another zip and a .tar.gz (nested archives, M10). */
export async function nestedArchive(): Promise<Buffer> {
  const inner = await zipBuffer((zip) => zip.addBuffer(Buffer.from('inner file'), 'inner.txt'));
  return zipBuffer((zip) => {
    zip.addBuffer(inner, 'inner.zip');
    zip.addBuffer(gzipSync(Buffer.alloc(4096)), 'data.tar.gz');
    zip.addBuffer(Buffer.from('readme'), 'readme.txt');
  });
}

export interface LargeMessage {
  chunks: () => Iterable<Buffer>;
  /** SHA-256 (hex) of each attachment's decoded bytes, known once `chunks` was consumed. */
  attachmentSha256: string[];
  attachmentSizes: number[];
}

/**
 * A message close to MIME_MAX_MESSAGE_BYTES (51 MiB with the default limits), generated as a
 * stream: a text body and two base64 attachments of 20 MiB and 17 MiB of random bytes. Nothing
 * larger than one 57 KiB block is held in memory.
 */
export function largeMessage(sizes: number[] = [20 * 1024 * 1024, 17 * 1024 * 1024]): LargeMessage {
  const result: LargeMessage = { chunks, attachmentSha256: [], attachmentSizes: sizes };
  function* chunks(): Iterable<Buffer> {
    yield Buffer.from(
      [
        'From: Large <large@example.org>',
        'To: rcpt@example.net',
        'Subject: large message near the limit',
        'MIME-Version: 1.0',
        'Content-Type: multipart/mixed; boundary="large-b"',
        '',
        '--large-b',
        'Content-Type: text/plain; charset=utf-8',
        '',
        'See the attachments.',
        '',
      ].join(CRLF),
    );
    for (const [i, size] of sizes.entries()) {
      yield Buffer.from(
        [
          '--large-b',
          'Content-Type: application/octet-stream',
          `Content-Disposition: attachment; filename="blob-${i}.bin"`,
          'Content-Transfer-Encoding: base64',
          '',
          '',
        ].join(CRLF),
      );
      const hash = createHash('sha256');
      // 57 bytes encode to one 76-character line; blocks of 1024 lines.
      const blockBytes = 57 * 1024;
      for (let sent = 0; sent < size; sent += blockBytes) {
        const bytes = randomBytes(Math.min(blockBytes, size - sent));
        hash.update(bytes);
        yield Buffer.from(base64Lines(bytes) + CRLF);
      }
      result.attachmentSha256[i] = hash.digest('hex');
    }
    yield Buffer.from(`--large-b--${CRLF}`);
  }
  return result;
}
