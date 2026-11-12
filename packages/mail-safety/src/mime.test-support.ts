import { Writable, Readable } from 'node:stream';
import { pipeline } from 'node:stream/promises';
import { Splitter, type MimeNode, type SplitterChunk } from '@zone-eu/mailsplit';
import * as libbase64 from 'libbase64';
import * as libqp from 'libqp';
import iconv from 'iconv-lite';

/** Test support: synthetic MIME messages and a splitter-based part reader. */

export const CRLF = '\r\n';

export function message(headers: string[], body: string, eol = CRLF): Buffer {
  return Buffer.from(
    [
      'From: Sender <sender@ext.example>',
      'To: a@corp.example',
      'Subject: test',
      'Message-ID: <t1@ext.example>',
      'MIME-Version: 1.0',
      ...headers,
    ].join(eol) +
      eol +
      eol +
      body,
    'latin1',
  );
}

export function multipart(
  subtype: string,
  boundary: string,
  parts: string[],
  eol = CRLF,
  extraHeaders: string[] = [],
): { headers: string[]; body: string } {
  return {
    headers: [`Content-Type: multipart/${subtype}; boundary="${boundary}"`, ...extraHeaders],
    body: parts.map((p) => `--${boundary}${eol}${p}${eol}`).join('') + `--${boundary}--${eol}`,
  };
}

export const part = (headers: string[], body: string, eol = CRLF): string =>
  `${headers.join(eol)}${eol}${eol}${body}`;

export const b64 = (s: string, charset = 'utf-8'): string =>
  libbase64.wrap(libbase64.encode(iconv.encode(s, charset)), 76).replace(/\r?\n/g, CRLF);
export const qp = (s: string, charset = 'utf-8'): string =>
  libqp.wrap(libqp.encode(iconv.encode(s, charset)), 76).replace(/\r?\n/g, CRLF);

export interface ReadPart {
  contentType: string;
  encoding: string;
  charset: string;
  filename: string | null;
  /** Header block bytes as written. */
  header: string;
  /** Raw (encoded) body bytes. */
  raw: Buffer;
  /** Transfer-decoded and charset-decoded text. */
  text: string;
}

/** Splits a message into its leaves with raw and decoded bodies. */
export async function readParts(eml: Buffer): Promise<ReadPart[]> {
  const out: Array<{ node: MimeNode; chunks: Buffer[] }> = [];
  await pipeline(
    Readable.from([eml]),
    new Splitter({ ignoreEmbedded: false }),
    new Writable({
      objectMode: true,
      write(chunk: SplitterChunk, _e, cb) {
        if (chunk.type === 'node') out.push({ node: chunk, chunks: [] });
        else if (chunk.type === 'body') out[out.length - 1]!.chunks.push(chunk.value);
        cb();
      },
    }),
  );
  return out
    .filter((p) => !p.node.multipart)
    .map((p) => {
      const raw = Buffer.concat(p.chunks);
      const encoding = (p.node.encoding || '7bit').toLowerCase();
      const charset = (p.node.charset || 'us-ascii').toLowerCase();
      const decoded =
        encoding === 'base64'
          ? libbase64.decode(raw.toString('latin1'))
          : encoding === 'quoted-printable'
            ? libqp.decode(raw)
            : raw;
      return {
        contentType: (p.node.contentType || 'text/plain').toLowerCase(),
        encoding,
        charset,
        filename: p.node.filename || null,
        header: p.node.getHeaders().toString('latin1'),
        raw,
        text: iconv.encodingExists(charset)
          ? iconv.decode(decoded, charset)
          : decoded.toString('latin1'),
      };
    });
}
