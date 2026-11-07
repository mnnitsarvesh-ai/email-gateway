import { createHash } from 'node:crypto';
import { deflateSync } from 'node:zlib';

/**
 * A small hand-written PDF writer for the synthetic corpus (step 4.5 §9): text pages
 * (Helvetica, WinAnsi), uncompressed or Flate content streams, an image-only page (no text
 * layer), and the Standard security handler revision 2 (RC4 40-bit) with a user password so
 * pdfjs raises its `PasswordException`. Output is a valid PDF 1.4 file with an exact xref.
 */

export interface PdfOptions {
  /** Flate-compress the content streams. */
  compress?: boolean;
  /** Pages with an image and no text (a "scanned" document). */
  imageOnly?: boolean;
  /** Encrypt with this user password (RC4 40-bit, R2). */
  userPassword?: string;
}

const escapeString = (text: string): string =>
  text.replace(/\\/g, '\\\\').replace(/\(/g, '\\(').replace(/\)/g, '\\)');

/** RC4 (the PDF Standard security handler cipher). */
export function rc4(key: Uint8Array, data: Uint8Array): Buffer {
  const s = new Uint8Array(256);
  for (let i = 0; i < 256; i += 1) s[i] = i;
  let j = 0;
  for (let i = 0; i < 256; i += 1) {
    j = (j + s[i]! + key[i % key.length]!) & 0xff;
    [s[i], s[j]] = [s[j]!, s[i]!];
  }
  const out = Buffer.alloc(data.length);
  let i = 0;
  j = 0;
  for (let k = 0; k < data.length; k += 1) {
    i = (i + 1) & 0xff;
    j = (j + s[i]!) & 0xff;
    [s[i], s[j]] = [s[j]!, s[i]!];
    out[k] = data[k]! ^ s[(s[i]! + s[j]!) & 0xff]!;
  }
  return out;
}

const PAD = Buffer.from('28BF4E5E4E758A4164004E56FFFA01082E2E00B6D0683E802F0CA9FE6453697A', 'hex');
const md5 = (...parts: Uint8Array[]): Buffer => {
  const hash = createHash('md5');
  for (const part of parts) hash.update(part);
  return hash.digest();
};
const padPassword = (password: string): Buffer =>
  Buffer.concat([Buffer.from(password, 'latin1'), PAD]).subarray(0, 32);

interface Security {
  key: Buffer;
  o: Buffer;
  u: Buffer;
  p: number;
  id: Buffer;
}

function standardSecurity(userPassword: string): Security {
  const owner = padPassword(`${userPassword}-owner`);
  const user = padPassword(userPassword);
  const o = rc4(md5(owner).subarray(0, 5), user);
  const p = -44;
  const pBytes = Buffer.alloc(4);
  pBytes.writeInt32LE(p);
  const id = md5(Buffer.from(`dlp-corpus:${userPassword}`));
  const key = md5(user, o, pBytes, id).subarray(0, 5);
  const u = rc4(key, PAD);
  return { key, o, u, p, id };
}

const objectKey = (security: Security, num: number): Buffer => {
  const suffix = Buffer.from([num & 0xff, (num >> 8) & 0xff, (num >> 16) & 0xff, 0, 0]);
  return md5(security.key, suffix).subarray(0, Math.min(security.key.length + 5, 16));
};

/** Builds a PDF with one page per entry of `pages` (each a list of text lines). */
export function buildPdf(pages: readonly (readonly string[])[], options: PdfOptions = {}): Buffer {
  const security = options.userPassword ? standardSecurity(options.userPassword) : null;
  const objects: Buffer[] = [];
  const pageCount = pages.length;
  // Object numbers: 1 catalog, 2 pages, 3 font, 4 image; then per page: page, content.
  const pageObject = (i: number) => 5 + i * 2;
  const contentObject = (i: number) => 6 + i * 2;
  const stream = (num: number, data: Buffer, extra = ''): Buffer => {
    let body = options.compress ? deflateSync(data) : data;
    const filter = options.compress ? '/Filter /FlateDecode ' : '';
    if (security) body = rc4(objectKey(security, num), body);
    return Buffer.concat([
      Buffer.from(`<< ${filter}${extra}/Length ${body.length} >>\nstream\n`, 'latin1'),
      body,
      Buffer.from('\nendstream', 'latin1'),
    ]);
  };
  objects[1] = Buffer.from('<< /Type /Catalog /Pages 2 0 R >>', 'latin1');
  objects[2] = Buffer.from(
    `<< /Type /Pages /Kids [${pages.map((_, i) => `${pageObject(i)} 0 R`).join(' ')}] /Count ${pageCount} >>`,
    'latin1',
  );
  objects[3] = Buffer.from(
    '<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica /Encoding /WinAnsiEncoding >>',
    'latin1',
  );
  objects[4] = stream(
    4,
    Buffer.from([0x80]),
    '/Type /XObject /Subtype /Image /Width 1 /Height 1 /ColorSpace /DeviceGray /BitsPerComponent 8 ',
  );
  pages.forEach((lines, i) => {
    objects[pageObject(i)] = Buffer.from(
      `<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Contents ${contentObject(i)} 0 R /Resources << /Font << /F1 3 0 R >> /XObject << /Im1 4 0 R >> >> >>`,
      'latin1',
    );
    const content = options.imageOnly
      ? 'q 400 0 0 400 100 200 cm /Im1 Do Q'
      : [
          'BT',
          '/F1 11 Tf',
          '14 TL',
          '72 740 Td',
          ...lines.map((line) => `(${escapeString(line)}) Tj T*`),
          'ET',
        ].join('\n');
    objects[contentObject(i)] = stream(contentObject(i), Buffer.from(content, 'latin1'));
  });
  let encryptRef = '';
  if (security) {
    const num = objects.length;
    objects[num] = Buffer.from(
      `<< /Filter /Standard /V 1 /R 2 /O <${security.o.toString('hex')}> /U <${security.u.toString('hex')}> /P ${security.p} >>`,
      'latin1',
    );
    encryptRef = ` /Encrypt ${num} 0 R /ID [<${security.id.toString('hex')}> <${security.id.toString('hex')}>]`;
  }
  const chunks: Buffer[] = [Buffer.from('%PDF-1.4\n%\xe2\xe3\xcf\xd3\n', 'latin1')];
  let offset = chunks[0]!.length;
  const offsets: number[] = [];
  for (let num = 1; num < objects.length; num += 1) {
    offsets[num] = offset;
    const chunk = Buffer.concat([
      Buffer.from(`${num} 0 obj\n`, 'latin1'),
      objects[num]!,
      Buffer.from('\nendobj\n', 'latin1'),
    ]);
    chunks.push(chunk);
    offset += chunk.length;
  }
  const xref = [
    'xref',
    `0 ${objects.length}`,
    '0000000000 65535 f ',
    ...offsets.slice(1).map((o) => `${String(o).padStart(10, '0')} 00000 n `),
    'trailer',
    `<< /Size ${objects.length} /Root 1 0 R${encryptRef} >>`,
    'startxref',
    String(offset),
    '%%EOF',
    '',
  ].join('\n');
  chunks.push(Buffer.from(xref, 'latin1'));
  return Buffer.concat(chunks);
}
