import { gunzipSync, inflateRawSync } from 'node:zlib';
import type { FileTypeId } from '@email-gateway/security-contracts';
import type { WalkSummary } from '../extract/types';

/**
 * Test support only (excluded from the build): a minimal stand-in for the 4.2 shared walker
 * (`apps/email-worker/.../inspector/inspect.ts`), with the same visitor contract — entries are
 * visited depth-first and post-order (a container's entries before the container), paths are
 * index paths (`"0"`, `"2/1"`), encrypted entries are never visited, a depth or entry limit
 * stops the walk and is reported. The real walker is WP3's; this one lets the package test
 * its extraction session without importing an app.
 */

export type Visitor = (
  data: Buffer,
  path: string,
  depth: number,
  type: FileTypeId,
  ext: FileTypeId | null,
  name: string | null,
) => void | Promise<void>;

export interface TestWalkLimits {
  maxDepth: number;
  maxEntries: number;
}

const startsWith = (data: Buffer, hex: string) =>
  data.subarray(0, hex.length / 2).equals(Buffer.from(hex, 'hex'));

export function detectTestType(data: Buffer): FileTypeId {
  if (data.subarray(0, 5).toString('latin1') === '%PDF-') return 'pdf';
  if (startsWith(data, '504b0304') || startsWith(data, '504b0506')) return 'zip';
  if (startsWith(data, '1f8b')) return 'gzip';
  if (startsWith(data, '89504e47')) return 'png';
  if (startsWith(data, 'ffd8ff')) return 'jpeg';
  if (startsWith(data, 'd0cf11e0a1b11ae1')) return 'ole_office';
  if (startsWith(data, '377abcaf271c')) return '7z';
  const head = data.subarray(0, 4096);
  if (head.includes(0)) return 'unknown';
  const text = head.toString('utf8').trimStart().toLowerCase();
  if (text.startsWith('<!doctype html') || text.startsWith('<html')) return 'html';
  if (text.startsWith('<?xml')) return 'xml';
  if (/^(?:received|from|mime-version|message-id|subject):/.test(text)) return 'eml';
  return 'text';
}

interface ZipEntry {
  name: string;
  flags: number;
  method: number;
  compressedSize: number;
  offset: number;
}

function zipEntries(zip: Buffer): ZipEntry[] {
  let eocd = -1;
  for (let i = zip.length - 22; i >= Math.max(0, zip.length - 65_557); i -= 1) {
    if (zip.readUInt32LE(i) === 0x06054b50) {
      eocd = i;
      break;
    }
  }
  if (eocd < 0) throw new Error('no end of central directory');
  const count = zip.readUInt16LE(eocd + 10);
  let p = zip.readUInt32LE(eocd + 16);
  const entries: ZipEntry[] = [];
  for (let k = 0; k < count; k += 1) {
    if (zip.readUInt32LE(p) !== 0x02014b50) throw new Error('bad central directory');
    const flags = zip.readUInt16LE(p + 8);
    const method = zip.readUInt16LE(p + 10);
    const compressedSize = zip.readUInt32LE(p + 20);
    const nameLength = zip.readUInt16LE(p + 28);
    const extraLength = zip.readUInt16LE(p + 30);
    const commentLength = zip.readUInt16LE(p + 32);
    const offset = zip.readUInt32LE(p + 42);
    const name = zip.subarray(p + 46, p + 46 + nameLength).toString('utf8');
    entries.push({ name, flags, method, compressedSize, offset });
    p += 46 + nameLength + extraLength + commentLength;
  }
  return entries;
}

function entryData(zip: Buffer, entry: ZipEntry): Buffer {
  const nameLength = zip.readUInt16LE(entry.offset + 26);
  const extraLength = zip.readUInt16LE(entry.offset + 28);
  const start = entry.offset + 30 + nameLength + extraLength;
  const raw = zip.subarray(start, start + entry.compressedSize);
  return entry.method === 0 ? Buffer.from(raw) : inflateRawSync(raw);
}

function subtype(names: readonly string[], mimetype: string | null): FileTypeId {
  const has = (prefix: string) => names.some((n) => n.startsWith(prefix));
  if (names.includes('[Content_Types].xml')) {
    if (has('word/')) return 'ooxml_word';
    if (has('xl/')) return 'ooxml_excel';
    if (has('ppt/')) return 'ooxml_powerpoint';
  }
  if (mimetype?.startsWith('application/vnd.oasis.opendocument')) return 'odf';
  return 'zip';
}

const extensionType = (name: string | null): FileTypeId | null => {
  const ext = name?.split('.').pop()?.toLowerCase();
  if (ext === 'py' || ext === 'sh') return 'script_shell';
  if (ext === 'js') return 'script_js';
  if (ext === 'html' || ext === 'htm') return 'html';
  return null;
};

export async function testWalk(
  bytes: Buffer,
  visitor: Visitor,
  limits: TestWalkLimits = { maxDepth: 3, maxEntries: 1000 },
): Promise<{ detected: FileTypeId; walk: WalkSummary }> {
  const summary: WalkSummary = {
    encrypted: false,
    limitReached: false,
    malformed: false,
    unsupported: false,
  };
  let entries = 0;
  const walkContainer = async (
    data: Buffer,
    type: FileTypeId,
    depth: number,
    prefix: string | null,
  ): Promise<FileTypeId> => {
    if (type === '7z') {
      summary.unsupported = true;
      return type;
    }
    if (type !== 'zip' && type !== 'gzip') return type;
    if (depth >= limits.maxDepth) {
      summary.limitReached = true;
      return type;
    }
    const path = (i: number) => (prefix === null ? String(i) : `${prefix}/${i}`);
    if (type === 'gzip') {
      let inner: Buffer;
      try {
        inner = gunzipSync(data);
      } catch {
        summary.malformed = true;
        return type;
      }
      await visitEntry(inner, path(0), depth + 1, null);
      return type;
    }
    let list: ZipEntry[];
    try {
      list = zipEntries(data);
    } catch {
      summary.malformed = true;
      return type;
    }
    let mimetype: string | null = null;
    for (let i = 0; i < list.length; i += 1) {
      const entry = list[i]!;
      if (entry.name.endsWith('/')) continue;
      if (entry.flags & 1) {
        summary.encrypted = true;
        continue;
      }
      if (entries >= limits.maxEntries) {
        summary.limitReached = true;
        break;
      }
      entries += 1;
      const content = entryData(data, entry);
      if (entry.name === 'mimetype') mimetype = content.toString('latin1');
      await visitEntry(content, path(i), depth + 1, entry.name);
    }
    return subtype(
      list.map((e) => e.name),
      mimetype,
    );
  };
  const visitEntry = async (data: Buffer, path: string, depth: number, name: string | null) => {
    let type = detectTestType(data);
    type = await walkContainer(data, type, depth, path);
    if (type === 'text') type = extensionType(name) ?? type;
    await visitor(data, path, depth, type, extensionType(name), name);
  };
  let detected = detectTestType(bytes);
  if (detected === 'zip' || detected === 'gzip' || detected === '7z') {
    detected = await walkContainer(bytes, detected, 0, null);
  }
  return { detected, walk: summary };
}
