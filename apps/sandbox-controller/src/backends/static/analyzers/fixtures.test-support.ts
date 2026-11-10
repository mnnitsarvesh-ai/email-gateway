import { deflateRawSync, deflateSync } from 'node:zlib';

/**
 * Synthetic fixtures for the static analyzer unit tests (step 4.6 X4: "synthetic fixtures
 * generated in the test, never real malware"). Every builder writes a minimal, structurally valid
 * file of its format whose content is chosen by the test (benign text that merely contains the
 * keywords or imports an analyzer looks for). Test support only (excluded from the build).
 */

const CHUNK_DECOMPRESSED = 4096;

/** Wraps `data` as raw (uncompressed) MS-OVBA chunks: wraps `data` as raw (uncompressed) chunks. */
export function rawContainer(data: Buffer): Buffer {
  const parts: Buffer[] = [Buffer.from([0x01])];
  for (let i = 0; i < data.length; i += CHUNK_DECOMPRESSED) {
    const chunk = Buffer.alloc(CHUNK_DECOMPRESSED, 0);
    data.copy(chunk, 0, i, Math.min(data.length, i + CHUNK_DECOMPRESSED));
    const header = Buffer.alloc(2);
    header.writeUInt16LE(((CHUNK_DECOMPRESSED + 2 - 3) & 0x0fff) | (0b011 << 12));
    parts.push(header, chunk);
  }
  return Buffer.concat(parts);
}

/**
 * A minimal MS-OVBA compressor (literal + copy tokens with a greedy match search), used by the
 * unit tests to build synthetic VBA projects. Correct by construction against
 * `decompressOvba` (round-trip tested); never used on sample input.
 */
export function compressOvba(data: Buffer): Buffer {
  const parts: Buffer[] = [Buffer.from([0x01])];
  for (let start = 0; start < data.length || start === 0; start += CHUNK_DECOMPRESSED) {
    const chunk = data.subarray(start, Math.min(data.length, start + CHUNK_DECOMPRESSED));
    const body: number[] = [];
    let i = 0;
    while (i < chunk.length) {
      const flagIndex = body.length;
      body.push(0);
      let flags = 0;
      for (let bit = 0; bit < 8 && i < chunk.length; bit += 1) {
        let bitCount = 4;
        while (1 << bitCount < i) bitCount += 1;
        const lengthMask = 0xffff >> bitCount;
        const maxLength = lengthMask + 3;
        const maxOffset = 1 << (16 - bitCount);
        let bestLength = 0;
        let bestOffset = 0;
        for (let candidate = i - 1; candidate >= 0 && i - candidate <= maxOffset; candidate -= 1) {
          let length = 0;
          while (
            length < maxLength &&
            i + length < chunk.length &&
            chunk[candidate + length] === chunk[i + length]
          ) {
            length += 1;
          }
          if (length > bestLength) {
            bestLength = length;
            bestOffset = i - candidate;
          }
        }
        if (i > 0 && bestLength >= 3) {
          const token = (((bestOffset - 1) << (16 - bitCount)) | (bestLength - 3)) & 0xffff;
          body.push(token & 0xff, token >> 8);
          flags |= 1 << bit;
          i += bestLength;
        } else {
          body.push(chunk[i] as number);
          i += 1;
        }
      }
      body[flagIndex] = flags;
    }
    const header = Buffer.alloc(2);
    if (body.length > CHUNK_DECOMPRESSED) {
      // Incompressible: a raw chunk (4096 bytes, zero-padded at the end of the stream).
      const raw = Buffer.alloc(CHUNK_DECOMPRESSED, 0);
      chunk.copy(raw);
      header.writeUInt16LE(((CHUNK_DECOMPRESSED + 2 - 3) & 0x0fff) | (0b011 << 12));
      parts.push(header, raw);
    } else {
      header.writeUInt16LE(((body.length + 2 - 3) & 0x0fff) | (0b011 << 12) | 0x8000);
      parts.push(header, Buffer.from(body));
    }
    if (chunk.length === 0) break;
  }
  return Buffer.concat(parts);
}

// ---------------------------------------------------------------------------------------------
// Compound File Binary (MS-CFB v3, 512-byte sectors, mini stream for streams < 4096 bytes)
// ---------------------------------------------------------------------------------------------

export interface CfbNode {
  name: string;
  type: 'storage' | 'stream';
  data?: Buffer;
  children?: CfbNode[];
}

const FREESECT = 0xffffffff;
const ENDOFCHAIN = 0xfffffffe;
const FATSECT = 0xfffffffd;
const NOSTREAM = 0xffffffff;

interface FlatEntry {
  name: string;
  type: 1 | 2 | 5;
  child: number;
  right: number;
  data: Buffer;
  start: number;
  size: number;
}

export function buildCfb(children: CfbNode[]): Buffer {
  const entries: FlatEntry[] = [
    {
      name: 'Root Entry',
      type: 5,
      child: NOSTREAM,
      right: NOSTREAM,
      data: Buffer.alloc(0),
      start: ENDOFCHAIN,
      size: 0,
    },
  ];
  const add = (nodes: CfbNode[], parent: number): void => {
    let previous = -1;
    for (const node of nodes) {
      const id = entries.length;
      entries.push({
        name: node.name,
        type: node.type === 'storage' ? 1 : 2,
        child: NOSTREAM,
        right: NOSTREAM,
        data: node.data ?? Buffer.alloc(0),
        start: ENDOFCHAIN,
        size: node.type === 'stream' ? (node.data?.length ?? 0) : 0,
      });
      if (previous < 0) (entries[parent] as FlatEntry).child = id;
      else (entries[previous] as FlatEntry).right = id;
      previous = id;
      if (node.type === 'storage') add(node.children ?? [], id);
    }
  };
  add(children, 0);

  // Mini stream for small streams, regular sectors for the others.
  const mini: Buffer[] = [];
  const miniFat: number[] = [];
  const big: FlatEntry[] = [];
  for (const e of entries) {
    if (e.type !== 2 || e.size === 0) continue;
    if (e.size < 4096) {
      const sectors = Math.ceil(e.size / 64);
      e.start = miniFat.length;
      for (let i = 0; i < sectors; i += 1)
        miniFat.push(i === sectors - 1 ? ENDOFCHAIN : miniFat.length + 1);
      const padded = Buffer.alloc(sectors * 64);
      e.data.copy(padded);
      mini.push(padded);
    } else {
      big.push(e);
    }
  }
  const miniStream = Buffer.concat(mini);
  const sectorsOf = (bytes: number): number => Math.ceil(bytes / 512);
  const dirSectors = sectorsOf(entries.length * 128);
  const miniFatSectors = sectorsOf(miniFat.length * 4);
  const miniStreamSectors = sectorsOf(miniStream.length);
  const bigSectors = big.map((e) => sectorsOf(e.size));
  const dataSectors =
    dirSectors + miniFatSectors + miniStreamSectors + bigSectors.reduce((a, b) => a + b, 0);
  let fatSectors = 1;
  while (fatSectors * 128 < fatSectors + dataSectors) fatSectors += 1;

  const fat: number[] = [];
  for (let i = 0; i < fatSectors; i += 1) fat.push(FATSECT);
  const chain = (count: number): number => {
    if (count === 0) return ENDOFCHAIN;
    const start = fat.length;
    for (let i = 0; i < count; i += 1) fat.push(i === count - 1 ? ENDOFCHAIN : fat.length + 1);
    return start;
  };
  const firstDir = chain(dirSectors);
  const firstMiniFat = chain(miniFatSectors);
  const root = entries[0] as FlatEntry;
  root.start = chain(miniStreamSectors);
  root.size = miniStream.length;
  big.forEach((e, i) => {
    e.start = chain(bigSectors[i] as number);
  });
  while (fat.length % 128 !== 0) fat.push(FREESECT);

  const header = Buffer.alloc(512, 0);
  Buffer.from([0xd0, 0xcf, 0x11, 0xe0, 0xa1, 0xb1, 0x1a, 0xe1]).copy(header, 0);
  header.writeUInt16LE(0x3e, 0x18);
  header.writeUInt16LE(3, 0x1a);
  header.writeUInt16LE(0xfffe, 0x1c);
  header.writeUInt16LE(9, 0x1e);
  header.writeUInt16LE(6, 0x20);
  header.writeUInt32LE(fatSectors, 0x2c);
  header.writeUInt32LE(firstDir, 0x30);
  header.writeUInt32LE(4096, 0x38);
  header.writeUInt32LE(miniFatSectors > 0 ? firstMiniFat : ENDOFCHAIN, 0x3c);
  header.writeUInt32LE(miniFatSectors, 0x40);
  header.writeUInt32LE(ENDOFCHAIN, 0x44);
  header.writeUInt32LE(0, 0x48);
  for (let i = 0; i < 109; i += 1)
    header.writeUInt32LE(i < fatSectors ? i : FREESECT, 0x4c + i * 4);

  const fatBytes = Buffer.alloc(fat.length * 4);
  fat.forEach((v, i) => fatBytes.writeUInt32LE(v >>> 0, i * 4));
  const dir = Buffer.alloc(dirSectors * 512, 0);
  for (let id = 0; id < dirSectors * 4; id += 1) {
    const at = id * 128;
    const e = entries[id];
    if (!e) {
      dir.writeUInt32LE(NOSTREAM, at + 68);
      dir.writeUInt32LE(NOSTREAM, at + 72);
      dir.writeUInt32LE(NOSTREAM, at + 76);
      continue;
    }
    const name = Buffer.from(`${e.name}\0`, 'utf16le');
    name.copy(dir, at, 0, Math.min(64, name.length));
    dir.writeUInt16LE(Math.min(64, name.length), at + 64);
    dir[at + 66] = e.type;
    dir[at + 67] = 1;
    dir.writeUInt32LE(NOSTREAM, at + 68);
    dir.writeUInt32LE(e.right >>> 0, at + 72);
    dir.writeUInt32LE(e.child >>> 0, at + 76);
    dir.writeUInt32LE(e.start >>> 0, at + 116);
    dir.writeUInt32LE(e.type === 1 ? 0 : e.size, at + 120);
  }
  const miniFatBytes = Buffer.alloc(miniFatSectors * 512, 0xff);
  miniFat.forEach((v, i) => miniFatBytes.writeUInt32LE(v >>> 0, i * 4));
  const pad = (b: Buffer): Buffer =>
    Buffer.concat([b, Buffer.alloc((512 - (b.length % 512)) % 512)]);
  return Buffer.concat([
    header,
    fatBytes,
    dir,
    miniFatBytes,
    pad(miniStream),
    ...big.map((e) => pad(e.data)),
  ]);
}

/** The records of a VBA `dir` stream for the given modules (MS-OVBA 2.3.4.2, minimal). */
export function vbaDirStream(modules: { name: string; textOffset: number }[]): Buffer {
  const parts: Buffer[] = [];
  const record = (id: number, data: Buffer): void => {
    const head = Buffer.alloc(6);
    head.writeUInt16LE(id, 0);
    head.writeUInt32LE(data.length, 2);
    parts.push(head, data);
  };
  const u16 = (v: number) => {
    const b = Buffer.alloc(2);
    b.writeUInt16LE(v);
    return b;
  };
  const u32 = (v: number) => {
    const b = Buffer.alloc(4);
    b.writeUInt32LE(v);
    return b;
  };
  record(0x0001, u32(1)); // PROJECTSYSKIND: win32
  // PROJECTVERSION: Id, Reserved (=4), VersionMajor (4), VersionMinor (2).
  const version = Buffer.alloc(12);
  version.writeUInt16LE(0x0009, 0);
  version.writeUInt32LE(4, 2);
  version.writeUInt32LE(1, 6);
  version.writeUInt16LE(0, 10);
  parts.push(version);
  record(0x000f, u16(modules.length)); // PROJECTMODULES
  record(0x0013, u16(0xffff)); // PROJECTCOOKIE
  for (const m of modules) {
    record(0x0019, Buffer.from(m.name, 'latin1'));
    record(0x0047, Buffer.from(m.name, 'utf16le'));
    record(0x001a, Buffer.from(m.name, 'latin1'));
    record(0x0032, Buffer.from(m.name, 'utf16le'));
    record(0x0031, u32(m.textOffset));
    record(0x0021, Buffer.alloc(0)); // MODULETYPE procedural
    record(0x002b, Buffer.alloc(0)); // MODULETERMINATOR
  }
  record(0x0010, Buffer.alloc(0)); // dir terminator
  return Buffer.concat(parts);
}

/**
 * A VBA project storage named `VBA` with one module whose source is `source` (compressed after a
 * dummy performance cache, as Office writes it).
 */
export function vbaStorage(source: string, moduleName = 'Module1'): CfbNode {
  const cache = Buffer.alloc(37, 0xcc);
  const module = Buffer.concat([cache, compressOvba(Buffer.from(source, 'latin1'))]);
  return {
    name: 'VBA',
    type: 'storage',
    children: [
      {
        name: 'dir',
        type: 'stream',
        data: compressOvba(vbaDirStream([{ name: moduleName, textOffset: cache.length }])),
      },
      { name: moduleName, type: 'stream', data: module },
      {
        name: '_VBA_PROJECT',
        type: 'stream',
        data: Buffer.from([0xcc, 0x61, 0xff, 0xff, 0x00, 0x00, 0x00]),
      },
    ],
  };
}

// ---------------------------------------------------------------------------------------------
// ZIP / OOXML
// ---------------------------------------------------------------------------------------------

export function buildZip(entries: { name: string; data: Buffer; store?: boolean }[]): Buffer {
  const locals: Buffer[] = [];
  const centrals: Buffer[] = [];
  let offset = 0;
  for (const e of entries) {
    const name = Buffer.from(e.name, 'utf8');
    const compressed = e.store ? e.data : deflateRawSync(e.data);
    const method = e.store ? 0 : 8;
    const local = Buffer.alloc(30);
    local.writeUInt32LE(0x04034b50, 0);
    local.writeUInt16LE(20, 4);
    local.writeUInt16LE(method, 8);
    local.writeUInt32LE(compressed.length, 18);
    local.writeUInt32LE(e.data.length, 22);
    local.writeUInt16LE(name.length, 26);
    locals.push(local, name, compressed);
    const central = Buffer.alloc(46);
    central.writeUInt32LE(0x02014b50, 0);
    central.writeUInt16LE(20, 4);
    central.writeUInt16LE(20, 6);
    central.writeUInt16LE(method, 10);
    central.writeUInt32LE(compressed.length, 20);
    central.writeUInt32LE(e.data.length, 24);
    central.writeUInt16LE(name.length, 28);
    central.writeUInt32LE(offset, 42);
    centrals.push(central, name);
    offset += 30 + name.length + compressed.length;
  }
  const cd = Buffer.concat(centrals);
  const eocd = Buffer.alloc(22);
  eocd.writeUInt32LE(0x06054b50, 0);
  eocd.writeUInt16LE(entries.length, 8);
  eocd.writeUInt16LE(entries.length, 10);
  eocd.writeUInt32LE(cd.length, 12);
  eocd.writeUInt32LE(offset, 16);
  return Buffer.concat([...locals, cd, eocd]);
}

const CONTENT_TYPES = Buffer.from(
  '<?xml version="1.0"?><Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"></Types>',
);

/** A minimal Word package; `parts` adds or overrides entries. */
export function buildDocx(parts: Record<string, Buffer | string>): Buffer {
  const base: Record<string, Buffer | string> = {
    '[Content_Types].xml': CONTENT_TYPES,
    '_rels/.rels':
      '<?xml version="1.0"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"></Relationships>',
    'word/document.xml':
      '<?xml version="1.0"?><w:document><w:body><w:p><w:r><w:t>Hello</w:t></w:r></w:p></w:body></w:document>',
  };
  return buildZip(
    Object.entries({ ...base, ...parts }).map(([name, data]) => ({
      name,
      data: Buffer.isBuffer(data) ? data : Buffer.from(data, 'utf8'),
    })),
  );
}

// ---------------------------------------------------------------------------------------------
// PE (PE32, i386)
// ---------------------------------------------------------------------------------------------

export interface PeOptions {
  imports?: Record<string, string[]>;
  sectionNames?: [string, string];
  /** Random (high-entropy) code section. */
  packedCode?: boolean;
  overlay?: Buffer;
}

export function buildPe(options: PeOptions = {}): Buffer {
  const imports = options.imports ?? { 'kernel32.dll': ['ExitProcess'] };
  const [textName, idataName] = options.sectionNames ?? ['.text', '.idata'];
  const FILE_ALIGN = 0x200;
  const TEXT_RVA = 0x1000;
  const IDATA_RVA = 0x2000;

  // .idata: descriptors, ILTs, hint/name entries, DLL names.
  const dlls = Object.entries(imports);
  const descriptorsSize = (dlls.length + 1) * 20;
  let cursor = descriptorsSize;
  const ilts = dlls.map(([, fns]) => {
    const at = cursor;
    cursor += (fns.length + 1) * 4;
    return at;
  });
  const hintNames: number[][] = [];
  const dllNameAt: number[] = [];
  const blobs: { at: number; data: Buffer }[] = [];
  dlls.forEach(([dll, fns]) => {
    const offsets: number[] = [];
    for (const fn of fns) {
      const data = Buffer.concat([Buffer.alloc(2), Buffer.from(`${fn}\0`, 'latin1')]);
      const padded = data.length % 2 ? Buffer.concat([data, Buffer.alloc(1)]) : data;
      offsets.push(cursor);
      blobs.push({ at: cursor, data: padded });
      cursor += padded.length;
    }
    hintNames.push(offsets);
    dllNameAt.push(cursor);
    const name = Buffer.from(`${dll}\0`, 'latin1');
    blobs.push({ at: cursor, data: name });
    cursor += name.length;
  });
  const idata = Buffer.alloc(Math.ceil(cursor / FILE_ALIGN) * FILE_ALIGN);
  dlls.forEach((_, i) => {
    const d = i * 20;
    idata.writeUInt32LE(IDATA_RVA + (ilts[i] as number), d);
    idata.writeUInt32LE(IDATA_RVA + (dllNameAt[i] as number), d + 12);
    idata.writeUInt32LE(IDATA_RVA + (ilts[i] as number), d + 16);
    (hintNames[i] as number[]).forEach((hn, j) =>
      idata.writeUInt32LE(IDATA_RVA + hn, (ilts[i] as number) + j * 4),
    );
  });
  for (const b of blobs) b.data.copy(idata, b.at);

  const text = Buffer.alloc(0x800, 0x90);
  if (options.packedCode) {
    for (let i = 0; i < text.length; i += 1) text[i] = Math.floor(Math.random() * 256);
  }

  const headers = Buffer.alloc(0x400);
  headers.write('MZ', 0, 'latin1');
  headers.writeUInt32LE(0x80, 0x3c);
  headers.writeUInt32LE(0x00004550, 0x80);
  const coff = 0x84;
  headers.writeUInt16LE(0x14c, coff);
  headers.writeUInt16LE(2, coff + 2);
  headers.writeUInt16LE(0xe0, coff + 16);
  headers.writeUInt16LE(0x102, coff + 18);
  const opt = coff + 20;
  headers.writeUInt16LE(0x10b, opt);
  headers.writeUInt32LE(16, opt + 92);
  headers.writeUInt32LE(IDATA_RVA, opt + 96 + 8);
  headers.writeUInt32LE(descriptorsSize, opt + 96 + 12);
  const sections = opt + 0xe0;
  const writeSection = (
    at: number,
    name: string,
    rva: number,
    raw: number,
    size: number,
    flags: number,
  ) => {
    headers.write(name.slice(0, 8), at, 'latin1');
    headers.writeUInt32LE(size, at + 8);
    headers.writeUInt32LE(rva, at + 12);
    headers.writeUInt32LE(size, at + 16);
    headers.writeUInt32LE(raw, at + 20);
    headers.writeUInt32LE(flags >>> 0, at + 36);
  };
  writeSection(sections, textName, TEXT_RVA, 0x400, text.length, 0x60000020);
  writeSection(sections + 40, idataName, IDATA_RVA, 0x400 + text.length, idata.length, 0xc0000040);
  return Buffer.concat([headers, text, idata, options.overlay ?? Buffer.alloc(0)]);
}

// ---------------------------------------------------------------------------------------------
// ELF, LNK, PDF
// ---------------------------------------------------------------------------------------------

export function buildElf(options: { body?: Buffer } = {}): Buffer {
  const header = Buffer.alloc(64);
  header.writeUInt32BE(0x7f454c46, 0);
  header[4] = 2;
  header[5] = 1;
  header[6] = 1;
  header.writeUInt16LE(2, 16); // ET_EXEC
  header.writeUInt16LE(0x3e, 18); // x86-64
  header.writeUInt32LE(1, 20);
  header.writeBigUInt64LE(64n, 32); // phoff
  header.writeBigUInt64LE(0n, 40); // shoff
  header.writeUInt16LE(64, 52);
  header.writeUInt16LE(56, 54);
  header.writeUInt16LE(1, 56);
  header.writeUInt16LE(64, 58);
  header.writeUInt16LE(0, 60);
  return Buffer.concat([header, Buffer.alloc(56), options.body ?? Buffer.alloc(256)]);
}

export function buildLnk(options: { relativePath?: string; arguments?: string } = {}): Buffer {
  const header = Buffer.alloc(0x4c);
  header.writeUInt32LE(0x4c, 0);
  Buffer.from('0114020000000000c000000000000046', 'hex').copy(header, 4);
  let flags = 0x80; // IsUnicode
  const strings: Buffer[] = [];
  const str = (value: string): Buffer => {
    const count = Buffer.alloc(2);
    count.writeUInt16LE(value.length);
    return Buffer.concat([count, Buffer.from(value, 'utf16le')]);
  };
  if (options.relativePath !== undefined) {
    flags |= 0x08;
    strings.push(str(options.relativePath));
  }
  if (options.arguments !== undefined) {
    flags |= 0x20;
    strings.push(str(options.arguments));
  }
  header.writeUInt32LE(flags, 0x14);
  return Buffer.concat([header, ...strings]);
}

/** A tiny PDF; `objects` are raw object bodies; `objectStream` is put into a Flate ObjStm. */
export function buildPdf(objects: string[], objectStream?: string): Buffer {
  const parts: Buffer[] = [Buffer.from('%PDF-1.7\n%\xe2\xe3\xcf\xd3\n', 'latin1')];
  objects.forEach((body, i) =>
    parts.push(Buffer.from(`${String(i + 1)} 0 obj\n${body}\nendobj\n`, 'latin1')),
  );
  if (objectStream !== undefined) {
    const data = deflateSync(Buffer.from(objectStream, 'latin1'));
    const n = objects.length + 1;
    parts.push(
      Buffer.from(
        `${String(n)} 0 obj\n<< /Type /ObjStm /N 1 /First 4 /Length ${String(data.length)} /Filter /FlateDecode >>\nstream\n`,
        'latin1',
      ),
      data,
      Buffer.from('\nendstream\nendobj\n', 'latin1'),
    );
  }
  parts.push(Buffer.from('trailer\n<< /Root 1 0 R >>\n%%EOF\n', 'latin1'));
  return Buffer.concat(parts);
}
