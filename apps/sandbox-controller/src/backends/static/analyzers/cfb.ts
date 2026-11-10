/**
 * A bounded reader of the Compound File Binary format ([MS-CFB]; OLE2: .doc, .xls, .ppt, .msi,
 * vbaProject.bin). Header, DIFAT/FAT, directory entries (tree walk with parents), mini stream
 * and stream reads with cycle detection and caps. Pure; throws `CfbError` on malformed input.
 */

export class CfbError extends Error {
  override readonly name = 'CfbError';
  constructor(readonly code: string) {
    super(`compound file: ${code}`);
  }
}

export const CFB_SIGNATURE = Buffer.from([0xd0, 0xcf, 0x11, 0xe0, 0xa1, 0xb1, 0x1a, 0xe1]);
const FREESECT = 0xffffffff;
const ENDOFCHAIN = 0xfffffffe;
const NOSTREAM = 0xffffffff;
const MAX_ENTRIES = 4096;
const MAX_STREAM_BYTES = 16 * 1024 * 1024;

export interface CfbEntry {
  id: number;
  name: string;
  /** 1 storage, 2 stream, 5 root. */
  type: number;
  left: number;
  right: number;
  child: number;
  start: number;
  size: number;
  parent: number | null;
}

export function isCfb(bytes: Buffer): boolean {
  return bytes.length >= 512 && bytes.subarray(0, 8).equals(CFB_SIGNATURE);
}

export class CompoundFile {
  readonly entries: CfbEntry[] = [];
  private readonly sectorSize: number;
  private readonly miniSectorSize: number;
  private readonly miniCutoff: number;
  private readonly fat: number[];
  private miniFat: number[] = [];
  private miniStream: Buffer = Buffer.alloc(0);

  constructor(private readonly bytes: Buffer) {
    if (!isCfb(bytes)) throw new CfbError('signature');
    if (bytes.readUInt16LE(0x1c) !== 0xfffe) throw new CfbError('byte_order');
    const shift = bytes.readUInt16LE(0x1e);
    if (shift !== 9 && shift !== 12) throw new CfbError('sector_shift');
    this.sectorSize = 1 << shift;
    const miniShift = bytes.readUInt16LE(0x20);
    if (miniShift !== 6) throw new CfbError('mini_sector_shift');
    this.miniSectorSize = 1 << miniShift;
    this.miniCutoff = bytes.readUInt32LE(0x38);
    const fatSectors = bytes.readUInt32LE(0x2c);
    const firstDir = bytes.readUInt32LE(0x30);
    const firstMiniFat = bytes.readUInt32LE(0x3c);
    const miniFatSectors = bytes.readUInt32LE(0x40);
    const firstDifat = bytes.readUInt32LE(0x44);
    const difatSectors = bytes.readUInt32LE(0x48);
    const maxSectors = Math.ceil(bytes.length / this.sectorSize);
    if (fatSectors > maxSectors || difatSectors > maxSectors || miniFatSectors > maxSectors) {
      throw new CfbError('counts');
    }

    // DIFAT: 109 entries in the header, then the DIFAT chain.
    const fatSectorIds: number[] = [];
    for (let i = 0; i < 109 && fatSectorIds.length < fatSectors; i += 1) {
      const sid = bytes.readUInt32LE(0x4c + i * 4);
      if (sid !== FREESECT) fatSectorIds.push(sid);
    }
    let difat = firstDifat;
    const seenDifat = new Set<number>();
    const perDifat = this.sectorSize / 4 - 1;
    while (difat !== ENDOFCHAIN && difat !== FREESECT && fatSectorIds.length < fatSectors) {
      if (seenDifat.has(difat) || seenDifat.size > maxSectors) throw new CfbError('difat_cycle');
      seenDifat.add(difat);
      const offset = this.sectorOffset(difat);
      for (let i = 0; i < perDifat && fatSectorIds.length < fatSectors; i += 1) {
        const sid = bytes.readUInt32LE(offset + i * 4);
        if (sid !== FREESECT) fatSectorIds.push(sid);
      }
      difat = bytes.readUInt32LE(offset + perDifat * 4);
    }
    this.fat = [];
    for (const sid of fatSectorIds) {
      const offset = this.sectorOffset(sid);
      for (let i = 0; i < this.sectorSize / 4; i += 1)
        this.fat.push(bytes.readUInt32LE(offset + i * 4));
    }

    // Directory.
    const dir = this.readChain(firstDir, MAX_ENTRIES * 128);
    const count = Math.min(Math.floor(dir.length / 128), MAX_ENTRIES);
    for (let id = 0; id < count; id += 1) {
      const at = id * 128;
      const nameLength = Math.min(dir.readUInt16LE(at + 64), 64);
      const name = dir.subarray(at, at + Math.max(0, nameLength - 2)).toString('utf16le');
      this.entries.push({
        id,
        name,
        type: dir[at + 66] as number,
        left: dir.readUInt32LE(at + 68),
        right: dir.readUInt32LE(at + 72),
        child: dir.readUInt32LE(at + 76),
        start: dir.readUInt32LE(at + 116),
        size: dir.readUInt32LE(at + 120),
        parent: null,
      });
    }
    const root = this.entries[0];
    if (!root || root.type !== 5) throw new CfbError('root');
    this.linkParents();

    if (firstMiniFat !== ENDOFCHAIN && firstMiniFat !== FREESECT && miniFatSectors > 0) {
      const miniFatBytes = this.readChain(firstMiniFat, miniFatSectors * this.sectorSize);
      for (let i = 0; i + 4 <= miniFatBytes.length; i += 4)
        this.miniFat.push(miniFatBytes.readUInt32LE(i));
      this.miniStream = this.readChain(root.start, Math.min(root.size, MAX_STREAM_BYTES));
    }
  }

  private sectorOffset(sid: number): number {
    const offset = (sid + 1) * this.sectorSize;
    if (sid >= ENDOFCHAIN - 16 || offset + this.sectorSize > this.bytes.length)
      throw new CfbError('sector_range');
    return offset;
  }

  private readChain(start: number, maxBytes: number): Buffer {
    const parts: Buffer[] = [];
    let total = 0;
    let sid = start;
    const seen = new Set<number>();
    while (sid !== ENDOFCHAIN && total < maxBytes) {
      if (sid === FREESECT || seen.has(sid) || sid >= this.fat.length) throw new CfbError('chain');
      seen.add(sid);
      const offset = this.sectorOffset(sid);
      parts.push(this.bytes.subarray(offset, offset + this.sectorSize));
      total += this.sectorSize;
      sid = this.fat[sid] as number;
    }
    return Buffer.concat(parts).subarray(0, Math.min(total, maxBytes));
  }

  private readMiniChain(start: number, size: number): Buffer {
    const parts: Buffer[] = [];
    let total = 0;
    let sid = start;
    const seen = new Set<number>();
    while (sid !== ENDOFCHAIN && total < size) {
      if (sid === FREESECT || seen.has(sid) || sid >= this.miniFat.length)
        throw new CfbError('mini_chain');
      seen.add(sid);
      const offset = sid * this.miniSectorSize;
      if (offset + this.miniSectorSize > this.miniStream.length) throw new CfbError('mini_range');
      parts.push(this.miniStream.subarray(offset, offset + this.miniSectorSize));
      total += this.miniSectorSize;
      sid = this.miniFat[sid] as number;
    }
    return Buffer.concat(parts).subarray(0, size);
  }

  /** Walks the red-black sibling trees from the root, recording each entry's parent storage. */
  private linkParents(): void {
    const visited = new Set<number>();
    const stack: { id: number; parent: number }[] = [];
    const root = this.entries[0] as CfbEntry;
    visited.add(0);
    if (root.child !== NOSTREAM) stack.push({ id: root.child, parent: 0 });
    while (stack.length > 0) {
      const { id, parent } = stack.pop() as { id: number; parent: number };
      const entry = this.entries[id];
      if (!entry || visited.has(id)) continue;
      visited.add(id);
      entry.parent = parent;
      if (entry.left !== NOSTREAM) stack.push({ id: entry.left, parent });
      if (entry.right !== NOSTREAM) stack.push({ id: entry.right, parent });
      if ((entry.type === 1 || entry.type === 5) && entry.child !== NOSTREAM) {
        stack.push({ id: entry.child, parent: id });
      }
    }
  }

  /** Children (streams and storages) of a storage entry. */
  children(storageId: number): CfbEntry[] {
    return this.entries.filter((e) => e.parent === storageId);
  }

  /** The bytes of a stream entry (≤ 16 MiB). */
  read(entry: CfbEntry): Buffer {
    if (entry.type !== 2) throw new CfbError('not_a_stream');
    const size = Math.min(entry.size, MAX_STREAM_BYTES);
    if (size === 0) return Buffer.alloc(0);
    if (entry.size < this.miniCutoff) return this.readMiniChain(entry.start, size);
    return this.readChain(entry.start, size);
  }
}
