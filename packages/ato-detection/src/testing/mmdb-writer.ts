/**
 * Minimal MaxMind DB (MMDB) format 2.0 writer (test kit; step 8.4 D7): an IPv6 search tree with
 * 24-bit records (IPv4 networks under `::/96`, which is where readers look up IPv4 addresses), a
 * data section with the types the GeoIP2 models use (map, UTF-8 string, double, uint16, uint32,
 * uint64, int32, array, boolean) and the metadata section. Deterministic: equal input gives equal
 * bytes (no timestamps; identical records are stored once). Never used at runtime — production
 * reads operator-provided MaxMind files.
 */
import { parseCidr } from '../net';

export type MmdbNumber =
  | { type: 'double'; value: number }
  | { type: 'uint16'; value: number }
  | { type: 'uint32'; value: number }
  | { type: 'uint64'; value: number | bigint }
  | { type: 'int32'; value: number };

export type MmdbValue =
  | string
  | boolean
  | number
  | MmdbNumber
  | readonly MmdbValue[]
  | { readonly [key: string]: MmdbValue };

export const mmdb = {
  double: (value: number): MmdbNumber => ({ type: 'double', value }),
  uint16: (value: number): MmdbNumber => ({ type: 'uint16', value }),
  uint32: (value: number): MmdbNumber => ({ type: 'uint32', value }),
  uint64: (value: number | bigint): MmdbNumber => ({ type: 'uint64', value }),
  int32: (value: number): MmdbNumber => ({ type: 'int32', value }),
};

export interface MmdbNetwork {
  /** IPv4 or IPv6 CIDR (networks must not overlap). */
  cidr: string;
  data: { readonly [key: string]: MmdbValue };
}

export interface MmdbSpec {
  databaseType: string;
  description: Record<string, string>;
  /** Seconds since the epoch (metadata `build_epoch`). */
  buildEpoch: number;
  languages?: readonly string[];
  networks: readonly MmdbNetwork[];
}

const METADATA_MARKER = Buffer.from([0xab, 0xcd, 0xef, ...Buffer.from('MaxMind.com', 'ascii')]);

const TYPE = {
  utf8: 2,
  double: 3,
  uint16: 5,
  uint32: 6,
  map: 7,
  int32: 8,
  uint64: 9,
  array: 11,
  boolean: 14,
} as const;

function control(type: number, size: number): Buffer {
  const head: number[] = [];
  let first = type <= 7 ? type << 5 : 0;
  const extra: number[] = [];
  if (size < 29) {
    first |= size;
  } else if (size < 29 + 256) {
    first |= 29;
    extra.push(size - 29);
  } else if (size < 285 + 65536) {
    first |= 30;
    const v = size - 285;
    extra.push((v >> 8) & 0xff, v & 0xff);
  } else {
    first |= 31;
    const v = size - 65821;
    extra.push((v >> 16) & 0xff, (v >> 8) & 0xff, v & 0xff);
  }
  head.push(first);
  if (type > 7) head.push(type - 7);
  return Buffer.from([...head, ...extra]);
}

function uintBytes(value: number | bigint): Buffer {
  let v = BigInt(value);
  if (v < 0n) throw new Error('unsigned value expected');
  const bytes: number[] = [];
  while (v > 0n) {
    bytes.unshift(Number(v & 0xffn));
    v >>= 8n;
  }
  return Buffer.from(bytes);
}

/** Encodes one value in the MMDB data format. */
export function encodeMmdbValue(value: MmdbValue): Buffer {
  if (typeof value === 'string') {
    const bytes = Buffer.from(value, 'utf8');
    return Buffer.concat([control(TYPE.utf8, bytes.length), bytes]);
  }
  if (typeof value === 'boolean') return control(TYPE.boolean, value ? 1 : 0);
  if (typeof value === 'number') {
    return Number.isInteger(value) && value >= 0 && value <= 0xffffffff
      ? encodeMmdbValue(mmdb.uint32(value))
      : encodeMmdbValue(mmdb.double(value));
  }
  if (Array.isArray(value)) {
    return Buffer.concat([
      control(TYPE.array, value.length),
      ...value.map((v: MmdbValue) => encodeMmdbValue(v)),
    ]);
  }
  const obj = value as Record<string, unknown>;
  if (typeof obj.type === 'string' && 'value' in obj && Object.keys(obj).length === 2) {
    const n = obj as unknown as MmdbNumber;
    switch (n.type) {
      case 'double': {
        const b = Buffer.alloc(8);
        b.writeDoubleBE(n.value);
        return Buffer.concat([control(TYPE.double, 8), b]);
      }
      case 'uint16':
      case 'uint32':
      case 'uint64': {
        const b = uintBytes(n.value);
        const max = n.type === 'uint16' ? 2 : n.type === 'uint32' ? 4 : 8;
        if (b.length > max) throw new Error(`${n.type} out of range`);
        return Buffer.concat([control(TYPE[n.type], b.length), b]);
      }
      case 'int32': {
        const b = Buffer.alloc(4);
        b.writeInt32BE(n.value);
        return Buffer.concat([control(TYPE.int32, 4), b]);
      }
    }
  }
  const entries = Object.entries(value as Record<string, MmdbValue>);
  return Buffer.concat([
    control(TYPE.map, entries.length),
    ...entries.flatMap(([k, v]) => [encodeMmdbValue(k), encodeMmdbValue(v)]),
  ]);
}

interface TrieNode {
  left: TrieNode | number | null;
  right: TrieNode | number | null;
}

/** Writes an MMDB v2 database (IPv6 tree, 24-bit records). */
export function writeMmdb(spec: MmdbSpec): Buffer {
  // Data section: identical records are written once.
  const dataParts: Buffer[] = [];
  const offsets = new Map<string, number>();
  let dataLength = 0;
  const dataOffset = (data: MmdbNetwork['data']): number => {
    const encoded = encodeMmdbValue(data);
    const key = encoded.toString('base64');
    const known = offsets.get(key);
    if (known !== undefined) return known;
    offsets.set(key, dataLength);
    dataParts.push(encoded);
    dataLength += encoded.length;
    return dataLength - encoded.length;
  };

  const root: TrieNode = { left: null, right: null };
  for (const network of spec.networks) {
    const parsed = parseCidr(network.cidr);
    if (!parsed) throw new Error(`invalid CIDR ${network.cidr}`);
    const bytes = Buffer.alloc(16);
    let prefix = parsed.prefix;
    if (parsed.version === 4) {
      parsed.start.copy(bytes, 12);
      prefix += 96;
    } else {
      parsed.start.copy(bytes, 0);
    }
    if (prefix === 0) throw new Error('a /0 network is not supported');
    const offset = dataOffset(network.data);
    let node = root;
    for (let i = 0; i < prefix; i++) {
      const bit = (bytes[i >> 3]! >> (7 - (i & 7))) & 1;
      const side = bit === 0 ? 'left' : 'right';
      const last = i === prefix - 1;
      const next = node[side];
      if (last) {
        if (next !== null) throw new Error(`overlapping network ${network.cidr}`);
        node[side] = offset;
      } else {
        if (typeof next === 'number') throw new Error(`overlapping network ${network.cidr}`);
        if (next === null) node[side] = { left: null, right: null };
        node = node[side] as TrieNode;
      }
    }
  }

  // Breadth-first numbering (root = 0).
  const nodes: TrieNode[] = [];
  const index = new Map<TrieNode, number>();
  const queue: TrieNode[] = [root];
  while (queue.length > 0) {
    const n = queue.shift()!;
    index.set(n, nodes.length);
    nodes.push(n);
    for (const child of [n.left, n.right]) {
      if (child !== null && typeof child === 'object') queue.push(child);
    }
  }
  const nodeCount = nodes.length;
  if (nodeCount + 16 + dataLength >= 1 << 24)
    throw new Error('database too large for 24-bit records');
  const record = (r: TrieNode | number | null): number => {
    if (r === null) return nodeCount;
    if (typeof r === 'number') return nodeCount + 16 + r;
    return index.get(r)!;
  };
  const tree = Buffer.alloc(nodeCount * 6);
  nodes.forEach((n, i) => {
    tree.writeUIntBE(record(n.left), i * 6, 3);
    tree.writeUIntBE(record(n.right), i * 6 + 3, 3);
  });

  const metadata = encodeMmdbValue({
    binary_format_major_version: mmdb.uint16(2),
    binary_format_minor_version: mmdb.uint16(0),
    build_epoch: mmdb.uint64(spec.buildEpoch),
    database_type: spec.databaseType,
    description: spec.description,
    ip_version: mmdb.uint16(6),
    languages: [...(spec.languages ?? ['en'])],
    node_count: mmdb.uint32(nodeCount),
    record_size: mmdb.uint16(24),
  });
  return Buffer.concat([tree, Buffer.alloc(16), ...dataParts, METADATA_MARKER, metadata]);
}
