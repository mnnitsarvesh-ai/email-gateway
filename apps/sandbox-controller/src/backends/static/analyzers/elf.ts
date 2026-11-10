import { type Analysis, entropy } from './analysis';

/**
 * ELF analyzer (step 4.6 X4 `elf`): header sanity (class, byte order, version, type, header
 * size, program/section header tables inside the file) and packing (`UPX!` marker, entropy).
 */

export function isElf(bytes: Buffer): boolean {
  return bytes.length >= 16 && bytes.readUInt32BE(0) === 0x7f454c46;
}

export function analyzeElf(bytes: Buffer, analysis: Analysis): void {
  if (!isElf(bytes)) {
    analysis.fact('elf.parsed', false);
    return;
  }
  analysis.format = 'elf';
  analysis.supported = true;
  const cls = bytes[4];
  const data = bytes[5];
  const is64 = cls === 2;
  const le = data === 1;
  const headerSize = is64 ? 64 : 52;
  let sane = (cls === 1 || cls === 2) && (data === 1 || data === 2) && bytes[6] === 1;
  if (sane && bytes.length >= headerSize) {
    const u16 = (o: number) => (le ? bytes.readUInt16LE(o) : bytes.readUInt16BE(o));
    const u32 = (o: number) => (le ? bytes.readUInt32LE(o) : bytes.readUInt32BE(o));
    const off = (o: number) =>
      is64 ? Number(le ? bytes.readBigUInt64LE(o) : bytes.readBigUInt64BE(o)) : u32(o);
    const type = u16(16);
    const machine = u16(18);
    const phoff = off(is64 ? 32 : 28);
    const shoff = off(is64 ? 40 : 32);
    const ehsize = u16(is64 ? 52 : 40);
    const phentsize = u16(is64 ? 54 : 42);
    const phnum = u16(is64 ? 56 : 44);
    const shentsize = u16(is64 ? 58 : 46);
    const shnum = u16(is64 ? 60 : 48);
    analysis.fact('elf.class', is64 ? 'elf64' : 'elf32');
    analysis.fact('elf.type', type);
    analysis.fact('elf.machine', machine);
    const inFile = (offset: number, size: number, count: number) =>
      count === 0 || (offset > 0 && offset + size * count <= bytes.length);
    sane =
      type >= 1 &&
      type <= 4 &&
      ehsize === headerSize &&
      inFile(phoff, phentsize, phnum) &&
      inFile(shoff, shentsize, shnum);
    analysis.fact('elf.sectionHeaders', shnum);
  } else {
    sane = false;
  }
  analysis.fact('elf.headerSane', sane);
  let packed = 0;
  if (bytes.includes(Buffer.from('UPX!', 'latin1'))) {
    packed += 1;
    analysis.token('UPX!');
  }
  // A stripped, packed ELF often has no section headers and a high overall entropy.
  if (bytes.length >= 4096 && entropy(bytes) > 7.2) packed += 1;
  if (packed > 0) analysis.add('static.elf_packed', packed);
}
