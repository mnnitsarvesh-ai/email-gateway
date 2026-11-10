import { type Analysis, entropy } from './analysis';

/**
 * PE (Windows executable) analyzer (step 4.6 X4 `pe`): DOS and PE headers, machine, sections
 * (names, entropy, executable flag), the import table (DLL and function names, no disassembly)
 * and the overlay. Every offset is bounds-checked; malformed input ends the parse with a fact,
 * never an exception out of the analyzer.
 */

const MAX_SECTIONS = 96;
const MAX_DLLS = 256;
const MAX_FUNCTIONS = 8192;
const MAX_NAME = 256;

const IMAGE_SCN_CNT_CODE = 0x20;
const IMAGE_SCN_MEM_EXECUTE = 0x20000000;

const PACKER_SECTIONS = new Set([
  'UPX0',
  'UPX1',
  'UPX2',
  'UPX!',
  '.UPX0',
  '.UPX1',
  '.aspack',
  '.adata',
  'ASPack',
  '.MPRESS1',
  '.MPRESS2',
  'MPRESS1',
  'MPRESS2',
]);

const INJECTION = {
  alloc: ['VirtualAllocEx', 'NtAllocateVirtualMemory', 'ZwAllocateVirtualMemory'],
  write: ['WriteProcessMemory', 'NtWriteVirtualMemory', 'ZwWriteVirtualMemory'],
  thread: [
    'CreateRemoteThread',
    'CreateRemoteThreadEx',
    'RtlCreateUserThread',
    'NtCreateThreadEx',
    'QueueUserAPC',
    'NtQueueApcThread',
    'SetThreadContext',
  ],
  unmap: ['NtUnmapViewOfSection', 'ZwUnmapViewOfSection'],
} as const;
const DOWNLOAD = ['URLDownloadToFileA', 'URLDownloadToFileW', 'URLDownloadToFile'];
const INTERNET_OPEN = ['InternetOpenUrlA', 'InternetOpenUrlW', 'InternetOpenUrl'];
const EXEC = [
  'WinExec',
  'ShellExecuteA',
  'ShellExecuteW',
  'ShellExecuteExA',
  'ShellExecuteExW',
  'ShellExecute',
];
const ANTI_DEBUG = ['IsDebuggerPresent', 'CheckRemoteDebuggerPresent'];

interface Section {
  name: string;
  virtualAddress: number;
  virtualSize: number;
  rawSize: number;
  rawPointer: number;
  characteristics: number;
}

class Reader {
  constructor(readonly b: Buffer) {}
  ok(offset: number, length: number): boolean {
    return (
      Number.isInteger(offset) && offset >= 0 && length >= 0 && offset + length <= this.b.length
    );
  }
  u16(o: number): number | null {
    return this.ok(o, 2) ? this.b.readUInt16LE(o) : null;
  }
  u32(o: number): number | null {
    return this.ok(o, 4) ? this.b.readUInt32LE(o) : null;
  }
  u64(o: number): bigint | null {
    return this.ok(o, 8) ? this.b.readBigUInt64LE(o) : null;
  }
  cstr(o: number, max = MAX_NAME): string | null {
    if (!this.ok(o, 1)) return null;
    const end = this.b.indexOf(0, o);
    const stop = end < 0 ? Math.min(this.b.length, o + max) : Math.min(end, o + max);
    const s = this.b.subarray(o, stop).toString('latin1');
    return /^[\x20-\x7e]*$/.test(s) ? s : null;
  }
}

/** True when the bytes start with a DOS header pointing at a PE signature. */
export function isPe(bytes: Buffer): boolean {
  if (bytes.length < 0x40 || bytes[0] !== 0x4d || bytes[1] !== 0x5a) return false;
  const lfanew = bytes.readUInt32LE(0x3c);
  return lfanew + 4 <= bytes.length && bytes.readUInt32LE(lfanew) === 0x00004550;
}

function rvaToOffset(rva: number, sections: Section[]): number | null {
  for (const s of sections) {
    const size = Math.max(s.virtualSize, s.rawSize);
    if (rva >= s.virtualAddress && rva < s.virtualAddress + size) {
      const delta = rva - s.virtualAddress;
      if (delta >= s.rawSize) return null;
      return s.rawPointer + delta;
    }
  }
  return null;
}

export function analyzePe(bytes: Buffer, analysis: Analysis): void {
  const r = new Reader(bytes);
  if (!isPe(bytes)) {
    analysis.fact('pe.parsed', false);
    return;
  }
  analysis.format = 'pe';
  analysis.supported = true;
  const pe = bytes.readUInt32LE(0x3c);
  const coff = pe + 4;
  const machine = r.u16(coff);
  const sectionCount = r.u16(coff + 2);
  const optSize = r.u16(coff + 16);
  if (machine === null || sectionCount === null || optSize === null) {
    analysis.fact('pe.parsed', false);
    return;
  }
  analysis.fact('pe.machine', `0x${machine.toString(16)}`);
  const opt = coff + 20;
  const magic = r.u16(opt);
  const pe32plus = magic === 0x20b;
  if (magic !== 0x10b && magic !== 0x20b) {
    analysis.fact('pe.parsed', false);
    return;
  }
  analysis.fact('pe.format', pe32plus ? 'pe32plus' : 'pe32');
  const dirCountOffset = opt + (pe32plus ? 108 : 92);
  const dirs = opt + (pe32plus ? 112 : 96);
  const dirCount = Math.min(r.u32(dirCountOffset) ?? 0, 16);
  const dir = (index: number): { rva: number; size: number } | null => {
    if (index >= dirCount) return null;
    const rva = r.u32(dirs + index * 8);
    const size = r.u32(dirs + index * 8 + 4);
    return rva === null || size === null ? null : { rva, size };
  };

  // Sections.
  const sections: Section[] = [];
  const sectionTable = opt + optSize;
  const count = Math.min(sectionCount, MAX_SECTIONS);
  for (let i = 0; i < count; i += 1) {
    const at = sectionTable + i * 40;
    if (!r.ok(at, 40)) break;
    const rawName = bytes.subarray(at, at + 8);
    const nul = rawName.indexOf(0);
    const name = rawName.subarray(0, nul < 0 ? 8 : nul).toString('latin1');
    sections.push({
      name: /^[\x20-\x7e]{0,8}$/.test(name) ? name : '',
      virtualSize: bytes.readUInt32LE(at + 8),
      virtualAddress: bytes.readUInt32LE(at + 12),
      rawSize: bytes.readUInt32LE(at + 16),
      rawPointer: bytes.readUInt32LE(at + 20),
      characteristics: bytes.readUInt32LE(at + 36),
    });
  }
  analysis.fact('pe.sections', sections.length);
  let packed = 0;
  let maxExecEntropy = 0;
  let rawEnd = 0;
  for (const s of sections) {
    if (PACKER_SECTIONS.has(s.name)) {
      packed += 1;
      analysis.token(s.name);
    }
    const start = s.rawPointer;
    const end = Math.min(bytes.length, s.rawPointer + s.rawSize);
    if (s.rawSize > 0 && start < bytes.length) rawEnd = Math.max(rawEnd, end);
    const executable = (s.characteristics & (IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_CNT_CODE)) !== 0;
    if (executable && end - start >= 512) {
      const h = entropy(bytes.subarray(start, end));
      maxExecEntropy = Math.max(maxExecEntropy, h);
      if (h > 7.2) packed += 1;
    }
  }
  analysis.fact('pe.maxExecEntropy', maxExecEntropy);
  if (packed > 0) analysis.add('static.pe_packed', packed);

  // Overlay: bytes after the last section, excluding an Authenticode certificate at the end.
  const security = dir(4);
  let fileEnd = bytes.length;
  if (
    security &&
    security.size > 0 &&
    security.rva >= rawEnd &&
    security.rva + security.size <= bytes.length
  ) {
    // The security directory's "RVA" is a file offset.
    if (security.rva + security.size >= bytes.length - 8) fileEnd = security.rva;
  }
  if (rawEnd > 0 && fileEnd > rawEnd) {
    analysis.fact('pe.overlayBytes', fileEnd - rawEnd);
    analysis.add('static.pe_overlay');
  }

  // Imports.
  const imports = new Set<string>();
  const importDir = dir(1);
  let dlls = 0;
  if (importDir && importDir.rva !== 0) {
    let descriptor = rvaToOffset(importDir.rva, sections);
    let functions = 0;
    while (descriptor !== null && dlls < MAX_DLLS && r.ok(descriptor, 20)) {
      const originalThunk = bytes.readUInt32LE(descriptor);
      const nameRva = bytes.readUInt32LE(descriptor + 12);
      const firstThunk = bytes.readUInt32LE(descriptor + 16);
      if (originalThunk === 0 && nameRva === 0 && firstThunk === 0) break;
      dlls += 1;
      let thunk = rvaToOffset(originalThunk !== 0 ? originalThunk : firstThunk, sections);
      const width = pe32plus ? 8 : 4;
      while (thunk !== null && functions < MAX_FUNCTIONS && r.ok(thunk, width)) {
        let byName: number | null;
        if (pe32plus) {
          const value = r.u64(thunk) as bigint;
          if (value === 0n) break;
          byName = (value & 0x8000000000000000n) !== 0n ? null : Number(value & 0x7fffffffn);
        } else {
          const value = r.u32(thunk) as number;
          if (value === 0) break;
          byName = (value & 0x80000000) !== 0 ? null : value;
        }
        functions += 1;
        if (byName !== null) {
          const hintName = rvaToOffset(byName, sections);
          const name = hintName === null ? null : r.cstr(hintName + 2);
          if (name) imports.add(name);
        }
        thunk += width;
      }
      descriptor += 20;
    }
    analysis.fact('pe.importFunctions', functions);
  }
  analysis.fact('pe.importDlls', dlls);

  const matched = (names: readonly string[]): string[] => names.filter((n) => imports.has(n));
  const families = {
    alloc: matched(INJECTION.alloc),
    write: matched(INJECTION.write),
    thread: matched(INJECTION.thread),
    unmap: matched(INJECTION.unmap),
  };
  const injection =
    (families.write.length > 0 && (families.thread.length > 0 || families.unmap.length > 0)) ||
    (families.alloc.length > 0 && families.thread.length > 0);
  if (injection) {
    const all = [...families.alloc, ...families.write, ...families.thread, ...families.unmap];
    all.forEach((n) => analysis.token(n));
    analysis.add('static.pe_injection_imports', all.length);
  }
  const download = matched(DOWNLOAD);
  const internet = matched(INTERNET_OPEN);
  const exec = matched(EXEC);
  if (download.length > 0 || (internet.length > 0 && exec.length > 0)) {
    [...download, ...internet, ...exec].forEach((n) => analysis.token(n));
    analysis.add('static.pe_downloader_imports', download.length + internet.length + exec.length);
  }
  const antiDebug = matched(ANTI_DEBUG);
  if (antiDebug.length > 0) {
    antiDebug.forEach((n) => analysis.token(n));
    analysis.add('static.pe_anti_debug', antiDebug.length);
  }
}
