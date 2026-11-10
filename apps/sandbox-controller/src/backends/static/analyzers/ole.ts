import type { Analysis } from './analysis';
import { CfbError, type CfbEntry, CompoundFile, isCfb } from './cfb';
import { decompressOvba, OvbaError } from './ovba';

/**
 * OLE / VBA analyzer (step 4.6 X4 `ole`): walks the compound file, finds every VBA project
 * (a storage `VBA` holding a `dir` stream), decompresses the `dir` stream (MS-OVBA), reads each
 * module's stream name and text offset and decompresses the module source (bounded), then looks
 * for auto-exec entry points and shell/download calls. Embedded OLE objects (`ObjectPool`,
 * `\x01Ole10Native`) are reported. The source text never leaves this function: only codes,
 * counts and the matched keyword tokens.
 */

const MAX_MODULES = 128;
const MAX_MODULE_SOURCE = 2 * 1024 * 1024;
const MAX_TOTAL_SOURCE = 8 * 1024 * 1024;

const AUTO_EXEC = /\b(AutoOpen|Document_Open|Workbook_Open|Auto_Open|AutoExec)\b/gi;
const SHELL = [
  { token: 'WScript.Shell', re: /WScript\.Shell/i },
  { token: 'CreateObject(Shell)', re: /CreateObject\s*\(\s*"[^"\r\n]{0,64}Shell/i },
  { token: 'Shell', re: /(^|[^A-Za-z0-9_.])Shell\s*[( ]/im },
  { token: 'ShellExecute', re: /\bShellExecute(A|W)?\b/i },
  { token: 'URLDownloadToFile', re: /\bURLDownloadToFile(A|W)?\b/i },
  { token: 'powershell', re: /\bpowershell\b/i },
];

interface VbaModule {
  streamName: string;
  textOffset: number;
}

/** Parses the decompressed `dir` stream records (MS-OVBA 2.3.4.2). */
export function parseDirStream(dir: Buffer): VbaModule[] {
  const modules: VbaModule[] = [];
  let current: VbaModule | null = null;
  let pos = 0;
  while (pos + 6 <= dir.length && modules.length < MAX_MODULES) {
    const id = dir.readUInt16LE(pos);
    let size = dir.readUInt32LE(pos + 2);
    // PROJECTVERSION: Reserved (=4) is not the size of the 6 bytes that follow.
    if (id === 0x0009) size = 6;
    const data = pos + 6;
    if (data + size > dir.length) break;
    if (id === 0x001a) {
      current = { streamName: dir.subarray(data, data + size).toString('latin1'), textOffset: 0 };
    } else if (id === 0x0032 && current && size > 0) {
      const unicode = dir.subarray(data, data + size).toString('utf16le');
      if (unicode.length > 0) current.streamName = unicode;
    } else if (id === 0x0031 && current && size === 4) {
      current.textOffset = dir.readUInt32LE(data);
    } else if (id === 0x002b && current) {
      modules.push(current);
      current = null;
    }
    pos = data + size;
  }
  return modules;
}

export interface VbaSourceScan {
  modules: number;
  autoExec: string[];
  shell: string[];
}

/** Scans one module's source text for the keyword families. */
export function scanVbaSource(source: string, scan: VbaSourceScan): void {
  for (const match of source.matchAll(AUTO_EXEC)) {
    const token = match[1] as string;
    if (!scan.autoExec.includes(token)) scan.autoExec.push(token);
  }
  for (const { token, re } of SHELL) {
    if (re.test(source) && !scan.shell.includes(token)) scan.shell.push(token);
  }
}

function findVbaStorages(cfb: CompoundFile): CfbEntry[] {
  return cfb.entries.filter(
    (e) =>
      e.type === 1 &&
      e.name.toUpperCase() === 'VBA' &&
      cfb.children(e.id).some((c) => c.type === 2 && c.name.toLowerCase() === 'dir'),
  );
}

/**
 * Analyzes one compound file. Returns false when the bytes are not a compound file. `nested`
 * marks a `vbaProject.bin` from an OOXML package (format stays `ooxml`).
 */
export function analyzeOle(bytes: Buffer, analysis: Analysis, nested = false): boolean {
  if (!isCfb(bytes)) {
    if (!nested) analysis.fact('ole.parsed', false);
    return false;
  }
  let cfb: CompoundFile;
  try {
    cfb = new CompoundFile(bytes);
  } catch (error) {
    analysis.fact('ole.error', error instanceof CfbError ? error.code : 'parse');
    return true;
  }
  if (!nested) {
    analysis.format = 'ole';
    analysis.supported = true;
  }
  analysis.fact(nested ? 'ooxml.vbaEntries' : 'ole.entries', cfb.entries.length);

  const scan: VbaSourceScan = { modules: 0, autoExec: [], shell: [] };
  let totalSource = 0;
  let undecodable = 0;
  for (const storage of findVbaStorages(cfb)) {
    const children = cfb.children(storage.id);
    const dirEntry = children.find((c) => c.type === 2 && c.name.toLowerCase() === 'dir');
    if (!dirEntry) continue;
    let modules: VbaModule[];
    try {
      modules = parseDirStream(decompressOvba(cfb.read(dirEntry), 0, 1024 * 1024));
    } catch {
      undecodable += 1;
      continue;
    }
    for (const module of modules) {
      const stream = children.find(
        (c) => c.type === 2 && c.name.toLowerCase() === module.streamName.toLowerCase(),
      );
      if (!stream) continue;
      scan.modules += 1;
      try {
        const raw = cfb.read(stream);
        if (module.textOffset >= raw.length) continue;
        const remaining = MAX_TOTAL_SOURCE - totalSource;
        if (remaining <= 0) break;
        const source = decompressOvba(
          raw,
          module.textOffset,
          Math.min(MAX_MODULE_SOURCE, remaining),
        );
        totalSource += source.length;
        scanVbaSource(source.toString('latin1'), scan);
      } catch (error) {
        if (error instanceof OvbaError || error instanceof CfbError) undecodable += 1;
        else throw error;
      }
    }
  }
  if (undecodable > 0) analysis.fact('ole.vbaUndecodable', undecodable);
  if (scan.modules > 0) {
    analysis.fact('ole.vbaModules', scan.modules);
    analysis.add('static.office_macro', scan.modules);
  }
  scan.autoExec.forEach((t) => analysis.token(t));
  scan.shell.forEach((t) => analysis.token(t));
  if (scan.autoExec.length > 0) analysis.add('static.office_auto_exec', scan.autoExec.length);
  if (scan.shell.length > 0) analysis.add('static.office_macro_shell', scan.shell.length);
  // X14 M1 "office_auto_exec with office_macro_shell" (§12 WP1 deviation 1): its own code.
  if (scan.autoExec.length > 0 && scan.shell.length > 0)
    analysis.add('static.office_auto_exec_shell');

  const objects = cfb.entries.filter(
    (e) =>
      (e.type === 1 && e.name === 'ObjectPool') || (e.type === 2 && e.name === '\u0001Ole10Native'),
  ).length;
  if (objects > 0) analysis.add('static.office_ole_object', objects);
  return true;
}
