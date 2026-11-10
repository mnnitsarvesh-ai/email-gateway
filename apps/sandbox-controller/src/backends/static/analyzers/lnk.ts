import type { Analysis } from './analysis';
import { scanScriptText } from './script';

/**
 * Windows Shell Link (.lnk) analyzer (step 4.6 X4 `lnk`, [MS-SHLLINK]): header and link CLSID,
 * the link-info base path and the string data (relative path, working directory, command-line
 * arguments). A shortcut whose target or arguments name a shell or LOLBin is `lnk_command`; the
 * arguments are also run through the script families.
 */

const HEADER_SIZE = 0x4c;
const LINK_CLSID = Buffer.from('0114020000000000c000000000000046', 'hex');
const COMMAND =
  /\b(powershell|pwsh|cmd|mshta|rundll32|wscript|cscript|regsvr32|certutil|bitsadmin|conhost|forfiles)(\.exe)?\b/i;

export function isLnk(bytes: Buffer): boolean {
  return (
    bytes.length >= HEADER_SIZE &&
    bytes.readUInt32LE(0) === HEADER_SIZE &&
    bytes.subarray(4, 20).equals(LINK_CLSID)
  );
}

export function analyzeLnk(bytes: Buffer, analysis: Analysis): void {
  if (!isLnk(bytes)) {
    analysis.fact('lnk.parsed', false);
    return;
  }
  analysis.format = 'lnk';
  analysis.supported = true;
  analysis.add('static.lnk_present');
  const flags = bytes.readUInt32LE(0x14);
  const unicode = (flags & 0x80) !== 0;
  let pos = HEADER_SIZE;
  const strings: string[] = [];
  let args = '';
  try {
    if (flags & 0x01) {
      if (pos + 2 > bytes.length) throw new Error('idlist');
      pos += 2 + bytes.readUInt16LE(pos);
    }
    if (flags & 0x02) {
      if (pos + 28 > bytes.length) throw new Error('linkinfo');
      const size = bytes.readUInt32LE(pos);
      const baseOffset = bytes.readUInt32LE(pos + 16);
      if (baseOffset > 0 && baseOffset < size && pos + size <= bytes.length) {
        const start = pos + baseOffset;
        const end = bytes.indexOf(0, start);
        strings.push(
          bytes
            .subarray(start, end < 0 ? Math.min(bytes.length, start + 1024) : end)
            .toString('latin1'),
        );
      }
      pos += size;
    }
    // StringData in order: NAME, RELATIVE_PATH, WORKING_DIR, ARGUMENTS, ICON_LOCATION.
    const order: [number, string][] = [
      [0x04, 'name'],
      [0x08, 'relative'],
      [0x10, 'workdir'],
      [0x20, 'arguments'],
      [0x40, 'icon'],
    ];
    for (const [flag, kind] of order) {
      if (!(flags & flag)) continue;
      if (pos + 2 > bytes.length) throw new Error('string');
      const chars = bytes.readUInt16LE(pos);
      const length = unicode ? chars * 2 : chars;
      if (pos + 2 + length > bytes.length) throw new Error('string');
      const value = bytes
        .subarray(pos + 2, pos + 2 + length)
        .toString(unicode ? 'utf16le' : 'latin1');
      pos += 2 + length;
      if (kind === 'arguments') args = value;
      if (kind === 'relative' || kind === 'arguments') strings.push(value);
    }
  } catch {
    analysis.fact('lnk.truncated', true);
  }
  analysis.fact('lnk.hasArguments', args.length > 0);
  analysis.fact('lnk.argumentChars', args.length);
  const target = strings.join(' ');
  const command = COMMAND.exec(target);
  if (command) {
    analysis.token((command[1] as string).toLowerCase());
    analysis.add('static.lnk_command');
  }
  if (args.length > 0) scanScriptText(args, analysis);
}
