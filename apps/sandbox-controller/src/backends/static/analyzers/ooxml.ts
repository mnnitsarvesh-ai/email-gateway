import { ANALYSIS_BOUNDS, type Analysis } from './analysis';
import { hostOfAuthority } from './generic';
import { analyzeOle } from './ole';
import { isZip, readCentralDirectory, readEntry, ZipError, type ZipEntry } from './zip';

/**
 * Office Open XML analyzer (step 4.6 X4 `ooxml`): the package's central directory (bounded), a
 * `vbaProject.bin` → the OLE/VBA analyzer, relationships with `TargetMode="External"` on
 * `attachedTemplate` / `oleObject` / `frame` (remote template injection), `DDE` / `DDEAUTO` field
 * codes (Word field instructions, Excel `ddeLink`), embedded `oleObject*.bin`.
 */

const MAX_XML_BYTES = 4 * 1024 * 1024;
const EXTERNAL_TYPES = /\/(attachedTemplate|oleObject|frame)$/i;
const RELATIONSHIP = /<Relationship\b([^>]{0,4096})>/gi;
const ATTRIBUTE = /\b(Type|Target|TargetMode)\s*=\s*("([^"]*)"|'([^']*)')/g;

function attributes(tag: string): Record<string, string> {
  const out: Record<string, string> = {};
  for (const match of tag.matchAll(ATTRIBUTE)) {
    out[match[1] as string] = match[3] ?? match[4] ?? '';
  }
  return out;
}

function entryText(bytes: Buffer, entry: ZipEntry, analysis: Analysis): string | null {
  const max = Math.min(MAX_XML_BYTES, ANALYSIS_BOUNDS.inflateEntryBytes);
  if (!analysis.reserveInflate(Math.min(entry.uncompressedSize, max))) return null;
  try {
    const data = readEntry(bytes, entry, max);
    return data ? data.toString('utf8') : null;
  } catch {
    return null;
  }
}

/** Word field instructions in document order (split runs joined), then the DDE test. */
export function hasDdeField(xml: string): boolean {
  const instructions: string[] = [];
  for (const match of xml.matchAll(/<w:instrText\b[^>]*>([^<]{0,4096})<\/w:instrText>/g)) {
    instructions.push(match[1] as string);
  }
  for (const match of xml.matchAll(/\bw:instr\s*=\s*"([^"]{0,4096})"/g))
    instructions.push(match[1] as string);
  return /(^|[\s"])DDE(AUTO)?\b/i.test(instructions.join(''));
}

export function analyzeOoxml(bytes: Buffer, analysis: Analysis): void {
  if (!isZip(bytes)) {
    analysis.fact('ooxml.parsed', false);
    return;
  }
  let entries: ZipEntry[];
  try {
    entries = readCentralDirectory(bytes);
  } catch (error) {
    analysis.fact('ooxml.error', error instanceof ZipError ? error.code : 'parse');
    return;
  }
  analysis.format = 'ooxml';
  analysis.supported = true;
  analysis.fact('ooxml.entries', entries.length);
  let external = 0;
  let dde = 0;
  let oleObjects = 0;
  let skipped = 0;
  for (const entry of entries) {
    const name = entry.name;
    const lower = name.toLowerCase();
    if (lower.endsWith('vbaproject.bin')) {
      if (
        !analysis.reserveInflate(
          Math.min(entry.uncompressedSize, ANALYSIS_BOUNDS.inflateEntryBytes),
        )
      ) {
        skipped += 1;
        continue;
      }
      try {
        const data = readEntry(bytes, entry, ANALYSIS_BOUNDS.inflateEntryBytes);
        if (data) analyzeOle(data, analysis, true);
        else skipped += 1;
      } catch {
        skipped += 1;
      }
      continue;
    }
    if (/(^|\/)embeddings\/oleobject[^/]*\.bin$/.test(lower)) {
      oleObjects += 1;
      continue;
    }
    if (lower.endsWith('.rels')) {
      const xml = entryText(bytes, entry, analysis);
      if (xml === null) {
        skipped += 1;
        continue;
      }
      for (const match of xml.matchAll(RELATIONSHIP)) {
        const attrs = attributes(match[1] as string);
        if ((attrs.TargetMode ?? '').toLowerCase() !== 'external') continue;
        const target = attrs.Target ?? '';
        const authority = /^[a-z][a-z0-9+.-]*:\/\/([^/?#]+)/i.exec(target)?.[1];
        const parsed = authority ? hostOfAuthority(authority) : null;
        if (parsed?.host) analysis.host(parsed.host);
        if (parsed?.ip) analysis.ip(parsed.ip);
        if (EXTERNAL_TYPES.test(attrs.Type ?? '')) {
          external += 1;
          analysis.token(/\/([A-Za-z]+)$/.exec(attrs.Type ?? '')?.[1] ?? 'external');
        }
      }
      continue;
    }
    if (/^word\/(document|header\d*|footer\d*|footnotes|endnotes)\.xml$/.test(lower)) {
      const xml = entryText(bytes, entry, analysis);
      if (xml === null) skipped += 1;
      else if (hasDdeField(xml)) dde += 1;
      continue;
    }
    if (/^xl\/externallinks\/externallink\d*\.xml$/.test(lower)) {
      const xml = entryText(bytes, entry, analysis);
      if (xml === null) skipped += 1;
      else if (/<ddeLink\b/.test(xml)) dde += 1;
    }
  }
  if (skipped > 0) analysis.fact('ooxml.skippedEntries', skipped);
  if (external > 0) analysis.add('static.office_external_template', external);
  if (dde > 0) analysis.add('static.office_dde', dde);
  if (oleObjects > 0) analysis.add('static.office_ole_object', oleObjects);
}
