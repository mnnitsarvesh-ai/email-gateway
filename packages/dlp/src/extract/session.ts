import {
  fileTypeFamily,
  type DlpExtractFormat,
  type DlpNotExtractedReason,
  type FileTypeId,
} from '@email-gateway/security-contracts';
import { DLP_EXTRACTOR_VERSION } from '../versions';
import {
  officePartRole,
  odfTables,
  odfText,
  presentationPartText,
  sharedStrings,
  sheetTable,
  wordPartOrder,
  wordPartText,
  type OfficePartRole,
} from './office';
import { extractPdfText } from './pdf';
import { capText, csvDelimiter, decodeText, delimitedToTable } from './text';
import {
  DEFAULT_EXTRACT_LIMITS,
  EMPTY_WALK,
  type DlpExtractedSegment,
  type DlpExtraction,
  type ExtractHint,
  type ExtractLimits,
  type WalkSummary,
} from './types';
import { XmlParseError } from './xml';

/**
 * Attachment extraction (step 4.5 D4). The DLP extractor child runs the shared 4.2 walker
 * (`inspectBytes` with a no-op YARA engine) and passes `session.visitor` as its entry visitor;
 * `finish()` then composes the extraction result. A non-container attachment is extracted
 * directly by `finish()`. Pure functions over in-memory buffers: no files, no network, no
 * child processes, no `@email-gateway/bec`.
 *
 * The walker visits entries post-order (a container's entries before the container), so the
 * children of a zip are buffered per parent path until the parent's type is known: for an
 * office document the selected parts (D4 part table) become its text and its other XML parts
 * are dropped; for a plain archive every child keeps its own extraction.
 */

const CONTAINERS: ReadonlySet<FileTypeId> = new Set<FileTypeId>([
  'zip',
  'gzip',
  'tar',
  'ooxml_word',
  'ooxml_excel',
  'ooxml_powerpoint',
  'ooxml_macro',
  'odf',
  'jar',
  'apk',
]);
const OFFICE: ReadonlySet<FileTypeId> = new Set<FileTypeId>([
  'ooxml_word',
  'ooxml_excel',
  'ooxml_powerpoint',
  'ooxml_macro',
  'odf',
]);

const SOURCE_EXTENSIONS = new Set([
  'py',
  'js',
  'mjs',
  'cjs',
  'ts',
  'tsx',
  'jsx',
  'java',
  'kt',
  'scala',
  'c',
  'h',
  'cc',
  'cpp',
  'hpp',
  'cs',
  'go',
  'php',
  'rb',
  'sh',
  'bash',
  'zsh',
  'ps1',
  'sql',
  'swift',
  'rs',
  'pl',
  'r',
  'lua',
  'm',
  'vb',
  'yaml',
  'yml',
  'tf',
]);
const IMAGE_THUMBNAIL = /^docProps\/thumbnail\.[a-z]{3,4}$|^Thumbnails\/thumbnail\.png$/;

/** Lower-case extension of an entry name, or null. */
export const extensionOf = (name: string | null): string | null => {
  if (!name) return null;
  const base = name.slice(name.lastIndexOf('/') + 1);
  const dot = base.lastIndexOf('.');
  return dot <= 0
    ? null
    : base
        .slice(dot + 1)
        .toLowerCase()
        .slice(0, 16);
};

/** The extraction format of a text-like entry by its extension / declared type. */
export function textFormat(
  type: FileTypeId,
  ext: string | null,
  declared: string | null,
): DlpExtractFormat {
  const contentType = declared?.toLowerCase().split(';')[0]?.trim() ?? '';
  if (type === 'html') return 'html';
  if (type === 'eml') return 'eml';
  if (ext === 'csv' || contentType === 'text/csv') return 'csv';
  if (ext === 'tsv' || ext === 'tab' || contentType === 'text/tab-separated-values') return 'tsv';
  if (ext === 'json' || contentType === 'application/json') return 'json';
  if (fileTypeFamily(type) === 'script' || (ext !== null && SOURCE_EXTENSIONS.has(ext)))
    return 'source';
  if (type === 'xml' || type === 'svg' || ext === 'xml') return 'xml';
  return 'text';
}

/** The extraction format of a detected type. */
export function formatOf(
  type: FileTypeId,
  ext: string | null,
  declared: string | null,
  odfKind?: string,
): DlpExtractFormat {
  switch (type) {
    case 'pdf':
      return 'pdf';
    case 'ooxml_word':
      return 'docx';
    case 'ooxml_excel':
      return 'xlsx';
    case 'ooxml_powerpoint':
      return 'pptx';
    case 'ooxml_macro':
      return ext === 'xlsm' ? 'xlsx' : ext === 'pptm' ? 'pptx' : 'docx';
    case 'odf':
      return odfKind === 'spreadsheet' ? 'ods' : odfKind === 'presentation' ? 'odp' : 'odt';
    case 'zip':
    case 'jar':
    case 'apk':
      return 'zip';
    case 'gzip':
      return 'gzip';
    case 'tar':
      return 'tar';
    default:
      break;
  }
  const family = fileTypeFamily(type);
  if (family === 'image') return 'image';
  if (family === 'text' || family === 'markup' || family === 'script' || type === 'eml') {
    return textFormat(type, ext, declared);
  }
  return 'unsupported';
}

interface Pending {
  path: string;
  name: string | null;
  type: FileTypeId;
  role: OfficePartRole | null;
  /** Office parts: text or raw XML (sheets / ODF content need their siblings). */
  partText?: string;
  partXml?: string;
  partTruncated?: boolean;
  partError?: boolean;
  /** The entry's own extraction (filtered when the parent is an office document). */
  segments: DlpExtractedSegment[];
  reasons: DlpNotExtractedReason[];
  /**
   * `text`: XML/text parts (an office parent drops them: its selected parts are its text);
   * `document`: PDFs and nested containers (kept); `image` (kept as `image` unless it is the
   * document's own thumbnail); `other`: unsupported binaries (inside an office document only
   * embedded objects keep `unsupported_type`; fonts, printer settings and macro storage do not).
   */
  kind: 'text' | 'document' | 'image' | 'other';
}

const kindOf = (format: DlpExtractFormat): Pending['kind'] =>
  format === 'image'
    ? 'image'
    : format === 'unsupported'
      ? 'other'
      : format === 'pdf' || CONTAINER_FORMATS.has(format)
        ? 'document'
        : 'text';

const CONTAINER_FORMATS: ReadonlySet<DlpExtractFormat> = new Set<DlpExtractFormat>([
  'zip',
  'gzip',
  'tar',
  'docx',
  'xlsx',
  'pptx',
  'odt',
  'ods',
  'odp',
]);
const EMBEDDED_OBJECT = /(?:^|\/)embeddings\/|^Object [0-9]+\//;

/** Buffered XML of office parts that need their siblings (UTF-16 code units). */
const MAX_BUFFERED_XML_CHARS = 32 * 1024 * 1024;

export class ExtractionSession {
  private readonly limits: ExtractLimits;
  private readonly children = new Map<string, Pending[]>();
  private entries = 0;
  private chars = 0;
  private bufferedXml = 0;
  private truncatedByBudget = false;

  constructor(
    private readonly hint: ExtractHint,
    limits: Partial<ExtractLimits> = {},
  ) {
    this.limits = { ...DEFAULT_EXTRACT_LIMITS, ...limits };
  }

  /** The walker's entry visitor (`onEntry(data, path, depth, type, ext, name)`). */
  readonly visitor = async (
    data: Buffer,
    path: string,
    _depth: number,
    type: FileTypeId,
    _ext: FileTypeId | null,
    name: string | null,
  ): Promise<void> => {
    this.entries += 1;
    const parent = path.includes('/') ? path.slice(0, path.lastIndexOf('/')) : '';
    const role = name ? officePartRole(name) : null;
    const ext = extensionOf(name);
    const pending: Pending = {
      path,
      name,
      type,
      role,
      segments: [],
      reasons: [],
      kind: kindOf(formatOf(type, ext, null)),
    };
    if (OFFICE.has(type)) {
      const office = this.office(path, type, this.takeChildren(path), ext);
      pending.segments = office.segments;
      pending.reasons = office.reasons;
    } else if (CONTAINERS.has(type)) {
      for (const child of this.takeChildren(path)) {
        pending.segments.push(...child.segments);
        pending.reasons.push(...child.reasons);
      }
    } else if (role) {
      // A selected office part: parsed now, composed when the parent is visited.
      this.officePart(pending, data);
      pending.kind = 'text';
    } else {
      const leaf = await this.extractLeaf(data, path, type, ext, null);
      pending.segments = leaf.segments;
      pending.reasons = leaf.reasons;
    }
    const list = this.children.get(parent) ?? [];
    list.push(pending);
    this.children.set(parent, list);
  };

  private takeChildren(path: string): Pending[] {
    const list = this.children.get(path) ?? [];
    this.children.delete(path);
    return list;
  }

  private officePart(pending: Pending, data: Buffer): void {
    const role = pending.role!;
    const xml = decodeText(data).text;
    const max = this.limits.maxTextChars;
    try {
      if (role.family === 'docx') {
        const part = wordPartText(xml, max);
        pending.partText = part.text;
        pending.partTruncated = part.truncated;
      } else if (role.family === 'pptx') {
        const part = presentationPartText(xml, max);
        pending.partText = part.text;
        pending.partTruncated = part.truncated;
      } else if (role.family === 'odf' && role.part === 'mimetype') {
        pending.partText = xml.trim().slice(0, 128);
      } else if (this.bufferedXml + xml.length <= MAX_BUFFERED_XML_CHARS) {
        // xlsx shared strings / sheets and ODF content / styles need their siblings.
        pending.partXml = xml;
        this.bufferedXml += xml.length;
      } else {
        pending.partTruncated = true;
        this.truncatedByBudget = true;
      }
    } catch (error) {
      pending.partError = true;
      if (!(error instanceof XmlParseError)) throw error;
    }
  }

  /** Text of an office document from its buffered parts (D4 part table). */
  private office(
    path: string,
    type: FileTypeId,
    parts: Pending[],
    ext: string | null,
  ): { segments: DlpExtractedSegment[]; reasons: DlpNotExtractedReason[] } {
    const segmentPath = path === '' ? 'attachment' : path;
    const segments: DlpExtractedSegment[] = [];
    const reasons: DlpNotExtractedReason[] = [];
    const max = this.limits.maxTextChars;
    const mimetype =
      parts.find((p) => p.role?.family === 'odf' && p.role.part === 'mimetype')?.partText ?? '';
    const odfKind = mimetype.startsWith('application/vnd.oasis.opendocument.spreadsheet')
      ? 'spreadsheet'
      : mimetype.startsWith('application/vnd.oasis.opendocument.presentation')
        ? 'presentation'
        : 'text';
    const format = formatOf(type, ext, null, odfKind);
    const family =
      type === 'odf' ? 'odf' : format === 'xlsx' ? 'xlsx' : format === 'pptx' ? 'pptx' : 'docx';
    for (const part of parts) {
      if (part.partError) reasons.push('parse_error');
      const name = part.name ?? '';
      if (part.kind === 'document') {
        segments.push(...part.segments);
        reasons.push(...part.reasons);
      } else if (part.kind === 'image') {
        if (!IMAGE_THUMBNAIL.test(name)) reasons.push('image');
      } else if (part.kind === 'other' && EMBEDDED_OBJECT.test(name)) {
        reasons.push('unsupported_type');
      }
    }
    const textSegment = (text: string, truncated: boolean) => {
      if (text.length > 0 || truncated)
        segments.push({ path: segmentPath, format, kind: 'text', text, truncated });
    };
    try {
      if (family === 'docx') {
        const body = parts
          .filter((p) => p.role?.family === 'docx' && p.partText !== undefined)
          .sort((a, b) => wordPartOrder(a.name ?? '') - wordPartOrder(b.name ?? ''));
        const text = body
          .map((p) => p.partText)
          .filter((t) => t && t.length > 0)
          .join('\n');
        textSegment(
          capText(text, max).text,
          body.some((p) => p.partTruncated) || text.length > max,
        );
      } else if (family === 'pptx') {
        const slides = parts
          .filter((p) => p.role?.family === 'pptx' && p.partText !== undefined)
          .sort((a, b) => orderOf(a.role) - orderOf(b.role));
        const text = slides
          .map((p) => p.partText)
          .filter((t) => t && t.length > 0)
          .join('\n');
        textSegment(
          capText(text, max).text,
          slides.some((p) => p.partTruncated) || text.length > max,
        );
      } else if (family === 'xlsx') {
        const sharedPart = parts.find((p) => p.role?.family === 'xlsx' && p.role.part === 'shared');
        const shared = sharedPart?.partXml ? sharedStrings(sharedPart.partXml) : [];
        const sheets = parts
          .filter((p) => p.role?.family === 'xlsx' && p.role.part === 'sheet')
          .sort((a, b) => orderOf(a.role) - orderOf(b.role));
        for (const sheet of sheets) {
          if (sheet.partXml === undefined) {
            if (sheet.partTruncated)
              segments.push({
                path: segmentPath,
                format,
                kind: 'table',
                text: '',
                headers: [],
                truncated: true,
              });
            continue;
          }
          try {
            const table = sheetTable(sheet.partXml, shared, max, this.limits.maxTableColumns);
            if (table.text.length > 0) {
              segments.push({
                path: segmentPath,
                format,
                kind: 'table',
                text: table.text,
                headers: table.headers,
                truncated: table.truncated,
              });
            }
          } catch (error) {
            if (!(error instanceof XmlParseError)) throw error;
            reasons.push('parse_error');
          }
        }
      } else {
        const content = parts.find((p) => p.role?.family === 'odf' && p.role.part === 'content');
        const styles = parts.find((p) => p.role?.family === 'odf' && p.role.part === 'styles');
        if (content?.partXml !== undefined) {
          if (odfKind === 'spreadsheet') {
            for (const table of odfTables(content.partXml, max, this.limits.maxTableColumns)) {
              segments.push({
                path: segmentPath,
                format,
                kind: 'table',
                text: table.text,
                headers: table.headers,
                truncated: table.truncated,
              });
            }
          } else {
            const part = odfText(content.partXml, max);
            textSegment(part.text, part.truncated);
          }
        } else if (content?.partTruncated) {
          textSegment('', true);
        }
        if (styles?.partXml !== undefined) {
          const part = odfText(styles.partXml, max);
          textSegment(part.text, part.truncated);
        }
      }
    } catch (error) {
      if (!(error instanceof XmlParseError)) throw error;
      reasons.push('parse_error');
    }
    for (const part of parts) {
      if (part.partXml !== undefined) this.bufferedXml -= part.partXml.length;
    }
    return { segments, reasons };
  }

  /** Extraction of one non-container entry (or a non-container attachment). */
  private async extractLeaf(
    data: Uint8Array,
    path: string,
    type: FileTypeId,
    ext: string | null,
    declared: string | null,
  ): Promise<{ segments: DlpExtractedSegment[]; reasons: DlpNotExtractedReason[] }> {
    const segmentPath = path === '' ? 'attachment' : path;
    const format = formatOf(type, ext, declared);
    const max = this.limits.maxTextChars;
    if (format === 'image') return { segments: [], reasons: ['image'] };
    if (format === 'unsupported') return { segments: [], reasons: ['unsupported_type'] };
    if (format === 'pdf') {
      const pdf = await extractPdfText(data, this.limits.pdfMaxPages, max);
      if (pdf.status === 'not_extracted') return { segments: [], reasons: pdf.reasons };
      const capped = capText(pdf.pages.join('\n'), max);
      return {
        segments: [
          {
            path: segmentPath,
            format,
            kind: 'text',
            text: capped.text,
            truncated: pdf.truncated || capped.truncated,
          },
        ],
        reasons: pdf.reasons,
      };
    }
    const decoded = decodeText(data).text;
    if (format === 'csv' || format === 'tsv') {
      const table = delimitedToTable(
        decoded,
        format === 'tsv' ? '\t' : csvDelimiter(decoded),
        max,
        this.limits.maxTableColumns,
      );
      return {
        segments: [
          {
            path: segmentPath,
            format,
            kind: 'table',
            text: table.text,
            headers: table.headers,
            truncated: table.truncated,
          },
        ],
        reasons: [],
      };
    }
    const capped = capText(decoded, max);
    const segment: DlpExtractedSegment = {
      path: segmentPath,
      format,
      kind: format === 'html' ? 'html' : 'text',
      text: capped.text,
      truncated: capped.truncated,
    };
    // message/rfc822: transfer-encoded parts inside are not decoded (D4, §10).
    return { segments: [segment], reasons: format === 'eml' ? ['unsupported_type'] : [] };
  }

  /**
   * Composes the extraction result. `detectedType` is the attachment's detected (and refined)
   * type from the walker; `walk` its summary (encrypted entries, limits, malformed, unsupported).
   */
  async finish(
    bytes: Uint8Array,
    detectedType: FileTypeId,
    walk: WalkSummary = EMPTY_WALK,
  ): Promise<DlpExtraction> {
    const ext = this.hint.filenameExt?.toLowerCase() ?? null;
    let segments: DlpExtractedSegment[];
    let reasons: DlpNotExtractedReason[];
    let format: DlpExtractFormat;
    if (OFFICE.has(detectedType)) {
      const office = this.office('', detectedType, this.takeChildren(''), ext);
      segments = office.segments;
      reasons = office.reasons;
      format =
        segments.find((s) => s.path === 'attachment')?.format ?? formatOf(detectedType, ext, null);
    } else if (CONTAINERS.has(detectedType)) {
      segments = [];
      reasons = [];
      for (const child of this.takeChildren('')) {
        segments.push(...child.segments);
        reasons.push(...child.reasons);
      }
      format = formatOf(detectedType, ext, null);
    } else {
      const leaf = await this.extractLeaf(
        bytes,
        '',
        detectedType,
        ext,
        this.hint.declaredContentType,
      );
      segments = leaf.segments;
      reasons = leaf.reasons;
      format = formatOf(detectedType, ext, this.hint.declaredContentType);
    }
    if (walk.encrypted) reasons.push('encrypted');
    if (walk.limitReached) reasons.push('archive_limit');
    if (walk.malformed) reasons.push('parse_error');
    if (walk.unsupported) reasons.push('unsupported_type');
    return this.compose(format, segments, reasons);
  }

  private compose(
    format: DlpExtractFormat,
    raw: DlpExtractedSegment[],
    rawReasons: DlpNotExtractedReason[],
  ): DlpExtraction {
    const segments: DlpExtractedSegment[] = [];
    let truncated = this.truncatedByBudget;
    for (const segment of raw) {
      if (segments.length >= this.limits.maxSegments) {
        truncated = true;
        break;
      }
      const room = this.limits.maxTextChars - this.chars;
      if (room <= 0 && segment.text.length > 0) {
        truncated = true;
        break;
      }
      const capped = capText(segment.text, Math.max(0, room));
      this.chars += capped.text.length;
      segments.push({
        ...segment,
        text: capped.text,
        truncated: segment.truncated || capped.truncated,
      });
      if (capped.truncated) truncated = true;
    }
    if (truncated && segments.length > 0) segments[segments.length - 1]!.truncated = true;
    const reasons = [...new Set(rawReasons)].sort();
    const anyTruncated = segments.some((s) => s.truncated);
    const status =
      segments.length === 0 && (reasons.length > 0 || truncated)
        ? 'not_extracted'
        : reasons.length > 0 || anyTruncated || truncated
          ? 'partial'
          : 'extracted';
    return {
      extractorVersion: DLP_EXTRACTOR_VERSION,
      status,
      format,
      reasons,
      segments: segments.filter((s) => s.text.length > 0 || s.truncated),
      entriesVisited: this.entries,
    };
  }
}

const orderOf = (role: OfficePartRole | null): number => (role && 'order' in role ? role.order : 0);

/** Extracts a non-container attachment (convenience; the walker is not needed). */
export async function extractAttachment(
  bytes: Uint8Array,
  detectedType: FileTypeId,
  hint: ExtractHint,
  limits: Partial<ExtractLimits> = {},
): Promise<DlpExtraction> {
  if (CONTAINERS.has(detectedType)) {
    throw new Error(
      'containers are extracted through the shared walker (ExtractionSession.visitor)',
    );
  }
  return new ExtractionSession(hint, limits).finish(bytes, detectedType);
}

export const isContainerType = (type: FileTypeId): boolean => CONTAINERS.has(type);
