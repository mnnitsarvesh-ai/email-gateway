import { createRequire } from 'node:module';
import { dirname, join } from 'node:path';
import { pathToFileURL } from 'node:url';
import type { DlpNotExtractedReason } from '@email-gateway/security-contracts';
import { capText } from './text';

/**
 * PDF text through `pdfjs-dist` 4.10.38, legacy build (step 4.5 D4; ≥ 4.2.67, the
 * CVE-2024-4367 fix): `isEvalSupported: false`, `disableFontFace: true`,
 * `useSystemFonts: false`, `stopAtErrors: false`, packaged CMaps, `getTextContent` per page up
 * to the page cap. pdfjs-dist is ESM-only and `tsc` under `module: commonjs` rewrites
 * `import()` into `require()`, so it is loaded through a preserved dynamic import.
 */

/** A dynamic `import()` that the CommonJS emit does not rewrite into `require()`. */
// eslint-disable-next-line @typescript-eslint/no-implied-eval
const importEsm = new Function('specifier', 'return import(specifier)') as (
  specifier: string,
) => Promise<unknown>;

interface TextItem {
  str?: string;
  hasEOL?: boolean;
}

interface PdfPage {
  getTextContent(): Promise<{ items: TextItem[] }>;
  cleanup(): void;
}

interface PdfDocument {
  numPages: number;
  getPage(n: number): Promise<PdfPage>;
  destroy(): Promise<void>;
}

interface PdfjsModule {
  version: string;
  getDocument(params: Record<string, unknown>): {
    promise: Promise<PdfDocument>;
    destroy(): Promise<void>;
  };
}

const PDFJS_DIR = dirname(require.resolve('pdfjs-dist/package.json'));
export const PDFJS_ENTRY = join(PDFJS_DIR, 'legacy', 'build', 'pdf.mjs');

/**
 * Lines pdfjs logs while its module initializes in Node: the optional `@napi-rs/canvas`
 * (deliberately not installed: root `pnpm.overrides` removes it) and the DOMMatrix /
 * ImageData / Path2D polyfills (rendering only; text extraction needs none of them). They are
 * printed before any `verbosity` option can apply, so they are dropped during the import only.
 */
const IMPORT_WARNINGS = [
  'Warning: Cannot load "@napi-rs/canvas"',
  'Warning: Cannot polyfill `DOMMatrix`',
  'Warning: Cannot polyfill `ImageData`',
  'Warning: Cannot polyfill `Path2D`',
];

/**
 * The preserved dynamic import works in Node (compiled `dist`, the extractor child, under the
 * permission model). A VM context without an import callback (vitest's module runner) refuses
 * it with `ERR_VM_DYNAMIC_IMPORT_CALLBACK_MISSING`; there the synchronous `require()` of an ES
 * module (unflagged since Node 22.12; pdf.mjs has no top-level await) loads the same file.
 */
export async function importPdfjsModule(): Promise<unknown> {
  try {
    return await importEsm(pathToFileURL(PDFJS_ENTRY).href);
  } catch (error) {
    if ((error as { code?: unknown }).code !== 'ERR_VM_DYNAMIC_IMPORT_CALLBACK_MISSING')
      throw error;
    return createRequire(__filename)(PDFJS_ENTRY) as unknown;
  }
}

let loading: Promise<PdfjsModule> | null = null;

/** Loads the pdfjs legacy build once. */
export function loadPdfjs(): Promise<PdfjsModule> {
  loading ??= (async () => {
    /* eslint-disable no-console */
    const original = console.log;
    console.log = (...args: unknown[]) => {
      const first = typeof args[0] === 'string' ? args[0] : '';
      if (IMPORT_WARNINGS.some((w) => first.startsWith(w))) return;
      original(...args);
    };
    try {
      return (await importPdfjsModule()) as PdfjsModule;
    } finally {
      console.log = original;
    }
    /* eslint-enable no-console */
  })();
  return loading;
}

export interface PdfText {
  status: 'extracted' | 'not_extracted';
  reasons: DlpNotExtractedReason[];
  /** One string per page read. */
  pages: string[];
  /** Pages beyond the cap or text beyond the character cap. */
  truncated: boolean;
  numPages: number;
}

/** Fewer characters than this on every page together = no text layer. */
export const PDF_MIN_TEXT_CHARS = 16;

/** The error name pdfjs gives a password-protected document. */
export const isPasswordError = (error: unknown): boolean =>
  error !== null &&
  typeof error === 'object' &&
  (error as { name?: unknown }).name === 'PasswordException';

export async function extractPdfText(
  bytes: Uint8Array,
  maxPages: number,
  maxChars: number,
): Promise<PdfText> {
  const pdfjs = await loadPdfjs();
  const task = pdfjs.getDocument({
    // pdfjs transfers the buffer to its worker: give it a copy.
    data: new Uint8Array(bytes),
    isEvalSupported: false,
    disableFontFace: true,
    useSystemFonts: false,
    stopAtErrors: false,
    enableXfa: false,
    disableAutoFetch: true,
    disableStream: true,
    verbosity: 0,
    cMapUrl: `${join(PDFJS_DIR, 'cmaps')}/`,
    cMapPacked: true,
    standardFontDataUrl: `${join(PDFJS_DIR, 'standard_fonts')}/`,
  });
  let document: PdfDocument;
  try {
    document = await task.promise;
  } catch (error) {
    await task.destroy().catch(() => undefined);
    return {
      status: 'not_extracted',
      reasons: [isPasswordError(error) ? 'encrypted' : 'parse_error'],
      pages: [],
      truncated: false,
      numPages: 0,
    };
  }
  try {
    const numPages = document.numPages;
    const read = Math.min(numPages, maxPages);
    const pages: string[] = [];
    let chars = 0;
    let truncated = numPages > maxPages;
    let pageErrors = false;
    for (let n = 1; n <= read; n += 1) {
      try {
        const page = await document.getPage(n);
        const content = await page.getTextContent();
        let text = '';
        for (const item of content.items) {
          if (typeof item.str === 'string') text += item.str;
          if (item.hasEOL) text += '\n';
        }
        page.cleanup();
        const capped = capText(text, Math.max(0, maxChars - chars));
        chars += capped.text.length;
        pages.push(capped.text);
        if (capped.truncated) {
          truncated = true;
          break;
        }
      } catch {
        pageErrors = true;
        pages.push('');
      }
    }
    const total = pages.reduce((sum, p) => sum + p.trim().length, 0);
    if (total < PDF_MIN_TEXT_CHARS) {
      return {
        status: 'not_extracted',
        reasons: [pageErrors ? 'parse_error' : 'no_text_layer'],
        pages: [],
        truncated: false,
        numPages,
      };
    }
    return {
      status: 'extracted',
      reasons: pageErrors ? ['parse_error'] : [],
      pages,
      truncated,
      numPages,
    };
  } finally {
    await document.destroy().catch(() => undefined);
  }
}
