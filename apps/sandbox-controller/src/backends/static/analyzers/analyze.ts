import { Analysis, type AnalysisResult, latin1 } from './analysis';
import { analyzeElf } from './elf';
import { analyzeGeneric } from './generic';
import { analyzeHtml, looksLikeMarkup } from './html';
import { analyzeLnk } from './lnk';
import { analyzeOle } from './ole';
import { analyzeOoxml } from './ooxml';
import { analyzePdf } from './pdf';
import { analyzePe } from './pe';
import { analyzeScript } from './script';

/**
 * The static analysis of one sample (step 4.6 X4), run inside the analyzer child: the format
 * analyzer chosen by the detected type (with a magic-byte check inside each analyzer), then the
 * generic checks. Never throws for a property of the sample: a parse failure of one analyzer is
 * a fact and the remaining analyzers still run.
 */

/** Detected types the static backend analyzes (format analyzer or generic text checks). */
export const STATIC_SUPPORTED_TYPES: readonly string[] = Object.freeze([
  'pdf',
  'ooxml_word',
  'ooxml_excel',
  'ooxml_powerpoint',
  'ooxml_macro',
  'ole_office',
  'msi',
  'rtf',
  'pe_executable',
  'elf',
  'lnk',
  'script_js',
  'script_vbs',
  'script_ps1',
  'script_batch',
  'script_shell',
  'hta',
  'html',
  'svg',
  'xml',
  'text',
  'unknown',
]);

const TEXT_TYPES = new Set([
  'rtf',
  'script_js',
  'script_vbs',
  'script_ps1',
  'script_batch',
  'script_shell',
  'hta',
  'html',
  'svg',
  'xml',
  'text',
]);
const COMPRESSED_BY_DESIGN = new Set([
  'ooxml_word',
  'ooxml_excel',
  'ooxml_powerpoint',
  'ooxml_macro',
]);

function safely(analysis: Analysis, name: string, run: () => void): void {
  try {
    run();
  } catch {
    analysis.fact(`${name}.error`, 'parse');
  }
}

function analyzeRtf(bytes: Buffer, analysis: Analysis): void {
  const text = latin1(bytes);
  if (!text.startsWith('{\\rtf')) {
    analysis.fact('rtf.parsed', false);
    return;
  }
  analysis.format = 'rtf';
  analysis.supported = true;
  const objects = (text.match(/\\objdata\b/g) ?? []).length;
  if (objects > 0) analysis.add('static.office_ole_object', objects);
  if (/\\fldinst[^}]{0,512}\bDDE(AUTO)?\b/i.test(text)) analysis.add('static.office_dde');
}

export function analyzeSample(bytes: Buffer, detectedType: string): AnalysisResult {
  const analysis = new Analysis();
  analysis.fact('sizeBytes', bytes.length);
  switch (detectedType) {
    case 'pe_executable':
      safely(analysis, 'pe', () => analyzePe(bytes, analysis));
      break;
    case 'elf':
      safely(analysis, 'elf', () => analyzeElf(bytes, analysis));
      break;
    case 'ole_office':
    case 'msi':
      safely(analysis, 'ole', () => analyzeOle(bytes, analysis));
      break;
    case 'ooxml_word':
    case 'ooxml_excel':
    case 'ooxml_powerpoint':
    case 'ooxml_macro':
      safely(analysis, 'ooxml', () => analyzeOoxml(bytes, analysis));
      break;
    case 'pdf':
      safely(analysis, 'pdf', () => analyzePdf(bytes, analysis));
      break;
    case 'html':
    case 'svg':
    case 'xml':
      safely(analysis, 'html', () =>
        analyzeHtml(
          bytes,
          analysis,
          detectedType === 'svg' || looksLikeMarkup(bytes) === 'svg' ? 'svg' : 'html',
        ),
      );
      break;
    case 'hta':
      safely(analysis, 'html', () => analyzeHtml(bytes, analysis, 'html'));
      safely(analysis, 'script', () => analyzeScript(bytes, analysis));
      break;
    case 'script_js':
    case 'script_vbs':
    case 'script_ps1':
    case 'script_batch':
    case 'script_shell':
      safely(analysis, 'script', () => analyzeScript(bytes, analysis));
      break;
    case 'lnk':
      safely(analysis, 'lnk', () => analyzeLnk(bytes, analysis));
      break;
    case 'rtf':
      safely(analysis, 'rtf', () => analyzeRtf(bytes, analysis));
      break;
    default:
      // text, unknown: generic checks only.
      analysis.supported = STATIC_SUPPORTED_TYPES.includes(detectedType);
  }
  safely(analysis, 'generic', () =>
    analyzeGeneric(bytes, analysis, {
      text: TEXT_TYPES.has(detectedType),
      skipEntropy: COMPRESSED_BY_DESIGN.has(detectedType) || analysis.format === 'pdf',
    }),
  );
  // A type the backend supports stays supported even when its bytes did not parse: the generic
  // checks ran and the facts record the parse failure.
  if (STATIC_SUPPORTED_TYPES.includes(detectedType)) analysis.supported = true;
  return analysis.result();
}
