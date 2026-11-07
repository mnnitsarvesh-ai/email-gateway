import { type Deadline } from '@email-gateway/bec';
import { isAlnumCode, isDigitCode, isUpperCode, isWordAt } from '../scan/chars';
import { mrzFieldValid } from '../validators';
import { enabled, type DetectorContext } from './context';

/**
 * Line- and segment-structure detectors (step 4.5 D5): CR1 private keys (PEM and GCP
 * service-account JSON), PP2 ICAO 9303 machine-readable zones, PI3 dates of birth, SC1 source
 * code, and the currency-amount count of FI1. Hand-written, linear scans.
 */

// ---------------------------------------------------------------------------------------------
// CR1: PEM private keys and GCP service-account keys
// ---------------------------------------------------------------------------------------------

const PEM_BEGIN = '-----BEGIN ';
const PEM_LABELS = new Map<string, string>([
  ['PRIVATE KEY', 'PKCS8'],
  ['RSA PRIVATE KEY', 'RSA'],
  ['EC PRIVATE KEY', 'EC'],
  ['DSA PRIVATE KEY', 'DSA'],
  ['OPENSSH PRIVATE KEY', 'OPENSSH'],
  ['ENCRYPTED PRIVATE KEY', 'ENCRYPTED'],
  ['PGP PRIVATE KEY BLOCK', 'PGP'],
]);
/** A private key body is at most this far from its BEGIN line (16 KiB keys and armor). */
const PEM_MAX_BODY = 16_384;

const isBase64Body = (c: number): boolean => isAlnumCode(c) || c === 43 || c === 47 || c === 61;

export function scanPrivateKeys(ctx: DetectorContext, deadline: Deadline): void {
  if (!enabled(ctx, 'CR1')) return;
  const { text } = ctx;
  let i = text.indexOf(PEM_BEGIN);
  while (i >= 0) {
    deadline.check();
    const labelStart = i + PEM_BEGIN.length;
    const close = text.indexOf('-----', labelStart);
    const label =
      close > labelStart && close - labelStart <= 32 ? text.slice(labelStart, close) : '';
    const keyType = PEM_LABELS.get(label);
    if (keyType) {
      const headerEnd = close + 5;
      const endMarker = `-----END ${label}-----`;
      // Bounded search: the END line must follow within PEM_MAX_BODY.
      const window = text.slice(headerEnd, headerEnd + PEM_MAX_BODY + endMarker.length);
      const relative = window.indexOf(endMarker);
      const endAt = relative < 0 ? -1 : headerEnd + relative;
      let body = 0;
      let stop = headerEnd;
      if (endAt >= 0) {
        // Count base64 characters of body lines (armor headers such as `Version:` are skipped).
        let lineStart = headerEnd;
        for (let k = headerEnd; k <= endAt; k += 1) {
          if (k === endAt || text.charCodeAt(k) === 10) {
            const line = text.slice(lineStart, k).trim();
            if (!line.includes(':')) {
              let ok = line.length > 0;
              for (let m = 0; m < line.length && ok; m += 1) ok = isBase64Body(line.charCodeAt(m));
              if (ok) body += line.length;
            }
            lineStart = k + 1;
          }
        }
        stop = endAt + endMarker.length;
      }
      ctx.emit({
        detector: 'CR1',
        segment: ctx.segment,
        start: i,
        end: stop,
        value: text.slice(i, stop),
        compact: `pem:${keyType}:${i}`,
        base: body >= 64 ? 0.95 : 0.6,
        context: [],
        contextBonus: 0,
        requiresContext: false,
        negative: null,
        codePenalty: false,
        extra: { keyType, pemHeader: text.slice(i, headerEnd) },
      });
      i = text.indexOf(PEM_BEGIN, stop);
    } else {
      i = text.indexOf(PEM_BEGIN, labelStart);
    }
  }
  scanServiceAccountKey(ctx);
}

/** `"type": "service_account"` and a `"private_key"` string in the same segment. */
function scanServiceAccountKey(ctx: DetectorContext): void {
  const { text } = ctx;
  const typeAt = text.indexOf('"type"');
  if (typeAt < 0) return;
  let typeIsServiceAccount = false;
  for (let at = typeAt; at >= 0 && !typeIsServiceAccount; at = text.indexOf('"type"', at + 1)) {
    let k = at + 6;
    while (text[k] === ' ' || text[k] === '\t') k += 1;
    if (text[k] !== ':') continue;
    k += 1;
    while (text[k] === ' ' || text[k] === '\t') k += 1;
    typeIsServiceAccount = text.startsWith('"service_account"', k);
  }
  if (!typeIsServiceAccount) return;
  const keyAt = text.indexOf('"private_key"');
  if (keyAt < 0) return;
  let k = keyAt + 13;
  while (text[k] === ' ' || text[k] === '\t' || text[k] === ':') k += 1;
  if (text[k] !== '"') return;
  let end = k + 1;
  while (end < text.length && end - k < PEM_MAX_BODY && text[end] !== '"')
    end += text[end] === '\\' ? 2 : 1;
  ctx.emit({
    detector: 'CR1',
    segment: ctx.segment,
    start: keyAt,
    end: Math.min(text.length, end + 1),
    value: text.slice(keyAt, Math.min(text.length, end + 1)),
    compact: `gcp:${keyAt}`,
    base: end - k > 64 ? 0.95 : 0.6,
    context: [],
    contextBonus: 0,
    requiresContext: false,
    negative: null,
    codePenalty: false,
    extra: { keyType: 'GCP', pemHeader: '"private_key"' },
  });
}

// ---------------------------------------------------------------------------------------------
// PP2: machine-readable zones (TD3 2 × 44, TD1 3 × 30)
// ---------------------------------------------------------------------------------------------

const isMrzChar = (c: number): boolean => isUpperCode(c) || isDigitCode(c) || c === 60;

interface Line {
  start: number;
  end: number;
  text: string;
}

const mrzLine = (line: Line, length: number): boolean => {
  if (line.text.length !== length) return false;
  for (let i = 0; i < length; i += 1) if (!isMrzChar(line.text.charCodeAt(i))) return false;
  return true;
};

/** TD3 line 2 check digits (document number, birth date, expiry, personal number, composite). */
export function td3Valid(line2: string): boolean {
  return (
    mrzFieldValid(line2.slice(0, 9), line2[9]!) &&
    mrzFieldValid(line2.slice(13, 19), line2[19]!) &&
    mrzFieldValid(line2.slice(21, 27), line2[27]!) &&
    (line2.slice(28, 42) === '<'.repeat(14) && line2[42] === '<'
      ? true
      : mrzFieldValid(line2.slice(28, 42), line2[42]!)) &&
    mrzFieldValid(line2.slice(0, 10) + line2.slice(13, 20) + line2.slice(21, 43), line2[43]!)
  );
}

/** TD1 check digits (document number, birth date, expiry, composite). */
export function td1Valid(l1: string, l2: string): boolean {
  return (
    mrzFieldValid(l1.slice(5, 14), l1[14]!) &&
    mrzFieldValid(l2.slice(0, 6), l2[6]!) &&
    mrzFieldValid(l2.slice(8, 14), l2[14]!) &&
    mrzFieldValid(l1.slice(5, 30) + l2.slice(0, 7) + l2.slice(8, 15) + l2.slice(18, 29), l2[29]!)
  );
}

function linesOf(text: string, deadline: Deadline): Line[] {
  const lines: Line[] = [];
  let start = 0;
  for (let i = 0; i <= text.length; i += 1) {
    if (i === text.length || text.charCodeAt(i) === 10) {
      deadline.check();
      let end = i;
      while (end > start && (text.charCodeAt(end - 1) === 13 || text.charCodeAt(end - 1) === 32))
        end -= 1;
      let s = start;
      while (s < end && text.charCodeAt(s) === 32) s += 1;
      // Only lines that could be MRZ lines are materialized.
      lines.push({
        start: s,
        end,
        text: end - s === 44 || end - s === 30 ? text.slice(s, end) : '',
      });
      start = i + 1;
    }
  }
  return lines;
}

export function scanMrz(ctx: DetectorContext, deadline: Deadline): void {
  if (!enabled(ctx, 'PP2')) return;
  const lines = linesOf(ctx.text, deadline);
  const emit = (first: Line, last: Line, documentNumber: string) =>
    ctx.emit({
      detector: 'PP2',
      segment: ctx.segment,
      start: first.start,
      end: last.end,
      value: ctx.text.slice(first.start, last.end),
      compact: documentNumber,
      base: 0.9,
      context: [],
      contextBonus: 0,
      requiresContext: false,
      negative: null,
      codePenalty: false,
      extra: { documentNumber },
    });
  for (let i = 0; i < lines.length; i += 1) {
    const l1 = lines[i]!;
    const l2 = lines[i + 1];
    if (l2 && mrzLine(l1, 44) && mrzLine(l2, 44) && l1.text[0] === 'P' && td3Valid(l2.text)) {
      emit(l1, l2, l2.text.slice(0, 9).replace(/</g, ''));
      i += 1;
      continue;
    }
    const l3 = lines[i + 2];
    if (
      l2 &&
      l3 &&
      mrzLine(l1, 30) &&
      mrzLine(l2, 30) &&
      mrzLine(l3, 30) &&
      'IAC'.includes(l1.text[0]!) &&
      td1Valid(l1.text, l2.text)
    ) {
      emit(l1, l3, l1.text.slice(5, 14).replace(/</g, ''));
      i += 2;
    }
  }
}

// ---------------------------------------------------------------------------------------------
// PI3: dates of birth
// ---------------------------------------------------------------------------------------------

const MONTHS = new Map<string, number>([
  ['jan', 1],
  ['january', 1],
  ['feb', 2],
  ['february', 2],
  ['mar', 3],
  ['march', 3],
  ['apr', 4],
  ['april', 4],
  ['may', 5],
  ['jun', 6],
  ['june', 6],
  ['jul', 7],
  ['july', 7],
  ['aug', 8],
  ['august', 8],
  ['sep', 9],
  ['sept', 9],
  ['september', 9],
  ['oct', 10],
  ['october', 10],
  ['nov', 11],
  ['november', 11],
  ['dec', 12],
  ['december', 12],
]);

export const calendarValid = (year: number, month: number, day: number): boolean => {
  if (month < 1 || month > 12 || day < 1) return false;
  const days = new Date(Date.UTC(year, month, 0)).getUTCDate();
  return day <= days;
};

const DATE_CHARS = (c: number): boolean => isDigitCode(c) || c === 47 || c === 45 || c === 46;

/** A numeric date token (`dd/mm/yyyy`, `dd-mm-yyyy`, `dd.mm.yyyy`, `yyyy-mm-dd`) or null. */
export function parseNumericDate(
  token: string,
): { year: number; month: number; day: number } | null {
  if (token.length < 8 || token.length > 10) return null;
  const sep = token.match(/^[0-9]{1,4}([/.-])[0-9]{1,2}\1[0-9]{1,4}$/);
  if (!sep) return null;
  const [a, b, c] = token.split(sep[1]!) as [string, string, string];
  if (a.length === 4 && sep[1] === '-' && c.length <= 2) {
    return { year: Number(a), month: Number(b), day: Number(c) };
  }
  if (c.length === 4 && a.length <= 2) return { year: Number(c), month: Number(b), day: Number(a) };
  return null;
}

export function scanDates(ctx: DetectorContext, from: number, to: number): void {
  if (!enabled(ctx, 'PI3')) return;
  const { text } = ctx;
  const currentYear = ctx.now.getUTCFullYear();
  const emit = (start: number, end: number, date: { year: number; month: number; day: number }) => {
    if (date.year < 1900 || date.year > currentYear) return;
    if (!calendarValid(date.year, date.month, date.day)) return;
    ctx.emit({
      detector: 'PI3',
      segment: ctx.segment,
      start,
      end,
      value: text.slice(start, end),
      compact: `${date.year}-${String(date.month).padStart(2, '0')}-${String(date.day).padStart(2, '0')}`,
      base: 0.3,
      context: ['dob'],
      contextBonus: 0.5,
      requiresContext: true,
      negative: null,
      codePenalty: false,
      extra: {},
    });
  };
  const end = Math.min(to, text.length);
  for (let i = Math.max(0, from); i < end; i += 1) {
    const c = text.charCodeAt(i);
    if (
      !isDigitCode(c) ||
      (i > 0 && (DATE_CHARS(text.charCodeAt(i - 1)) || isWordAt(text, i - 1)))
    ) {
      continue;
    }
    let j = i;
    while (j < text.length && j - i <= 10 && DATE_CHARS(text.charCodeAt(j))) j += 1;
    let stop = j;
    while (stop > i && !isDigitCode(text.charCodeAt(stop - 1))) stop -= 1;
    if (stop - i >= 8 && stop - i <= 10 && !isWordAt(text, j)) {
      const numeric = parseNumericDate(text.slice(i, stop));
      if (numeric) emit(i, stop, numeric);
    }
    // `d Mon yyyy`
    if (j - i <= 2 && text.charCodeAt(j) === 32) {
      let m = j + 1;
      while (m < text.length && m - j <= 10 && /[A-Za-z]/.test(text[m]!)) m += 1;
      const month = MONTHS.get(text.slice(j + 1, m).toLowerCase());
      let y = m;
      if (text[y] === ',') y += 1;
      if (month && text.charCodeAt(y) === 32) {
        const yearStart = y + 1;
        let ye = yearStart;
        while (ye < text.length && ye - yearStart < 5 && isDigitCode(text.charCodeAt(ye))) ye += 1;
        if (ye - yearStart === 4 && !isWordAt(text, ye)) {
          emit(i, ye, {
            year: Number(text.slice(yearStart, ye)),
            month,
            day: Number(text.slice(i, j)),
          });
        }
      }
    }
    i = j;
  }
}

// ---------------------------------------------------------------------------------------------
// SC1: source code heuristics
// ---------------------------------------------------------------------------------------------

export const SOURCE_CODE_MIN_CHARS = 200;

const LANGUAGE_KEYWORDS: Readonly<Record<string, readonly string[]>> = {
  python: ['def', 'import', 'from', 'elif', 'self', 'lambda', 'print', 'class', 'return', 'None'],
  javascript: [
    'function',
    'const',
    'let',
    'var',
    'export',
    'require',
    'async',
    'await',
    'interface',
    '=>',
  ],
  java: [
    'public',
    'private',
    'protected',
    'package',
    'static',
    'void',
    'class',
    'new',
    'final',
    'throws',
  ],
  c: [
    '#include',
    '#define',
    'int',
    'char',
    'struct',
    'unsigned',
    'printf',
    'sizeof',
    'typedef',
    'void',
  ],
  csharp: [
    'using',
    'namespace',
    'public',
    'private',
    'class',
    'var',
    'string',
    'void',
    'override',
    'async',
  ],
  go: ['func', 'package', 'import', 'type', 'struct', 'defer', 'go', 'chan', ':=', 'var'],
  php: [
    '<?php',
    'function',
    'echo',
    '$this',
    'public',
    'namespace',
    'use',
    'require_once',
    'array',
    'foreach',
  ],
  ruby: [
    'def',
    'end',
    'require',
    'module',
    'class',
    'puts',
    'attr_accessor',
    'do',
    'elsif',
    'unless',
  ],
  shell: ['#!/bin/sh', '#!/bin/bash', 'echo', 'fi', 'then', 'export', 'done', 'esac', 'if', 'for'],
  sql: [
    'select',
    'insert',
    'update',
    'delete',
    'create',
    'from',
    'where',
    'join',
    'table',
    'values',
  ],
};

const CODE_STARTS = new Set([
  'def',
  'class',
  'import',
  'from',
  'return',
  'if',
  'elif',
  'else',
  'for',
  'while',
  'function',
  'const',
  'let',
  'var',
  'public',
  'private',
  'protected',
  'static',
  'package',
  'using',
  'namespace',
  'func',
  'fn',
  'select',
  'insert',
  'update',
  'create',
  'echo',
  'export',
  'try',
  'catch',
  'switch',
  'case',
  'struct',
  'type',
  'module',
  'require',
  'end',
  'fi',
  'done',
  'int',
  'void',
  'char',
  'async',
  'await',
  'interface',
  'enum',
  'throw',
  'new',
  'unless',
  'puts',
]);

const firstWord = (line: string): string => {
  let i = 0;
  while (i < line.length && (line[i] === ' ' || line[i] === '\t')) i += 1;
  let j = i;
  while (j < line.length && j - i < 24 && /[#!$<?A-Za-z_/:=.]/.test(line[j]!)) j += 1;
  return line.slice(i, j);
};

/** Whether a (trimmed) line looks like a line of code. */
export function codeIndicatorLine(raw: string): boolean {
  const line = raw.trim();
  if (line.length === 0) return false;
  const word = firstWord(line).toLowerCase();
  const last = line[line.length - 1]!;
  if (line.startsWith('#include') || line.startsWith('#!') || line.startsWith('<?php')) return true;
  if (line === '}' || line === '};' || line === '{' || line === 'end') return true;
  if (last === ';' || last === '{' || last === '}') return true;
  if (line.includes('=>') || line.includes(':=') || line.includes('->') || line.includes('::'))
    return true;
  if (CODE_STARTS.has(word) && (last === ':' || line.includes('(') || line.includes(' = ')))
    return true;
  if (/^[A-Za-z_$][A-Za-z0-9_$.]{0,40} ?\+?= ?\S/.test(line.slice(0, 64)) && !line.includes('. '))
    return true;
  return false;
}

export interface SourceCodeScore {
  score: number;
  language: string;
  lines: number;
}

/** SC1 per segment (≥ 200 code units): ratio of code-indicator lines, language by keywords. */
export function sourceCodeScore(
  text: string,
  sourceFile: boolean,
  deadline: Deadline,
): SourceCodeScore | null {
  if (text.length < SOURCE_CODE_MIN_CHARS) return null;
  let lines = 0;
  let indicators = 0;
  let indented = 0;
  const hits = new Map<string, number>();
  let start = 0;
  for (let i = 0; i <= text.length; i += 1) {
    if (i < text.length && text.charCodeAt(i) !== 10) continue;
    deadline.check();
    const line = text.slice(start, Math.min(i, start + 512));
    start = i + 1;
    if (line.trim().length === 0) continue;
    lines += 1;
    if (codeIndicatorLine(line)) indicators += 1;
    if (line.startsWith('    ') || line.startsWith('\t')) indented += 1;
    const word = firstWord(line);
    for (const [language, keywords] of Object.entries(LANGUAGE_KEYWORDS)) {
      for (const keyword of keywords) {
        if (
          word === keyword ||
          word.toLowerCase() === keyword ||
          (keyword.length > 2 && line.includes(`${keyword} `))
        ) {
          hits.set(language, (hits.get(language) ?? 0) + 1);
          break;
        }
      }
    }
  }
  if (lines < 5 && !sourceFile) return null;
  const ratio = lines === 0 ? 0 : indicators / lines;
  const shebang = text.startsWith('#!') ? 0.2 : 0;
  const indentation = lines > 0 && indented / lines >= 0.2 ? 0.1 : 0;
  const score = Math.min(1, ratio * 1.2 + shebang + indentation + (sourceFile ? 0.3 : 0));
  let language = 'unknown';
  let best = 0;
  for (const [name, count] of hits) {
    if (count > best) {
      best = count;
      language = name;
    }
  }
  return { score: Math.round(score * 100) / 100, language, lines };
}

// ---------------------------------------------------------------------------------------------
// FI1: currency amounts
// ---------------------------------------------------------------------------------------------

const SYMBOLS = ['₹', '$', '€', '£'];
const CODES_BEFORE = ['INR', 'USD', 'EUR', 'GBP', 'Rs.', 'Rs', 'RS.', 'rs.'];
const WORDS_AFTER = ['rupees', 'Rupees', 'INR', 'USD', 'EUR', 'GBP'];

/** The end of a number (`1,23,456.78`) starting at `i`, or -1. */
const numberEnd = (text: string, i: number): number => {
  if (!isDigitCode(text.charCodeAt(i))) return -1;
  let j = i;
  while (
    j < text.length &&
    j - i < 24 &&
    (isDigitCode(text.charCodeAt(j)) || (text[j] === ',' && isDigitCode(text.charCodeAt(j + 1))))
  )
    j += 1;
  if (text[j] === '.' && isDigitCode(text.charCodeAt(j + 1))) {
    j += 1;
    while (j < text.length && isDigitCode(text.charCodeAt(j)) && j - i < 28) j += 1;
  }
  return j;
};

/** Counts currency amounts in a segment (₹ / Rs. / INR / rupees / $ / USD / € / EUR / £ / GBP). */
export function countCurrencyAmounts(text: string, max: number, deadline: Deadline): number {
  let count = 0;
  for (let i = 0; i < text.length && count < max; i += 1) {
    deadline.check();
    const c = text[i]!;
    let after = -1;
    if (SYMBOLS.includes(c)) after = i + 1;
    else if (!isWordAt(text, i - 1)) {
      const code = CODES_BEFORE.find((k) => text.startsWith(k, i));
      if (code && !(code.endsWith('.') ? false : /[A-Za-z]/.test(text[i + code.length] ?? '')))
        after = i + code.length;
    }
    if (after >= 0) {
      if (text[after] === ' ') after += 1;
      const end = numberEnd(text, after);
      if (end > 0) {
        count += 1;
        i = end - 1;
        continue;
      }
    }
    if (
      isDigitCode(text.charCodeAt(i)) &&
      !isWordAt(text, i - 1) &&
      !(i > 0 && /[.,]/.test(text[i - 1]!))
    ) {
      const end = numberEnd(text, i);
      if (end > 0) {
        const k = text[end] === ' ' ? end + 1 : end;
        if (WORDS_AFTER.some((w) => text.startsWith(w, k) && !isWordAt(text, k + w.length))) {
          count += 1;
        }
        i = end - 1;
      }
    }
  }
  return count;
}
