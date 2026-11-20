/**
 * Small RFC 5322 helpers shared by journal intake and cross-source dedupe (step 8.6): header
 * field splitting with unfolding, address-list parsing to addr-specs and a tolerant date parser.
 * Pure and bounded: they never allocate more than the input.
 */

export interface HeaderField {
  /** The field name as written. */
  name: string;
  /** The unfolded value (CRLF / LF + WSP become the WSP), leading whitespace removed. */
  value: string;
}

/**
 * The fields of a header block (bytes up to the first empty line; anything after it is ignored).
 * Lines without a colon that are not continuations are skipped. Bytes are read as latin1 so
 * every byte survives (header names and addresses are ASCII; 8-bit values stay opaque).
 */
export function parseHeaderFields(block: Buffer | string): HeaderField[] {
  const text = typeof block === 'string' ? block : block.toString('latin1');
  const fields: HeaderField[] = [];
  let current: HeaderField | null = null;
  for (const raw of text.split('\n')) {
    const line = raw.endsWith('\r') ? raw.slice(0, -1) : raw;
    if (line === '') break;
    if (line[0] === ' ' || line[0] === '\t') {
      if (current) current.value += line;
      continue;
    }
    const colon = line.indexOf(':');
    if (colon <= 0) {
      current = null;
      continue;
    }
    current = { name: line.slice(0, colon).trim(), value: line.slice(colon + 1).trimStart() };
    fields.push(current);
  }
  return fields;
}

/** Every value of a field (case-insensitive name), in order. */
export function headerValues(fields: readonly HeaderField[], name: string): string[] {
  const wanted = name.toLowerCase();
  return fields.filter((f) => f.name.toLowerCase() === wanted).map((f) => f.value);
}

/** Removes RFC 5322 comments (nested, outside quoted strings) and returns the rest. */
export function stripComments(value: string): string {
  let out = '';
  let depth = 0;
  let quoted = false;
  for (let i = 0; i < value.length; i++) {
    const c = value[i]!;
    if (c === '\\' && i + 1 < value.length && (quoted || depth > 0)) {
      if (depth === 0) out += c + value[i + 1];
      i++;
      continue;
    }
    if (depth === 0 && c === '"') quoted = !quoted;
    if (!quoted && c === '(') {
      depth++;
      continue;
    }
    if (!quoted && c === ')' && depth > 0) {
      depth--;
      if (depth === 0) out += ' ';
      continue;
    }
    if (depth === 0) out += c;
  }
  return out;
}

const ADDR_SPEC = /^[^\s@<>()[\]\\,;:]+@[A-Za-z0-9](?:[A-Za-z0-9.-]{0,251}[A-Za-z0-9])?$/;
const QUOTED_LOCAL_ADDR_SPEC =
  /^"(?:[^"\\\r\n]|\\.){1,64}"@[A-Za-z0-9](?:[A-Za-z0-9.-]{0,251}[A-Za-z0-9])?$/;

/**
 * Validates an addr-spec and returns it with the domain lower-cased (and a trailing dot
 * removed); null when it is not `local@domain` with a dot-atom or quoted local part and a host
 * name domain, or longer than 320 characters.
 */
export function normalizeAddrSpec(value: string): string | null {
  const v = value.trim().replace(/\.$/, '');
  if (v.length < 3 || v.length > 320) return null;
  if (!ADDR_SPEC.test(v) && !QUOTED_LOCAL_ADDR_SPEC.test(v)) return null;
  const at = v.lastIndexOf('@');
  const local = v.slice(0, at);
  const domain = v.slice(at + 1).toLowerCase();
  if (local.length > 64 && !local.startsWith('"')) return null;
  if (domain.includes('..')) return null;
  return `${local}@${domain}`;
}

/**
 * The addr-specs of an address list (`To`, `Cc`, `From`, …): display names, angle addresses,
 * comments, quoted strings and groups (`team: a@x, b@y;`) are handled; entries that are not a
 * valid addr-spec are skipped. Domains are lower-cased; local parts are kept as written.
 */
export function parseAddressList(value: string): string[] {
  const out: string[] = [];
  const text = stripComments(value);
  let token = '';
  let quoted = false;
  let angle = false;
  const flush = () => {
    const entry = token.trim();
    token = '';
    if (entry === '') return;
    const open = entry.lastIndexOf('<');
    const close = entry.lastIndexOf('>');
    const spec =
      open >= 0 && close > open
        ? entry.slice(open + 1, close).replace(/^@[^:]*:/, '') // obsolete route
        : entry;
    const normalized = normalizeAddrSpec(spec.replace(/\s+/g, ''));
    if (normalized !== null) out.push(normalized);
  };
  for (let i = 0; i < text.length; i++) {
    const c = text[i]!;
    if (c === '\\' && quoted && i + 1 < text.length) {
      token += c + text[i + 1];
      i++;
      continue;
    }
    if (c === '"' && !angle) quoted = !quoted;
    if (!quoted) {
      if (c === '<') angle = true;
      else if (c === '>') angle = false;
      else if (!angle && (c === ',' || c === ';')) {
        flush();
        continue;
      } else if (!angle && c === ':') {
        // A group display name ends here; its members follow.
        token = '';
        continue;
      }
    }
    token += c;
  }
  flush();
  return out;
}

const MONTHS: Record<string, number> = {
  jan: 0,
  feb: 1,
  mar: 2,
  apr: 3,
  may: 4,
  jun: 5,
  jul: 6,
  aug: 7,
  sep: 8,
  oct: 9,
  nov: 10,
  dec: 11,
};

/** Obsolete zone names (RFC 5322 §4.3); military letters are treated as `-0000` (unknown). */
const ZONES: Record<string, number> = {
  ut: 0,
  utc: 0,
  gmt: 0,
  z: 0,
  est: -300,
  edt: -240,
  cst: -360,
  cdt: -300,
  mst: -420,
  mdt: -360,
  pst: -480,
  pdt: -420,
};

/**
 * Epoch seconds of an RFC 5322 `Date` value, tolerant of the obsolete syntax: optional day of
 * week, comments, 2- and 3-digit years (RFC 5322 §4.3), missing seconds, month names in any
 * case (full names too), `UT`/`GMT`/North American zone names, military zones and a missing zone
 * (all read as UTC). Null when it is not a date (impossible calendar dates included).
 */
export function parseRfc5322Date(value: string | null | undefined): number | null {
  if (typeof value !== 'string' || value.length > 256) return null;
  const text = stripComments(value).replace(/\s+/g, ' ').trim();
  const m =
    /^(?:[A-Za-z]{3,9}\s*,?\s*)?(\d{1,2})[\s-]+([A-Za-z]{3,9})\.?[\s-]+(\d{2,4})\s+(\d{1,2})\s*:\s*(\d{2})(?:\s*:\s*(\d{2}))?(?:\s+([+-]\d{4}|[A-Za-z]{1,5}))?$/.exec(
      text,
    );
  if (m === null) return null;
  const day = Number(m[1]);
  const month = MONTHS[m[2]!.slice(0, 3).toLowerCase()];
  if (month === undefined) return null;
  let year = Number(m[3]);
  if (m[3]!.length === 2) year += year < 50 ? 2000 : 1900;
  else if (m[3]!.length === 3) year += 1900;
  if (year < 1900) return null;
  const hour = Number(m[4]);
  const minute = Number(m[5]);
  const second = m[6] === undefined ? 0 : Number(m[6]);
  if (hour > 23 || minute > 59 || second > 60) return null;
  let offsetMinutes = 0;
  const zone = m[7];
  if (zone !== undefined) {
    if (/^[+-]\d{4}$/.test(zone)) {
      const hh = Number(zone.slice(1, 3));
      const mm = Number(zone.slice(3, 5));
      if (mm > 59) return null;
      offsetMinutes = (zone[0] === '-' ? -1 : 1) * (hh * 60 + mm);
    } else {
      const named = ZONES[zone.toLowerCase()];
      if (named !== undefined) offsetMinutes = named;
      else if (!/^[A-IK-Za-ik-z]$/.test(zone)) return null;
    }
  }
  const utc = Date.UTC(year, month, day, hour, minute, Math.min(second, 59));
  const check = new Date(Date.UTC(year, month, day));
  if (check.getUTCMonth() !== month || check.getUTCDate() !== day) return null;
  return Math.floor(utc / 1000) - offsetMinutes * 60;
}
