/**
 * Parsers of clamd's null-terminated replies (clamd 1.4, `man clamd`): `VERSION`, `INSTREAM`
 * results and the `<id>: ` prefix of replies inside an `IDSESSION`. Pure functions; nothing
 * here keeps or logs reply text beyond the parsed fields.
 */

/** Engine and signature database of the clamd that answered. */
export interface ClamdVersion {
  /** Engine version, e.g. `1.4.6`. */
  engine: string;
  /** Daily database version, e.g. `28173`. */
  dbVersion: number;
  /** Build time of that database (UTC, from `Tue Nov  3 06:27:52 2026`). */
  dbTime: Date;
}

/** A definite scan answer: no signature matched, or the first matching signature. */
export type ClamdVerdict = { status: 'clean' } | { status: 'found'; signature: string };

/** What one INSTREAM reply line means (before the client turns it into a result or an error). */
export type ScanReply =
  | ClamdVerdict
  | { status: 'size_limit' }
  | { status: 'server_error' }
  | { status: 'invalid_signature' };

/** Signature names are used in reason signals, rows and metrics: printable ASCII only. */
export const CLAMD_SIGNATURE_PATTERN = /^[\x21-\x7e]{1,128}$/;
const ENGINE_PATTERN = /^[0-9][0-9A-Za-z.+_-]{0,31}$/;
const MONTHS = ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec'];
// ctime(3) format as printed by clamd: `Tue Nov  3 06:27:52 2026` (day padded with a space).
const CTIME_PATTERN =
  /^(?:Mon|Tue|Wed|Thu|Fri|Sat|Sun) (Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec) {1,2}(\d{1,2}) (\d{2}):(\d{2}):(\d{2}) (\d{4})$/;

export function isValidSignatureName(name: string): boolean {
  return CLAMD_SIGNATURE_PATTERN.test(name);
}

/** `Tue Nov  3 06:27:52 2026` → Date (UTC; the clamav image runs in UTC); null if malformed. */
export function parseCtime(text: string): Date | null {
  const match = CTIME_PATTERN.exec(text);
  if (!match) return null;
  const [, mon, day, hh, mm, ss, year] = match as unknown as [
    string,
    string,
    string,
    string,
    string,
    string,
    string,
  ];
  const month = MONTHS.indexOf(mon);
  const date = new Date(
    Date.UTC(Number(year), month, Number(day), Number(hh), Number(mm), Number(ss)),
  );
  // Rejects impossible dates (Feb 31 rolls over into March).
  if (date.getUTCDate() !== Number(day) || date.getUTCMonth() !== month) return null;
  if (Number(hh) > 23 || Number(mm) > 59 || Number(ss) > 59) return null;
  return date;
}

/**
 * `ClamAV 1.4.6/28173/Tue Nov  3 06:27:52 2026` → `{ engine, dbVersion, dbTime }`; null when the
 * text has another shape (including an engine-only `ClamAV 1.4.6` without a loaded database).
 */
export function parseVersion(text: string): ClamdVersion | null {
  const match = /^ClamAV ([^/\s]+)\/(\d{1,10})\/(.+)$/.exec(text.trim());
  if (!match) return null;
  const [, engine, db, time] = match as unknown as [string, string, string, string];
  if (!ENGINE_PATTERN.test(engine)) return null;
  const dbVersion = Number(db);
  if (!Number.isSafeInteger(dbVersion) || dbVersion > 0xffffffff) return null;
  const dbTime = parseCtime(time);
  if (!dbTime) return null;
  return { engine, dbVersion, dbTime };
}

/**
 * One INSTREAM reply: `stream: OK`, `stream: <signature> FOUND`, `INSTREAM size limit
 * exceeded. ERROR`, any other `… ERROR`; null for anything else.
 */
export function parseScanReply(text: string): ScanReply | null {
  if (text === 'stream: OK') return { status: 'clean' };
  const found = /^stream: (.+) FOUND$/.exec(text);
  if (found) {
    const signature = found[1] as string;
    return isValidSignatureName(signature)
      ? { status: 'found', signature }
      : { status: 'invalid_signature' };
  }
  if (/^INSTREAM size limit exceeded\.? ERROR$/.test(text)) return { status: 'size_limit' };
  if (/ ERROR$/.test(text)) return { status: 'server_error' };
  return null;
}

/** `2: stream: OK` → `{ id: 2, text: 'stream: OK' }`; a reply without an id prefix → `id: null`. */
export function splitSessionReply(reply: string): { id: number | null; text: string } {
  const match = /^(\d{1,9}): (.*)$/s.exec(reply);
  if (!match) return { id: null, text: reply };
  return { id: Number(match[1]), text: match[2] as string };
}

/**
 * Accumulates socket bytes and yields complete null-terminated replies. Bounded: a reply longer
 * than `maxReplyBytes` (clamd's are well below 1 KiB) or more than `maxReplies` replies is a
 * protocol error, so a hostile or broken peer cannot make the client buffer without limit.
 */
export class ReplyReader {
  private pending: Buffer = Buffer.alloc(0);
  private count = 0;

  constructor(
    private readonly maxReplyBytes = 4096,
    private readonly maxReplies = 8,
  ) {}

  /** Returns the replies completed by `chunk`; throws `'reply_too_large'` when a bound is exceeded. */
  push(chunk: Buffer): string[] {
    this.pending = this.pending.length === 0 ? chunk : Buffer.concat([this.pending, chunk]);
    const replies: string[] = [];
    let start = 0;
    for (;;) {
      const end = this.pending.indexOf(0, start);
      if (end < 0) break;
      if (end - start > this.maxReplyBytes) throw new Error('reply_too_large');
      replies.push(this.pending.toString('latin1', start, end).replace(/\n$/, ''));
      start = end + 1;
      this.count += 1;
      if (this.count > this.maxReplies) throw new Error('reply_too_large');
    }
    this.pending = this.pending.subarray(start);
    if (this.pending.length > this.maxReplyBytes) throw new Error('reply_too_large');
    return replies;
  }

  /** Bytes received after the last complete reply. */
  get trailingBytes(): number {
    return this.pending.length;
  }
}
