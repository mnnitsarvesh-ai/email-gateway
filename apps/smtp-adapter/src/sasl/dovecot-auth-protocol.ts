/**
 * Server side of the Dovecot authentication protocol v1.2, the subset Postfix's
 * `smtpd_sasl_type = dovecot` client uses (step 2.2 D10;
 * https://doc.dovecot.org/developer_manual/design/auth_protocol/). Line based, TAB-separated.
 */

/** D10: a longer line closes the connection. */
export const MAX_LINE_BYTES = 64 * 1024;

export class AuthProtocolError extends Error {}

export type Mechanism = 'PLAIN' | 'LOGIN';
export const MECHANISMS: readonly Mechanism[] = ['PLAIN', 'LOGIN'];

/** Handshake sent by the server on connect. */
export function handshake(pid: number, connectionId: number, cookie: string): string {
  return [
    'VERSION\t1\t2',
    'MECH\tPLAIN\tplaintext',
    'MECH\tLOGIN\tplaintext',
    `SPID\t${pid}`,
    `CUID\t${connectionId}`,
    `COOKIE\t${cookie}`,
    'DONE',
    '',
  ].join('\n');
}

/** Splits a byte stream into lines (LF, optional CR). Throws past MAX_LINE_BYTES. */
export class LineSplitter {
  private buffer: Buffer = Buffer.alloc(0);

  constructor(private readonly maxBytes = MAX_LINE_BYTES) {}

  push(chunk: Buffer): string[] {
    this.buffer = this.buffer.length === 0 ? chunk : Buffer.concat([this.buffer, chunk]);
    const lines: string[] = [];
    let newline: number;
    while ((newline = this.buffer.indexOf(0x0a)) !== -1) {
      if (newline > this.maxBytes) throw new AuthProtocolError('auth protocol line too long');
      let line = this.buffer.subarray(0, newline);
      if (line.length > 0 && line[line.length - 1] === 0x0d) line = line.subarray(0, -1);
      lines.push(line.toString('utf8'));
      this.buffer = this.buffer.subarray(newline + 1);
    }
    if (this.buffer.length > this.maxBytes) {
      throw new AuthProtocolError('auth protocol line too long');
    }
    return lines;
  }
}

export interface AuthRequest {
  id: string;
  mechanism: string;
  /** `name=value` parameters (first occurrence wins). */
  params: ReadonlyMap<string, string>;
  /** Value-less flags such as `secured`, `nologin`. */
  flags: ReadonlySet<string>;
}

const REQUEST_ID = /^[0-9]{1,10}$/;

/** `AUTH\t<id>\t<mech>\t<args…>` (fields after the command). */
export function parseAuthRequest(fields: readonly string[]): AuthRequest {
  const [id, mechanism, ...args] = fields;
  if (id === undefined || !REQUEST_ID.test(id) || !mechanism) {
    throw new AuthProtocolError('malformed AUTH request');
  }
  const params = new Map<string, string>();
  const flags = new Set<string>();
  for (const arg of args) {
    const eq = arg.indexOf('=');
    if (eq === -1) flags.add(arg);
    else if (!params.has(arg.slice(0, eq))) params.set(arg.slice(0, eq), arg.slice(eq + 1));
  }
  return { id, mechanism: mechanism.toUpperCase(), params, flags };
}

export function isRequestId(value: string | undefined): value is string {
  return value !== undefined && REQUEST_ID.test(value);
}

const BASE64 = /^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/;

/** Strict base64 decoding; null for invalid input. */
export function decodeBase64(value: string): Buffer | null {
  return BASE64.test(value) ? Buffer.from(value, 'base64') : null;
}

export const encodeBase64 = (value: string): string =>
  Buffer.from(value, 'utf8').toString('base64');

export interface PlainCredentials {
  authzid: string;
  authcid: string;
  password: string;
}

/** RFC 4616: `[authzid] NUL authcid NUL passwd`. Null when malformed or authcid is empty. */
export function decodePlain(response: string): PlainCredentials | null {
  const bytes = decodeBase64(response);
  if (!bytes) return null;
  const parts = bytes.toString('utf8').split('\0');
  if (parts.length !== 3) return null;
  const [authzid, authcid, password] = parts as [string, string, string];
  if (authcid === '' || password === '') return null;
  return { authzid, authcid, password };
}

/** Usernames echoed in replies must not break the line/TAB framing. */
// eslint-disable-next-line no-control-regex -- control characters are exactly what is refused
const SAFE_USERNAME = /^[^\x00-\x1f\x7f]{1,255}$/;
export const isSafeUsername = (username: string): boolean => SAFE_USERNAME.test(username);
