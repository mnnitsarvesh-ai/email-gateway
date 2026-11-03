/**
 * Postfix SMTP access policy delegation protocol.
 * http://www.postfix.org/SMTPD_POLICY_README.html
 *
 * Request: `name=value` lines terminated by an empty line.
 * Response: `action=<action>` followed by an empty line.
 */

export type PolicyRequest = Readonly<Record<string, string>>;

/** Upper bound on one request; Postfix requests are well under 2 KiB. */
export const MAX_REQUEST_BYTES = 16 * 1024;

export class PolicyProtocolError extends Error {}

/**
 * Incrementally splits a byte stream into complete requests. Handles requests spanning
 * multiple TCP chunks and several pipelined requests in one chunk.
 */
export class PolicyRequestParser {
  private buffer = '';

  push(chunk: string): PolicyRequest[] {
    this.buffer += chunk;
    if (Buffer.byteLength(this.buffer) > MAX_REQUEST_BYTES) {
      throw new PolicyProtocolError('policy request exceeds maximum size');
    }
    const requests: PolicyRequest[] = [];
    let end: number;
    while ((end = this.buffer.indexOf('\n\n')) !== -1) {
      requests.push(parseAttributes(this.buffer.slice(0, end)));
      this.buffer = this.buffer.slice(end + 2);
    }
    return requests;
  }
}

export function parseAttributes(block: string): PolicyRequest {
  const attributes: Record<string, string> = {};
  for (const line of block.split('\n')) {
    if (line === '') continue;
    const eq = line.indexOf('=');
    if (eq <= 0) throw new PolicyProtocolError('malformed policy attribute line');
    attributes[line.slice(0, eq)] = line.slice(eq + 1);
  }
  return attributes;
}

export function formatResponse(action: string): string {
  if (/[\r\n]/.test(action)) throw new PolicyProtocolError('action must be a single line');
  return `action=${action}\n\n`;
}

/** Postfix adds this prefix itself (`<rcpt>: Recipient address rejected: <text>`). */
const POSTFIX_RCPT_PREFIX = 'Recipient address rejected: ';

/**
 * Wire form of a policy action. Postfix answers `REJECT <text>` with `access_map_reject_code`
 * (554 by default), while step 2.2 specifies permanent policy rejections as `550` (D3:
 * `550 5.1.1`; §9 test plan: `550 5.7.1`). Postfix's numeric action `550 <text>` has the same
 * meaning as REJECT with an explicit code, so `REJECT` is sent as `550`. Postfix also prefixes
 * every restriction reply with `Recipient address rejected:` (or `End-of-data rejected:`), so a
 * leading copy of that phrase in our text is dropped to avoid saying it twice. `DUNNO` and
 * `DEFER_IF_PERMIT` (450, `defer_code`) pass through unchanged.
 */
export function postfixAction(action: string): string {
  if (!action.startsWith('REJECT ')) return action;
  const text = action.slice('REJECT '.length);
  const enhanced = /^5\.\d{1,3}\.\d{1,3} /.exec(text)?.[0] ?? '';
  const rest = text.slice(enhanced.length);
  const message = rest.startsWith(POSTFIX_RCPT_PREFIX)
    ? rest.slice(POSTFIX_RCPT_PREFIX.length)
    : rest;
  return `550 ${enhanced}${message}`;
}
