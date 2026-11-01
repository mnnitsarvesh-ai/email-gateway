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
