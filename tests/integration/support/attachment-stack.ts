import { randomUUID } from 'node:crypto';
import { stack } from './env';
import { base64Lines } from './mime';

/**
 * Helpers of the step 4.2 attachment stack suites (tests/integration/attachment-*.test.ts,
 * docs/plan/steps/10-attachment-scanning.md §9 "Stack"). Every attachment is generated at test
 * time by `@email-gateway/attachment-corpus` (EICAR assembled from fragments, no real malware,
 * nothing binary committed); this module only wraps the bytes into a MIME message.
 */
const CRLF = '\r\n';

export interface MessageAttachment {
  /** ASCII display filename (sent as the `filename` parameter). */
  filename: string;
  /** Declared `Content-Type` of the part. */
  contentType: string;
  bytes: Buffer;
}

/**
 * multipart/mixed: a plain-text body and one base64 part per attachment (7bit on the wire, CRLF
 * line endings, a unique Message-ID). `attachments: []` gives a single-part text message.
 */
export function attachmentMessage(options: {
  from: string;
  to: readonly string[];
  subject: string;
  attachments: readonly MessageAttachment[];
}): { text: string; messageId: string } {
  const messageId = `<${randomUUID()}@attachment.integration.test>`;
  const headers = [
    `From: ${options.from}`,
    `To: ${options.to.join(', ')}`,
    `Subject: ${options.subject}`,
    `Message-ID: ${messageId}`,
    `Date: ${new Date().toUTCString().replace('GMT', '+0000')}`,
    'MIME-Version: 1.0',
  ];
  if (options.attachments.length === 0) {
    const text = [
      ...headers,
      'Content-Type: text/plain; charset=utf-8',
      '',
      `Body of ${options.subject} (no attachments).`,
      '',
    ].join(CRLF);
    return { text, messageId };
  }
  const boundary = `mixed-${randomUUID()}`;
  const lines = [
    ...headers,
    `Content-Type: multipart/mixed; boundary="${boundary}"`,
    '',
    'This is a multi-part message in MIME format.',
    `--${boundary}`,
    'Content-Type: text/plain; charset=utf-8',
    'Content-Transfer-Encoding: 7bit',
    '',
    `Body of ${options.subject}; see the attachment.`,
  ];
  for (const a of options.attachments) {
    if (!/^[A-Za-z0-9._-]{1,64}$/.test(a.filename)) throw new Error(`filename ${a.filename}`);
    lines.push(
      `--${boundary}`,
      `Content-Type: ${a.contentType}; name="${a.filename}"`,
      `Content-Disposition: attachment; filename="${a.filename}"`,
      'Content-Transfer-Encoding: base64',
      '',
      base64Lines(a.bytes),
    );
  }
  lines.push(`--${boundary}--`, '');
  return { text: lines.join(CRLF), messageId };
}

/** Bytes that are unique per call (a run never hits a content-cache entry of another run). */
export function uniqueText(label: string): Buffer {
  return Buffer.from(
    `Quarterly figures (${label}).\r\nReference ${randomUUID()} ${randomUUID()}\r\n`,
    'utf8',
  );
}

/**
 * Sum of one counter of the delivery-worker's `/metrics` over the series whose labels include
 * `labels`; `undefined` when the worker cannot be reached.
 */
export async function deliveryWorkerCounter(
  name: string,
  labels: Record<string, string>,
): Promise<number | undefined> {
  try {
    const res = await fetch(
      `http://${stack.host}:${stack.ports.services['delivery-worker']}/metrics`,
      { signal: AbortSignal.timeout(5_000) },
    );
    if (!res.ok) return undefined;
    let total = 0;
    for (const line of (await res.text()).split('\n')) {
      if (!line.startsWith(`${name}{`)) continue;
      const match = /^[^{]+\{([^}]*)\} ([0-9.eE+-]+)$/.exec(line);
      if (!match) continue;
      const present = new Map([...match[1]!.matchAll(/(\w+)="([^"]*)"/g)].map((m) => [m[1], m[2]]));
      if (Object.entries(labels).every(([k, v]) => present.get(k) === v)) total += Number(match[2]);
    }
    return total;
  } catch {
    return undefined;
  }
}

/** Whether clamd answers `PING` on the host port (CLAMAV_HOST/CLAMAV_PORT of the local `.env`). */
export async function clamdResponds(timeoutMs = 3_000): Promise<boolean> {
  const { createConnection } = await import('node:net');
  const host = process.env.CLAMAV_HOST || '127.0.0.1';
  const port = Number(process.env.CLAMAV_PORT || process.env.CLAMAV_HOST_PORT || 3310);
  return new Promise((resolve) => {
    const socket = createConnection({ host, port });
    let reply = '';
    const done = (ok: boolean) => {
      socket.destroy();
      resolve(ok);
    };
    socket.setTimeout(timeoutMs, () => done(false));
    socket.on('error', () => done(false));
    socket.on('connect', () => socket.write('zPING\0'));
    socket.on('data', (chunk) => {
      reply += chunk.toString('latin1');
      if (reply.includes('\0')) done(reply.startsWith('PONG'));
    });
    socket.on('close', () => done(reply.startsWith('PONG')));
  });
}
