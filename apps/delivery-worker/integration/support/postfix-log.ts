import { appendFileSync, mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

const MONTHS = ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec'];
const pad = (n: number) => n.toString().padStart(2, '0');

/** `MMM DD HH:MM:SS` in UTC, the maillog_file format verified by WP2 (no year, no fraction). */
export function logTime(date: Date): string {
  return `${MONTHS[date.getUTCMonth()]} ${pad(date.getUTCDate())} ${pad(date.getUTCHours())}:${pad(date.getUTCMinutes())}:${pad(date.getUTCSeconds())}`;
}

/**
 * Lines in the exact Postfix 3.7.11 formats of docs/deployment/mail-routing.md ("Delivery log
 * line reference"), with the queue ids, tokens and addresses of a test.
 */
export const lines = {
  bind: (at: Date, queueId: string, token: string, listener: 'inbound' | 'outbound' = 'outbound') =>
    `${logTime(at)} out postfix/reinject-${listener}/smtpd[694]: ${queueId}: client=unknown[172.31.250.30], orig_queue_id=${token}, orig_client=mail.example.org[203.0.113.7]`,
  queueActive: (at: Date, queueId: string, sender: string, nrcpt: number) =>
    `${logTime(at)} out postfix/qmgr[212]: ${queueId}: from=<${sender}>, size=466, nrcpt=${nrcpt} (queue active)`,
  sent: (at: Date, queueId: string, to: string) =>
    `${logTime(at)} out postfix/smtp[698]: ${queueId}: to=<${to}>, relay=mx.sink.test[172.31.250.25]:25, delay=0.16, delays=0.09/0.05/0.02/0.01, dsn=2.0.0, status=sent (250 2.0.0 Ok: queued as 05221156A60)`,
  deferred: (at: Date, queueId: string, to: string) =>
    `${logTime(at)} out postfix/smtp[238]: ${queueId}: to=<${to}>, relay=mx.sink.test[172.31.250.25]:25, delay=0.11, delays=0.08/0.02/0.01/0, dsn=4.2.1, status=deferred (host mx.sink.test[172.31.250.25] said: 450 4.2.1 <${to}>: Recipient address rejected: Mailbox busy (in reply to RCPT TO command))`,
  bounced: (at: Date, queueId: string, to: string) =>
    `${logTime(at)} out postfix/smtp[286]: ${queueId}: to=<${to}>, relay=mx.sink.test[172.31.250.25]:25, delay=0.11, delays=0.06/0.02/0.02/0.01, dsn=5.1.1, status=bounced (host mx.sink.test[172.31.250.25] said: 550 5.1.1 <${to}>: Recipient address rejected: User unknown (in reply to RCPT TO command))`,
  senderDsn: (at: Date, queueId: string, dsnQueueId: string) =>
    `${logTime(at)} out postfix/bounce[287]: ${queueId}: sender non-delivery notification: ${dsnQueueId}`,
  removed: (at: Date, queueId: string) =>
    `${logTime(at)} out postfix/qmgr[212]: ${queueId}: removed`,
  health: (at: Date) =>
    `${logTime(at)} out postfix/postfix-script[1234]: the Postfix mail system is running: PID: 1`,
};

/** A temporary maillog file. */
export class TempLog {
  readonly dir = mkdtempSync(join(tmpdir(), 'dw-maillog-'));
  readonly path = join(this.dir, 'maillog');

  append(...text: string[]): void {
    appendFileSync(this.path, text.map((line) => `${line}\n`).join(''));
  }

  remove(): void {
    rmSync(this.dir, { recursive: true, force: true });
  }
}
