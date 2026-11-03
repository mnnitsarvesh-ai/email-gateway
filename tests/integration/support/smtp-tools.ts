import { composeExec, type RunResult } from './compose';

/**
 * SMTP clients that run INSIDE the `smtp-tools` container (Compose profile smtp-test): swaks,
 * Postfix's smtp-source and openssl. Every argument is passed as an argv element of
 * `docker compose exec -T`, never through a shell.
 */
export const TOOLS = 'smtp-tools';

/** One server reply from a swaks transcript (`<-` / `<**` lines, multi-line joined). */
export interface SmtpReply {
  code: number;
  /** Every line of the reply, e.g. `250-SIZE 52428800`, `250 CHUNKING`. */
  lines: string[];
  /** The final line, e.g. `554 5.7.1 <x@y>: Relay access denied`. */
  text: string;
}

export interface SwaksResult extends RunResult {
  /** Full transcript (stdout + stderr). Never contains passwords (--auth-hide-password). */
  transcript: string;
  /** Replies keyed by the command that caused them (`CONNECT`, `EHLO`, `MAIL`, `RCPT#0`…). */
  replies: Map<string, SmtpReply>;
  /** `queued as <id>` of the DATA reply, when present. */
  queueId: string | undefined;
}

export interface SwaksOptions {
  server: string;
  port: number;
  from?: string;
  to?: readonly string[];
  helo?: string;
  /** STARTTLS (required) */
  tls?: boolean;
  tlsCert?: string;
  tlsKey?: string;
  auth?: { mechanism?: 'PLAIN' | 'LOGIN'; username: string; password: string };
  /** Full message (headers + body). Sent on stdin with `--data -`. */
  data?: string;
  quitAfter?: 'CONNECT' | 'FIRST-HELO' | 'TLS' | 'HELO' | 'AUTH' | 'MAIL' | 'FROM' | 'RCPT';
  /** Extra raw swaks arguments (each one argv element). */
  extra?: readonly string[];
  timeoutMs?: number;
}

const COMMAND = /^ {1,2}(?:->|~>) {1,2}(\S+)/;
const REPLY = /^(?:<-|<\*\*|<~|<~\*) {1,2}(\d{3})([ -])(.*)$/;

/** Runs swaks in smtp-tools and parses the transcript. */
export async function swaks(options: SwaksOptions): Promise<SwaksResult> {
  const args = ['swaks', '--server', options.server, '--port', String(options.port)];
  args.push('--helo', options.helo ?? 'client.integration.test');
  // swaks sends its own default sender for an empty --from; `<>` is the null sender.
  if (options.from !== undefined) args.push('--from', options.from === '' ? '<>' : options.from);
  if (options.to?.length) args.push('--to', options.to.join(','));
  if (options.tls) args.push('--tls');
  if (options.tlsCert) args.push('--tls-cert', options.tlsCert);
  if (options.tlsKey) args.push('--tls-key', options.tlsKey);
  if (options.auth) {
    // swaks 20201014 takes any value starting with `-` for an option (also in `--opt=value` form
    // and SWAKS_OPT_* variables) and echoes it in its error: callers must not pass such secrets.
    if (options.auth.password.startsWith('-')) {
      throw new Error('swaks cannot pass a password that starts with "-"');
    }
    args.push(
      '--auth',
      options.auth.mechanism ?? 'PLAIN',
      '--auth-user',
      options.auth.username,
      '--auth-password',
      options.auth.password,
      '--auth-hide-password',
    );
  }
  if (options.data !== undefined) args.push('--data', '-');
  if (options.quitAfter) args.push('--quit-after', options.quitAfter);
  args.push('--timeout', '60', ...(options.extra ?? []));
  const result = await composeExec(TOOLS, args, {
    input: options.data !== undefined ? toCrlf(options.data) : undefined,
    timeoutMs: options.timeoutMs ?? 120_000,
  });
  const transcript = `${result.stdout}${result.stderr}`;
  const replies = parseTranscript(transcript);
  const dataReply = replies.get('DATA-END');
  const queueId = dataReply ? /queued as ([A-Za-z0-9]+)/.exec(dataReply.text)?.[1] : undefined;
  return { ...result, transcript, replies, queueId };
}

function toCrlf(message: string): string {
  return message.replace(/\r?\n/g, '\r\n');
}

/**
 * Assigns every server reply to the client command before it: `CONNECT` (banner), `EHLO`,
 * `STARTTLS`, `AUTH`, `MAIL`, `RCPT#<n>`, `DATA`, `DATA-END` (reply after the message), `QUIT`.
 * After STARTTLS the second EHLO is `EHLO-TLS`.
 */
export function parseTranscript(transcript: string): Map<string, SmtpReply> {
  const replies = new Map<string, SmtpReply>();
  let current = 'CONNECT';
  let rcpt = 0;
  let tlsDone = false;
  let pending: string[] = [];
  let inData = false;
  for (const line of transcript.split(/\r?\n/)) {
    const command = COMMAND.exec(line);
    if (command) {
      const verb = command[1]!.toUpperCase();
      if (inData) {
        // Message lines are echoed with `->` too; the terminating `.` ends the message.
        if (verb === '.') current = 'DATA-END';
        continue;
      }
      if (verb === 'EHLO' || verb === 'HELO' || verb === 'LHLO') {
        current = tlsDone ? 'EHLO-TLS' : 'EHLO';
      } else if (verb === 'RCPT') {
        current = `RCPT#${rcpt}`;
        rcpt += 1;
      } else if (verb.startsWith('MAIL')) current = 'MAIL';
      else current = verb;
      continue;
    }
    if (/^=== TLS started/.test(line)) tlsDone = true;
    const reply = REPLY.exec(line);
    if (!reply) continue;
    pending.push(`${reply[1]}${reply[2]}${reply[3]}`);
    if (reply[2] === ' ') {
      const parsed: SmtpReply = { code: Number(reply[1]), lines: pending, text: pending.at(-1)! };
      replies.set(current, parsed);
      if (current === 'DATA' && parsed.code === 354) inData = true;
      if (current === 'DATA-END') inData = false;
      pending = [];
    }
  }
  return replies;
}

/** The reply to `key`, or a descriptive failure including the transcript. */
export function reply(result: SwaksResult, key: string): SmtpReply {
  const found = result.replies.get(key);
  if (!found) {
    throw new Error(`No reply for ${key} in swaks transcript:\n${result.transcript}`);
  }
  return found;
}

export interface SmtpSourceOptions {
  /** host:port as seen from smtp-tools, e.g. `postfix:25`. */
  target: string;
  sessions: number;
  messages: number;
  from: string;
  to: string;
  /** Body size in bytes (smtp-source -l). */
  length?: number;
  subject?: string;
  timeoutMs?: number;
}

/**
 * Postfix's `smtp-source`: `sessions` parallel connections, `messages` in total, several messages
 * per connection (-d), so Postfix's connection-rate limits are not what is being measured.
 */
export function smtpSource(options: SmtpSourceOptions) {
  const args = [
    'smtp-source',
    '-d',
    '-s',
    String(options.sessions),
    '-m',
    String(options.messages),
    '-f',
    options.from,
    '-t',
    options.to,
    '-l',
    String(options.length ?? 2048),
    '-S',
    options.subject ?? 'smtp-source load',
    '-M',
    'load.integration.test',
    options.target,
  ];
  return composeExec(TOOLS, args, { timeoutMs: options.timeoutMs ?? 600_000 });
}

/** IPv4 addresses of the smtp-tools container (one per Compose network). */
export async function toolsAddresses(): Promise<string[]> {
  const result = await composeExec(TOOLS, ['hostname', '-i']);
  if (result.exitCode !== 0) throw new Error(`hostname -i failed: ${result.stderr}`);
  return result.stdout
    .trim()
    .split(/\s+/)
    .filter((ip) => /^\d{1,3}(\.\d{1,3}){3}$/.test(ip));
}

/** The negotiated TLS protocol of `openssl s_client -starttls smtp` (e.g. `TLSv1.3`). */
export async function starttlsProtocol(
  server: string,
  port: number,
  extra: readonly string[] = [],
): Promise<{ protocol: string | undefined; output: string; exitCode: number }> {
  const result = await composeExec(
    TOOLS,
    [
      'openssl',
      's_client',
      '-starttls',
      'smtp',
      '-connect',
      `${server}:${port}`,
      '-servername',
      server,
      '-brief',
      ...extra,
    ],
    { input: 'QUIT\r\n', timeoutMs: 30_000 },
  );
  const output = `${result.stdout}${result.stderr}`;
  const protocol = /Protocol version: (\S+)/.exec(output)?.[1];
  return { protocol, output, exitCode: result.exitCode };
}

/**
 * Creates a self-signed client certificate in smtp-tools (under /tmp) and returns its paths and
 * SHA-256 fingerprint of the DER certificate (lower-case hex, no colons).
 */
export async function clientCertificate(name: string) {
  if (!/^[a-z0-9-]{1,32}$/.test(name)) throw new Error('invalid certificate name');
  const certPath = `/tmp/${name}.crt`;
  const keyPath = `/tmp/${name}.key`;
  const created = await composeExec(TOOLS, [
    'openssl',
    'req',
    '-x509',
    '-newkey',
    'rsa:2048',
    '-nodes',
    '-keyout',
    keyPath,
    '-out',
    certPath,
    '-days',
    '1',
    '-subj',
    `/CN=${name}.client.integration.test`,
  ]);
  if (created.exitCode !== 0) throw new Error(`openssl req failed: ${created.stderr}`);
  const fp = await composeExec(TOOLS, [
    'openssl',
    'x509',
    '-in',
    certPath,
    '-noout',
    '-fingerprint',
    '-sha256',
  ]);
  const match = /=([0-9A-F:]+)/i.exec(fp.stdout);
  if (!match) throw new Error(`openssl x509 -fingerprint failed: ${fp.stderr}`);
  return {
    certPath,
    keyPath,
    fingerprint: match[1]!.replaceAll(':', '').toLowerCase(),
  };
}

/** Removes files created under /tmp of smtp-tools. */
export async function removeToolsFiles(paths: readonly string[]) {
  const safe = paths.filter((p) => /^\/tmp\/[a-z0-9.-]+$/.test(p));
  if (safe.length > 0) await composeExec(TOOLS, ['rm', '-f', ...safe]);
}
