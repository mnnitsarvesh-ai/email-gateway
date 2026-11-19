import net from 'node:net';
import tls from 'node:tls';

/** One SMTP reply (multi-line replies joined). */
interface Reply {
  code: number;
  lines: string[];
}

export interface SmtpProbeOptions {
  /** The destination host name (TLS SNI and certificate verification). */
  host: string;
  /** The resolved address to connect to. */
  address: string;
  port: number;
  /** EHLO name (`INTEGRATION_PROBE_HELO`). */
  helo: string;
  /** The recipient domain: `RCPT TO:<postmaster@domain>`. */
  domain: string;
  /** The preset's Postfix `match=` list (`nexthop:name:.suffix`). */
  verifyNames: string;
  timeoutMs: number;
  /** Trusted CAs (PEM); undefined = the system CAs. */
  ca?: string[];
}

export type SmtpProbeCode =
  | 'ok'
  | 'rcpt_refused'
  | 'rcpt_deferred'
  | 'mail_refused'
  | 'connect_failed'
  | 'timeout'
  | 'greeting_refused'
  | 'ehlo_refused'
  | 'starttls_unavailable'
  | 'starttls_refused'
  | 'tls_failed'
  | 'certificate_untrusted'
  | 'certificate_mismatch'
  | 'tls_version'
  | 'protocol_error';

export interface SmtpProbeResult {
  status: 'pass' | 'warn' | 'fail';
  code: SmtpProbeCode;
  evidence: {
    banner: string | null;
    tlsVersion: string | null;
    certificateSubject: string | null;
    certificateNames: string[];
    namesMatch: boolean | null;
    rcptReplyClass: '2xx' | '4xx' | '5xx' | null;
  };
}

class ProbeFailure extends Error {
  constructor(readonly probeCode: SmtpProbeCode) {
    super(probeCode);
    this.name = 'ProbeFailure';
  }
}

const MAX_REPLY_BYTES = 16_384;

/** Reads SMTP replies from a socket (plain or TLS). */
class ReplyReader {
  private buffer = '';
  private lines: string[] = [];
  private waiting: { resolve: (r: Reply) => void; reject: (e: Error) => void } | null = null;
  private queued: Reply[] = [];
  private failure: Error | null = null;
  private socket: net.Socket;
  private readonly onData = (chunk: Buffer) => this.push(chunk.toString('latin1'));
  private readonly onEnd = () => this.fail(new ProbeFailure('protocol_error'));
  private readonly onError = (error: Error) =>
    this.fail(error instanceof ProbeFailure ? error : new ProbeFailure('connect_failed'));

  constructor(socket: net.Socket) {
    this.socket = socket;
    this.attach(socket);
  }

  private attach(socket: net.Socket): void {
    socket.on('data', this.onData);
    socket.on('end', this.onEnd);
    socket.on('error', this.onError);
  }

  /** Moves the reader to the upgraded TLS socket (STARTTLS). */
  switchTo(socket: net.Socket): void {
    this.socket.off('data', this.onData);
    this.socket.off('end', this.onEnd);
    this.socket.off('error', this.onError);
    this.buffer = '';
    this.lines = [];
    this.socket = socket;
    this.attach(socket);
  }

  /** Detaches from the plain socket before the TLS handshake takes it over. */
  pause(): void {
    this.socket.off('data', this.onData);
    this.socket.off('end', this.onEnd);
    this.socket.off('error', this.onError);
  }

  fail(error: Error): void {
    if (this.failure) return;
    this.failure = error;
    const waiter = this.waiting;
    this.waiting = null;
    waiter?.reject(error);
  }

  private push(text: string): void {
    this.buffer += text;
    if (this.buffer.length > MAX_REPLY_BYTES) return this.fail(new ProbeFailure('protocol_error'));
    let index: number;
    while ((index = this.buffer.indexOf('\n')) >= 0) {
      const line = this.buffer.slice(0, index).replace(/\r$/, '');
      this.buffer = this.buffer.slice(index + 1);
      const match = /^(\d{3})([ -])(.*)$/.exec(line);
      if (!match) return this.fail(new ProbeFailure('protocol_error'));
      this.lines.push(match[3]!);
      if (match[2] === ' ') {
        const reply = { code: Number(match[1]), lines: this.lines };
        this.lines = [];
        if (this.waiting) {
          const waiter = this.waiting;
          this.waiting = null;
          waiter.resolve(reply);
        } else {
          this.queued.push(reply);
        }
      }
    }
  }

  next(): Promise<Reply> {
    if (this.failure) return Promise.reject(this.failure);
    const queued = this.queued.shift();
    if (queued) return Promise.resolve(queued);
    return new Promise((resolve, reject) => {
      this.waiting = { resolve, reject };
    });
  }
}

/**
 * Postfix `match=` semantics of a preset's `tls_verify_names` (D10): `nexthop` = the destination
 * host itself; a leading dot = any subdomain; otherwise an exact name. Certificate wildcards
 * (`*.example.com`) cover exactly one label.
 */
export function certificateNamesMatch(
  certificateNames: readonly string[],
  verifyNames: string,
  host: string,
): boolean {
  const patterns = verifyNames
    .split(':')
    .map((p) => p.trim().toLowerCase())
    .filter(Boolean)
    .map((p) => (p === 'nexthop' ? host.toLowerCase() : p));
  const names = certificateNames.map((n) => n.trim().toLowerCase().replace(/\.$/, ''));
  for (const name of names) {
    for (const pattern of patterns) {
      if (pattern.startsWith('.')) {
        const suffix = pattern.slice(1);
        if (name.endsWith(pattern)) return true;
        if (name.startsWith('*.')) {
          const rest = name.slice(2);
          if (rest === suffix || rest.endsWith(pattern)) return true;
        }
      } else {
        if (name === pattern) return true;
        if (name.startsWith('*.')) {
          const rest = name.slice(2);
          const dot = pattern.indexOf('.');
          if (dot > 0 && pattern.slice(dot + 1) === rest) return true;
        }
      }
    }
  }
  return false;
}

function namesOf(cert: tls.PeerCertificate | null): { subject: string | null; names: string[] } {
  if (!cert || Object.keys(cert).length === 0) return { subject: null, names: [] };
  const subject = typeof cert.subject?.CN === 'string' ? cert.subject.CN : null;
  const sans = (cert.subjectaltname ?? '')
    .split(',')
    .map((s) => s.trim())
    .filter((s) => s.startsWith('DNS:'))
    .map((s) => s.slice(4));
  return { subject, names: sans.length > 0 ? sans : subject ? [subject] : [] };
}

const clip = (value: string, max: number): string =>
  value.length > max ? value.slice(0, max) : value;

const replyClass = (code: number): '2xx' | '4xx' | '5xx' | null =>
  code >= 200 && code < 300
    ? '2xx'
    : code >= 400 && code < 500
      ? '4xx'
      : code >= 500
        ? '5xx'
        : null;

const FAIL_CODES: ReadonlySet<SmtpProbeCode> = new Set([
  'connect_failed',
  'timeout',
  'greeting_refused',
  'ehlo_refused',
  'starttls_unavailable',
  'starttls_refused',
  'tls_failed',
  'certificate_untrusted',
  'certificate_mismatch',
  'tls_version',
  'protocol_error',
]);

/**
 * The `inbound.smtp` reachability probe (D10, ADR-0079): connect, EHLO, STARTTLS (required),
 * certificate verified against the trusted CAs and the preset's names, TLS ≥ 1.2, EHLO again,
 * `MAIL FROM:<>`, `RCPT TO:<postmaster@domain>`, `RSET`, `QUIT`. **No DATA command is ever
 * sent** (the client has no code path that writes one). A connection or TLS failure is `fail`;
 * a 4xx/5xx at MAIL or RCPT is `warn` (providers may refuse probes from non-gateway addresses).
 * Evidence is non-secret: banner host, TLS version, certificate names, reply class.
 */
export async function probeSmtp(options: SmtpProbeOptions): Promise<SmtpProbeResult> {
  const evidence: SmtpProbeResult['evidence'] = {
    banner: null,
    tlsVersion: null,
    certificateSubject: null,
    certificateNames: [],
    namesMatch: null,
    rcptReplyClass: null,
  };
  let plain: net.Socket | null = null;
  let secure: tls.TLSSocket | null = null;
  let reader: ReplyReader | null = null;
  let timer: NodeJS.Timeout | undefined;
  const deadline = new Promise<never>((_, reject) => {
    timer = setTimeout(() => {
      reject(new ProbeFailure('timeout'));
      reader?.fail(new ProbeFailure('timeout'));
    }, options.timeoutMs);
  });
  deadline.catch(() => undefined);
  /** Every wait races the probe's overall deadline. */
  const step = <T>(promise: Promise<T>): Promise<T> => Promise.race([promise, deadline]);
  const send = (line: string) => {
    if (/^DATA\b/i.test(line) || /[\r\n]/.test(line)) throw new ProbeFailure('protocol_error');
    (secure ?? plain)!.write(`${line}\r\n`);
  };
  const outcome = (status: SmtpProbeResult['status'], code: SmtpProbeCode): SmtpProbeResult => ({
    status,
    code,
    evidence,
  });
  try {
    plain = net.connect({ host: options.address, port: options.port });
    plain.setNoDelay(true);
    reader = new ReplyReader(plain);
    await step(
      new Promise<void>((resolve, reject) => {
        plain!.once('connect', resolve);
        plain!.once('error', () => reject(new ProbeFailure('connect_failed')));
      }),
    );
    const greeting = await step(reader.next());
    evidence.banner = clip((greeting.lines[0] ?? '').split(/\s+/)[0] ?? '', 64) || null;
    if (greeting.code !== 220) return outcome('fail', 'greeting_refused');

    send(`EHLO ${options.helo}`);
    const ehlo = await step(reader.next());
    if (ehlo.code !== 250) return outcome('fail', 'ehlo_refused');
    if (!ehlo.lines.some((l) => /^STARTTLS\b/i.test(l.trim()))) {
      return outcome('fail', 'starttls_unavailable');
    }
    send('STARTTLS');
    const ready = await step(reader.next());
    if (ready.code !== 220) return outcome('fail', 'starttls_refused');

    reader.pause();
    secure = await step(
      new Promise<tls.TLSSocket>((resolve, reject) => {
        const socket = tls.connect({
          socket: plain!,
          servername: net.isIP(options.host) ? undefined : options.host,
          minVersion: 'TLSv1.2',
          rejectUnauthorized: true,
          ...(options.ca ? { ca: options.ca } : {}),
          // Names are checked below with the preset's match semantics.
          checkServerIdentity: () => undefined,
        });
        socket.once('secureConnect', () => resolve(socket));
        socket.once('error', (error: NodeJS.ErrnoException) => {
          const code = String(error.code ?? '');
          reject(
            new ProbeFailure(
              /CERT|SELF_SIGNED|UNABLE_TO|ISSUER/.test(code)
                ? 'certificate_untrusted'
                : /VERSION|PROTOCOL/.test(code)
                  ? 'tls_version'
                  : 'tls_failed',
            ),
          );
        });
      }),
    );
    const version = secure.getProtocol();
    evidence.tlsVersion = version;
    const { subject, names } = namesOf(secure.getPeerCertificate());
    evidence.certificateSubject = subject ? clip(subject, 128) : null;
    evidence.certificateNames = names.slice(0, 10).map((n) => clip(n, 128));
    evidence.namesMatch = certificateNamesMatch(names, options.verifyNames, options.host);
    if (version !== 'TLSv1.2' && version !== 'TLSv1.3') return outcome('fail', 'tls_version');
    if (!evidence.namesMatch) return outcome('fail', 'certificate_mismatch');
    reader.switchTo(secure);

    send(`EHLO ${options.helo}`);
    if ((await step(reader.next())).code !== 250) return outcome('fail', 'ehlo_refused');
    send('MAIL FROM:<>');
    const mail = await step(reader.next());
    if (mail.code !== 250) return outcome('warn', 'mail_refused');
    send(`RCPT TO:<postmaster@${options.domain}>`);
    const rcpt = await step(reader.next());
    evidence.rcptReplyClass = replyClass(rcpt.code);
    send('RSET');
    await step(reader.next()).catch(() => undefined);
    if (rcpt.code >= 200 && rcpt.code < 300) return outcome('pass', 'ok');
    return outcome('warn', rcpt.code >= 500 ? 'rcpt_refused' : 'rcpt_deferred');
  } catch (error) {
    const code = error instanceof ProbeFailure ? error.probeCode : 'connect_failed';
    return outcome(FAIL_CODES.has(code) ? 'fail' : 'warn', code);
  } finally {
    if (timer) clearTimeout(timer);
    try {
      if (secure && !secure.destroyed) secure.end('QUIT\r\n');
      else if (plain && !plain.destroyed) plain.end('QUIT\r\n');
    } catch {
      // best effort
    }
    setTimeout(() => {
      secure?.destroy();
      plain?.destroy();
    }, 1_000).unref();
  }
}
