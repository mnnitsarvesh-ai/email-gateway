/**
 * Pure parser of postfix-outbound's `maillog_file` lines (step 2.3 R9), for the Postfix 3.7
 * formats verified in docs/deployment/mail-routing.md ("Delivery log line reference"):
 *
 *   `MMM DD HH:MM:SS <host> postfix/<service>[pid]: <text>` (day zero-padded, no year, optional
 *   fraction of a second), the year inferred from the current UTC date.
 *
 * Unknown lines return null; nothing is guessed.
 */

export interface LogLineBase {
  /** Parsed timestamp (UTC, year inferred). */
  timestamp: Date;
  /** The timestamp exactly as written (signal keys use it, so re-reads dedupe). */
  rawTimestamp: string;
  /** 1000 for whole-second timestamps (the verified format), 1 with a fraction. */
  precisionMs: number;
  /** Syslog program name, e.g. `postfix/smtp`, `postfix/reinject-inbound/smtpd`. */
  program: string;
}

/** `client=…, orig_queue_id=dw1-…` on a reinjection listener: binds the queue id to a token. */
export interface BindLine extends LogLineBase {
  kind: 'bind';
  queueId: string;
  token: string;
  listener: 'reinject_inbound' | 'reinject_outbound';
}

/** qmgr `from=<…>, size=N, nrcpt=M (queue active)`. */
export interface QueueActiveLine extends LogLineBase {
  kind: 'queue_active';
  queueId: string;
  sender: string;
  size: number;
  nrcpt: number;
}

export type PostfixDeliveryStatus = 'sent' | 'deferred' | 'bounced' | 'expired';

/** `to=<a>, [orig_to=<a>,] relay=…, delay=…, delays=…, dsn=…, status=… (text)`. */
export interface RecipientResultLine extends LogLineBase {
  kind: 'recipient_result';
  queueId: string;
  address: string;
  origAddress: string | null;
  /** `none` → null. */
  relay: { host: string; ip: string | null; port: number | null } | null;
  dsn: string;
  status: PostfixDeliveryStatus;
  /** The parenthesized reply or reason text. */
  text: string;
  /** SMTP reply code found in the text (`250 …`, `host … said: 450 …`), else null. */
  smtpCode: number | null;
  /** An attempt against a remote server (relay known, or a connection-level failure). */
  remoteAttempt: boolean;
  delaySeconds: number | null;
}

/** qmgr `from=<…>, status=expired, returned to sender` (message level, V5). */
export interface MessageExpiredLine extends LogLineBase {
  kind: 'message_expired';
  queueId: string;
  sender: string;
}

/** bounce `sender|postmaster non-delivery|delay notification: DSNQID`. */
export interface NotificationLine extends LogLineBase {
  kind: 'notification';
  queueId: string;
  recipient: 'sender' | 'postmaster';
  type: 'non_delivery' | 'delay';
  dsnQueueId: string;
}

/** qmgr / postsuper `removed`: the queue file is gone. */
export interface RemovedLine extends LogLineBase {
  kind: 'removed';
  queueId: string;
}

/** Any other well-formed Postfix line (its timestamp still advances the tailer's clock). */
export interface OtherLine extends LogLineBase {
  kind: 'other';
}

export type PostfixLogEvent =
  | BindLine
  | QueueActiveLine
  | RecipientResultLine
  | MessageExpiredLine
  | NotificationLine
  | RemovedLine;

export type ParsedLine = PostfixLogEvent | OtherLine;

const MONTHS: Readonly<Record<string, number>> = {
  Jan: 0,
  Feb: 1,
  Mar: 2,
  Apr: 3,
  May: 4,
  Jun: 5,
  Jul: 6,
  Aug: 7,
  Sep: 8,
  Oct: 9,
  Nov: 10,
  Dec: 11,
};

const LINE =
  /^(?<ts>(?<mon>Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec) (?<day>[ 0-3]\d) (?<h>[0-2]\d):(?<m>[0-5]\d):(?<s>[0-6]\d)(?:\.(?<frac>\d{1,6}))?) (?<host>\S+) (?<prog>postfix(?:\/[A-Za-z0-9._-]+)+)\[(?<pid>\d+)\]: (?<text>.*)$/;
const QUEUE_ID = '[0-9A-Za-z]{6,32}';
const REINJECT_SMTPD = /^postfix\/reinject-(inbound|outbound)\/smtpd$/;
const BIND = new RegExp(`^(${QUEUE_ID}): client=[^,]*, orig_queue_id=(dw1-[0-9a-f]{32})(?:,|$)`);
const QUEUE_ACTIVE = new RegExp(
  `^(${QUEUE_ID}): from=<(.*)>, size=(\\d+), nrcpt=(\\d+) \\(queue active\\)$`,
);
const RECIPIENT = new RegExp(
  `^(${QUEUE_ID}): to=<([^>]*)>, (?:orig_to=<([^>]*)>, )?relay=([^,]+), (?:conn_use=\\d+, )?delay=([0-9.]+), delays=[0-9./]+, dsn=([245]\\.\\d{1,3}\\.\\d{1,3}), status=(sent|deferred|bounced|expired) \\((.*)\\)$`,
);
const EXPIRED = new RegExp(`^(${QUEUE_ID}): from=<(.*)>, status=expired, returned to sender$`);
const NOTIFICATION = new RegExp(
  `^(${QUEUE_ID}): (sender|postmaster) (non-delivery|delay) notification: (${QUEUE_ID})$`,
);
const REMOVED = new RegExp(`^(${QUEUE_ID}): removed$`);
const RELAY = /^(.+?)\[([^\]]*)\](?::(\d{1,5}))?$/;
const CODE_IN_TEXT = /(?:^|\bsaid: |\brefused to talk to me: )([2-5]\d\d)\b/;

/** Programs whose `to=` lines are delivery results (smtp, lmtp, error, retry, …). */
const RESULT_PROGRAMS =
  /^postfix\/(?:smtp|lmtp|error|retry|qmgr|bounce|local|virtual|discard|pipe)$/;

/**
 * Year of a `MMM DD` timestamp: the current UTC year, unless that puts the line more than one
 * day in the future (a December line read in January → previous year) or almost a year in the
 * past (a January line read on 31 December with a skewed clock → next year).
 */
export function inferTimestamp(
  month: number,
  day: number,
  hours: number,
  minutes: number,
  seconds: number,
  millis: number,
  now: Date,
): Date {
  const year = now.getUTCFullYear();
  const at = (y: number) => new Date(Date.UTC(y, month, day, hours, minutes, seconds, millis));
  const candidate = at(year);
  const dayMs = 86_400_000;
  if (candidate.getTime() - now.getTime() > dayMs) return at(year - 1);
  if (now.getTime() - candidate.getTime() > 358 * dayMs) return at(year + 1);
  return candidate;
}

function parseRelay(value: string): RecipientResultLine['relay'] {
  if (value === 'none') return null;
  const match = RELAY.exec(value);
  if (!match) return { host: value, ip: null, port: null };
  return { host: match[1]!, ip: match[2] || null, port: match[3] ? Number(match[3]) : null };
}

/** Parses one line (without its line terminator); null for anything that is not Postfix's. */
export function parsePostfixLogLine(line: string, now: Date = new Date()): ParsedLine | null {
  const match = LINE.exec(line.replace(/\r$/, ''));
  if (!match?.groups) return null;
  const g = match.groups;
  const month = MONTHS[g.mon!];
  if (month === undefined) return null;
  const day = Number(g.day!.trim());
  if (day < 1 || day > 31) return null;
  const millis = g.frac ? Math.floor(Number(`0.${g.frac}`) * 1000) : 0;
  const timestamp = inferTimestamp(month, day, Number(g.h), Number(g.m), Number(g.s), millis, now);
  if (Number.isNaN(timestamp.getTime())) return null;
  const base: LogLineBase = {
    timestamp,
    rawTimestamp: g.ts!,
    precisionMs: g.frac ? 1 : 1000,
    program: g.prog!,
  };
  const text = g.text!;
  const program = base.program;

  const reinject = REINJECT_SMTPD.exec(program);
  if (reinject) {
    // Only the reinjection listeners' syslog names bind (only $reinject_networks reach them).
    const bind = BIND.exec(text);
    if (bind) {
      return {
        ...base,
        kind: 'bind',
        queueId: bind[1]!,
        token: bind[2]!,
        listener: reinject[1] === 'inbound' ? 'reinject_inbound' : 'reinject_outbound',
      };
    }
    return { ...base, kind: 'other' };
  }

  if (program === 'postfix/qmgr') {
    const active = QUEUE_ACTIVE.exec(text);
    if (active) {
      return {
        ...base,
        kind: 'queue_active',
        queueId: active[1]!,
        sender: active[2]!,
        size: Number(active[3]),
        nrcpt: Number(active[4]),
      };
    }
    const expired = EXPIRED.exec(text);
    if (expired)
      return { ...base, kind: 'message_expired', queueId: expired[1]!, sender: expired[2]! };
  }

  if (program === 'postfix/qmgr' || program === 'postfix/postsuper') {
    const removed = REMOVED.exec(text);
    if (removed) return { ...base, kind: 'removed', queueId: removed[1]! };
  }

  if (program === 'postfix/bounce') {
    const notice = NOTIFICATION.exec(text);
    if (notice) {
      return {
        ...base,
        kind: 'notification',
        queueId: notice[1]!,
        recipient: notice[2] === 'sender' ? 'sender' : 'postmaster',
        type: notice[3] === 'delay' ? 'delay' : 'non_delivery',
        dsnQueueId: notice[4]!,
      };
    }
  }

  if (RESULT_PROGRAMS.test(program)) {
    const result = RECIPIENT.exec(text);
    if (result) {
      const relay = parseRelay(result[4]!);
      const reason = result[8]!;
      const code = CODE_IN_TEXT.exec(reason);
      const connectionLevel = /^(?:connect to|conversation with) /.test(reason);
      return {
        ...base,
        kind: 'recipient_result',
        queueId: result[1]!,
        address: result[2]!,
        origAddress: result[3] ?? null,
        relay,
        delaySeconds: Number.isFinite(Number(result[5])) ? Number(result[5]) : null,
        dsn: result[6]!,
        status: result[7] as PostfixDeliveryStatus,
        text: reason,
        smtpCode: code ? Number(code[1]) : null,
        // The error/retry transports never talk to a remote server.
        remoteAttempt:
          program !== 'postfix/error' &&
          program !== 'postfix/retry' &&
          (relay !== null || connectionLevel),
      };
    }
  }
  return { ...base, kind: 'other' };
}
