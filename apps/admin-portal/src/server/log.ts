import 'server-only';

/**
 * Minimal structured logger for the BFF (one JSON line per event, pino-compatible fields).
 * Callers pass only non-secret fields: never tokens, cookies, bodies, passwords or codes.
 */
export type LogLevel = 'debug' | 'info' | 'warn' | 'error';

const LEVELS: Record<LogLevel, number> = { debug: 20, info: 30, warn: 40, error: 50 };

export interface PortalLogger {
  info(msg: string, fields?: Record<string, unknown>): void;
  warn(msg: string, fields?: Record<string, unknown>): void;
  error(msg: string, fields?: Record<string, unknown>): void;
}

const FORBIDDEN_FIELDS = /token|cookie|password|secret|authorization|code|key/i;

function write(level: LogLevel, msg: string, fields: Record<string, unknown> = {}): void {
  const safe: Record<string, unknown> = {};
  for (const [name, value] of Object.entries(fields)) {
    safe[name] = FORBIDDEN_FIELDS.test(name) && name !== 'errorCode' ? '[redacted]' : value;
  }
  const line = JSON.stringify({
    level: LEVELS[level],
    time: Date.now(),
    service: 'admin-portal',
    msg,
    ...safe,
  });
  (level === 'error' || level === 'warn' ? process.stderr : process.stdout).write(`${line}\n`);
}

export const logger: PortalLogger = {
  info: (msg, fields) => write('info', msg, fields),
  warn: (msg, fields) => write('warn', msg, fields),
  error: (msg, fields) => write('error', msg, fields),
};
