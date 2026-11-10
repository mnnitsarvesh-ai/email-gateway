import { createHash } from 'node:crypto';
import { isIP } from 'node:net';
import { posix } from 'node:path';
import { isCanonicalIp, SANDBOX_OBSERVATION_BOUNDS } from '@email-gateway/security-contracts';

/**
 * Parser of the runner's `strace -f -q -tt -s 256 -o …` output (step 4.6 X6). Pure and bounded.
 * The trace is UNTRUSTED evidence (the sample can tamper with it in the same uid): every field is
 * pattern-checked, lists are capped, nothing here is ever a reason for `clean`.
 *
 * Extracted: processes (execve image basenames, parent, exit code / kill), connection attempts
 * (`connect()` and addressed `sendto()` on AF_INET/AF_INET6 sockets, loopback excluded, with the
 * outcome: refused, unreachable, timeout, or connected — non-blocking connects are resolved by the
 * following `getsockopt(SO_ERROR)`), writes denied outside `/scratch` (`EROFS`/`EACCES`/`EPERM`),
 * persistence and privilege-escalation attempts, container fingerprinting reads and fork failures
 * at the pids limit (`EAGAIN`).
 */

export type RawConnectionOutcome = 'refused' | 'unreachable' | 'timeout' | 'connected';

export interface TraceProcess {
  seq: number;
  parentSeq: number | null;
  image: string;
  argvSha256: string | null;
  exitCode: number | null;
  killedBy: 'timeout' | 'memory' | 'pids' | null;
}

export interface TraceConnection {
  ip: string;
  port: number;
  protocol: 'tcp' | 'udp';
  outcome: RawConnectionOutcome;
}

export interface TraceSummary {
  processes: TraceProcess[];
  processCount: number;
  /** Images of every exec'd process (bounded, unique). */
  images: string[];
  /** Shells exec'd by a process other than the root of the tree. */
  shellSpawns: number;
  connections: TraceConnection[];
  connectionAttempts: number;
  deniedWrites: number;
  persistenceAttempts: number;
  privilegeAttempts: number;
  environmentChecks: number;
  pidsLimitHits: number;
  linesParsed: number;
  /** The line cap was reached; later lines were ignored. */
  truncated: boolean;
}

export interface TraceContext {
  /** The run ended by the (inner or outer) wall timeout. */
  timedOut: boolean;
  /** The container's memory cgroup OOM-killed a process. */
  oomKilled: boolean;
  /** Paths writable by design (`/scratch`, `/tmp`). */
  writableRoots?: readonly string[];
  /** The sample's working directory (relative paths resolve against it). */
  cwd?: string;
}

export const TRACE_MAX_LINES = 200_000;
const MAX_LINE_LENGTH = 8_192;
const MAX_IMAGES = 32;
const SHELLS = new Set(['sh', 'ash', 'bash', 'dash', 'zsh', 'ksh', 'busybox']);
const PRIVILEGE_TOOLS = new Set([
  'su',
  'sudo',
  'doas',
  'mount',
  'umount',
  'unshare',
  'chroot',
  'nsenter',
  'setpriv',
  'capsh',
  'setcap',
  'pkexec',
  'newuidmap',
  'newgidmap',
  'insmod',
  'modprobe',
  'chown',
]);
const PRIVILEGE_SYSCALLS = new Set([
  'setuid',
  'setgid',
  'setreuid',
  'setregid',
  'setresuid',
  'setresgid',
  'unshare',
  'setns',
  'mount',
  'umount2',
  'chroot',
  'pivot_root',
  'ptrace',
]);
const WRITE_SYSCALLS = new Set([
  'creat',
  'mkdir',
  'mkdirat',
  'unlink',
  'unlinkat',
  'rmdir',
  'rename',
  'renameat',
  'renameat2',
  'link',
  'linkat',
  'symlink',
  'symlinkat',
  'chmod',
  'fchmodat',
  'fchmodat2',
  'chown',
  'lchown',
  'fchownat',
  'truncate',
  'mknod',
  'mknodat',
  'utimensat',
  'setxattr',
  'lsetxattr',
  'removexattr',
  'lremovexattr',
]);
const OPEN_SYSCALLS = new Set(['open', 'openat', 'openat2']);
const STAT_SYSCALLS = new Set([
  'stat',
  'lstat',
  'access',
  'faccessat',
  'faccessat2',
  'newfstatat',
  'statx',
]);
const DENIED_ERRNOS = new Set(['EROFS', 'EACCES', 'EPERM']);
const PERSISTENCE_PATHS = [
  /^\/etc\/(cron|crontab|anacrontab|init\.d|rc\d?\.d|rc\.local|profile|bash\.bashrc|systemd|ld\.so\.preload|passwd|shadow|group|sudoers|ssh)/,
  /^\/var\/spool\/cron/,
  /^\/root\//,
  /\/\.(bashrc|bash_profile|profile|ssh|config\/autostart)(\/|$)/,
  /^\/usr\/lib\/systemd/,
];
const ENVIRONMENT_PATHS = [
  /^\/\.dockerenv$/,
  /^\/run\/\.containerenv$/,
  /^\/proc\/1\/(cgroup|sched|environ|mountinfo)$/,
  /^\/sys\/class\/dmi\/id\//,
  /^\/sys\/hypervisor/,
  /^\/proc\/(vz|xen|scsi\/scsi)$/,
];
const CONNECT_ERRNO: Readonly<Record<string, RawConnectionOutcome>> = {
  ECONNREFUSED: 'refused',
  ECONNRESET: 'refused',
  EACCES: 'refused',
  EPERM: 'refused',
  ENETUNREACH: 'unreachable',
  EHOSTUNREACH: 'unreachable',
  EADDRNOTAVAIL: 'unreachable',
  EAFNOSUPPORT: 'unreachable',
  ENETDOWN: 'unreachable',
  EHOSTDOWN: 'unreachable',
  ETIMEDOUT: 'timeout',
};
const SO_ERROR_NUMERIC: Readonly<Record<string, string>> = {
  '0': 'OK',
  '111': 'ECONNREFUSED',
  '104': 'ECONNRESET',
  '101': 'ENETUNREACH',
  '113': 'EHOSTUNREACH',
  '110': 'ETIMEDOUT',
  '99': 'EADDRNOTAVAIL',
  '13': 'EACCES',
};
const OUTCOME_RANK: Readonly<Record<RawConnectionOutcome, number>> = {
  timeout: 0,
  unreachable: 1,
  refused: 2,
  connected: 3,
};

const LINE_PATTERN = /^(\d{1,9})\s+\d{2}:\d{2}:\d{2}\.\d{1,9}\s+(.*)$/;
const RESULT_PATTERN = /\)\s+=\s+(-?\d+|\?|0x[0-9a-fA-F]+)(?:\s+(E[A-Z0-9]+))?/g;
const IMAGE_SAFE = /[^A-Za-z0-9._+-]/g;

interface ProcState {
  seq: number;
  parentPid: number | null;
  image: string;
  argvSha256: string | null;
  exitCode: number | null;
  killedBy: TraceProcess['killedBy'];
  execed: boolean;
}

interface Syscall {
  name: string;
  args: string;
  result: string;
  errno: string | null;
}

/** Splits `name(args) = result [ERRNO (text)]` (the LAST unquoted result marker wins). */
export function parseSyscall(text: string): Syscall | null {
  const nameMatch = /^([a-z_][a-z0-9_]{0,31})\(/.exec(text);
  if (!nameMatch) return null;
  let last: RegExpExecArray | null = null;
  RESULT_PATTERN.lastIndex = 0;
  for (let m = RESULT_PATTERN.exec(text); m; m = RESULT_PATTERN.exec(text)) last = m;
  if (!last) return null;
  return {
    name: nameMatch[1]!,
    args: text.slice(nameMatch[0].length, last.index),
    result: last[1]!,
    errno: last[2] ?? null,
  };
}

/** The first `n` strace-quoted strings of an argument list (unescaped minimally). */
export function quotedStrings(args: string, n: number): string[] {
  const out: string[] = [];
  const pattern = /"((?:[^"\\]|\\.)*)"/g;
  for (let m = pattern.exec(args); m && out.length < n; m = pattern.exec(args)) {
    out.push(m[1]!.replace(/\\"/g, '"').replace(/\\\\/g, '\\'));
  }
  return out;
}

/** A process image basename that satisfies the observation pattern. */
export function imageName(path: string): string {
  const base = path.split('/').filter(Boolean).pop() ?? '';
  const safe = base.replace(IMAGE_SAFE, '_').slice(0, 64);
  return safe.length > 0 ? safe : 'unknown';
}

/** Canonical IP text (IPv4 dotted quad; IPv6 WHATWG form; v4-mapped → IPv4), or null. */
export function canonicalIp(raw: string): string | null {
  const family = isIP(raw);
  if (family === 4) {
    const quad = raw
      .split('.')
      .map((o) => String(Number(o)))
      .join('.');
    return isCanonicalIp(quad) ? quad : null;
  }
  if (family === 6) {
    let host: string;
    try {
      host = new URL(`http://[${raw}]/`).hostname.slice(1, -1);
    } catch {
      return null;
    }
    const mapped = /^::ffff:(\d+\.\d+\.\d+\.\d+)$/.exec(host);
    if (mapped) return canonicalIp(mapped[1]!);
    const hexMapped = /^::ffff:([0-9a-f]{1,4}):([0-9a-f]{1,4})$/.exec(host);
    if (hexMapped) {
      const hi = Number.parseInt(hexMapped[1]!, 16);
      const lo = Number.parseInt(hexMapped[2]!, 16);
      return `${hi >> 8}.${hi & 255}.${lo >> 8}.${lo & 255}`;
    }
    return isCanonicalIp(host) ? host : null;
  }
  return null;
}

export function isLoopback(ip: string): boolean {
  return ip.startsWith('127.') || ip === '::1';
}

/** `{sa_family=AF_INET…}` → address + port, or null for other families. */
export function parseSockaddr(args: string): { ip: string; port: number } | null {
  const port = /sin6?_port=htons\((\d{1,5})\)/.exec(args);
  if (!port) return null;
  let raw: string | undefined;
  if (args.includes('sa_family=AF_INET6')) {
    raw = /inet_pton\(AF_INET6,\s*"([0-9a-fA-F:.]{2,45})"/.exec(args)?.[1];
  } else if (args.includes('sa_family=AF_INET')) {
    raw = /inet_addr\("(\d{1,3}(?:\.\d{1,3}){3})"\)/.exec(args)?.[1];
  }
  if (!raw) return null;
  const ip = canonicalIp(raw);
  const portNumber = Number(port[1]);
  if (!ip || portNumber < 1 || portNumber > 65_535) return null;
  return { ip, port: portNumber };
}

const sha256 = (text: string) => createHash('sha256').update(text, 'utf8').digest('hex');

function isWriteOpen(name: string, args: string): boolean {
  if (!OPEN_SYSCALLS.has(name)) return false;
  return /O_WRONLY|O_RDWR|O_CREAT|O_TRUNC|O_APPEND/.test(args);
}

function resolvePath(path: string, cwd: string): string {
  if (path.startsWith('/')) return path;
  return `${cwd.replace(/\/$/, '')}/${path}`;
}

function insideRoots(path: string, roots: readonly string[]): boolean {
  // Lexical `..` segments are not resolved by the kernel trace; treat them as outside.
  if (path.split('/').includes('..')) return false;
  return roots.some((root) => path === root || path.startsWith(`${root}/`));
}

/** Parses a strace text (bounded by `TRACE_MAX_LINES`). */
export function parseTrace(text: string, context: TraceContext): TraceSummary {
  const roots = context.writableRoots ?? ['/scratch', '/tmp', '/dev/shm'];
  const cwd = context.cwd ?? '/scratch/work';
  const procs = new Map<number, ProcState>();
  const order: number[] = [];
  const tgidOf = new Map<number, number>();
  const pending = new Map<number, string>();
  const socketTypes = new Map<string, 'tcp' | 'udp'>();
  const pendingConnects = new Map<string, number>();
  const connections: TraceConnection[] = [];
  const connectionIndex = new Map<string, number>();
  let connectionAttempts = 0;
  let deniedWrites = 0;
  let persistenceAttempts = 0;
  let privilegeAttempts = 0;
  let environmentChecks = 0;
  let pidsLimitHits = 0;
  let shellSpawns = 0;
  let linesParsed = 0;
  let truncated = false;
  let rootPid: number | null = null;
  const images: string[] = [];

  const tgid = (pid: number) => tgidOf.get(pid) ?? pid;
  const ensureProc = (pid: number, parentPid: number | null): ProcState => {
    let proc = procs.get(pid);
    if (!proc) {
      const parent = parentPid === null ? undefined : procs.get(parentPid);
      proc = {
        seq: order.length,
        parentPid,
        image: parent?.image ?? 'unknown',
        argvSha256: null,
        exitCode: null,
        killedBy: null,
        execed: false,
      };
      procs.set(pid, proc);
      order.push(pid);
    }
    return proc;
  };
  const recordConnection = (connection: TraceConnection) => {
    connectionAttempts += 1;
    const key = `${connection.protocol}|${connection.ip}|${connection.port}`;
    const existing = connectionIndex.get(key);
    if (existing !== undefined) {
      const current = connections[existing]!;
      if (OUTCOME_RANK[connection.outcome] > OUTCOME_RANK[current.outcome]) {
        current.outcome = connection.outcome;
      }
      return existing;
    }
    if (connections.length >= SANDBOX_OBSERVATION_BOUNDS.connections) return -1;
    connections.push(connection);
    connectionIndex.set(key, connections.length - 1);
    return connections.length - 1;
  };

  const lines = text.split('\n');
  for (const rawLine of lines) {
    if (linesParsed >= TRACE_MAX_LINES) {
      truncated = true;
      break;
    }
    if (rawLine.length === 0) continue;
    linesParsed += 1;
    const line = rawLine.length > MAX_LINE_LENGTH ? rawLine.slice(0, MAX_LINE_LENGTH) : rawLine;
    const match = LINE_PATTERN.exec(line);
    if (!match) continue;
    const pid = Number(match[1]);
    let body = match[2]!;
    if (rootPid === null) {
      rootPid = pid;
      ensureProc(pid, null);
    }

    // Exit / kill notices.
    const exited = /^\+\+\+ exited with (-?\d+) \+\+\+$/.exec(body);
    if (exited) {
      const proc = procs.get(tgid(pid));
      if (proc && tgid(pid) === pid) proc.exitCode = Number(exited[1]);
      continue;
    }
    const killed = /^\+\+\+ killed by (SIG[A-Z0-9]+)/.exec(body);
    if (killed) {
      const proc = procs.get(tgid(pid));
      if (proc && tgid(pid) === pid && killed[1] === 'SIGKILL') {
        proc.killedBy = context.oomKilled ? 'memory' : context.timedOut ? 'timeout' : null;
      }
      continue;
    }
    if (body.startsWith('---')) continue;

    // Unfinished / resumed joins.
    const unfinished = body.indexOf(' <unfinished ...>');
    if (unfinished >= 0) {
      pending.set(pid, body.slice(0, unfinished));
      continue;
    }
    const resumed = /^<\.\.\. ([a-z_0-9]+) resumed>(.*)$/.exec(body);
    if (resumed) {
      const head = pending.get(pid);
      pending.delete(pid);
      if (head === undefined || !head.startsWith(`${resumed[1]}(`)) continue;
      body = head + resumed[2]!;
    }

    const call = parseSyscall(body);
    if (!call) continue;
    const owner = tgid(pid);
    const { name, args, result, errno } = call;
    const ok = errno === null && result !== '?' && !result.startsWith('-');

    switch (name) {
      case 'clone':
      case 'clone3':
      case 'fork':
      case 'vfork': {
        if (errno === 'EAGAIN') {
          pidsLimitHits += 1;
          break;
        }
        const child = Number(result);
        if (!ok || !Number.isInteger(child) || child <= 0) break;
        if (/CLONE_THREAD/.test(args)) {
          tgidOf.set(child, owner);
        } else {
          ensureProc(child, owner);
        }
        break;
      }
      case 'execve':
      case 'execveat': {
        const [path] = quotedStrings(args, 1);
        const image = imageName(path ?? '');
        if (PRIVILEGE_TOOLS.has(image)) privilegeAttempts += 1;
        if (!ok) break;
        const proc = ensureProc(owner, null);
        const argv = /\[(.*?)\](?:,\s*0x[0-9a-f]+|,\s*\[)/.exec(args)?.[1] ?? '';
        const wasShell = SHELLS.has(image);
        if (wasShell && owner !== rootPid) shellSpawns += 1;
        proc.image = image;
        proc.argvSha256 = sha256(argv);
        proc.execed = true;
        if (images.length < MAX_IMAGES && !images.includes(image)) images.push(image);
        break;
      }
      case 'socket': {
        if (!ok) break;
        if (!/AF_INET6?\b/.test(args)) break;
        const type = /SOCK_DGRAM/.test(args) ? 'udp' : /SOCK_STREAM/.test(args) ? 'tcp' : null;
        if (type) socketTypes.set(`${owner}:${result}`, type);
        break;
      }
      case 'connect': {
        const fd = /^(\d+),/.exec(args)?.[1];
        const address = parseSockaddr(args);
        if (!fd || !address || isLoopback(address.ip)) break;
        const key = `${owner}:${fd}`;
        const protocol = socketTypes.get(key) ?? 'tcp';
        if (ok) {
          recordConnection({ ...address, protocol, outcome: 'connected' });
        } else if (errno === 'EINPROGRESS' || errno === 'EALREADY' || errno === 'EAGAIN') {
          const index = recordConnection({ ...address, protocol, outcome: 'timeout' });
          if (index >= 0) pendingConnects.set(key, index);
        } else {
          recordConnection({
            ...address,
            protocol,
            outcome: CONNECT_ERRNO[errno ?? ''] ?? 'unreachable',
          });
        }
        break;
      }
      case 'getsockopt': {
        const so = /^(\d+),\s*SOL_SOCKET,\s*SO_ERROR,\s*\[([A-Z0-9]+)\]/.exec(args);
        if (!so) break;
        const key = `${owner}:${so[1]}`;
        const index = pendingConnects.get(key);
        if (index === undefined) break;
        pendingConnects.delete(key);
        const code = SO_ERROR_NUMERIC[so[2]!] ?? so[2]!;
        const outcome: RawConnectionOutcome =
          code === 'OK' || code === '0' ? 'connected' : (CONNECT_ERRNO[code] ?? 'unreachable');
        const current = connections[index];
        if (current && OUTCOME_RANK[outcome] > OUTCOME_RANK[current.outcome]) {
          current.outcome = outcome;
        }
        break;
      }
      case 'sendto':
      case 'sendmsg': {
        const address = parseSockaddr(args);
        if (!address || isLoopback(address.ip)) break;
        const fd = /^(\d+),/.exec(args)?.[1];
        const protocol = (fd && socketTypes.get(`${owner}:${fd}`)) || 'udp';
        recordConnection({
          ...address,
          protocol,
          outcome: ok ? 'timeout' : (CONNECT_ERRNO[errno ?? ''] ?? 'unreachable'),
        });
        break;
      }
      default:
        break;
    }

    if (PRIVILEGE_SYSCALLS.has(name)) privilegeAttempts += 1;

    if (OPEN_SYSCALLS.has(name) || WRITE_SYSCALLS.has(name) || STAT_SYSCALLS.has(name)) {
      const paths = quotedStrings(args, 2).map((p) => resolvePath(p, cwd));
      const normalized = paths.map((p) => posix.normalize(p));
      const writeIntent = WRITE_SYSCALLS.has(name) || isWriteOpen(name, args);
      if (writeIntent) {
        const outside = paths.some((p) => !insideRoots(p, roots));
        if (outside && errno !== null && DENIED_ERRNOS.has(errno)) deniedWrites += 1;
        if (normalized.some((p) => PERSISTENCE_PATHS.some((re) => re.test(p))))
          persistenceAttempts += 1;
      } else if (normalized.some((p) => ENVIRONMENT_PATHS.some((re) => re.test(p)))) {
        environmentChecks += 1;
      }
    }
  }

  const listed = order.slice(0, SANDBOX_OBSERVATION_BOUNDS.processes);
  const seqOf = new Map(order.map((pid, index) => [pid, index] as const));
  const processes: TraceProcess[] = listed
    .map((pid) => procs.get(pid)!)
    .filter((proc) => proc.seq <= SANDBOX_OBSERVATION_BOUNDS.processSeqMax)
    .map((proc) => {
      const parentSeq = proc.parentPid === null ? null : (seqOf.get(proc.parentPid) ?? null);
      return {
        seq: proc.seq,
        parentSeq:
          parentSeq !== null && parentSeq <= SANDBOX_OBSERVATION_BOUNDS.processSeqMax
            ? parentSeq
            : null,
        image: proc.image,
        argvSha256: proc.argvSha256,
        exitCode: proc.exitCode,
        killedBy: proc.killedBy,
      };
    });

  return {
    processes,
    processCount: Math.min(order.length, SANDBOX_OBSERVATION_BOUNDS.counterMax),
    images,
    shellSpawns,
    connections,
    connectionAttempts,
    deniedWrites,
    persistenceAttempts,
    privilegeAttempts,
    environmentChecks,
    pidsLimitHits,
    linesParsed,
    truncated,
  };
}
