#!/usr/bin/env node
// Sandbox runner bootstrap (step 4.6 X6, docs/plan/steps/14-sandbox.md; ADR-0039).
//
// LOCAL/CI ONLY — the hardened-container runner is NOT A VM BOUNDARY. It shares the Docker VM's
// kernel; it exists to exercise the sandbox orchestration with synthetic benign probes and the
// EICAR test string only. Production never executes unknown files (threat model §8).
//
// The trusted entrypoint of `email-gateway/sandbox-runner:local` (user 65532, read-only root,
// tmpfs /scratch and /tmp, no capabilities, no-new-privileges, seccomp, the internal
// `sandbox-detonation` network whose only peer is the recording sinkhole). Protocol (the
// controller's `src/runner/runner-protocol.ts` is the authoritative description):
//
//   stdin   u32be headerLength | header JSON | sample bytes        (then EOF)
//           header = { v: 1, taskId, profile: 'execute', detectedType, wallTimeoutMs,
//                      maxArtifacts, maxArtifactBytes, maxTotalArtifactBytes, sampleSize }
//   stdout  "EGSB" u8(1) | frames: u8 type | u32be length | payload  ... | 0xff 0 0 0 0
//           0x01 report JSON, 0x02 file (u16be metaLength | meta JSON | bytes), 0x03 trace,
//           0x04 sample stdout, 0x05 sample stderr
//
// The sample runs as `sh` (script_shell) or `node` (script_js) under
// `strace -f -q -tt -s 256 -e trace=<process,network,%file,…> -o /tmp/eg/trace` with an EMPTY
// environment (PATH only), cwd /scratch/work, in its own process group, with an inner timeout of
// `wallTimeoutMs - 2 s` after which the group and every other process of the container are
// SIGKILLed. Afterwards it lists the files the sample left under /scratch (hashes, sizes, the
// first bytes as a type hint — never names), and writes ONE framed report. Everything this
// script emits is untrusted evidence for the controller (the sample runs with the same uid and
// can tamper with it); the controller parses it with strict bounded schemas.
//
// `--self-test` reports the runner's own restrictions (uid, capabilities, no_new_privs, seccomp
// mode, read-only root, writable /scratch, routes, resolver, Docker socket, environment, AppArmor
// label, DNS answer for a probe name) as one framed report; the controller judges them.
import { spawn } from 'node:child_process';
import { createHash } from 'node:crypto';
import { lookup } from 'node:dns/promises';
import fs from 'node:fs';
import path from 'node:path';

const MAGIC = Buffer.from('EGSB\u0001', 'latin1');
export const FRAME = Object.freeze({
  report: 0x01,
  file: 0x02,
  trace: 0x03,
  stdout: 0x04,
  stderr: 0x05,
  screenshot: 0x06,
  end: 0xff,
});
const MAX_HEADER_BYTES = 64 * 1024;
const MAX_SAMPLE_BYTES = 64 * 1024 * 1024;
const MAX_TRACE_BYTES = 2 * 1024 * 1024;
const MAX_STREAM_BYTES = 64 * 1024;
const MAX_LISTED_FILES = 32;
const MAX_WALK_ENTRIES = 4096;
const HEAD_BYTES = 16;
const SCRATCH = '/scratch';
const IN_DIR = `${SCRATCH}/in`;
const WORK_DIR = `${SCRATCH}/work`;
const TRACE_DIR = '/tmp/eg';
const TRACE_FILE = `${TRACE_DIR}/trace`;
const SAMPLE_PATH = `${IN_DIR}/sample`;
const SAMPLE_PATH_ENV = { PATH: '/usr/local/bin:/usr/bin:/bin' };
const TRACE_SET =
  'trace=process,network,%file,setuid,setgid,setreuid,setregid,setresuid,setresgid,unshare,setns,mount,umount2,chroot,pivot_root,ptrace';

// ---------------------------------------------------------------------------------------------
// Framing (exported for the unit test)
// ---------------------------------------------------------------------------------------------

export function frame(type, payload) {
  const head = Buffer.alloc(5);
  head.writeUInt8(type, 0);
  head.writeUInt32BE(payload.length, 1);
  return Buffer.concat([head, payload]);
}

export function fileFrame(meta, bytes) {
  const metaBytes = Buffer.from(JSON.stringify(meta), 'utf8');
  const len = Buffer.alloc(2);
  len.writeUInt16BE(metaBytes.length, 0);
  return frame(FRAME.file, Buffer.concat([len, metaBytes, bytes]));
}

/** Parses `u32be length | header JSON | sample` (bounded); throws on anything malformed. */
export function parseInput(buffer) {
  if (buffer.length < 4) throw new Error('input_truncated');
  const headerLength = buffer.readUInt32BE(0);
  if (headerLength < 2 || headerLength > MAX_HEADER_BYTES) throw new Error('header_length');
  if (buffer.length < 4 + headerLength) throw new Error('input_truncated');
  const header = JSON.parse(buffer.subarray(4, 4 + headerLength).toString('utf8'));
  if (header === null || typeof header !== 'object' || header.v !== 1) {
    throw new Error('header_version');
  }
  const int = (value, min, max) => Number.isInteger(value) && value >= min && value <= max;
  if (!int(header.wallTimeoutMs, 1_000, 600_000)) throw new Error('header_wall');
  if (!int(header.maxArtifacts, 0, 16)) throw new Error('header_artifacts');
  if (!int(header.maxArtifactBytes, 1, 8_388_608)) throw new Error('header_artifact_bytes');
  if (!int(header.maxTotalArtifactBytes, 1, 33_554_432)) throw new Error('header_total_bytes');
  if (!int(header.sampleSize, 0, MAX_SAMPLE_BYTES)) throw new Error('header_sample_size');
  if (typeof header.detectedType !== 'string' || !/^[a-z0-9_]{1,32}$/.test(header.detectedType)) {
    throw new Error('header_type');
  }
  const sample = buffer.subarray(4 + headerLength);
  if (sample.length !== header.sampleSize) throw new Error('sample_size_mismatch');
  return { header, sample };
}

/** The interpreter for a detected type, or null (the controller only sends these two). */
export function interpreterFor(detectedType) {
  if (detectedType === 'script_shell') return ['/bin/sh', SAMPLE_PATH];
  if (detectedType === 'script_js') return ['/usr/local/bin/node', SAMPLE_PATH];
  return null;
}

// ---------------------------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------------------------

function readStdin(limit) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    let size = 0;
    process.stdin.on('data', (chunk) => {
      size += chunk.length;
      if (size > limit) {
        reject(new Error('input_too_large'));
        process.stdin.destroy();
        return;
      }
      chunks.push(chunk);
    });
    process.stdin.on('end', () => resolve(Buffer.concat(chunks)));
    process.stdin.on('error', reject);
  });
}

function writeOut(buffers) {
  return new Promise((resolve) => {
    const data = Buffer.concat([MAGIC, ...buffers, frame(FRAME.end, Buffer.alloc(0))]);
    process.stdout.write(data, () => resolve());
  });
}

const sha256 = (data) => createHash('sha256').update(data).digest('hex');

function readCgroup(name) {
  try {
    return fs.readFileSync(`/sys/fs/cgroup/${name}`, 'utf8');
  } catch {
    return null;
  }
}

function cgroupStats() {
  const cpu = readCgroup('cpu.stat') ?? '';
  const events = readCgroup('memory.events') ?? '';
  const num = (text, key) => {
    const match = new RegExp(`^${key} (\\d+)$`, 'm').exec(text);
    return match ? Number(match[1]) : null;
  };
  return {
    cpuUsageUsec: num(cpu, 'usage_usec'),
    nrThrottled: num(cpu, 'nr_throttled'),
    throttledUsec: num(cpu, 'throttled_usec'),
    oomKill: num(events, 'oom_kill'),
    cpuMax: (readCgroup('cpu.max') ?? '').trim().slice(0, 64) || null,
    pidsMax: (readCgroup('pids.max') ?? '').trim().slice(0, 32) || null,
    memoryMax: (readCgroup('memory.max') ?? '').trim().slice(0, 32) || null,
  };
}

/** Every pid of the container except pid 1 (the init) and this process. */
function otherPids() {
  const pids = [];
  try {
    for (const entry of fs.readdirSync('/proc')) {
      if (!/^\d+$/.test(entry)) continue;
      const pid = Number(entry);
      if (pid !== 1 && pid !== process.pid) pids.push(pid);
    }
  } catch {
    // /proc unreadable: nothing more to kill.
  }
  return pids;
}

function killEverything(groupLeader) {
  try {
    process.kill(-groupLeader, 'SIGKILL');
  } catch {
    // Group already gone.
  }
  // A sample can leave its process group (setsid); kill every other process of the container.
  for (let round = 0; round < 3; round += 1) {
    const pids = otherPids();
    if (pids.length === 0) return;
    for (const pid of pids) {
      try {
        process.kill(pid, 'SIGKILL');
      } catch {
        // Gone or not ours.
      }
    }
  }
}

function collectBounded(stream, limit) {
  const state = { chunks: [], kept: 0, total: 0 };
  stream.on('data', (chunk) => {
    state.total += chunk.length;
    if (state.kept < limit) {
      const part = chunk.subarray(0, limit - state.kept);
      state.chunks.push(part);
      state.kept += part.length;
    }
  });
  return state;
}

function readHead(file, limit) {
  let fd;
  try {
    fd = fs.openSync(file, fs.constants.O_RDONLY | fs.constants.O_NOFOLLOW);
    const buffer = Buffer.alloc(limit);
    const read = fs.readSync(fd, buffer, 0, limit, 0);
    return buffer.subarray(0, read);
  } catch {
    return Buffer.alloc(0);
  } finally {
    if (fd !== undefined) fs.closeSync(fd);
  }
}

function hashFile(file) {
  const hash = createHash('sha256');
  let fd;
  try {
    fd = fs.openSync(file, fs.constants.O_RDONLY | fs.constants.O_NOFOLLOW);
    const buffer = Buffer.alloc(64 * 1024);
    for (;;) {
      const read = fs.readSync(fd, buffer, 0, buffer.length, null);
      if (read === 0) break;
      hash.update(buffer.subarray(0, read));
    }
    return hash.digest('hex');
  } catch {
    return null;
  } finally {
    if (fd !== undefined) fs.closeSync(fd);
  }
}

/** Regular files under /scratch except the sample itself (bounded walk; no symlinks followed). */
export function listDropped(root = SCRATCH, exclude = new Set([SAMPLE_PATH])) {
  const files = [];
  let entries = 0;
  let total = 0;
  const walk = (dir, depth) => {
    if (depth > 16) return;
    let names;
    try {
      names = fs.readdirSync(dir);
    } catch {
      return;
    }
    names.sort();
    for (const name of names) {
      entries += 1;
      if (entries > MAX_WALK_ENTRIES) return;
      const full = path.join(dir, name);
      let stat;
      try {
        stat = fs.lstatSync(full);
      } catch {
        continue;
      }
      if (stat.isDirectory()) walk(full, depth + 1);
      else if (stat.isFile() && !exclude.has(full)) {
        total += 1;
        if (files.length < MAX_LISTED_FILES) {
          files.push({ path: full, size: stat.size, executable: (stat.mode & 0o111) !== 0 });
        }
      }
    }
  };
  walk(root, 0);
  return { files, total, walkTruncated: entries > MAX_WALK_ENTRIES };
}

function scratchFull() {
  try {
    const stat = fs.statfsSync(SCRATCH);
    return stat.bavail * stat.bsize < 64 * 1024;
  } catch {
    return false;
  }
}

function readTrace() {
  try {
    const size = fs.statSync(TRACE_FILE).size;
    const fd = fs.openSync(TRACE_FILE, 'r');
    try {
      const length = Math.min(size, MAX_TRACE_BYTES);
      const buffer = Buffer.alloc(length);
      const read = fs.readSync(fd, buffer, 0, length, 0);
      return { bytes: buffer.subarray(0, read), total: size };
    } finally {
      fs.closeSync(fd);
    }
  } catch {
    return { bytes: Buffer.alloc(0), total: 0 };
  }
}

// ---------------------------------------------------------------------------------------------
// Execute mode
// ---------------------------------------------------------------------------------------------

async function execute() {
  const started = Date.now();
  let input;
  try {
    input = parseInput(await readStdin(4 + MAX_HEADER_BYTES + MAX_SAMPLE_BYTES));
  } catch (error) {
    const report = { v: 1, mode: 'execute', inputError: String(error.message).slice(0, 64) };
    await writeOut([frame(FRAME.report, Buffer.from(JSON.stringify(report)))]);
    return;
  }
  const { header, sample } = input;
  const command = interpreterFor(header.detectedType);
  if (!command) {
    const report = { v: 1, mode: 'execute', inputError: 'type_not_supported' };
    await writeOut([frame(FRAME.report, Buffer.from(JSON.stringify(report)))]);
    return;
  }

  fs.mkdirSync(IN_DIR, { recursive: true, mode: 0o700 });
  fs.mkdirSync(WORK_DIR, { recursive: true, mode: 0o700 });
  fs.mkdirSync(TRACE_DIR, { recursive: true, mode: 0o700 });
  fs.writeFileSync(SAMPLE_PATH, sample, { mode: 0o500 });
  fs.chmodSync(SAMPLE_PATH, 0o500);

  const before = cgroupStats();
  const innerTimeoutMs = Math.max(1_000, header.wallTimeoutMs - 2_000);
  const child = spawn(
    '/usr/bin/strace',
    ['-f', '-q', '-tt', '-s', '256', '-e', TRACE_SET, '-o', TRACE_FILE, '--', ...command],
    { cwd: WORK_DIR, env: SAMPLE_PATH_ENV, detached: true, stdio: ['ignore', 'pipe', 'pipe'] },
  );
  const out = collectBounded(child.stdout, MAX_STREAM_BYTES);
  const err = collectBounded(child.stderr, MAX_STREAM_BYTES);
  let timedOut = false;
  let spawnError = null;
  const timer = setTimeout(() => {
    timedOut = true;
    killEverything(child.pid);
  }, innerTimeoutMs);
  const exit = await new Promise((resolve) => {
    child.on('error', (error) => {
      spawnError = String(error.code ?? 'spawn_failed').slice(0, 32);
      resolve({ code: null, signal: null });
    });
    child.on('close', (code, signal) => resolve({ code, signal }));
  });
  clearTimeout(timer);
  // Anything the sample left running (daemonized, setsid) dies before the scratch is listed.
  killEverything(child.pid ?? 0);
  const after = cgroupStats();

  const dropped = listDropped();
  const full = scratchFull();
  const trace = readTrace();
  const buffers = [];
  let artifactCount = 0;
  let artifactBytes = 0;
  let filesOmitted = 0;
  const files = [];
  dropped.files.forEach((file, seq) => {
    const head = readHead(file.path, HEAD_BYTES);
    const digest = hashFile(file.path);
    if (digest === null) return;
    files.push({
      seq,
      pathSha256: sha256(Buffer.from(file.path, 'utf8')),
      size: file.size,
      sha256: digest,
      head: head.toString('base64'),
      executable: file.executable,
    });
    const fits =
      artifactCount < header.maxArtifacts - 1 && // one slot is kept for the process log
      file.size <= header.maxArtifactBytes &&
      artifactBytes + file.size <= header.maxTotalArtifactBytes;
    if (!fits) {
      filesOmitted += 1;
      return;
    }
    let bytes;
    try {
      bytes = fs.readFileSync(file.path);
    } catch {
      filesOmitted += 1;
      return;
    }
    artifactCount += 1;
    artifactBytes += bytes.length;
    buffers.push(fileFrame({ seq }, bytes));
  });

  const report = {
    v: 1,
    mode: 'execute',
    inputError: null,
    spawnError,
    exit: { code: exit.code, signal: exit.signal },
    timedOut,
    innerTimeoutMs,
    durationMs: Date.now() - started,
    stdoutBytes: out.total,
    stderrBytes: err.total,
    traceBytes: trace.total,
    traceTruncated: trace.total > trace.bytes.length,
    scratchFull: full,
    files,
    filesTotal: dropped.total,
    filesOmitted: filesOmitted + Math.max(0, dropped.total - dropped.files.length),
    cgroup: { before, after },
  };
  await writeOut([
    frame(FRAME.report, Buffer.from(JSON.stringify(report), 'utf8')),
    frame(FRAME.trace, trace.bytes),
    frame(FRAME.stdout, Buffer.concat(out.chunks)),
    frame(FRAME.stderr, Buffer.concat(err.chunks)),
    ...buffers,
  ]);
}

// ---------------------------------------------------------------------------------------------
// Self-test mode
// ---------------------------------------------------------------------------------------------

function statusField(name) {
  try {
    const match = new RegExp(`^${name}:\\s*(\\S+)`, 'm').exec(
      fs.readFileSync('/proc/self/status', 'utf8'),
    );
    return match ? match[1] : null;
  } catch {
    return null;
  }
}

function canWrite(file) {
  try {
    fs.writeFileSync(file, 'x');
    fs.unlinkSync(file);
    return true;
  } catch (error) {
    return String(error.code ?? 'error');
  }
}

/** /proc/net/route as { iface, destination, gateway, mask } (dotted quads). */
function routes() {
  const quad = (hex) =>
    [0, 1, 2, 3].map((i) => parseInt(hex.slice(6 - i * 2, 8 - i * 2), 16)).join('.');
  try {
    return fs
      .readFileSync('/proc/net/route', 'utf8')
      .split('\n')
      .slice(1)
      .map((line) => line.trim().split(/\s+/))
      .filter((cols) => cols.length >= 8)
      .slice(0, 16)
      .map((cols) => ({
        iface: cols[0].slice(0, 16),
        destination: quad(cols[1]),
        gateway: quad(cols[2]),
        mask: quad(cols[7]),
      }));
  } catch {
    return [];
  }
}

function resolver() {
  let text = '';
  try {
    text = fs.readFileSync('/etc/resolv.conf', 'utf8').slice(0, 4096);
  } catch {
    // Missing resolver configuration is reported as empty.
  }
  const nameservers = [...text.matchAll(/^nameserver\s+(\S+)/gm)].map((m) => m[1]).slice(0, 8);
  const ext = /^#\s*ExtServers:\s*\[([^\]]*)\]/m.exec(text);
  const extServers = ext
    ? ext[1]
        .split(/[\s,]+/)
        .map((s) => s.replace(/^host\(|\)$/g, ''))
        .filter(Boolean)
        .slice(0, 8)
    : [];
  return { nameservers, extServers };
}

async function selfTest() {
  // The controller closes stdin immediately; drain it so the attach completes.
  process.stdin.resume();
  const apparmor = (() => {
    try {
      return fs.readFileSync('/proc/self/attr/current', 'utf8').trim().slice(0, 64);
    } catch {
      return null;
    }
  })();
  let dnsAnswer = null;
  try {
    const answer = await Promise.race([
      lookup('eg-self-test.sandbox.invalid', { family: 4 }),
      new Promise((_, reject) => setTimeout(() => reject(new Error('timeout')), 5_000)),
    ]);
    dnsAnswer = answer.address;
  } catch (error) {
    dnsAnswer = `error:${String(error.code ?? error.message).slice(0, 24)}`;
  }
  const scratchProbe = `${SCRATCH}/.eg-self-test`;
  const report = {
    v: 1,
    mode: 'self-test',
    uid: process.getuid(),
    gid: process.getgid(),
    capEff: statusField('CapEff'),
    capPrm: statusField('CapPrm'),
    capBnd: statusField('CapBnd'),
    noNewPrivs: statusField('NoNewPrivs'),
    seccomp: statusField('Seccomp'),
    rootWrite: canWrite('/.eg-self-test'),
    etcWrite: canWrite('/etc/.eg-self-test'),
    scratchWrite: canWrite(scratchProbe),
    routes: routes(),
    resolver: resolver(),
    dnsAnswer,
    dockerSocket: ['/var/run/docker.sock', '/run/docker.sock'].some((p) => fs.existsSync(p)),
    envKeys: Object.keys(process.env).sort().slice(0, 32),
    apparmor,
    cgroup: cgroupStats(),
  };
  await writeOut([frame(FRAME.report, Buffer.from(JSON.stringify(report), 'utf8'))]);
}

// ---------------------------------------------------------------------------------------------

const isMain =
  process.argv[1] && path.resolve(process.argv[1]) === new URL(import.meta.url).pathname;
if (isMain) {
  const run = process.argv.includes('--self-test') ? selfTest : execute;
  run()
    .then(() => process.exit(0))
    .catch(async (error) => {
      const report = {
        v: 1,
        mode: 'error',
        inputError: String(error?.code ?? 'internal').slice(0, 32),
      };
      await writeOut([frame(FRAME.report, Buffer.from(JSON.stringify(report)))]);
      process.exit(70);
    });
}
