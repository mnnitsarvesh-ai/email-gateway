/**
 * Entry of an attachment inspector child process (step 4.2 A4). Spawned by `InspectorPool` with
 * an empty environment (NODE_ENV, PATH and, in tests only, EG_INSPECTOR_SELFTEST), no stdin or
 * stdout, stderr piped to the worker, the IPC channel, a private 0700 working directory, the V8
 * heap cap, Node's permission model (no child processes, no file writes, reads of the
 * application and the rules only) and, on Linux, `prlimit --cpu --core=0`.
 *
 * It compiles the YARA bundle once (argv[2] = rules directory, argv[3] = YARA timeout ms),
 * reports its handshake, then inspects one buffer at a time: `{ op: 'inspect' }` →
 * `{ op: 'result', ok, result | code }`. No credentials, no network, no process spawning (this
 * module graph never imports `child_process`, enforced by a unit test), no temporary files; the
 * bytes stay in memory and are dropped after the reply.
 */
import { inspectBytes } from './inspect';
import {
  type ChildMessage,
  isWorkerMessage,
  type SelftestMode,
  type WorkerMessage,
} from './protocol';
import { BundleError } from './bundle';
import { YaraXScanner } from './yara-scanner';

const send = (message: ChildMessage): void => {
  if (process.connected && process.send) process.send(message);
};

const selftestEnabled = process.env.EG_INSPECTOR_SELFTEST === '1';

/** Test hooks proving the worker's CPU, memory, wall-clock and crash handling (A4). */
function selftest(mode: SelftestMode): void {
  switch (mode) {
    case 'cpu': {
      // Spin until killed.
      let x = 0;
      for (;;) x = (x + 1) % 1_000_003;
    }
    case 'memory': {
      // Grow native memory (outside the V8 heap) until killed by the RSS watchdog.
      const hold: Buffer[] = [];
      const grow = (): void => {
        hold.push(Buffer.alloc(16 * 1024 * 1024, 1));
        setTimeout(grow, 10);
      };
      grow();
      return;
    }
    case 'hang':
      // Idle (no CPU) until the wall-clock timeout fires.
      setInterval(() => undefined, 60_000);
      return;
    case 'crash':
      process.abort();
  }
}

async function handle(message: WorkerMessage, scanner: YaraXScanner): Promise<void> {
  if (message.op === 'selftest') {
    if (!selftestEnabled) {
      send({ op: 'result', id: message.id, ok: false, code: 'selftest_disabled' });
      return;
    }
    selftest(message.mode);
    return;
  }
  if (message.op !== 'inspect') {
    // An extraction job belongs to the DLP extractor child (step 4.5 D4), never to this one.
    send({ op: 'result', id: message.id, ok: false, code: 'unsupported_op' });
    return;
  }
  const bytes = Buffer.from(
    message.bytes.buffer,
    message.bytes.byteOffset,
    message.bytes.byteLength,
  );
  try {
    const result = await inspectBytes(bytes, message.limits, scanner);
    send({ op: 'result', id: message.id, ok: true, result });
  } catch {
    send({ op: 'result', id: message.id, ok: false, code: 'inspect_error' });
  }
}

function main(): void {
  const rulesDir = process.argv[2];
  const yaraTimeoutMs = Number(process.argv[3]);
  if (!rulesDir || !Number.isFinite(yaraTimeoutMs)) {
    send({ op: 'fatal', code: 'usage' });
    process.exit(2);
  }
  let scanner: YaraXScanner;
  try {
    scanner = new YaraXScanner(rulesDir, yaraTimeoutMs);
  } catch (error) {
    send({ op: 'fatal', code: error instanceof BundleError ? error.code : 'yara_init_failed' });
    process.exit(3);
  }
  // One job at a time: the pool never sends a second job before the reply.
  let queue = Promise.resolve();
  process.on('message', (raw: unknown) => {
    if (!isWorkerMessage(raw)) return;
    queue = queue.then(() => handle(raw, scanner));
  });
  process.on('disconnect', () => process.exit(0));
  send({
    op: 'ready',
    yaraXVersion: scanner.yaraXVersion,
    bundleId: scanner.bundleId,
    ruleCount: scanner.ruleCount,
  });
}

main();
