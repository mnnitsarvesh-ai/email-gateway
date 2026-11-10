/**
 * Entry of the static analyzer child (step 4.6 X4). Started by `AnalyzerChildRunner` (one child
 * per task, never reused) with an EMPTY environment, `cwd` = the task scratch directory, the V8
 * heap cap and Node's permission model: reads of this directory and `<scratch>/in` only, writes
 * to `<scratch>/out` only, no child processes, no worker threads, no addons; on Linux under
 * `prlimit` (CPU, address space, no core files). stdin/stdout are closed; stderr is read by the
 * parent only to classify a fatal V8 exit, never logged.
 *
 * It reports its handshake, analyzes exactly one sample (`<scratch>/in/sample`, mode 0400, never
 * executable) and replies with a bounded result. It never evaluates the sample: no `eval`, no
 * `vm`, no JavaScript engine for page scripts, no external tools — only the pure analyzers of
 * this directory.
 */
import { readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { ANALYZER_VERSION } from './analyzers/analysis';
import { analyzeSample } from './analyzers/analyze';
import {
  type ChildMessage,
  isParentMessage,
  type ParentMessage,
  type SelftestMode,
} from './protocol';

/** The largest sample the child reads (the controller's ceiling, 64 MiB). */
const MAX_SAMPLE_BYTES = 67_108_864;

const send = (message: ChildMessage): void => {
  if (process.connected && process.send) process.send(message);
};

const selftestEnabled = process.argv.includes('--selftest');

function attempt(run: () => void): string {
  try {
    run();
    return 'allowed';
  } catch (error) {
    const code = (error as { code?: unknown }).code;
    return code === 'ERR_ACCESS_DENIED' ? 'denied' : 'failed';
  }
}

/** Test probes proving the parent's limits and the child's isolation (unit tests only). */
function selftest(mode: SelftestMode, path: string | undefined): void {
  switch (mode) {
    case 'cpu': {
      let x = 0;
      for (;;) x = (x + 1) % 1_000_003;
    }
    case 'memory': {
      // Native memory outside the V8 heap until the RSS watchdog kills the child.
      const hold: Buffer[] = [];
      const grow = (): void => {
        hold.push(Buffer.alloc(16 * 1024 * 1024, 1));
        setTimeout(grow, 5);
      };
      grow();
      return;
    }
    case 'heap': {
      // JavaScript heap until V8 aborts at --max-old-space-size.
      const hold: string[][] = [];
      for (;;) hold.push(new Array<string>(100_000).fill('x'.repeat(16)));
    }
    case 'hang':
      setInterval(() => undefined, 60_000);
      return;
    case 'crash':
      process.abort();
      return;
    case 'write_outside':
      send({
        op: 'probe',
        mode,
        outcome: attempt(() => writeFileSync(path ?? '/tmp/eg-probe', 'x')),
      });
      return;
    case 'write_output':
      send({
        op: 'probe',
        mode,
        outcome: attempt(() => writeFileSync(join(process.cwd(), 'out', 'probe'), 'x')),
      });
      return;
    case 'spawn':
      send({
        op: 'probe',
        mode,
        outcome: attempt(() => {
          // Loaded only for this probe: the analyzers never import child_process.
          // eslint-disable-next-line @typescript-eslint/no-require-imports
          const cp = require('node:child_process') as {
            execFileSync(file: string, args: string[]): Buffer;
          };
          cp.execFileSync('/bin/echo', ['probe']);
        }),
      });
      return;
    case 'env':
      send({ op: 'probe', mode, outcome: `keys:${String(Object.keys(process.env).length)}` });
      return;
  }
}

let busy = false;

function handle(message: ParentMessage): void {
  if (message.op === 'selftest') {
    if (!selftestEnabled) {
      send({ op: 'result', ok: false, code: 'selftest_disabled' });
      return;
    }
    selftest(message.mode, message.path);
    return;
  }
  if (busy) {
    send({ op: 'result', ok: false, code: 'busy' });
    return;
  }
  busy = true;
  let bytes: Buffer;
  try {
    bytes = readFileSync(message.samplePath);
  } catch (error) {
    const code = (error as { code?: unknown }).code;
    send({
      op: 'result',
      ok: false,
      code: code === 'ERR_ACCESS_DENIED' ? 'sample_denied' : 'sample_unreadable',
    });
    return;
  }
  if (bytes.length > MAX_SAMPLE_BYTES) {
    send({ op: 'result', ok: false, code: 'sample_too_large' });
    return;
  }
  try {
    send({ op: 'result', ok: true, analysis: analyzeSample(bytes, message.detectedType) });
  } catch {
    send({ op: 'result', ok: false, code: 'analyze_error' });
  }
}

process.on('message', (raw: unknown) => {
  if (isParentMessage(raw)) handle(raw);
});
process.on('disconnect', () => process.exit(0));
send({ op: 'ready', version: ANALYZER_VERSION });
