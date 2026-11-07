/**
 * Entry of a DLP extractor child process (step 4.5 D4). Spawned by the generalized 4.2 child
 * pool (`ChildPool` with `extractorDescriptor`) with the inspector's isolation: an empty
 * environment (NODE_ENV, PATH and, in tests only, EG_INSPECTOR_SELFTEST), no stdin or stdout,
 * stderr piped to the worker, the IPC channel, a private 0700 working directory, the V8 heap cap
 * (DLP_EXTRACTOR_HEAP_MB), Node's permission model (no child processes, no file writes, reads of
 * the application and the workspace only) and, on Linux, `prlimit --cpu --core=0`.
 *
 * Per job `{ op: 'extract', bytes, limits, hint }` it walks the attachment with the shared 4.2
 * walker (`inspectBytes` with the no-op YARA engine, so it reaches exactly the entries the
 * attachment inspector reaches within the same platform limits) and extracts every reached
 * entry with `@email-gateway/dlp/extract` (`ExtractionSession`). Entry names stay in this
 * process's memory; the reply addresses entries by index path. No credentials, no network, no
 * process spawning (this module graph never imports `child_process`, `@email-gateway/bec` or an
 * AI SDK; enforced by a unit test), no temporary files; the bytes are dropped after the reply.
 */
import { DLP_EXTRACTOR_VERSION, ExtractionSession, loadPdfjs } from '@email-gateway/dlp/extract';
import { inspectBytes } from '../../attachment/inspector/inspect';
import {
  type ChildMessage,
  isWorkerMessage,
  type SelftestMode,
  type WorkerMessage,
} from '../../attachment/inspector/protocol';
import { NOOP_YARA_ENGINE } from '../../attachment/inspector/yara-engine';
import { isExtractJobLimits, notExtracted, walkSummaryOf } from './extraction';

const send = (message: ChildMessage): void => {
  if (process.connected && process.send) process.send(message);
};

const selftestEnabled = process.env.EG_INSPECTOR_SELFTEST === '1';

/** Test hooks proving the worker's CPU, memory, wall-clock and crash handling (as 4.2 A4). */
function selftest(mode: SelftestMode): void {
  switch (mode) {
    case 'cpu': {
      let x = 0;
      for (;;) x = (x + 1) % 1_000_003;
    }
    case 'memory': {
      const hold: Buffer[] = [];
      const grow = (): void => {
        hold.push(Buffer.alloc(16 * 1024 * 1024, 1));
        setTimeout(grow, 10);
      };
      grow();
      return;
    }
    case 'hang':
      setInterval(() => undefined, 60_000);
      return;
    case 'crash':
      process.abort();
  }
}

async function handle(message: WorkerMessage): Promise<void> {
  if (message.op === 'selftest') {
    if (!selftestEnabled) {
      send({ op: 'result', id: message.id, ok: false, code: 'selftest_disabled' });
      return;
    }
    selftest(message.mode);
    return;
  }
  if (message.op !== 'extract') {
    // An inspection job belongs to the attachment inspector child, never to this one.
    send({ op: 'result', id: message.id, ok: false, code: 'unsupported_op' });
    return;
  }
  if (!isExtractJobLimits(message.limits)) {
    send({ op: 'result', id: message.id, ok: false, code: 'invalid_limits' });
    return;
  }
  const { walk, extract } = message.limits;
  const bytes = Buffer.from(
    message.bytes.buffer,
    message.bytes.byteOffset,
    message.bytes.byteLength,
  );
  const hint = {
    declaredContentType:
      typeof message.hint?.declaredContentType === 'string'
        ? message.hint.declaredContentType.slice(0, 255)
        : null,
    filenameExt:
      typeof message.hint?.filenameExt === 'string'
        ? message.hint.filenameExt.toLowerCase().slice(0, 16)
        : null,
  };
  try {
    const session = new ExtractionSession(hint, extract);
    const inspection = await inspectBytes(bytes, walk, NOOP_YARA_ENGINE, {
      onEntry: session.visitor,
    });
    const extraction = await session.finish(
      bytes,
      inspection.type.detected,
      walkSummaryOf(inspection),
    );
    send({ op: 'result', id: message.id, ok: true, extraction });
  } catch {
    // A document the extractors cannot read is a property of the file: a definite
    // `parse_error` (never clean), not a crash that would be retried.
    send({ op: 'result', id: message.id, ok: true, extraction: notExtracted('parse_error') });
  }
}

async function main(): Promise<void> {
  // pdfjs is loaded before the handshake: a child that cannot load it (permission model, missing
  // files) refuses to start instead of reporting every PDF as a parse error.
  try {
    await loadPdfjs();
  } catch {
    send({ op: 'fatal', code: 'pdfjs_unavailable' });
    process.exit(3);
  }
  let queue = Promise.resolve();
  process.on('message', (raw: unknown) => {
    if (!isWorkerMessage(raw)) return;
    queue = queue.then(() => handle(raw));
  });
  process.on('disconnect', () => process.exit(0));
  send({ op: 'ready', kind: 'dlp-extractor', extractorVersion: DLP_EXTRACTOR_VERSION });
}

void main();
