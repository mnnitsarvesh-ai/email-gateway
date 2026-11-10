import { mkdirSync, writeFileSync } from 'node:fs';
import { chromium } from 'playwright-core';
import {
  encodeRenderOutput,
  MAX_HEADER_BYTES,
  MAX_SAMPLE_BYTES,
  parseRenderInput,
  RenderInputError,
} from './frame';
import { emptyReport, renderSample, type RenderReport } from './render';

/**
 * Entrypoint of a sandbox BROWSER runner (step 4.6 X6): `node dist/sandbox-render/render-main.js`
 * in a disposable container from `email-gateway/url-browser-worker:local`, started and verified
 * by the sandbox-controller's hardened-container backend. LOCAL/CI ONLY — NOT A VM BOUNDARY.
 *
 * Reads the framed input (header + sample) from stdin, writes the sample under /scratch/in
 * (0400), renders it (`render.ts`) and writes ONE framed report (+ the screenshot) to stdout. A
 * watchdog writes whatever was collected and exits at `wallTimeoutMs − 1 s`. It never reads the
 * url-browser-worker's configuration, broker settings or any secret (the container has none).
 */

const SCRATCH = '/scratch';

function readStdin(limit: number): Promise<Buffer> {
  return new Promise((resolve, reject) => {
    const chunks: Buffer[] = [];
    let size = 0;
    process.stdin.on('data', (chunk: Buffer) => {
      size += chunk.length;
      if (size > limit) {
        process.stdin.destroy();
        reject(new RenderInputError('input_too_large'));
        return;
      }
      chunks.push(chunk);
    });
    process.stdin.on('end', () => resolve(Buffer.concat(chunks)));
    process.stdin.on('error', () => reject(new RenderInputError('stdin_error')));
  });
}

function emit(report: RenderReport, screenshot: Buffer | null): Promise<void> {
  return new Promise((resolve) => {
    process.stdout.write(encodeRenderOutput(report, screenshot), () => resolve());
  });
}

/** Writes the sample read-only under /scratch/in and returns its file:// URL. */
export function writeSampleFile(
  sample: Buffer,
  detectedType: 'html' | 'svg',
  root = SCRATCH,
): string {
  for (const dir of ['in', 'home', 'tmp'])
    mkdirSync(`${root}/${dir}`, { recursive: true, mode: 0o700 });
  const path = `${root}/in/sample.${detectedType}`;
  writeFileSync(path, sample, { mode: 0o400 });
  return `file://${path}`;
}

async function main(): Promise<void> {
  // Playwright's own temporary files (profile, artifacts) go to the scratch tmpfs.
  process.env.TMPDIR = `${SCRATCH}/tmp`;
  let input: ReturnType<typeof parseRenderInput>;
  try {
    input = parseRenderInput(await readStdin(4 + MAX_HEADER_BYTES + MAX_SAMPLE_BYTES));
  } catch (error) {
    const code = error instanceof RenderInputError ? error.code : 'input_invalid';
    await emit({ ...emptyReport(code) }, null);
    return;
  }
  mkdirSync(`${SCRATCH}/tmp`, { recursive: true, mode: 0o700 });
  const started = Date.now();
  let finished = false;
  const watchdog = setTimeout(
    () => {
      if (finished) return;
      finished = true;
      const report = emptyReport('timeout');
      report.durationMs = Date.now() - started;
      void emit(report, null).then(() => process.exit(0));
    },
    Math.max(1_000, input.header.wallTimeoutMs - 1_000),
  );
  const result = await renderSample(input.header, input.sample, {
    launch: (options) => chromium.launch(options),
    writeSample: (sample, type) => writeSampleFile(sample, type),
  });
  if (finished) return;
  finished = true;
  clearTimeout(watchdog);
  await emit(result.report, result.screenshot);
}

if (require.main === module) {
  main()
    .then(() => process.exit(0))
    .catch(async () => {
      await emit(emptyReport('internal'), null);
      process.exit(70);
    });
}
