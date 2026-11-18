import { readdirSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';

/**
 * The worker ships as CommonJS (`nest build`), the unit tests run the TypeScript sources as ES
 * modules. A local binding named `exports`, `module` or `require` therefore behaves differently in
 * production: `tsc` rewrites references to the module's own exported constants as `exports.X`, and
 * a local `exports` turns them into properties of that local value. Step 8.1 WP6 found exactly this
 * in `components.ts` (`const exports = new ExportBuilder(…)` made `EDISCOVERY_POLL_MS` undefined in
 * the container and the ediscovery loops spun on NaN sleeps), invisible to every source-level test.
 */
const RESTRICTED =
  /\b(?:const|let|var|function|class)\s+(exports|module|require)\b|\(\s*(?:exports|module|require)\s*[,)]/;

function sources(dir: string): string[] {
  return readdirSync(dir, { withFileTypes: true }).flatMap((entry) => {
    const path = join(dir, entry.name);
    if (entry.isDirectory()) return sources(path);
    return entry.name.endsWith('.ts') && !entry.name.endsWith('.test.ts') ? [path] : [];
  });
}

describe('CommonJS module bindings', () => {
  it('no production source declares a local exports, module or require', () => {
    const offenders = sources(__dirname).flatMap((file) =>
      readFileSync(file, 'utf8')
        .split('\n')
        .map((line, i) => ({ file, line: i + 1, text: line }))
        .filter(({ text }) => !text.trimStart().startsWith('//') && RESTRICTED.test(text)),
    );
    expect(offenders).toEqual([]);
  });
});
