import { readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';
import type { IntegrationProvider } from '../types';
import {
  exampleApiModeGuideInput,
  generateApiModeGuide,
  renderApiModeGuideMarkdown,
} from './api-mode-guide';

/**
 * The customer guides of API mode (step API-1 D12, WP2): `docs/integrations/api-mode-microsoft-
 * 365.md` and `api-mode-google-workspace.md` embed the guide the generator renders for the
 * example connection of each provider, so the documentation never drifts from what customers
 * download. The pattern of `journal-intake-docs-templates.test.ts`; regenerate the embedded blocks
 * with `UPDATE_GUIDE_DOCS=1 pnpm --filter @email-gateway/provider-integrations test --
 * api-mode-docs`.
 */

const DOCS = join(__dirname, '../../../../docs/integrations');
const FILES: ReadonlyArray<[string, IntegrationProvider]> = [
  ['api-mode-microsoft-365.md', 'microsoft_365'],
  ['api-mode-google-workspace.md', 'google_workspace'],
];
const begin = (provider: IntegrationProvider) =>
  `<!-- BEGIN GENERATED GUIDE api-mode ${provider} (do not edit; see the note above) -->`;
const end = (provider: IntegrationProvider) => `<!-- END GENERATED GUIDE api-mode ${provider} -->`;

/** The rendered example guide with every heading one level down (the document owns the h1). */
export function embeddedApiModeGuide(provider: IntegrationProvider): string {
  const markdown = renderApiModeGuideMarkdown(
    generateApiModeGuide(exampleApiModeGuideInput(provider)),
  );
  const lines: string[] = [];
  let fenced = false;
  for (const line of markdown.trimEnd().split('\n')) {
    if (line.startsWith('```')) fenced = !fenced;
    lines.push(!fenced && /^#{1,5} /.test(line) ? `#${line}` : line);
  }
  return lines.join('\n');
}

describe.each(FILES)('docs/integrations/%s template', (file, provider) => {
  it('embeds exactly the generated example guide', () => {
    const path = join(DOCS, file);
    const doc = readFileSync(path, 'utf8');
    const start = doc.indexOf(begin(provider));
    const stop = doc.indexOf(end(provider));
    expect(start, `${file} has the generated block markers`).toBeGreaterThan(-1);
    expect(stop).toBeGreaterThan(start);
    const expected = `\n<!-- prettier-ignore-start -->\n${embeddedApiModeGuide(provider)}\n<!-- prettier-ignore-end -->\n`;
    const actual = doc.slice(start + begin(provider).length, stop);
    if (process.env.UPDATE_GUIDE_DOCS === '1' && actual !== expected) {
      writeFileSync(
        path,
        `${doc.slice(0, start + begin(provider).length)}${expected}${doc.slice(stop)}`,
      );
      return;
    }
    expect(actual).toBe(expected);
  });

  it('uses only documentation placeholders and no secret-shaped value', () => {
    const doc = readFileSync(join(DOCS, file), 'utf8');
    for (const forbidden of [
      'wh' + 'sec_',
      'AK' + 'IA',
      'gh' + 'p_',
      's' + 'k-',
      'eg' + 'k_',
      '-----' + 'BEGIN',
    ]) {
      expect(doc).not.toContain(forbidden);
    }
    expect(doc).toContain('example.com');
    expect(doc).toContain('gateway.example.net');
    expect(doc).toContain('11111111-2222-3333-4444-555555555555');
  });
});
