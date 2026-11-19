import { readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';
import type { IntegrationProvider } from '../types';
import { renderSetupGuideMarkdown } from './markdown';
import { exampleSetupGuideInput, generateSetupGuide } from './setup-guide';

/**
 * The customer documentation templates (step 8.2 D14): `docs/integrations/microsoft-365.md` and
 * `google-workspace.md` embed the guide the generator renders for the example connection
 * (placeholders `example.com`, `gateway.example.net`, `11111111-2222-3333-4444-555555555555`), so
 * the documentation can never drift from what customers download. Regenerate the embedded block
 * with `UPDATE_GUIDE_DOCS=1 pnpm --filter @email-gateway/provider-integrations test -- docs-templates`.
 */

const DOCS = join(__dirname, '../../../../docs/integrations');
const FILES: Record<IntegrationProvider, string> = {
  microsoft_365: 'microsoft-365.md',
  google_workspace: 'google-workspace.md',
};
const BEGIN = '<!-- BEGIN GENERATED GUIDE (do not edit; see the note above) -->';
const END = '<!-- END GENERATED GUIDE -->';

/** The rendered example guide with every heading one level down (the document owns the h1). */
export function embeddedGuide(provider: IntegrationProvider): string {
  const markdown = renderSetupGuideMarkdown(generateSetupGuide(exampleSetupGuideInput(provider)));
  const lines: string[] = [];
  let fenced = false;
  for (const line of markdown.trimEnd().split('\n')) {
    if (line.startsWith('```')) fenced = !fenced;
    lines.push(!fenced && /^#{1,5} /.test(line) ? `#${line}` : line);
  }
  return lines.join('\n');
}

describe.each(Object.entries(FILES) as [IntegrationProvider, string][])(
  'docs/integrations/%s template',
  (provider, file) => {
    it('embeds exactly the generated example guide', () => {
      const path = join(DOCS, file);
      const doc = readFileSync(path, 'utf8');
      const start = doc.indexOf(BEGIN);
      const end = doc.indexOf(END);
      expect(start, `${file} has the generated block markers`).toBeGreaterThan(-1);
      expect(end).toBeGreaterThan(start);
      const expected = `\n<!-- prettier-ignore-start -->\n${embeddedGuide(provider)}\n<!-- prettier-ignore-end -->\n`;
      const actual = doc.slice(start + BEGIN.length, end);
      if (process.env.UPDATE_GUIDE_DOCS === '1' && actual !== expected) {
        writeFileSync(path, `${doc.slice(0, start + BEGIN.length)}${expected}${doc.slice(end)}`);
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
  },
);
