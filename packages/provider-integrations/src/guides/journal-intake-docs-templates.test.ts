import { readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';
import type { JournalIntakeKind } from './attestations';
import { exampleJournalIntakeGuideInput, generateJournalIntakeGuide } from './journal-intake-guide';
import { renderJournalIntakeGuideMarkdown } from './markdown';

/**
 * The customer guides of journal intake (step 8.6 D10, WP6): `docs/integrations/journal-intake-
 * microsoft-365.md`, `journal-intake-google-workspace.md` and `journal-intake-on-premises.md`
 * embed the guide the generator renders for the example source of each kind (the on-premises
 * document embeds both on-premises kinds), so the documentation never drifts from what customers
 * download. The pattern of the step 8.2 `docs-templates.test.ts`; regenerate the embedded blocks
 * with `UPDATE_GUIDE_DOCS=1 pnpm --filter @email-gateway/provider-integrations test --
 * journal-intake-docs`.
 */

const DOCS = join(__dirname, '../../../../docs/integrations');
const FILES: ReadonlyArray<[string, readonly JournalIntakeKind[]]> = [
  ['journal-intake-microsoft-365.md', ['microsoft_365_journal']],
  ['journal-intake-google-workspace.md', ['google_workspace_copy']],
  ['journal-intake-on-premises.md', ['exchange_onprem_journal', 'smtp_bcc']],
];
const begin = (kind: JournalIntakeKind) =>
  `<!-- BEGIN GENERATED GUIDE ${kind} (do not edit; see the note above) -->`;
const end = (kind: JournalIntakeKind) => `<!-- END GENERATED GUIDE ${kind} -->`;

/** The rendered example guide with every heading one level down (the document owns the h1). */
export function embeddedJournalIntakeGuide(kind: JournalIntakeKind): string {
  const markdown = renderJournalIntakeGuideMarkdown(
    generateJournalIntakeGuide(exampleJournalIntakeGuideInput(kind)),
  );
  const lines: string[] = [];
  let fenced = false;
  for (const line of markdown.trimEnd().split('\n')) {
    if (line.startsWith('```')) fenced = !fenced;
    lines.push(!fenced && /^#{1,5} /.test(line) ? `#${line}` : line);
  }
  return lines.join('\n');
}

describe.each(FILES)('docs/integrations/%s template', (file, kinds) => {
  it.each(kinds)('embeds exactly the generated example guide of %s', (kind) => {
    const path = join(DOCS, file);
    const doc = readFileSync(path, 'utf8');
    const start = doc.indexOf(begin(kind));
    const stop = doc.indexOf(end(kind));
    expect(start, `${file} has the generated block markers of ${kind}`).toBeGreaterThan(-1);
    expect(stop).toBeGreaterThan(start);
    const expected = `\n<!-- prettier-ignore-start -->\n${embeddedJournalIntakeGuide(kind)}\n<!-- prettier-ignore-end -->\n`;
    const actual = doc.slice(start + begin(kind).length, stop);
    if (process.env.UPDATE_GUIDE_DOCS === '1' && actual !== expected) {
      writeFileSync(
        path,
        `${doc.slice(0, start + begin(kind).length)}${expected}${doc.slice(stop)}`,
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
    expect(doc).toContain('journal.gateway.example.net');
    // The example address is masked in the embedded guide (as for a journal:read holder).
    expect(doc).not.toContain('journal-exampleexampleexampleexamp@');
  });
});
