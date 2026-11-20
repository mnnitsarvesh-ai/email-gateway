import { type JournalIntakeGuide, JOURNAL_INTAKE_KIND_LABELS } from './journal-intake-guide';
import type { SetupGuide, SetupGuideSection, SetupGuideStep } from './setup-guide';

/** Escapes Markdown control characters in plain text (values come from configuration and rows). */
const text = (value: string): string => value.replace(/([\\`*_[\]<>|#])/g, '\\$1');

const fence = (code: string): string => {
  let marker = '```';
  while (code.includes(marker)) marker += '`';
  return marker;
};

function renderStep(step: SetupGuideStep, sectionNumber: number, index: number): string[] {
  const lines: string[] = [
    `<a id="${step.id}"></a>`,
    '',
    `### ${sectionNumber}.${index + 1} ${text(step.title)}`,
    '',
  ];
  for (const p of step.paragraphs) lines.push(text(p), '');
  if (step.values && step.values.length > 0) {
    lines.push('| Item | Value |', '| --- | --- |');
    for (const v of step.values)
      lines.push(`| ${text(v.label)} | \`${v.value.replace(/`/g, "'").replace(/\|/g, '\\|')}\` |`);
    lines.push('');
  }
  for (const command of step.commands ?? []) {
    const marker = fence(command.code);
    lines.push(
      `${marker}${command.language === 'dns' ? 'dns' : command.language}`,
      command.code,
      marker,
      '',
    );
  }
  if (step.warning) lines.push(`> **Warning:** ${text(step.warning)}`, '');
  if (step.attestation) {
    const a = step.attestation;
    lines.push(
      `> **Attestation \`${a.code}\`** (your statement, not a gateway check): ${text(a.statement)}`,
      `> Status: ${a.attested ? `confirmed ${a.attestedAt ?? ''}`.trim() : 'not confirmed yet'}`,
      '',
    );
  }
  return lines;
}

/**
 * The shared renderer of every guide (8.2 setup guides, 8.6 journal intake guides): the given
 * head lines (title, generation line, notice; already Markdown), a contents list and the numbered
 * sections with their steps, values, commands, warnings and attestations.
 */
export function renderGuideMarkdown(
  head: readonly string[],
  sections: readonly SetupGuideSection[],
): string {
  const lines: string[] = [
    ...head,
    '## Contents',
    '',
    ...sections.map((s) => `${s.number}. [${text(s.title)}](#${s.id})`),
    '',
  ];
  for (const section of sections) {
    lines.push(
      `<a id="${section.id}"></a>`,
      '',
      `## ${section.number}. ${text(section.title)}`,
      '',
    );
    for (const p of section.paragraphs) lines.push(text(p), '');
    section.steps.forEach((step, i) => lines.push(...renderStep(step, section.number, i)));
  }
  return `${lines
    .join('\n')
    .replace(/\n{3,}/g, '\n\n')
    .trimEnd()}\n`;
}

/** The Markdown download of a guide (D14, `text/markdown; charset=utf-8`). */
export function renderSetupGuideMarkdown(guide: SetupGuide): string {
  const provider = guide.provider === 'microsoft_365' ? 'Microsoft 365' : 'Google Workspace';
  return renderGuideMarkdown(
    [
      `# ${provider} setup guide: ${text(guide.connection.displayName)}`,
      '',
      `Generated ${guide.generatedAt} (\`${guide.schema}\`).`,
      ...(guide.connection.tenantId
        ? [`Tenant: ${text(guide.connection.tenantName ?? '')} (\`${guide.connection.tenantId}\`).`]
        : []),
      '',
      `> ${text(guide.notice)}`,
      '',
    ],
    guide.sections,
  );
}

/** The Markdown download of a journal intake guide (step 8.6 D10, `text/markdown`). */
export function renderJournalIntakeGuideMarkdown(guide: JournalIntakeGuide): string {
  return renderGuideMarkdown(
    [
      `# Journal intake setup guide: ${text(guide.source.displayName)}`,
      '',
      `Generated ${guide.generatedAt} (\`${guide.schema}\`).`,
      `Source type: ${text(JOURNAL_INTAKE_KIND_LABELS[guide.kind])}.`,
      '',
      `> ${text(guide.notice)}`,
      '',
    ],
    guide.sections,
  );
}

/** `setup-<provider>-<connection-name-slug>.md` (D14). */
export function setupGuideFileName(guide: Pick<SetupGuide, 'provider' | 'connection'>): string {
  const slug =
    guide.connection.displayName
      .normalize('NFKD')
      .toLowerCase()
      .replace(/[^a-z0-9]+/g, '-')
      .replace(/^-+|-+$/g, '')
      .slice(0, 64) || 'connection';
  const provider = guide.provider === 'microsoft_365' ? 'microsoft-365' : 'google-workspace';
  return `setup-${provider}-${slug}.md`;
}

/** `journal-intake-<kind>-<source-name-slug>.md` (step 8.6 D10). */
export function journalIntakeGuideFileName(
  guide: Pick<JournalIntakeGuide, 'kind' | 'source'>,
): string {
  const slug =
    guide.source.displayName
      .normalize('NFKD')
      .toLowerCase()
      .replace(/[^a-z0-9]+/g, '-')
      .replace(/^-+|-+$/g, '')
      .slice(0, 64) || 'source';
  return `journal-intake-${guide.kind.replace(/_/g, '-')}-${slug}.md`;
}
