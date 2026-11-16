import { readFileSync } from 'node:fs';
import { join } from 'node:path';

/** Documents shared by the builder tests (synthetic; ids are fixed test UUIDs). */

/** The brief's example (design B5): outbound confidential data is quarantined and alerted. */
export const BRIEF_EXAMPLE = {
  dslVersion: 'policy-dsl/1',
  direction: 'outbound',
  priority: 10,
  rules: [
    {
      id: 'quarantine-confidential',
      priority: 10,
      description: 'Hold confidential data leaving the organization',
      when: {
        all: [{ field: 'dlp.categories', op: 'contains_any', value: ['confidential'] }],
      },
      actions: [{ type: 'QUARANTINE' }, { type: 'ALERT', severity: 'warning' }],
    },
  ],
};

/** The exact text of design B5 for the brief's example. */
export const BRIEF_EXAMPLE_TEXT = [
  'Rule quarantine-confidential (priority 10): Hold confidential data leaving the organization',
  'IF:',
  '  Email direction is Outbound',
  '  AND DLP data categories contain any of Confidential',
  'THEN:',
  '  Quarantine',
  '  AND Alert administrators (severity: warning)',
].join('\n');

/** Every ```json block of docs/architecture/policy-dsl.md that is a policy (has `dslVersion`). */
export function docsPolicyBlocks(): Array<{ index: number; doc: Record<string, unknown> }> {
  const text = readFileSync(
    join(__dirname, '../../../../../../../docs/architecture/policy-dsl.md'),
    'utf8',
  );
  return [...text.matchAll(/```json\n([\s\S]*?)```/g)]
    .map((match, index) => ({ index, doc: JSON.parse(match[1]!) as unknown }))
    .filter(
      (block): block is { index: number; doc: Record<string, unknown> } =>
        typeof block.doc === 'object' &&
        block.doc !== null &&
        !Array.isArray(block.doc) &&
        'dslVersion' in block.doc,
    );
}
