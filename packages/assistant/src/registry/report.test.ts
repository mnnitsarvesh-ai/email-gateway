import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';
import {
  CAPABILITY_REPORT_OUT,
  generateOutputs,
  readOpenApi,
} from '../../scripts/generate-registry';
import { buildRegistry } from './build';
import { ASSISTANT_PROGRAM_PHASE } from './manifest';
import { NATIVE_TOOLS } from './native';
import { NOT_APPLICABLE_OPERATIONS, OPERATION_TOOLS, REGISTRY_VERSION } from './registry';
import {
  CAPABILITY_REPORT_PREAMBLE,
  CAPABILITY_REPORT_TITLE,
  renderCapabilityReport,
} from './report';

/** Step AI-6 D12: the generated final capability report (brief §16). */

const build = {
  version: REGISTRY_VERSION,
  tools: [...OPERATION_TOOLS],
  notApplicable: [...NOT_APPLICABLE_OPERATIONS],
};

describe('chat capability report (D12)', () => {
  const report = renderCapabilityReport(build);

  it('is deterministic and starts with the fixed preamble', () => {
    expect(renderCapabilityReport(build)).toBe(report);
    expect(report.startsWith(`${CAPABILITY_REPORT_TITLE}\n`)).toBe(true);
    expect(report).toContain(CAPABILITY_REPORT_PREAMBLE.join('\n'));
    expect(report).toContain(`program phase **${ASSISTANT_PROGRAM_PHASE}**`);
    expect(ASSISTANT_PROGRAM_PHASE).toBe('AI-6');
    for (const phrase of [
      'Same permissions as the portal',
      'Writes only after the user confirms them',
      're-authenticate',
      'Critical actions are portal only',
      'No message bodies or attachments',
      'previews, downloads',
      'No credentials, consent or secret-returning routes',
      'Conversations are private',
      '`pseudonymized`',
    ])
      expect(report, phrase).toContain(phrase);
  });

  it('totals match the registry; every module has a section', () => {
    const enabled = [...OPERATION_TOOLS, ...NATIVE_TOOLS].filter((t) => t.enabled);
    const reads = enabled.filter((t) => t.access === 'read').length;
    expect(report).toContain(
      `- Enabled chat tools: ${enabled.length} (read ${reads}, write ${enabled.length - reads}).`,
    );
    expect(report).toContain(
      `- API operations: ${OPERATION_TOOLS.length + NOT_APPLICABLE_OPERATIONS.length}; chat tools ${OPERATION_TOOLS.length} from OpenAPI operations plus ${NATIVE_TOOLS.length} native tools; not applicable ${NOT_APPLICABLE_OPERATIONS.length}.`,
    );
    const modules = new Set([
      ...OPERATION_TOOLS.map((t) => t.module),
      ...NOT_APPLICABLE_OPERATIONS.map((op) => op.module),
    ]);
    for (const module of modules) expect(report, module).toContain(`## Module \`${module}\``);
    const sections = [...report.matchAll(/^## Module `([^`]+)`$/gm)].map((m) => m[1]!);
    expect(sections).toEqual([...sections].sort((a, b) => a.localeCompare(b, 'en')));
  });

  it('lists every critical operation explicitly and the not-applicable reasons per module', () => {
    const critical = NOT_APPLICABLE_OPERATIONS.filter((op) => op.risk === 'critical');
    expect(critical.length).toBeGreaterThan(0);
    const section = report.slice(report.indexOf('## Critical operations (portal only)'));
    for (const op of critical) expect(section, op.operationId).toContain(`\`${op.operationId}\``);
    expect(report).toContain(`- Critical operations, portal only: ${critical.length}.`);
    for (const op of NOT_APPLICABLE_OPERATIONS)
      expect(report, op.operationId).toContain(`\`${op.operationId}\``);
    expect(report).toContain('## Module `reports`');
    expect(report).toMatch(
      /- Native tools: `report_generate` \(read, `read_audited`, `none`\), `report_send_email` \(write, `medium`, `confirm\+impact`\)\./,
    );
  });

  it('is written by the generator and covered by --check (in sync on disk)', async () => {
    const { files } = await generateOutputs();
    expect(Object.keys(files)).toContain(CAPABILITY_REPORT_OUT);
    expect(readFileSync(CAPABILITY_REPORT_OUT, 'utf8')).toBe(files[CAPABILITY_REPORT_OUT]);
    expect(buildRegistry(readOpenApi(), new Map()).version).toMatch(/^[0-9a-f]{16}$/);
  }, 60_000);
});
