import { confirmationSpecOf } from '../confirmations/specs';
import { ASSISTANT_PROGRAM_PHASE } from './manifest';
import { API_PREFIX, type RegistryBuild } from './build';
import { NATIVE_TOOLS } from './native';
import { CHECK_COMMAND, GENERATE_COMMAND } from './render';
import {
  TOOL_RISKS,
  type NotApplicableOperation,
  type OperationTool,
  type ToolConfirm,
} from './types';

/**
 * The final chat capability report (step AI-6 D12, brief §16): a second generated document next
 * to the capability matrix, written by `scripts/generate-registry.ts` and covered by `--check`.
 * Every number and list comes from the registry build (OpenAPI operations classified by the
 * manifest) and the native tools, so the report cannot drift from what the executor enforces.
 * Output is unformatted and deterministic; the generator formats it with Prettier.
 */

export const CAPABILITY_REPORT_TITLE = '# Chat capability report';

const CONFIRM_CLASSES: readonly ToolConfirm[] = [
  'none',
  'confirm',
  'confirm+impact',
  'confirm+impact+reauth',
];

/** The fixed preamble: what chat can and cannot do (I1–I27 of the program in plain words). */
export const CAPABILITY_REPORT_PREAMBLE: readonly string[] = [
  '## What chat can and cannot do',
  '',
  '- **Same permissions as the portal.** Every chat tool is one API operation (or one of the native report tools) run as the signed-in user, through the same authentication, permission, tenant-scope, rate-limit and audit pipeline as the portal. The assistant sees only the tools the user may call; a call outside them is refused by the server.',
  '- **Writes only after the user confirms them.** The model can only propose a change: every write shows a confirmation card with its impact and runs only when the user confirms it there. High-risk changes (and changes that weaken security or compliance controls) also need the user to re-authenticate in the card. Nothing is confirmed by typing in chat.',
  '- **Critical actions are portal only.** Operations classified `critical` (for example organization deletion, legal-hold release, record disposal, archive key rotation) are never chat tools; the chat links to the portal page.',
  '- **No message bodies or attachments.** Chat never reads or returns email bodies, attachments, previews, downloads, raw messages or unmasked values (`reveal`); those stay in the portal (ADR-0048/0062). Reports are built from aggregate report APIs only.',
  '- **No credentials, consent or secret-returning routes.** Sign-in, MFA, session, password and API-key ceremonies, OAuth consent, client secrets, certificates and every route that returns a secret are not chat tools. The assistant never asks for, repeats or stores passwords, keys, tokens or one-time codes.',
  '- **Conversations are private.** Only the owner reads a conversation. Administrators with `audit:read` see metadata (turns, tool calls, confirmations, reports, ratings), never message text, titles, transcripts, result cards or report HTML.',
  '- **Data-sharing levels.** `metadata` (default): the model receives tool results minimized and capped, with credential fields dropped and untrusted text marked. `pseudonymized`: in addition, e-mail addresses, IP addresses, domains and person names are replaced by stable per-conversation placeholders before anything reaches the model and mapped back in the answer the user sees.',
  '- **Background reports.** Security reports for windows longer than seven days are generated in the background with a short-lived, read-only token of the user’s own live session; no credential is stored.',
  '',
];

interface ToolCounts {
  enabled: number;
  read: number;
  write: number;
  disabled: number;
  risks: Map<string, number>;
  confirms: Map<string, number>;
  escalationRules: number;
  escalatedTools: number;
}

function countTools(tools: readonly OperationTool[]): ToolCounts {
  const counts: ToolCounts = {
    enabled: 0,
    read: 0,
    write: 0,
    disabled: 0,
    risks: new Map(),
    confirms: new Map(),
    escalationRules: 0,
    escalatedTools: 0,
  };
  for (const tool of tools) {
    if (!tool.enabled) {
      counts.disabled += 1;
      continue;
    }
    counts.enabled += 1;
    if (tool.access === 'read') counts.read += 1;
    else counts.write += 1;
    counts.risks.set(tool.risk, (counts.risks.get(tool.risk) ?? 0) + 1);
    counts.confirms.set(tool.confirm, (counts.confirms.get(tool.confirm) ?? 0) + 1);
    const rules =
      tool.access === 'write' ? (confirmationSpecOf(tool.operationId)?.escalate?.length ?? 0) : 0;
    counts.escalationRules += rules;
    if (rules > 0) counts.escalatedTools += 1;
  }
  return counts;
}

const listOf = (entries: ReadonlyArray<readonly [string, number]>): string =>
  entries.length > 0 ? entries.map(([key, value]) => `${key} ${value}`).join(', ') : 'none';

const riskText = (counts: ToolCounts): string =>
  listOf(
    TOOL_RISKS.filter((risk) => counts.risks.has(risk)).map(
      (risk) => [`\`${risk}\``, counts.risks.get(risk)!] as const,
    ),
  );

const confirmText = (counts: ToolCounts): string =>
  listOf(
    CONFIRM_CLASSES.filter((confirm) => counts.confirms.has(confirm)).map(
      (confirm) => [`\`${confirm}\``, counts.confirms.get(confirm)!] as const,
    ),
  );

const summaryOf = (op: NotApplicableOperation): string =>
  op.summary.replace(/\s+/g, ' ').trim().replace(/\.$/, '');

const opPath = (op: { method: string; pathTemplate: string }): string =>
  `${op.method} \`${op.pathTemplate.startsWith(API_PREFIX) ? op.pathTemplate.slice(API_PREFIX.length) : op.pathTemplate}\``;

const byPath = (
  a: { pathTemplate: string; method: string },
  b: { pathTemplate: string; method: string },
): number =>
  a.pathTemplate.localeCompare(b.pathTemplate, 'en') || a.method.localeCompare(b.method, 'en');

/** `not_applicable` operations grouped by reason (reasons sorted, operations by path). */
function groupByReason(
  ops: readonly NotApplicableOperation[],
): Array<[string, NotApplicableOperation[]]> {
  const groups = new Map<string, NotApplicableOperation[]>();
  for (const op of ops) groups.set(op.reason, [...(groups.get(op.reason) ?? []), op]);
  return [...groups.entries()]
    .sort(([a], [b]) => a.localeCompare(b, 'en'))
    .map(([reason, list]) => [reason, [...list].sort(byPath)]);
}

function toolLines(counts: ToolCounts): string[] {
  return [
    `- Enabled chat tools: ${counts.enabled} (read ${counts.read}, write ${counts.write})${
      counts.disabled > 0 ? `; classified but not enabled: ${counts.disabled}` : ''
    }.`,
    `- By risk: ${riskText(counts)}.`,
    `- Confirmation classes (enabled tools): ${confirmText(counts)}.`,
    `- Conditional risk escalations: ${counts.escalationRules} rule${
      counts.escalationRules === 1 ? '' : 's'
    } on ${counts.escalatedTools} write tool${counts.escalatedTools === 1 ? '' : 's'}.`,
  ];
}

/** The capability report document (`docs/assistant/CHAT_CAPABILITY_REPORT.md`). */
export function renderCapabilityReport(build: RegistryBuild): string {
  const tools = [...build.tools, ...NATIVE_TOOLS];
  const totals = countTools(tools);
  const operations = build.tools.length + build.notApplicable.length;
  const critical = build.notApplicable.filter((op) => op.risk === 'critical');
  const nativeEnabled = NATIVE_TOOLS.filter((tool) => tool.enabled);
  const modules = [
    ...new Set([...tools.map((t) => t.module), ...build.notApplicable.map((op) => op.module)]),
  ].sort((a, b) => a.localeCompare(b, 'en'));

  const lines: string[] = [
    CAPABILITY_REPORT_TITLE,
    '',
    `Generated by \`${GENERATE_COMMAND}\` from \`docs/api/openapi.json\`, the registry manifest (\`packages/assistant/src/registry/manifest.ts\`), the confirmation specs and the native tools. **Do not edit by hand**: \`${CHECK_COMMAND}\` fails when this file is stale. The operation-level detail is in [UI_TO_CHAT_CAPABILITY_MATRIX.md](UI_TO_CHAT_CAPABILITY_MATRIX.md). Design: \`docs/plan/steps/34-ai-chat-hardening-operations.md\` (D12), brief §16.`,
    '',
    `Registry version \`${build.version}\`; program phase **${ASSISTANT_PROGRAM_PHASE}**.`,
    '',
    ...CAPABILITY_REPORT_PREAMBLE,
    '## Totals',
    '',
    `- API operations: ${operations}; chat tools ${build.tools.length} from OpenAPI operations plus ${NATIVE_TOOLS.length} native tools; not applicable ${build.notApplicable.length}.`,
    ...toolLines(totals),
    `- Native assistant tools: ${NATIVE_TOOLS.length} (enabled ${nativeEnabled.length}): ${NATIVE_TOOLS.map((tool) => `\`${tool.name}\``).join(', ')}.`,
    `- Not applicable by reason: ${groupByReason(build.notApplicable)
      .map(([reason, ops]) => `${reason} ${ops.length}`)
      .join('; ')}.`,
    `- Critical operations, portal only: ${critical.length}.`,
    '',
  ];

  for (const module of modules) {
    const moduleTools = tools.filter((tool) => tool.module === module);
    const natives = moduleTools.filter((tool) => tool.native === true);
    const notApplicable = build.notApplicable.filter((op) => op.module === module);
    const criticalOps = notApplicable.filter((op) => op.risk === 'critical').sort(byPath);
    lines.push(`## Module \`${module}\``, '');
    if (moduleTools.length > 0) lines.push(...toolLines(countTools(moduleTools)));
    else lines.push('- Enabled chat tools: none.');
    if (natives.length > 0)
      lines.push(
        `- Native tools: ${natives
          .map((tool) => `\`${tool.name}\` (${tool.access}, \`${tool.risk}\`, \`${tool.confirm}\`)`)
          .join(', ')}.`,
      );
    if (notApplicable.length > 0) {
      lines.push(`- Not applicable: ${notApplicable.length}.`);
      for (const [reason, ops] of groupByReason(notApplicable))
        lines.push(
          `  - ${reason} (${ops.length}): ${ops.map((op) => `\`${op.operationId}\``).join(', ')}.`,
        );
    } else lines.push('- Not applicable: none.');
    if (criticalOps.length > 0) {
      lines.push('- Critical, portal only:');
      for (const op of criticalOps)
        lines.push(
          `  - ${opPath(op)} (\`${op.operationId}\`): ${summaryOf(op)}${
            op.portalRoute ? `; portal page \`${op.portalRoute}\`` : ''
          }.`,
        );
    }
    lines.push('');
  }

  lines.push(
    '## Critical operations (portal only)',
    '',
    ...(critical.length > 0
      ? [...critical]
          .sort((a, b) => a.module.localeCompare(b.module, 'en') || byPath(a, b))
          .map(
            (op) => `- \`${op.module}\`: ${opPath(op)} (\`${op.operationId}\`): ${summaryOf(op)}.`,
          )
      : ['(none)']),
    '',
  );
  return lines.join('\n');
}
