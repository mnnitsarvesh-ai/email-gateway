import { REPORT_RANGES, REPORT_SECTIONS } from '../reports/types';
import type { OperationTool } from './types';

/**
 * Native assistant tools (step AI-R, design `docs/plan/steps/31-ai-chat-reports.md` D1,
 * ADR-0095): registry records that are not OpenAPI operations. The api executes them with its own
 * services (a fixed composition of loopback reads for `report_generate`; a confirmed delivery for
 * `report_send_email`), never through the loopback: their path templates start with `native:`,
 * which the loopback client refuses. Their operation ids `AssistantNative_<camel>` never occur in
 * `docs/api/openapi.json` (registry check). They are hand-written here, next to the generated
 * `OPERATION_TOOLS`, and included in the capability matrix and the `REGISTRY_VERSION` hash.
 */

export const NATIVE_PATH_PREFIX = 'native:';
export const NATIVE_OPERATION_ID = /^AssistantNative_[A-Za-z]+$/;

export const REPORT_GENERATE_TESTED_BY = 'apps/api/integration/assistant-reports.test.ts';
export const REPORT_SEND_EMAIL_TESTED_BY = 'apps/api/integration/assistant-report-emails.test.ts';

/** A ref to the report row of an earlier `report_generate` call (`@r<seq>.1`). */
export const REPORT_REF_PATTERN = '^@r\\d{1,9}\\.\\d{1,5}$';

/** Recipient address limit (RFC 5321 path length less the angle brackets). */
export const RECIPIENT_MAX_LENGTH = 254;

const REPORT_REQUIREMENT = { mode: 'all', permissions: ['report:read'] } as const;

export const REPORT_GENERATE: OperationTool = {
  name: 'report_generate',
  operationId: 'AssistantNative_reportGenerate',
  method: 'POST',
  pathTemplate: `${NATIVE_PATH_PREFIX}report_generate`,
  native: true,
  module: 'reports',
  summary: 'Generate a security report (HTML dashboard) for a period',
  description:
    'Builds a dashboard-style HTML security report from the report APIs (traffic, threats, domains, delivery, processing, URL clicks, quarantine, ATO) for the last 24 hours, 7 days (default), 30 days or a UTC range. Windows longer than 7 days are generated in the background. It appears in the chat.',
  inputSchema: {
    type: 'object',
    properties: {
      range: {
        type: 'string',
        enum: [...REPORT_RANGES],
        description: 'Period ending now (default 7d); ignored when from and to are given',
      },
      from: {
        type: 'string',
        format: 'date-time',
        description: 'Inclusive start of an explicit window (ISO 8601; together with to)',
      },
      to: {
        type: 'string',
        format: 'date-time',
        description: 'Exclusive end of an explicit window (ISO 8601; together with from)',
      },
      sections: {
        type: 'array',
        items: { type: 'string', enum: [...REPORT_SECTIONS] },
        uniqueItems: true,
        minItems: 1,
        maxItems: REPORT_SECTIONS.length,
        description: 'Sections to include (default all)',
      },
    },
    dependencies: { from: ['to'], to: ['from'] },
    additionalProperties: false,
  },
  pathParams: [],
  queryParams: [],
  hasBody: false,
  requirement: { ...REPORT_REQUIREMENT, permissions: [...REPORT_REQUIREMENT.permissions] },
  platformOnly: false,
  idempotency: null,
  rateClass: null,
  cursor: null,
  access: 'read',
  risk: 'read_audited',
  confirm: 'none',
  phase: 'AI-R',
  enabled: true,
  status: 'IMPLEMENTED',
  portalRoute: null,
  portalPages: [],
  display: { title: 'Generate security report', resourceType: 'assistant_report' },
  untrustedFields: [],
  bind: {},
  redactParams: [],
  limitations: null,
  testedBy: REPORT_GENERATE_TESTED_BY,
};

export const REPORT_SEND_EMAIL: OperationTool = {
  name: 'report_send_email',
  operationId: 'AssistantNative_reportSendEmail',
  method: 'POST',
  pathTemplate: `${NATIVE_PATH_PREFIX}report_send_email`,
  native: true,
  module: 'reports',
  summary: 'Email a generated security report',
  description:
    'Emails a report generated in this conversation as HTML (body and attachment) to the user, an active user of the organization or an address in one of its verified domains. Defaults: the latest report of this conversation and the user’s own address. The user confirms it in a card.',
  inputSchema: {
    type: 'object',
    properties: {
      reportId: {
        anyOf: [
          { type: 'string', format: 'uuid' },
          { type: 'string', pattern: REPORT_REF_PATTERN },
        ],
        description: 'The report id or its ref (@r<n>.1); default the latest report of this chat',
      },
      to: {
        type: 'string',
        format: 'email',
        maxLength: RECIPIENT_MAX_LENGTH,
        pattern: '^[!-~]+$',
        description: 'One email address without a display name; default your own address',
      },
    },
    additionalProperties: false,
  },
  pathParams: [],
  queryParams: [],
  hasBody: false,
  requirement: { ...REPORT_REQUIREMENT, permissions: [...REPORT_REQUIREMENT.permissions] },
  platformOnly: false,
  idempotency: null,
  rateClass: null,
  cursor: null,
  access: 'write',
  risk: 'medium',
  confirm: 'confirm+impact',
  phase: 'AI-R',
  enabled: true,
  status: 'IMPLEMENTED',
  portalRoute: '/assistant',
  portalPages: [],
  display: { title: 'Email security report', resourceType: 'assistant_report_delivery' },
  untrustedFields: [],
  bind: {},
  redactParams: [],
  limitations: null,
  testedBy: REPORT_SEND_EMAIL_TESTED_BY,
};

/** The native tools of the program (step AI-R: exactly two). */
export const NATIVE_TOOLS: readonly OperationTool[] = [REPORT_GENERATE, REPORT_SEND_EMAIL];

/** True for a native record (`native: true`, a `native:` path template). */
export function isNativeTool(tool: Pick<OperationTool, 'native' | 'pathTemplate'>): boolean {
  return tool.native === true && tool.pathTemplate.startsWith(NATIVE_PATH_PREFIX);
}
