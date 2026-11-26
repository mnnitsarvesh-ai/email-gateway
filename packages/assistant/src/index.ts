// @email-gateway/assistant: providers, prompt, context, results and the tool registry of the AI
// assistant (docs/plan/steps/28-ai-chat-management.md, ADR-0091/0092), the reports of step
// AI-R (docs/plan/steps/31-ai-chat-reports.md, ADR-0095) and the hardening of step AI-6
// (docs/plan/steps/34-ai-chat-hardening-operations.md: pseudonymization, provider routing, the
// capability report). Only apps/api depends on this package; the portal may import its types.
export * from './providers/types';
export * from './providers/meta-tools';
export * from './providers/anthropic';
export * from './providers/openai-compatible';
export * from './providers/fake';
export * from './providers/factory';
export * from './providers/breaker';
export * from './providers/prices';
export * from './providers/retry';
export * from './providers/routing';
export * from './prompt/system';
export * from './context/window';
export * from './results/types';
export * from './results/sanitize';
export * from './results/shape';
export * from './results/minimize';
export * from './results/card';
export * from './results/stream';
export * from './confirmations/types';
export * from './confirmations/canonical';
export * from './confirmations/digest';
export * from './confirmations/specs';
export * from './confirmations/guards';
export * from './confirmations/escalation';
export * from './confirmations/impact';
export * from './confirmations/updates';
export * from './registry/types';
export * from './registry/manifest';
export * from './registry/registry';
export {
  NATIVE_OPERATION_ID,
  NATIVE_PATH_PREFIX,
  RECIPIENT_MAX_LENGTH,
  REPORT_GENERATE,
  REPORT_GENERATE_TESTED_BY,
  REPORT_REF_PATTERN,
  REPORT_SEND_EMAIL,
  REPORT_SEND_EMAIL_TESTED_BY,
} from './registry/native';
export * from './reports';
export * from './pseudonym';
export {
  CAPABILITY_REPORT_PREAMBLE,
  CAPABILITY_REPORT_TITLE,
  renderCapabilityReport,
} from './registry/report';
export { API_PREFIX, phaseIndex, toolNameOf } from './registry/build';
