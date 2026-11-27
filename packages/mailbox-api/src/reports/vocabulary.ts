/**
 * Vocabularies of user-reported phishing in API mode (step API-3, design note 37 §3.1
 * `api_user_reports`, C10, C11, C12, §5). String unions that mirror the Prisma enums of the
 * `api_mode_clawback_reporting` migration; unit tests pin every list.
 */

/** `api_user_reports.status` (C11.1). */
export const REPORT_STATUSES = [
  'received',
  'parsing',
  'scanning',
  'pending_triage',
  'in_review',
  'resolved',
  'rejected',
] as const;
export type ReportStatus = (typeof REPORT_STATUSES)[number];

/** `api_user_reports.identification` (C10.2). */
export const REPORT_IDENTIFICATIONS = ['attachment', 'inline', 'none', 'unsupported'] as const;
export type ReportIdentification = (typeof REPORT_IDENTIFICATIONS)[number];

/** `api_user_reports.reject_reason` codes (§5). */
export const REPORT_REJECT_REASONS = [
  'external_reporter',
  'loop',
  'auto_submitted',
  'rate_limited',
  'analyst_rejected',
  'too_large',
  'parse_failed',
] as const;
export type ReportRejectReason = (typeof REPORT_REJECT_REASONS)[number];

/** `api_user_reports.assessment` (C11.2). */
export const REPORT_ASSESSMENTS = ['malicious', 'suspicious', 'clean', 'unknown'] as const;
export type ReportAssessment = (typeof REPORT_ASSESSMENTS)[number];

/** `api_user_reports.analyst_verdict` (C11.4, API3-17). */
export const REPORT_ANALYST_VERDICTS = [
  'malicious',
  'phishing_simulation',
  'spam',
  'clean',
  'inconclusive',
] as const;
export type ReportAnalystVerdict = (typeof REPORT_ANALYST_VERDICTS)[number];

/** `api_user_reports.ack_feedback` / `result_feedback` (C12). */
export const REPORT_FEEDBACK_STATES = ['none', 'queued', 'skipped'] as const;
export type ReportFeedbackState = (typeof REPORT_FEEDBACK_STATES)[number];

/** `mail.report.feedback_requested.v1` `kind` (C12). */
export const REPORT_FEEDBACK_KINDS = ['received', 'resolved'] as const;
export type ReportFeedbackKind = (typeof REPORT_FEEDBACK_KINDS)[number];
