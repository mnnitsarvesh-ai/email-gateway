import { z } from 'zod';

/**
 * AI assistant events (step AI-R, docs/plan/steps/31-ai-chat-reports.md D5, D8, §4.3;
 * ADR-0095).
 *
 * `assistant.report.email_requested.v1`: a confirmed `report_send_email` of the assistant. The
 * api's `ReportDeliveryService` writes it through `message_outbox` (`aggregate_type =
 * 'assistant_report_delivery'`, `aggregate_id` = the delivery's public id, `eventId` = the same
 * public id) in the confirm transaction that inserts the `ai_chat_report_deliveries` row. It is
 * published to `email.policy` and bound to `email.notifications` (topology v15); the
 * notification-worker reads the delivery and its report on the writer, scoped to the envelope's
 * organization, fetches the stored HTML from object storage and sends one mail.
 *
 * Strict and ids only: the delivery and report public ids and the request time. No recipient
 * address, HTML, figure, title or organization name (I5, I16, I17; the content guard on publish
 * sees metadata only).
 */
export const assistantReportEmailRequestedV1 = z.strictObject({
  /** `ai_chat_report_deliveries.public_id` (UUIDv7). */
  deliveryId: z.uuid(),
  /** `ai_chat_reports.public_id` (UUIDv7). */
  reportId: z.uuid(),
  /** `ai_chat_report_deliveries.requested_at`. */
  requestedAt: z.iso.datetime(),
});
export type AssistantReportEmailRequestedV1 = z.infer<typeof assistantReportEmailRequestedV1>;

/**
 * `assistant.report.generate_requested.v1` (step AI-6 D5, §4.2; ADR-0096): a security report
 * window too long for the turn became a background job. The api's turn engine writes it through
 * `message_outbox` (`aggregate_type = 'assistant_report_job'`, `aggregate_id` = the job's public
 * id, `eventId` = the same public id) in the transaction that inserts the `queued`
 * `ai_chat_reports` row and its `ai_chat_report_jobs` row. It is published to `email.policy` and
 * bound to `assistant.reports` (topology v16); the api-assistant `ReportJobConsumer` loads the
 * job on the writer, scoped to the envelope's organization, and generates the report through the
 * loopback with a short-lived GET-only token of the requesting user's live session (I26).
 *
 * Strict and ids only: the job and report public ids and the request time. No window, section,
 * title, session id, credential or organization name (the job row holds them; the content guard
 * on publish sees metadata only).
 */
export const assistantReportGenerateRequestedV1 = z.strictObject({
  /** `ai_chat_report_jobs.public_id` (UUIDv7). */
  jobId: z.uuid(),
  /** `ai_chat_reports.public_id` (UUIDv7) of the `queued` report. */
  reportId: z.uuid(),
  /** `ai_chat_report_jobs.created_at`. */
  requestedAt: z.iso.datetime(),
});
export type AssistantReportGenerateRequestedV1 = z.infer<typeof assistantReportGenerateRequestedV1>;
