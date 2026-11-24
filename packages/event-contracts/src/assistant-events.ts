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
