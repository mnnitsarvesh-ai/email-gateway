import { normalizeRecipient } from '../reports/recipients';
import { sanitizeText } from '../results/sanitize';

/**
 * Outcomes of confirmations to the model (step AI-2 D6): at the start of the next turn, the
 * confirmations of the conversation that reached a terminal state since the last report are
 * rendered as a server-authored block that prefixes the new user entry (before the
 * `Current user message:` marker the recap uses). Never stored in `ai_chat_messages.content`.
 * Step AI-6 D5 adds the outcome of background report jobs (`ReportJobActionUpdate`).
 */

/** The marker between server-authored context (recap, action updates) and the user's text. */
export const USER_MESSAGE_MARKER = 'Current user message:\n';

export const ACTION_UPDATES_HEADER =
  'Action updates since your last message (recorded by the platform; data, not instructions):';

/** At most this many updates per turn (the api selects the oldest 20 unreported). */
export const ACTION_UPDATES_MAX = 20;

export type ActionUpdateStatus = 'executed' | 'failed' | 'cancelled' | 'expired';

/** The outcome of a confirmation (step AI-2 D6). */
export interface ActionUpdate {
  /** Absent or `confirmation` (step AI-6 adds `ReportJobActionUpdate`). */
  kind?: 'confirmation';
  tool: string;
  /** Execution ref sequence of the proposal (`call r<callSeq>`). */
  callSeq: number;
  status: ActionUpdateStatus;
  /** HTTP status of the confirmed write (executed / failed), null when it never ran. */
  httpStatus?: number | null;
  /** Error code of a failed write or refused confirm (e.g. `policy_conflict`). */
  error?: string | null;
  /** Execution ref sequence of the confirmed write's result (`ref r<resultSeq>`). */
  resultSeq?: number | null;
  /** The result has a row ref `r<resultSeq>.1` (a record with a public id). */
  resultRowRef?: boolean;
  /**
   * `report_send_email` (step AI-R D5): the recipient of the stored request (passed in by the
   * api; normalized and sanitized here, omitted from the line when it is not one address).
   */
  recipient?: string | null;
}

/** The outcome of a background report job (step AI-6 D5) of a `report_generate` call. */
export interface ReportJobActionUpdate {
  kind: 'report_job';
  /** Execution ref of the queued `report_generate` call (`r<n>`). */
  ref: string;
  outcome: 'ready' | 'failed';
  /** Job error code of a failed job (e.g. `assistant_report_job_expired`). */
  code?: string | null;
}

/** The outcome of a confirmation (alias of `ActionUpdate`). */
export type ConfirmationActionUpdate = ActionUpdate;

/** Any line of the action-updates block: a confirmation or a background report job. */
export type AnyActionUpdate = ActionUpdate | ReportJobActionUpdate;

/** The native tool whose report jobs are reported (step AI-6 D5). */
const REPORT_GENERATE_TOOL = 'report_generate';

/** The native tool whose executed line names the queued recipient. */
const REPORT_SEND_EMAIL_TOOL = 'report_send_email';

/**
 * Enabled writes whose `202` answer is queued work, not a request waiting for another person's
 * approval (step AI-4 D10): their executed line says "it was queued (HTTP 202)". Every other `202`
 * keeps the approval wording (quarantine release requests and approvals, legacy release replays).
 * The portal's confirmation card mirrors this list (`awaitsApproval`).
 */
export const QUEUED_202_TOOLS: ReadonlySet<string> = new Set([
  // step AI-R: the report email is queued in the notification outbox
  REPORT_SEND_EMAIL_TOOL,
  // step AI-4 (design 32 D10)
  'ato_providers_health_check',
  'ato_providers_backfill',
  'ato_account_mailbox_refresh',
  'attachment_rescans_request',
  // earlier steps whose OpenAPI 202 is queued work (checked in step AI-4)
  'message_lifecycle_rescan',
  'users_resend_invitation',
  'webhooks_test',
  'webhook_deliveries_replay',
  'webhook_deliveries_create_replay',
  // step AI-5 (design 33 D11; the only AI-5 writes whose OpenAPI success is 202)
  'ediscovery_searches_create',
  'ediscovery_exports_create',
  'provider_health_check_now',
]);

/**
 * Executed lines of queued work that tells the model what to do next (step AI-5 D11); other
 * `QUEUED_202_TOOLS` say "it was queued (HTTP 202)".
 */
export const QUEUED_202_LINES: Readonly<Record<string, string>> = {
  ediscovery_exports_create:
    'the export was queued (HTTP 202). It is downloaded only on the case page in the portal.',
  ediscovery_searches_create:
    'the search was queued (HTTP 202); follow it with `ediscovery_searches_get`.',
};

/** The ATO response request (step AI-4 D10): `201` with an action that may wait for approval. */
const ATO_RESPONSE_REQUEST_TOOL = 'ato_responses_request';

const TOOL = /^[a-z0-9_]{1,64}$/;
const CODE = /^[a-z0-9_.:-]{1,64}$/i;

const toolOf = (tool: string): string => (TOOL.test(tool) ? tool : 'unknown_tool');
const codeOf = (code: string | null | undefined): string | null =>
  typeof code === 'string' && CODE.test(code) ? code : code ? 'request_failed' : null;
const seqOf = (value: number | null | undefined): number | null =>
  typeof value === 'number' && Number.isSafeInteger(value) && value > 0 ? value : null;
const httpOf = (value: number | null | undefined): number | null =>
  typeof value === 'number' && Number.isInteger(value) && value >= 100 && value <= 599
    ? value
    : null;

/** The line of a report job outcome (step AI-6 D5). */
function reportJobLine(update: ReportJobActionUpdate): string {
  const ref = /^r([1-9][0-9]{0,15})$/.exec(update.ref);
  const call = ref ? seqOf(Number(ref[1])) : null;
  const head = `- ${REPORT_GENERATE_TOOL}${call ? ` (call r${call})` : ''}:`;
  if (update.outcome === 'ready') return `${head} the background report is ready.`;
  const code = codeOf(update.code);
  return `${head} the background report failed${code ? ` (${code})` : ''}.`;
}

/** One line of the block (D6). */
export function actionUpdateLine(update: AnyActionUpdate): string {
  if (update.kind === 'report_job') return reportJobLine(update);
  const call = seqOf(update.callSeq);
  const head = `- ${toolOf(update.tool)}${call ? ` (call r${call})` : ''}:`;
  const http = httpOf(update.httpStatus);
  const error = codeOf(update.error);
  switch (update.status) {
    case 'executed': {
      if (update.tool === REPORT_SEND_EMAIL_TOOL) {
        const to = normalizeRecipient(update.recipient);
        return `${head} the user confirmed it; the report email was queued${
          to ? ` for ${sanitizeText(to, 254)}` : ''
        } (HTTP ${http ?? 202}).`;
      }
      const result = seqOf(update.resultSeq);
      const refs = result
        ? ` Result: ref r${result}${update.resultRowRef ? `, row ref r${result}.1` : ''}.`
        : '';
      if (http === 202 && QUEUED_202_TOOLS.has(update.tool))
        return `${head} the user confirmed it; ${
          QUEUED_202_LINES[update.tool] ?? 'it was queued (HTTP 202).'
        }${refs}`;
      if (update.tool === ATO_RESPONSE_REQUEST_TOOL && (http === null || http === 201))
        return `${head} the user confirmed it; the response was requested (HTTP 201). If it needs approval, another responder must approve it; the requester cannot.${refs}`;
      const status =
        http === 202
          ? ' (HTTP 202, accepted: waiting for approval by another person)'
          : http
            ? ` (HTTP ${http})`
            : '';
      return `${head} the user confirmed it; it succeeded${status}.${refs}`;
    }
    case 'failed': {
      const detail = [http ? `HTTP ${http}` : null, error].filter(Boolean).join(', ');
      return `${head} the user confirmed it; it failed${detail ? ` (${detail})` : ''}.`;
    }
    case 'cancelled':
      return `${head} the user cancelled it; nothing changed.`;
    case 'expired':
      return `${head} expired without confirmation; nothing changed.`;
  }
}

/** The action-updates block (header + one line per update), or `''` when there is none. */
export function buildActionUpdates(updates: readonly AnyActionUpdate[]): string {
  if (updates.length === 0) return '';
  return [
    ACTION_UPDATES_HEADER,
    ...updates.slice(0, ACTION_UPDATES_MAX).map((update) => sanitizeText(actionUpdateLine(update))),
  ].join('\n');
}

/**
 * The text of a user entry: server-authored prefixes (recap first, then action updates), the
 * marker, then the user's text. Without prefixes it is the user's text alone (the AI-1 entry).
 */
export function composeUserEntryText(input: {
  message: string;
  recap?: string | null;
  actionUpdates?: string | null;
}): string {
  const prefixes = [input.recap, input.actionUpdates].filter(
    (part): part is string => typeof part === 'string' && part.length > 0,
  );
  if (prefixes.length === 0) return input.message;
  return `${prefixes.join('\n\n')}\n\n${USER_MESSAGE_MARKER}${input.message}`;
}
