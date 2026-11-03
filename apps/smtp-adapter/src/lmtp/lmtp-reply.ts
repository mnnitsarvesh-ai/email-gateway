import { LMTP_TEMPFAIL, type SmtpReply } from '../shared/replies';

/**
 * Thrown by an LMTP handler to answer a command (MAIL, RCPT) with a specific generic reply from
 * `shared/replies.ts`. Any other error a handler throws is an infrastructure fault and is
 * answered with `451 4.3.0` (invariant 2: never 5xx for infrastructure faults).
 */
export class LmtpReplyException extends Error {
  override readonly name = 'LmtpReplyException';

  constructor(readonly reply: SmtpReply) {
    super(reply.text);
  }
}

/** The reply for anything a handler threw: its own reply, or the generic tempfail. */
export function replyForError(err: unknown): SmtpReply {
  return err instanceof LmtpReplyException ? err.reply : LMTP_TEMPFAIL;
}
