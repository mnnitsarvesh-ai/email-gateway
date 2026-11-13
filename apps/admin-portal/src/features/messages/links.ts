/** Internal routes of the mail pages (design §3.1; linked from notification e-mails). */
export function messageHref(messageId: string): string {
  return `/messages/${encodeURIComponent(messageId)}`;
}

export function scansHref(messageId: string): string {
  return `${messageHref(messageId)}/scans`;
}

/** Attachment analysis search by hash (WP3 page `/attachments?sha256=`). */
export function attachmentSearchHref(sha256: string): string {
  return `/attachments?sha256=${encodeURIComponent(sha256)}`;
}
