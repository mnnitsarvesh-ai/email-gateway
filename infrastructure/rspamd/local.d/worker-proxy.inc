# Milter endpoint the inbound Postfix connects to during the SMTP session (ADR-0027, step 4.1 S11).
# The proxy scans in-process (self_scan). Its timeout stays below Postfix's
# milter_content_timeout (30s), so Postfix never waits longer than Rspamd itself.
bind_socket = "*:11332";
milter = yes;
timeout = 25s;
count = 1;
upstream "local" {
  default = yes;
  self_scan = yes;
}
# GTUBE and score >= RSPAMD_MILTER_REJECT_SCORE (actions.conf) are the only in-session rejects.
reject_message = "5.7.1 Message rejected as spam";
discard_on_reject = false;
quarantine_on_reject = false;
