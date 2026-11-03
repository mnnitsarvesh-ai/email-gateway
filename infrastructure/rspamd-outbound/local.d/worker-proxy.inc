# Milter endpoint used ONLY by postfix-outbound's 10027 reinject-outbound listener (step 2.2 D12).
# It signs for every peer, so it must be reachable from postfix-outbound only: all interfaces of
# a container attached only to the internal `dkim-signing` network (docker-compose.yml), and the
# sg-rspamd-outbound security group in AWS.
# The proxy scans in-process (self_scan); no separate scanner worker is involved.
bind_socket = "*:11332";
milter = yes;
timeout = 120s;
upstream "local" {
  default = yes;
  self_scan = yes;
}
