# Milter endpoint Postfix connects to during the SMTP session.
bind_socket = "*:11332";
milter = yes;
timeout = 120s;
upstream "local" {
  default = yes;
  self_scan = yes;
}
