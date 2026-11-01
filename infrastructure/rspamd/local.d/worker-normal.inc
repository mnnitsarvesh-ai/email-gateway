# HTTP scan endpoint (/checkv2) used by post-queue workers. No auth; reachable only on the
# internal network.
bind_socket = "*:11333";
