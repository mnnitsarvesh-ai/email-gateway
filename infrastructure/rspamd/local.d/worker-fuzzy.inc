# Local fuzzy storage (step 4.1 S12, S13). Hashes are added and deleted only through the
# controller (platform administrators, api scan-training route); the storage listens on loopback.
bind_socket = "127.0.0.1:11335";
count = 1;
backend = "redis";
expire = 90d;
# Pending additions/deletions are written to Redis every `sync` (default 60s); a short interval
# makes administrator training visible to scans within seconds.
sync = 5s;
allow_update = ["127.0.0.1", "::1"];
