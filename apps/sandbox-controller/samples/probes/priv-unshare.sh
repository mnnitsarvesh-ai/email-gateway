#!/bin/sh
# Synthetic benign probe (step 4.6 §9.3). NOT malware. One forbidden action: create a user and
# mount namespace (`unshare -U -r -m`). Prints one RESULT line.
if unshare -U -r -m true 2>/dev/null; then echo "RESULT priv-unshare SUCCEEDED"; else echo "RESULT priv-unshare BLOCKED"; fi
