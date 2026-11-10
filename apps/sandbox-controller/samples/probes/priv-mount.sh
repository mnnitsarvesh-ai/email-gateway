#!/bin/sh
# Synthetic benign probe (step 4.6 §9.3). NOT malware. One forbidden action: mount a tmpfs.
# Prints one RESULT line. Requires CAP_SYS_ADMIN, which runners never have.
mkdir -p /scratch/work/m
if mount -t tmpfs none /scratch/work/m 2>/dev/null; then echo "RESULT priv-mount SUCCEEDED"; umount /scratch/work/m; else echo "RESULT priv-mount BLOCKED"; fi
