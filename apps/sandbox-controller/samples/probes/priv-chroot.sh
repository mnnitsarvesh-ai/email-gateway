#!/bin/sh
# Synthetic benign probe (step 4.6 §9.3). NOT malware. One forbidden action: chroot. Prints one
# RESULT line. Requires CAP_SYS_CHROOT, which runners never have.
if chroot / /bin/true 2>/dev/null; then echo "RESULT priv-chroot SUCCEEDED"; else echo "RESULT priv-chroot BLOCKED"; fi
