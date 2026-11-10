#!/bin/sh
# Synthetic benign probe (step 4.6 §9.3, cleanup path "runner crash"). NOT malware. One action:
# SIGKILL every process this uid may signal (inside a runner: the runner's own bootstrap), so the
# runner dies without a report. NEVER run it outside a runner (it would kill your own processes).
echo "RESULT crash-runner START"
kill -9 -1
