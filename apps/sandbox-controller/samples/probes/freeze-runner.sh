#!/bin/sh
# Synthetic benign probe (step 4.6 §9.3, cleanup path "outer timeout"). NOT malware. One action:
# SIGSTOP every other process this uid may signal (inside a runner: the runner's bootstrap, so its
# inner timeout never fires) and sleep; the controller's outer timeout (wall + 5 s) must kill and
# remove the runner. NEVER run it outside a runner (it would freeze your own processes).
echo "RESULT freeze-runner START"
kill -STOP -1
sleep 600
