#!/bin/sh
# Synthetic benign probe (step 4.6 §9.3). NOT malware, but a resource-exhaustion test: a fork
# bomb. Inside a runner it is capped by the pids limit and killed at the wall timeout. NEVER run
# it outside a runner.
echo "RESULT fork-bomb START"
bomb() { bomb | bomb & }
bomb
sleep 3600
