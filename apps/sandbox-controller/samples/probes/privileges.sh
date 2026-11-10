#!/bin/sh
# Synthetic benign probe (step 4.6 §9.3). NOT malware. One action: report the runner's own
# privileges (uid, capabilities, no_new_privs, seccomp mode, Docker socket, environment). Reads
# only. Harmless anywhere.
echo "RESULT uid $(id -u)"
grep -E '^(CapEff|CapPrm|CapBnd|NoNewPrivs|Seccomp):' /proc/self/status | while read -r key value; do
  echo "RESULT status ${key%:} $value"
done
for sock in /var/run/docker.sock /run/docker.sock; do
  if [ -e "$sock" ]; then echo "RESULT docker-socket $sock PRESENT"; else echo "RESULT docker-socket $sock ABSENT"; fi
done
echo "RESULT env-count $(env | grep -cv '^PWD=\|^SHLVL=\|^_=')"
env | grep -v '^PWD=\|^SHLVL=\|^_=' | while IFS='=' read -r key _; do echo "RESULT env-key $key"; done
