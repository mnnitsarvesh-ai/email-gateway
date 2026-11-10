#!/bin/sh
# Synthetic benign probe (step 4.6 §9.3). NOT malware. One action: sleep far past the wall
# timeout (a "sleep evasion"); the runner must be killed within wall + 5 s. Harmless anywhere.
echo "RESULT long-sleep START"
sleep 600
echo "RESULT long-sleep WOKE"
