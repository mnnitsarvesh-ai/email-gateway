#!/bin/sh
# Synthetic benign probe (step 4.6 §9.3). NOT malware. One forbidden action: create the file
# @@PATH@@ (filled in by the test: a path on the read-only root, /proc/sys, or /scratch). Prints
# one RESULT line. Outside the sandbox it would create one small file; run it only in a runner.
target='@@PATH@@'
if (echo eg-probe > "$target") 2>/dev/null; then
  echo "RESULT fs-write $target WRITTEN"
  rm -f "$target" 2>/dev/null
else
  echo "RESULT fs-write $target BLOCKED"
fi
