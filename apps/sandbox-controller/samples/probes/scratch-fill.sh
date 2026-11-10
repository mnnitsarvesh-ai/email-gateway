#!/bin/sh
# Synthetic benign probe (step 4.6 §9.3). NOT malware. One forbidden action: fill the runner's
# /scratch tmpfs with zeros until the kernel refuses (ENOSPC at the tmpfs size) and leave it full.
# Prints the bytes written. Run it only in a runner (it would fill a real disk elsewhere).
dd if=/dev/zero of=/scratch/work/fill bs=1M count=4096 2>/dev/null
size=$(wc -c < /scratch/work/fill)
echo "RESULT scratch-fill $size"
