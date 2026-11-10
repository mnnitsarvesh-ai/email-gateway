#!/bin/sh
# Synthetic benign probe (step 4.6 §9.3, X4 static non-execution test). NOT malware. When (and
# only when) EXECUTED it writes the marker file ./eg-probe-marker in its working directory and
# asks DNS for eg-probe-marker.sandbox.invalid (answered by the recording sinkhole inside a
# runner). A backend that does not execute files leaves neither trace. Harmless anywhere.
echo eg-probe-marker > ./eg-probe-marker
nslookup eg-probe-marker.sandbox.invalid >/dev/null 2>&1
echo "RESULT benign-marker EXECUTED"
