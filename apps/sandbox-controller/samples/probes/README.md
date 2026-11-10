# Synthetic sandbox probes (step 4.6 §9.3)

Benign, synthetic test inputs for the hardened-container runner's escape-resistance and cleanup
suite (`apps/sandbox-controller/integration/runner/`, procedure and results in
[docs/security/sandbox-escape-testing.md](../../../../docs/security/sandbox-escape-testing.md)).
**None of them is malware**; each attempts exactly one forbidden action (or one resource abuse) and
prints `RESULT …` lines. `@@NAME@@` placeholders are filled in by the test (targets read from
Docker at run time). The EICAR anti-virus test string is assembled from two parts at run time and
is never stored whole. The resource probes (fork bomb, memory bomb, scratch fill, crash/freeze)
must only ever run inside a runner. `benign-marker.*` is generic: when executed it writes
`./eg-probe-marker` and resolves `eg-probe-marker.sandbox.invalid`; a non-executing backend leaves
neither trace (the X4 static non-execution test).

The hardened-container runner is LOCAL/CI ONLY and NOT A VM BOUNDARY.
