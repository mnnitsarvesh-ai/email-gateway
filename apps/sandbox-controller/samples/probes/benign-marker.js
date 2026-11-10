// Synthetic benign probe (step 4.6 §9.3, X4 static non-execution test). NOT malware. When (and
// only when) EXECUTED it writes the marker file ./eg-probe-marker in its working directory and
// resolves eg-probe-marker.sandbox.invalid (answered by the recording sinkhole inside a runner).
// A backend that does not execute files leaves neither trace. Harmless anywhere.
require('fs').writeFileSync('./eg-probe-marker', 'eg-probe-marker\n');
require('dns').lookup('eg-probe-marker.sandbox.invalid', () => {
  console.log('RESULT benign-marker EXECUTED');
});
