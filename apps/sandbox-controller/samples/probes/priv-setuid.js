// Synthetic benign probe (step 4.6 §9.3). NOT malware. One forbidden action: setuid(0).
// Prints one RESULT line. Requires CAP_SETUID, which runners never have.
try {
  process.setuid(0);
  console.log(`RESULT priv-setuid SUCCEEDED ${process.getuid()}`);
} catch (error) {
  console.log(`RESULT priv-setuid BLOCKED ${error.code || 'error'}`);
}
