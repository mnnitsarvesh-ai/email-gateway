// Synthetic benign probe (step 4.6 §9.3; docs/security/sandbox-escape-testing.md). NOT malware.
// One forbidden action: a single TCP connect to @@HOST@@:@@PORT@@ (a name or an IP filled in by
// the test). Sends nothing. Prints one RESULT line. Harmless outside the sandbox.
const net = require('net');
const host = '@@HOST@@';
const port = Number('@@PORT@@');
const socket = net.connect({ host, port, timeout: 4000 });
socket.on('connect', () => {
  console.log(`RESULT tcp-connect ${host} ${port} REACHED ${socket.remoteAddress}`);
  socket.destroy();
});
socket.on('timeout', () => {
  console.log(`RESULT tcp-connect ${host} ${port} BLOCKED ETIMEDOUT`);
  socket.destroy();
});
socket.on('error', (error) => {
  console.log(`RESULT tcp-connect ${host} ${port} BLOCKED ${error.code || 'error'}`);
});
