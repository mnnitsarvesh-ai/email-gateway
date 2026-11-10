// Synthetic benign probe (step 4.6 §9.3). NOT malware. One forbidden action: open a TCP
// connection to @@HOST@@:@@PORT@@ and wait for a MySQL server greeting (protocol 10). Sends
// nothing, never authenticates. Prints one RESULT line. Harmless outside the sandbox.
const net = require('net');
const host = '@@HOST@@';
const port = Number('@@PORT@@');
const socket = net.connect({ host, port, timeout: 4000 });
let answered = false;
socket.on('data', (data) => {
  answered = true;
  const greeting = data.length > 5 && data[4] === 10;
  console.log(
    `RESULT mysql-handshake ${host} ${port} ${greeting ? 'HANDSHAKE' : 'NO_GREETING'} ${data.length}`,
  );
  socket.destroy();
});
socket.on('timeout', () => {
  console.log(`RESULT mysql-handshake ${host} ${port} BLOCKED ETIMEDOUT`);
  socket.destroy();
});
socket.on('end', () => {
  if (!answered) console.log(`RESULT mysql-handshake ${host} ${port} NO_GREETING closed`);
});
socket.on('error', (e) =>
  console.log(`RESULT mysql-handshake ${host} ${port} BLOCKED ${e.code || 'error'}`),
);
