// Synthetic benign probe (step 4.6 §9.3). NOT malware. One forbidden action: send a Redis
// PING to @@HOST@@:@@PORT@@ and wait for +PONG / -NOAUTH. Never authenticates. Prints one RESULT
// line. Harmless outside the sandbox.
const net = require('net');
const host = '@@HOST@@';
const port = Number('@@PORT@@');
const socket = net.connect({ host, port, timeout: 4000 }, () => socket.write('PING\r\n'));
let answered = false;
socket.on('data', (data) => {
  answered = true;
  const text = data.toString('latin1');
  const redis = text.startsWith('+PONG') || text.startsWith('-NOAUTH') || text.startsWith('-ERR');
  console.log(
    `RESULT redis-handshake ${host} ${port} ${redis ? 'HANDSHAKE' : 'NO_GREETING'} ${data.length}`,
  );
  socket.destroy();
});
socket.on('timeout', () => {
  console.log(`RESULT redis-handshake ${host} ${port} BLOCKED ETIMEDOUT`);
  socket.destroy();
});
socket.on('end', () => {
  if (!answered) console.log(`RESULT redis-handshake ${host} ${port} NO_GREETING closed`);
});
socket.on('error', (e) =>
  console.log(`RESULT redis-handshake ${host} ${port} BLOCKED ${e.code || 'error'}`),
);
