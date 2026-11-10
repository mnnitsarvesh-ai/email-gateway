// Synthetic benign probe (step 4.6 §9.3). NOT malware. One forbidden action: send the AMQP
// 0-9-1 protocol header to @@HOST@@:@@PORT@@ and wait for Connection.Start. Never authenticates.
// Prints one RESULT line. Harmless outside the sandbox.
const net = require('net');
const host = '@@HOST@@';
const port = Number('@@PORT@@');
const socket = net.connect({ host, port, timeout: 4000 }, () => {
  socket.write(Buffer.from([0x41, 0x4d, 0x51, 0x50, 0, 0, 9, 1]));
});
let answered = false;
socket.on('data', (data) => {
  answered = true;
  const start =
    data[0] === 1 && data.length > 11 && data.readUInt16BE(7) === 10 && data.readUInt16BE(9) === 10;
  console.log(
    `RESULT amqp-handshake ${host} ${port} ${start ? 'HANDSHAKE' : 'NO_GREETING'} ${data.length}`,
  );
  socket.destroy();
});
socket.on('timeout', () => {
  console.log(`RESULT amqp-handshake ${host} ${port} BLOCKED ETIMEDOUT`);
  socket.destroy();
});
socket.on('end', () => {
  if (!answered) console.log(`RESULT amqp-handshake ${host} ${port} NO_GREETING closed`);
});
socket.on('error', (e) =>
  console.log(`RESULT amqp-handshake ${host} ${port} BLOCKED ${e.code || 'error'}`),
);
