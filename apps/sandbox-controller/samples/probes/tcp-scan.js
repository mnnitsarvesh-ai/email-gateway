// Synthetic benign probe (step 4.6 §9.3). NOT malware. One forbidden action: a TCP connect
// scan of the host @@HOST@@ (the detonation network's gateway, i.e. the Docker VM's bridge
// address, filled in by the test) on a fixed list of ports. Sends nothing. Prints one RESULT line
// per port. Harmless outside the sandbox.
const net = require('net');
const host = '@@HOST@@';
const ports = [
  22, 53, 80, 111, 443, 2375, 2376, 3000, 3200, 3306, 3307, 3308, 5672, 6379, 6390, 8080, 9000,
  9001, 15672,
];
let pending = ports.length;
for (const port of ports) {
  const socket = net.connect({ host, port, timeout: 3000 });
  const done = (line) => {
    console.log(line);
    socket.destroy();
    pending -= 1;
  };
  socket.on('connect', () =>
    done(`RESULT tcp-scan ${host} ${port} REACHED ${socket.remoteAddress}`),
  );
  socket.on('timeout', () => done(`RESULT tcp-scan ${host} ${port} BLOCKED ETIMEDOUT`));
  socket.on('error', (e) => done(`RESULT tcp-scan ${host} ${port} BLOCKED ${e.code || 'error'}`));
}
