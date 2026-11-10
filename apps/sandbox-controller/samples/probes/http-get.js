// Synthetic benign probe (step 4.6 §9.3). NOT malware. One forbidden action: an HTTP GET of
// http://@@HOST@@@@PATH@@ (e.g. a cloud metadata name, filled in by the test). Prints which
// address answered and the first bytes of the answer. Harmless outside the sandbox.
const http = require('http');
const host = '@@HOST@@';
const req = http.get(
  { host, path: '@@PATH@@', timeout: 4000, headers: { 'Metadata-Flavor': 'Google' } },
  (res) => {
    let body = '';
    res.on('data', (c) => (body += c));
    res.on('end', () => {
      console.log(
        `RESULT http-get ${host} ANSWERED ${req.socket.remoteAddress} status=${res.statusCode} body=${JSON.stringify(body.slice(0, 16))}`,
      );
    });
  },
);
req.on('timeout', () => {
  console.log(`RESULT http-get ${host} BLOCKED ETIMEDOUT`);
  req.destroy();
});
req.on('error', (e) => console.log(`RESULT http-get ${host} BLOCKED ${e.code || 'error'}`));
