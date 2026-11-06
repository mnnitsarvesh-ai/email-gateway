// url-test (TEST-ONLY, step 4.3 U19, docs/plan/steps/11-url-protection.md): the local "Internet"
// for the URL engine, the click-service, the egress proxy and the browser worker. Zero
// dependencies, deterministic, generated content only (nothing harmful is committed).
//
//   HTTP  80   every corpus name (the Host header decides the page)
//   HTTPS 443  test-pki leaf `url-test` (/pki/url-test/{cert,key}.pem) whose SANs list every name
//   DNS   5300 udp+tcp, the rebinding responder (dns.mjs), reached through dns-sink
//
// Compose: profile smtp-test, networks urltest (203.0.113.10) and mailtest (172.31.250.60),
// published 127.0.0.1:${URL_TEST_HTTP_HOST_PORT:-18080} / ${URL_TEST_HTTPS_HOST_PORT:-18443}.
// Host-run suites reach it through URL_FETCH_TEST_DIAL_MAP after the guard validated
// 203.0.113.10. Routes: see ROUTES below and the README section of docs/plan/steps/11.
import { readFileSync } from 'node:fs';
import http from 'node:http';
import https from 'node:https';
import { createGzip } from 'node:zlib';
import { resetRebind, rebindPosition, startDns } from './dns.mjs';

const HTTP_PORT = Number(process.env.URL_TEST_HTTP_PORT ?? 80);
const HTTPS_PORT = Number(process.env.URL_TEST_HTTPS_PORT ?? 443);
const DNS_PORT = Number(process.env.URL_TEST_DNS_PORT ?? 5300);
const PKI_DIR = process.env.URL_TEST_PKI_DIR ?? '/pki/url-test';
const DAY = 86_400_000;

// --- SSRF redirect targets (/to/<case>) ------------------------------------------------------
export const REDIRECT_CASES = {
  loopback: 'http://127.0.0.1/',
  'loopback-short': 'http://127.1/',
  decimal: 'http://2130706433/',
  octal: 'http://0177.0.0.1/',
  hex: 'http://0x7f.0.0.1/',
  'v6-loopback': 'http://[::1]/',
  'v6-mapped-hex': 'http://[::ffff:7f00:1]/',
  'v6-mapped': 'http://[::ffff:127.0.0.1]/',
  zero: 'http://0.0.0.0/',
  'private-10': 'http://10.0.0.5/',
  'private-172': 'http://172.16.0.1/',
  'private-192': 'http://192.168.1.1/',
  cgnat: 'http://100.64.0.1/',
  metadata: 'http://169.254.169.254/latest/meta-data/',
  'metadata-v6': 'http://[fd00:ec2::254]/',
  'metadata-name': 'http://metadata.google.internal/',
  localhost: 'http://localhost/',
  port22: 'http://clean-site.test:22/',
  file: 'file:///etc/passwd',
  gopher: 'gopher://clean-site.test/',
};

// --- fake shortener (short-link.test /s/<code>) ----------------------------------------------
export const SHORT_CODES = {
  clean: 'http://clean-site.test/landing',
  evil: 'http://evil-site.test/landing',
  internal: 'http://127.0.0.1/',
  metadata: 'http://169.254.169.254/latest/meta-data/',
  chain10: 'http://redirect-chain.test/hop/10/clean',
  loop: 'http://short-link.test/s/loop',
  ip: 'http://203.0.113.10/landing',
  meta: 'http://redirect-chain.test/meta/clean',
  rebind: 'http://rebind.test/landing',
};

const CHAIN_TARGETS = {
  clean: 'http://clean-site.test/landing',
  evil: 'http://evil-site.test/landing',
  internal: 'http://127.0.0.1/',
  metadata: 'http://169.254.169.254/latest/meta-data/',
};

const page = (title, body) =>
  `<!doctype html><html><head><meta charset="utf-8"><title>${title}</title></head><body>${body}</body></html>\n`;

const LOGIN = (title, action) =>
  page(
    title,
    `<h1>${title}</h1><form method="post" action="${action}"><input name="user"><input type="password" name="pass"><button>Sign in</button></form>`,
  );

const BRAND_HOSTS = new Set([
  'examp1ebank.test',
  'xn--exmplebank-0qi.test',
  'examplebank-login.test',
]);

function send(res, status, headers, body = '') {
  res.writeHead(status, { 'cache-control': 'no-store', ...headers });
  res.end(body);
}
const html = (res, body, status = 200) =>
  send(res, status, { 'content-type': 'text/html; charset=utf-8' }, body);
const redirect = (res, location, status = 302) =>
  send(res, status, { location, 'content-type': 'text/plain' }, `-> ${location}\n`);
const json = (res, status, value) =>
  send(res, status, { 'content-type': 'application/rdap+json' }, `${JSON.stringify(value)}\n`);

// A compressed body of 64 MiB of zeros (~64 KiB gzip), generated once at start (streamed: never
// 64 MiB in memory, mem_limit 128m).
let gzipBomb = Buffer.alloc(0);
async function buildGzipBomb() {
  const gzip = createGzip({ level: 9 });
  const parts = [];
  gzip.on('data', (chunk) => parts.push(chunk));
  const zeros = Buffer.alloc(1024 * 1024);
  for (let i = 0; i < 64; i += 1) {
    if (!gzip.write(zeros)) await new Promise((resolve) => gzip.once('drain', resolve));
  }
  await new Promise((resolve) => gzip.end(resolve));
  gzipBomb = Buffer.concat(parts);
}

function rdap(res, name) {
  const domain = name.toLowerCase();
  const registered =
    domain === 'new-domain.test'
      ? new Date(Date.now() - 2 * DAY)
      : new Date('2015-01-01T00:00:00Z');
  json(res, 200, {
    objectClassName: 'domain',
    ldhName: domain,
    status: ['active'],
    events: [
      { eventAction: 'registration', eventDate: registered.toISOString() },
      {
        eventAction: 'expiration',
        eventDate: new Date(registered.getTime() + 3650 * DAY).toISOString(),
      },
    ],
  });
}

function handle(req, res) {
  const host = String(req.headers.host ?? '')
    .toLowerCase()
    .replace(/:\d+$/, '')
    .replace(/\.$/, '');
  const url = new URL(req.url ?? '/', 'http://url-test');
  const path = url.pathname;

  if (path === '/health') return send(res, 200, { 'content-type': 'text/plain' }, 'ok\n');
  if (path === '/reset') {
    resetRebind(url.searchParams.get('first') === 'private' ? 'private' : 'public');
    return send(
      res,
      200,
      { 'content-type': 'text/plain' },
      `rebind position ${rebindPosition()}\n`,
    );
  }

  if (host === 'rdap.test') {
    const match = /^\/domain\/([a-z0-9.-]+)$/i.exec(path);
    if (match) return rdap(res, match[1]);
    return json(res, 404, { errorCode: 404, title: 'not found' });
  }

  if (host === 'short-link.test') {
    const match = /^\/s\/([a-z0-9]+)$/.exec(path);
    if (match && SHORT_CODES[match[1]]) return redirect(res, SHORT_CODES[match[1]], 301);
    return html(res, page('Not found', '<p>unknown short code</p>'), 404);
  }

  if (host === 'redirect-chain.test') {
    const hop = /^\/hop\/(\d{1,2})\/([a-z]+)$/.exec(path);
    if (hop) {
      const n = Number(hop[1]);
      if (n > 0) return redirect(res, `/hop/${n - 1}/${hop[2]}`);
      return redirect(res, CHAIN_TARGETS[hop[2]] ?? CHAIN_TARGETS.clean);
    }
    const meta = /^\/meta\/([a-z]+)$/.exec(path);
    if (meta) {
      const target = CHAIN_TARGETS[meta[1]] ?? CHAIN_TARGETS.clean;
      return html(
        res,
        `<!doctype html><html><head><meta http-equiv="refresh" content="0; url=${target}"><title>Redirecting</title></head><body></body></html>\n`,
      );
    }
  }

  // DNS rebinding (U19): from rebind.test back to rebind.test, so the second hop resolves again
  // (the responder's next answer is the other address of the sequence).
  if (path === '/rebind-again') return redirect(res, 'http://rebind.test/landing');

  if (path.startsWith('/to/')) {
    const target = REDIRECT_CASES[path.slice(4)];
    if (target) return redirect(res, target);
    return html(res, page('Not found', '<p>unknown case</p>'), 404);
  }

  if (host === 'slow-site.test') {
    const timer = setTimeout(() => html(res, page('Slow', '<p>late</p>')), 30_000);
    res.once('close', () => clearTimeout(timer));
    return undefined;
  }
  if (host === 'trickle-site.test') {
    res.writeHead(200, { 'content-type': 'text/html; charset=utf-8' });
    const timer = setInterval(() => res.write('x'), 1000);
    res.once('close', () => clearInterval(timer));
    return undefined;
  }
  if (host === 'huge-site.test') {
    res.writeHead(200, { 'content-type': 'text/html; charset=utf-8' });
    const chunk = Buffer.alloc(65_536, 0x61);
    const pump = () => {
      while (!res.destroyed && res.write(chunk));
      if (!res.destroyed) res.once('drain', pump);
    };
    pump();
    return undefined;
  }
  if (host === 'many-headers.test') {
    const headers = { 'content-type': 'text/html; charset=utf-8' };
    for (let i = 0; i < 200; i += 1)
      headers[`x-filler-${String(i).padStart(3, '0')}`] = 'f'.repeat(320);
    return send(res, 200, headers, page('Headers', '<p>many</p>'));
  }
  if (host === 'gzip-bomb.test') {
    return send(
      res,
      200,
      { 'content-type': 'text/html; charset=utf-8', 'content-encoding': 'gzip' },
      gzipBomb,
    );
  }

  if (path === '/js-redirect') {
    return html(
      res,
      page(
        'Moving',
        '<script>setTimeout(function(){location.href="http://clean-site.test/landing";},100);</script>',
      ),
    );
  }
  if (path === '/js-fetch-internal') {
    return html(
      res,
      page(
        'Probe',
        '<script>for (const u of ["http://169.254.169.254/latest/meta-data/","http://127.0.0.1:3080/"]) { fetch(u, {mode:"no-cors"}).catch(function(){}); }</script><p>probing</p>',
      ),
    );
  }
  if (path === '/download') {
    return send(
      res,
      200,
      {
        'content-type': 'application/octet-stream',
        'content-disposition': 'attachment; filename="invoice.bin"',
      },
      Buffer.alloc(1024, 0x42),
    );
  }

  if (host === 'phish-login.test')
    return html(res, LOGIN('ExampleBank Sign in', 'http://collector-site.test/collect'));
  if (BRAND_HOSTS.has(host))
    return html(res, LOGIN('ExampleBank online banking', `http://${host}/session`));
  if (host === 'collector-site.test') return html(res, page('Thanks', '<p>received</p>'));
  if (host === 'evil-site.test')
    return html(res, page('Evil site', '<p>test page listed in the local feed by the suites</p>'));

  // /landing and everything else: a clean page.
  return html(
    res,
    page(
      'Clean landing page',
      `<p>Hello from ${host || 'url-test'}.</p><a href="/landing">home</a>`,
    ),
  );
}

await buildGzipBomb();
http.createServer(handle).listen(HTTP_PORT, '0.0.0.0');
let tls = 'disabled';
try {
  https
    .createServer(
      { key: readFileSync(`${PKI_DIR}/key.pem`), cert: readFileSync(`${PKI_DIR}/cert.pem`) },
      handle,
    )
    .listen(HTTPS_PORT, '0.0.0.0');
  tls = `${HTTPS_PORT}`;
} catch (error) {
  console.error(`url-test: HTTPS disabled (${error.code ?? error.message})`);
}
startDns(DNS_PORT);
console.log(
  `url-test: http ${HTTP_PORT}, https ${tls}, dns ${DNS_PORT} (gzip bomb ${gzipBomb.length} bytes)`,
);
