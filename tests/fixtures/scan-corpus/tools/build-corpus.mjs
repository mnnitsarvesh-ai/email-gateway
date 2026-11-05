#!/usr/bin/env node
// Writes the scan-corpus EML files (step 4.1, docs/plan/steps/09-rspamd.md §9) byte-exactly with
// CRLF line endings, DKIM-signs the clean.scan.test fixtures with the TEST-ONLY key in ../keys
// (relaxed/relaxed, rsa-sha256, fixed t= so the output is deterministic) and ARC-seals the arc/
// fixtures (RFC 8617, i=1, cv=none) with the same key for the test sealers
// arc-trusted.scan.test / arc-untrusted.scan.test (selector eg2026, published by dns-sink).
//
//   node tests/fixtures/scan-corpus/tools/build-corpus.mjs
//
// The expectations live in ../manifest.json (calibrated against the real rspamd/rspamd:3.12 of
// the Compose stack); re-run packages/rspamd's integration suite after changing a fixture.
import { createHash, createPrivateKey, sign } from 'node:crypto';
import { mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = join(dirname(fileURLToPath(import.meta.url)), '..');
const key = createPrivateKey(readFileSync(join(root, 'keys/eg2026.clean.scan.test.private')));
// 2026-11-01T00:00:00Z: signature timestamp of every signed fixture (no x= expiry).
const SIGNED_AT = 1793491200;
const SIGNED_HEADERS = [
  'from',
  'to',
  'subject',
  'date',
  'message-id',
  'mime-version',
  'content-type',
];

const crlf = (text) => text.replace(/\r?\n/g, '\r\n');

function relaxedBody(body) {
  const lines = body.split('\r\n').map((line) => line.replace(/[ \t]+/g, ' ').replace(/ $/, ''));
  while (lines.length > 0 && lines[lines.length - 1] === '') lines.pop();
  return lines.length === 0 ? '' : `${lines.join('\r\n')}\r\n`;
}

function relaxedHeader(raw) {
  const index = raw.indexOf(':');
  const name = raw.slice(0, index).trim().toLowerCase();
  const value = raw
    .slice(index + 1)
    .replace(/\r\n/g, '')
    .replace(/[ \t]+/g, ' ')
    .trim();
  return `${name}:${value}`;
}

/** Splits the header block into raw (still folded) fields. */
function headerFields(head) {
  const fields = [];
  for (const line of head.split('\r\n')) {
    if (/^[ \t]/.test(line) && fields.length > 0) fields[fields.length - 1] += `\r\n${line}`;
    else if (line !== '') fields.push(line);
  }
  return fields;
}

/** DKIM-signs a CRLF message for clean.scan.test / eg2026; returns the signed message. */
function dkimSign(message) {
  const split = message.indexOf('\r\n\r\n');
  const head = message.slice(0, split);
  const body = message.slice(split + 4);
  const bh = createHash('sha256').update(relaxedBody(body)).digest('base64');
  const fields = headerFields(head);
  const signed = SIGNED_HEADERS.map((name) => {
    const field = [...fields].reverse().find((f) => f.toLowerCase().startsWith(`${name}:`));
    if (!field) throw new Error(`missing header ${name}`);
    return relaxedHeader(field);
  });
  const unsignedTag =
    `DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed; d=clean.scan.test; s=eg2026;\r\n` +
    `\tt=${SIGNED_AT}; h=${SIGNED_HEADERS.join(':')};\r\n` +
    `\tbh=${bh};\r\n\tb=`;
  const data = `${signed.join('\r\n')}\r\n${relaxedHeader(unsignedTag)}`;
  const b = sign('sha256', Buffer.from(data), key).toString('base64');
  return `${unsignedTag}${b}\r\n${message}`;
}

/**
 * ARC-seals a CRLF message as instance i=1 (cv=none) of `sealer` / eg2026 (RFC 8617): an
 * ARC-Authentication-Results with `results`, an ARC-Message-Signature over SIGNED_HEADERS and the
 * body (relaxed/relaxed, like DKIM) and an ARC-Seal over the three ARC header fields (relaxed).
 */
function arcSeal(message, sealer, results) {
  const split = message.indexOf('\r\n\r\n');
  const head = message.slice(0, split);
  const body = message.slice(split + 4);
  const fields = headerFields(head);
  const aar = `ARC-Authentication-Results: i=1; ${sealer};\r\n\t${results}`;
  const bh = createHash('sha256').update(relaxedBody(body)).digest('base64');
  const signed = SIGNED_HEADERS.map((name) => {
    const field = [...fields].reverse().find((f) => f.toLowerCase().startsWith(`${name}:`));
    if (!field) throw new Error(`missing header ${name}`);
    return relaxedHeader(field);
  });
  const amsTag =
    `ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=${sealer}; s=eg2026;\r\n` +
    `\tt=${SIGNED_AT}; h=${SIGNED_HEADERS.join(':')};\r\n` +
    `\tbh=${bh};\r\n\tb=`;
  const amsData = `${signed.join('\r\n')}\r\n${relaxedHeader(amsTag)}`;
  const ams = `${amsTag}${sign('sha256', Buffer.from(amsData), key).toString('base64')}`;
  const asTag = `ARC-Seal: i=1; a=rsa-sha256; t=${SIGNED_AT}; cv=none; d=${sealer}; s=eg2026;\r\n\tb=`;
  const asData = [aar, ams, asTag].map(relaxedHeader).join('\r\n');
  const seal = `${asTag}${sign('sha256', Buffer.from(asData), key).toString('base64')}`;
  return `${seal}\r\n${ams}\r\n${aar}\r\n${message}`;
}

const fixtures = {};
const add = (file, text, { dkim = false, arc, alterAfterSigning } = {}) => {
  let message = crlf(text);
  if (dkim) message = dkimSign(message);
  if (arc) message = arcSeal(message, arc.sealer, arc.results);
  if (alterAfterSigning) message = alterAfterSigning(message);
  fixtures[file] = message;
};

const BUSINESS_TEXT = `Hello Bob,

Thank you for the meeting on Tuesday. As agreed, I am sending the summary of the next steps for
the warehouse inventory project.

1. Our team finishes the stock count for the north building by Friday.
2. Your team reviews the reconciliation sheet and sends comments next week.
3. We schedule a short call on the 14th to agree on the final numbers.

Please let me know if any of the dates do not work for you, and I will find another slot.

Kind regards,
Alice Martin
Operations Manager, Clean Example Ltd.
`;

// --- clean ------------------------------------------------------------------------------------
add(
  'clean/clean-dkim-aligned.eml',
  `From: Alice Martin <alice@clean.scan.test>
To: Bob Stone <bob@customer.scan.test>
Subject: Warehouse inventory: next steps
Date: Sun, 01 Nov 2026 09:15:00 +0000
Message-ID: <inventory-20261101-0915@clean.scan.test>
MIME-Version: 1.0
Content-Type: text/plain; charset=utf-8
Content-Transfer-Encoding: 7bit

${BUSINESS_TEXT}`,
  { dkim: true },
);

// --- spam -------------------------------------------------------------------------------------
add(
  'spam/gtube.eml',
  `From: Tester <tester@spam-sender.scan.test>
To: bob@customer.scan.test
Subject: GTUBE test message
Date: Sun, 01 Nov 2026 10:00:00 +0000
Message-ID: <gtube-20261101@spam-sender.scan.test>
MIME-Version: 1.0
Content-Type: text/plain; charset=us-ascii

This is the GTUBE, the Generic Test for Unsolicited Bulk Email.

XJS*C4JDBQADN1.NSBN3*2IDNEN*GTUBE-STANDARD-ANTI-UBE-TEST-EMAIL*C.34X
`,
);

add(
  'spam/rbl-dbl-lottery.eml',
  `From: "International Lottery Board" <claims@listed-spam.scan.test>
To: bob@customer.scan.test
Subject: CONGRATULATIONS!!! You have WON $1,500,000 USD - claim your prize today
Date: Sun, 01 Nov 2026 11:00:00 +0000
Message-ID: <win-778812@listed-spam.scan.test>
MIME-Version: 1.0
Content-Type: text/html; charset=utf-8
Content-Transfer-Encoding: 7bit

<html><body>
<p>Dear Lucky Winner,</p>
<p>Your email address has been selected in our INTERNATIONAL LOTTERY DRAW and you have WON
<b>$1,500,000.00 USD</b>!!! To claim your prize you must reply within 48 hours with your full
name, bank account number and a processing fee of $250.</p>
<p>Also enjoy CHEAP VIAGRA and CIALIS, 90% OFF, no prescription needed, discreet shipping
worldwide. Best prices on all meds, limited time offer!!!</p>
<p><a href="http://listed-spam.scan.test/claim?id=778812">CLICK HERE TO CLAIM YOUR MONEY NOW</a></p>
<p><a href="http://listed-spam.scan.test/pharmacy">Order your pills today</a></p>
<p>Act now! This offer will not be repeated. 100% guaranteed, risk free.</p>
</body></html>
`,
);

// --- spoofed ----------------------------------------------------------------------------------
add(
  'spoofed/spf-fail.eml',
  `From: Chief Executive <ceo@spoof.scan.test>
To: bob@customer.scan.test
Subject: Quick request
Date: Sun, 01 Nov 2026 12:00:00 +0000
Message-ID: <req-20261101-1200@spoof.scan.test>
MIME-Version: 1.0
Content-Type: text/plain; charset=utf-8

Hi Bob,

Are you at your desk? I need you to handle a confidential payment for a supplier today.
Reply to this email as soon as you can and I will send the details.

Thanks
`,
);

add(
  'spoofed/dkim-body-altered.eml',
  `From: Alice Martin <alice@clean.scan.test>
To: Bob Stone <bob@customer.scan.test>
Subject: Updated bank details for the next invoice
Date: Sun, 01 Nov 2026 13:00:00 +0000
Message-ID: <bank-20261101-1300@clean.scan.test>
MIME-Version: 1.0
Content-Type: text/plain; charset=utf-8
Content-Transfer-Encoding: 7bit

Hello Bob,

Please note that the payment details for invoice 2026-114 are unchanged. Pay to the account on
file as usual.

Kind regards,
Alice Martin
`,
  {
    dkim: true,
    // A man in the middle changes the body after signing: the body hash no longer matches.
    alterAfterSigning: (message) =>
      message.replace(
        'are unchanged. Pay to the account on\r\nfile as usual.',
        'have changed. Pay to IBAN XX00 9999 0000 1111 2222 from\r\nnow on.',
      ),
  },
);

add(
  'spoofed/dmarc-reject.eml',
  `From: Payroll <payroll@spoof.scan.test>
To: bob@customer.scan.test
Subject: Your payslip for October
Date: Sun, 01 Nov 2026 14:00:00 +0000
Message-ID: <payslip-20261101-1400@clean.scan.test>
MIME-Version: 1.0
Content-Type: text/plain; charset=utf-8

Hello,

Your payslip for October is ready. Please review it in the staff portal and contact payroll
if anything is unclear.

Payroll team
`,
);

add(
  'spoofed/dmarc-quarantine.eml',
  `From: Newsletter <news@quarantine.scan.test>
To: bob@customer.scan.test
Subject: Monthly product update
Date: Sun, 01 Nov 2026 14:30:00 +0000
Message-ID: <news-20261101-1430@clean.scan.test>
MIME-Version: 1.0
Content-Type: text/plain; charset=utf-8

Hello,

This month we shipped three improvements to the reporting module and fixed several bugs in the
export feature. Read the full release notes in your account.

The product team
`,
);

// --- phishing ---------------------------------------------------------------------------------
add(
  'phishing/link-mismatch.eml',
  `From: Alice Martin <alice@clean.scan.test>
To: Bob Stone <bob@customer.scan.test>
Subject: Please confirm your account
Date: Sun, 01 Nov 2026 15:00:00 +0000
Message-ID: <confirm-20261101-1500@clean.scan.test>
MIME-Version: 1.0
Content-Type: text/html; charset=utf-8
Content-Transfer-Encoding: 7bit

<html><body>
<p>Hello Bob,</p>
<p>We noticed a sign-in to your account from a new device. If this was not you, please review
your account activity at <a href="http://login.bad-url.scan.test/session/review">https://www.paypal.com/</a>
within 24 hours.</p>
<p>Thank you,<br>Account Security</p>
</body></html>
`,
  { dkim: true },
);

add(
  'phishing/known-bad-url.eml',
  `From: IT Service Desk <helpdesk@phish-sender.scan.test>
To: bob@customer.scan.test
Subject: Mailbox storage almost full
Date: Sun, 01 Nov 2026 15:30:00 +0000
Message-ID: <quota-20261101-1530@phish-sender.scan.test>
MIME-Version: 1.0
Content-Type: text/html; charset=utf-8

<html><body>
<p>Your mailbox has reached 98% of its quota. To keep receiving email,
<a href="http://bad-url.scan.test/mailbox/verify">verify your account here</a>.</p>
<p>IT Service Desk</p>
</body></html>
`,
);

// --- header anomaly ---------------------------------------------------------------------------
add(
  'header-anomaly/missing-and-duplicate-headers.eml',
  `From: "support@bank.scan.test" <service@anomaly-sender.scan.test>
From: Second Sender <second@anomaly-sender.scan.test>
To: bob@customer.scan.test
Subject: Account notice
MIME-Version: 1.0
Content-Type: text/plain; charset=utf-8

Please read the attached account notice and contact support if you have questions about the
recent changes to your account terms.
`,
);

add(
  'header-anomaly/display-name-address.eml',
  `From: "billing@bank.scan.test" <invoices@anomaly-sender.scan.test>
To: bob@customer.scan.test
Subject: Invoice 2026-0457 overdue
Date: Sun, 01 Nov 2026 16:00:00 +0000
Message-ID: <invoice-20261101-1600@anomaly-sender.scan.test>
MIME-Version: 1.0
Content-Type: text/plain; charset=utf-8

Hello,

Invoice 2026-0457 is now overdue. Please arrange the payment this week.

Billing department
`,
);

// --- arc ----------------------------------------------------------------------------------------
// A forwarded message whose header From (spoof.scan.test, p=reject) fails DMARC at the gateway,
// sealed by a forwarder whose ARC-Authentication-Results claim DMARC passed at its hop.
const FORWARDED = (subject, id) => `From: Payroll <payroll@spoof.scan.test>
To: bob@customer.scan.test
Subject: ${subject}
Date: Sun, 01 Nov 2026 17:00:00 +0000
Message-ID: <${id}@spoof.scan.test>
MIME-Version: 1.0
Content-Type: text/plain; charset=utf-8

Hello,

The October payroll run is complete. Your payslip is available in the staff portal; contact
payroll if anything is unclear.

Payroll team
`;
const FORWARDER_RESULTS =
  'spf=pass smtp.mailfrom=spoof.scan.test;\r\n\tdmarc=pass header.from=spoof.scan.test';

add(
  'arc/arc-trusted-dmarc-reject.eml',
  FORWARDED('Payroll run complete', 'payroll-arc-trusted-20261101'),
  { arc: { sealer: 'arc-trusted.scan.test', results: FORWARDER_RESULTS } },
);

add(
  'arc/arc-untrusted-dmarc-reject.eml',
  FORWARDED('Payroll run complete', 'payroll-arc-untrusted-20261101'),
  { arc: { sealer: 'arc-untrusted.scan.test', results: FORWARDER_RESULTS } },
);

add('arc/arc-broken-chain.eml', FORWARDED('Payroll run complete', 'payroll-arc-broken-20261101'), {
  arc: { sealer: 'arc-trusted.scan.test', results: FORWARDER_RESULTS },
  // Changed after sealing: the ARC-Message-Signature body hash no longer matches.
  alterAfterSigning: (message) =>
    message.replace('available in the staff portal', 'available at http://payroll.example'),
});

for (const [file, message] of Object.entries(fixtures)) {
  const target = join(root, file);
  mkdirSync(dirname(target), { recursive: true });
  writeFileSync(target, message);
}
console.log(`Wrote ${Object.keys(fixtures).length} fixtures to ${root}`);
