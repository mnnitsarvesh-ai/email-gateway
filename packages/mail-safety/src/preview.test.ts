import { describe, expect, it } from 'vitest';
import { defangUrl } from './defang';
import { maskDlp, MASK_CHAR } from './dlp-mask';
import { htmlToPreviewText } from './html-to-text';
import { quarantinePreviewSchema, renderPreview, type PreviewInput } from './preview';

const NOW = new Date('2026-11-12T12:00:00.000Z');
const CARD = '4539 1488 0343 6467';
const base: PreviewInput = {
  subject: 'Invoice',
  headers: [],
  textPart: null,
  htmlPart: null,
  attachments: [],
  urlVerdicts: [],
  now: NOW,
};
const preview = (patch: Partial<PreviewInput>) => {
  const p = renderPreview({ ...base, ...patch });
  expect(quarantinePreviewSchema.parse(p)).toEqual(p);
  return p;
};
const html = (body: string) => preview({ htmlPart: body });

describe('defangUrl', () => {
  it.each([
    [
      'https://login.bank.example/reset?id=1',
      'hxxps://login[.]bank[.]example/reset?id=1',
      'login[.]bank[.]example',
    ],
    ['http://user:pw@evil.test:8080/a#frag', 'hxxp://evil[.]test:8080/a', 'evil[.]test'],
    ['HTTP://WWW.Example.COM', 'hxxp://www[.]example[.]com/', 'www[.]example[.]com'],
    ['www.example.org/x', 'hxxp://www[.]example[.]org/x', 'www[.]example[.]org'],
    [
      'https://a.example/?u=https://b.example',
      'hxxps://a[.]example/?u=hxxps://b.example',
      'a[.]example',
    ],
    ['https://[2001:db8::1]/x', 'hxxps://[2001:db8::1]/x', '[2001:db8::1]'],
  ])('%s', (url, display, host) => {
    const d = defangUrl(url);
    expect(d.displayUrl).toBe(display);
    expect(d.host).toBe(host);
    expect(d.identitySha256).toMatch(/^[0-9a-f]{64}$/);
  });
  it('other schemes are removed; invalid input is defanged as text; long URLs are cut', () => {
    expect(defangUrl('javascript:alert(document.cookie)')).toEqual({
      displayUrl: 'javascript:[removed]',
      host: null,
      identitySha256: null,
    });
    expect(defangUrl('data:text/html;base64,PHNjcmlwdD4=').displayUrl).toBe('data:[removed]');
    expect(defangUrl('mailto:a@b.example').displayUrl).toBe('mailto:[removed]');
    expect(defangUrl('/relative/path.html')).toEqual({
      displayUrl: '/relative/path[.]html',
      host: null,
      identitySha256: null,
    });
    expect(defangUrl(`https://x.example/${'a'.repeat(400)}`).displayUrl).toHaveLength(256);
  });
});

describe('maskDlp', () => {
  it('cards keep the first 6 and the last 4; everything else is fully masked', () => {
    const r = maskDlp(`Card ${CARD} exp 12/29`, { now: NOW });
    expect(r.text).toBe(`Card 453914${MASK_CHAR.repeat(6)}6467 exp 12/29`);
    expect(r).toMatchObject({ masked: 1, categories: ['payment_card'] });
  });
  it.each([
    ['IBAN', 'IBAN GB82 WEST 1234 5698 7654 32 ok', 'GB82', 'bank_account'],
    ['Aadhaar', 'Aadhaar 2341 2341 2346 ok', '2341', 'national_id'],
    ['PAN', 'PAN ABCPE1234F ok', 'ABCPE1234F', 'national_id'],
    // Secret-shaped values are assembled at runtime so no literal looks like a real credential.
    ['AWS key', `key ${['AK', 'IA'].join('')}IOSFODNN7EXAMPLF ok`, 'IOSFODNN7', 'credential'],
    [
      'GitHub token',
      `tok ${['gh', 'p_'].join('')}${'abcdefghijklmnopqrstuvwxyz0123456789'} ok`,
      'abcdefghij',
      'credential',
    ],
    ['e-mail in the body', 'write to john.doe@example.com today', 'john.doe', 'personal_info'],
  ])('%s', (_n, text, secret, category) => {
    const r = maskDlp(text, { now: NOW });
    expect(r.text).not.toContain(secret);
    expect(r.text).toContain(MASK_CHAR);
    expect(r.masked).toBeGreaterThanOrEqual(1);
    expect(r.categories).toContain(category);
    expect(r.text.endsWith(' ok') || r.text.endsWith(' today')).toBe(true);
  });
  it('private keys are masked to at most 64 bullets', () => {
    const label = ['RSA', 'PRIVATE', 'KEY'].join(' ');
    const body = `MIIBOgIBAAJBA${'Kj34GkxFhD90vcNLYLInFEX6Ppy1tPf9Cnzj4p4WGeKLs1Pt8Qu'}`;
    const pem = `-----BEGIN ${label}-----\n${body}\n-----END ${label}-----`;
    const r = maskDlp(`x\n${pem}\ny`, { now: NOW });
    expect(r.text).toBe(`x\n${MASK_CHAR.repeat(64)}\ny`);
  });
  it('nothing to mask', () => {
    expect(maskDlp('hello world', { now: NOW })).toEqual({
      text: 'hello world',
      masked: 0,
      categories: [],
    });
    expect(maskDlp('', { now: NOW }).masked).toBe(0);
  });
});

describe('renderPreview sanitization corpus (Q11)', () => {
  const ACTIVE = [
    /<\s*script/i,
    /<\s*\/?\s*(iframe|object|embed|svg|form|style|img|a|base|link|meta)\b/i,
    /javascript:/i,
    /\bon[a-z]+\s*=/i,
    /data:/i,
    /src\s*=/i,
    /href\s*=/i,
    /url\(/i,
    /\bhttps?:\/\//i,
  ];
  const clean = (text: string) => {
    for (const re of ACTIVE) expect(text, String(re)).not.toMatch(re);
  };
  it('drops scripts, styles, event handlers, iframes, objects, forms, SVG, MathML, base and comments', () => {
    const p = html(`<!doctype html><html><head><base href="https://evil.test/"><title>T</title>
      <style>body{background:url(https://track.test/p.gif)}</style><script>alert(1)</script></head>
      <body onload="steal()"><p onclick="x()">Hello <b>there</b></p><!-- secret comment -->
      <iframe src="https://evil.test/frame">frame text</iframe><object data="x.swf">obj text</object>
      <embed src="x.swf"><form action="https://evil.test/login"><input name="pw">Form text<button>Go</button></form>
      <svg><text>svg text</text><script>alert(2)</script></svg><math><mi>m</mi></math>
      <noscript>noscript text</noscript><template><p>tpl</p></template><p>Bye</p></body></html>`);
    expect(p.body.source).toBe('html');
    expect(p.body.text).toBe('Hello there\n\nBye');
    clean(p.body.text);
    for (const hidden of [
      'secret comment',
      'frame text',
      'obj text',
      'Form text',
      'svg text',
      'noscript',
      'tpl',
      'alert',
    ]) {
      expect(p.body.text).not.toContain(hidden);
    }
  });
  it('images, media and data URIs become placeholders; no source survives', () => {
    const p =
      html(`<p>Logo <img src="https://track.test/pixel.gif?u=1" onerror="x()"> and <img src="data:image/png;base64,AAAA">
      <picture><source srcset="https://a.test/x.webp"><img src="https://a.test/x.png"></picture>
      <video src="https://v.test/v.mp4"></video><audio src="a.mp3"></audio></p>`);
    expect(p.body.text).toBe('Logo [image] and [image] [image] [media] [media]');
    clean(p.body.text);
  });
  it('anchors become text [link N]; links are listed defanged with verdicts, never clickable', () => {
    const evil = 'https://login.evil.test/reset';
    const p = preview({
      htmlPart: `<p><a href="${evil}" style="color:red">Reset password</a>, <a href="javascript:alert(1)">click</a>,
        <a href="${evil}">again</a>, <a href="mailto:x@y.example">mail</a> and https://plain.example/x in text.</p>`,
      urlVerdicts: [{ urlSha256: defangUrl(evil).identitySha256!, verdict: 'malicious' }],
    });
    expect(p.body.text).toBe(
      'Reset password [link 1], click [link 2], again [link 1], mail [link 3] and hxxps://plain[.]example/x [link 4] in text.',
    );
    expect(p.links).toEqual([
      {
        n: 1,
        displayUrl: 'hxxps://login[.]evil[.]test/reset',
        host: 'login[.]evil[.]test',
        verdict: 'malicious',
      },
      { n: 2, displayUrl: 'javascript:[removed]', host: null, verdict: null },
      { n: 3, displayUrl: 'mailto:[removed]', host: null, verdict: null },
      { n: 4, displayUrl: 'hxxps://plain[.]example/x', host: 'plain[.]example', verdict: null },
    ]);
    clean(p.body.text);
    const listed = JSON.stringify(p.links);
    expect(listed).not.toMatch(/alert|https?:\/\/|@/);
  });
  it('entities are decoded to text (never re-parsed as markup)', () => {
    const p = html('<p>Tom &amp; Jerry &lt;b&gt;bold&lt;/b&gt; &#x41;&#66; &copy; &nbsp;x</p>');
    expect(p.body.text).toBe('Tom & Jerry <b>bold</b> AB © \u00a0x');
  });
  it('bidi overrides, zero-width and control characters are removed; NFC', () => {
    const p = preview({
      textPart: 'Pay to\u202e gpj.exe\u200b now\u0007\r\nCafe\u0301 \u2066ok\u2069',
    });
    expect(p.body.text).toBe('Pay to gpj.exe now\nCafé ok');
  });
  it('malformed and unclosed HTML still yields text', () => {
    const p = html(
      '<div><p>One<p>Two<b>bold<i>both</b>italic</div><table><tr><td>a<td>b</table><ul><li>x<li>y',
    );
    expect(p.body.text).toBe('One\n\nTwoboldbothitalic\n\na\tb\n\n- x\n- y');
  });
  it('deeply nested HTML (20 000 levels) does not overflow the stack', () => {
    const deep = '<div>'.repeat(20_000) + 'deep text' + '</div>'.repeat(20_000);
    const p = html(deep);
    expect(p.body.text).toBe('deep text');
    const b = '<b><i>'.repeat(5_000) + 'formatted' + '</i></b>'.repeat(5_000);
    expect(html(b).body.text).toBe('formatted');
  });
  it('huge input is bounded and flagged truncated', () => {
    const p = preview({ textPart: 'word '.repeat(60_000), limits: { maxTextChars: 1000 } });
    expect(p.body.text.length).toBeLessThanOrEqual(1000);
    expect(p.body.truncated).toBe(true);
    const h = preview({ htmlPart: `<p>${'x '.repeat(1_000_000)}</p>` });
    expect(h.body.truncated).toBe(true);
    expect(h.body.text.length).toBeLessThanOrEqual(100_000);
    const nodes = preview({ htmlPart: '<i>a</i>'.repeat(10_000), limits: { maxHtmlNodes: 1000 } });
    expect(nodes.body.truncated).toBe(true);
  });
  it('a value cut by the range read of the caller is not shown partially', () => {
    const p = preview({ textPart: `Pay with ${CARD.slice(0, 9)}`, partsTruncated: true });
    expect(p.body.text).toBe('Pay with');
    expect(p.body.truncated).toBe(true);
  });
});

describe('renderPreview content selection and DLP (Q11)', () => {
  it('prefers the text part; falls back to HTML; reports unavailability', () => {
    expect(preview({ textPart: 'plain', htmlPart: '<p>html</p>' }).body).toMatchObject({
      source: 'text',
      text: 'plain',
    });
    expect(preview({ textPart: '  ', htmlPart: '<p>html</p>' }).body).toMatchObject({
      source: 'html',
      text: 'html',
    });
    expect(preview({}).body).toEqual({
      source: null,
      text: '',
      truncated: false,
      unavailableReason: 'no_text_part',
    });
    expect(preview({ unavailableReason: 'purged' }).body.unavailableReason).toBe('purged');
    expect(
      preview({ unavailableReason: 'not_parsed', textPart: 'x' }).body.unavailableReason,
    ).toBeNull();
  });
  it('masks DLP values in the subject, body and header values', () => {
    const p = preview({
      subject: `Card ${CARD}`,
      headers: [
        { name: 'Reply-To', value: 'billing <john.doe@example.com>' },
        { name: 'Bad Name', value: 'x' },
      ],
      textPart: `Number ${CARD}\nIBAN GB82 WEST 1234 5698 7654 32`,
    });
    expect(p.subject).toBe(`Card 453914${MASK_CHAR.repeat(6)}6467`);
    expect(p.headers).toHaveLength(1);
    expect(p.headers[0]!.value).not.toContain('john.doe');
    expect(p.body.text).not.toMatch(/0343|WEST 1234/);
    expect(p.dlp.masked).toBe(4);
    expect(p.dlp.categories).toEqual(['bank_account', 'payment_card', 'personal_info']);
  });
  it('header values and the subject are single-line, sanitized, defanged', () => {
    const p = preview({
      subject: 'Re: see https://evil.test/x\r\nBcc: injected',
      headers: [{ name: 'List-Unsubscribe', value: '<https://news.example/u?id=1>' }],
    });
    expect(p.subject).toBe('Re: see hxxps://evil[.]test/x Bcc: injected');
    expect(p.headers[0]!.value).toBe('<hxxps://news[.]example/u?id=1>');
  });
  it('attachments are listed sanitized, never served', () => {
    const p = preview({
      attachments: [
        {
          partIndex: 2,
          filename: 'invoice\u202efdp.exe',
          declaredType: 'Application/PDF',
          detectedType: 'application/x-dosexec',
          typeFamily: 'executable',
          sizeBytes: 1024,
          sha256: 'a'.repeat(64),
          verdict: 'malicious',
          reasonCodes: ['attachment.malware'],
          downloadable: false,
        },
        {
          partIndex: 3,
          filename: null,
          declaredType: 'not a type',
          detectedType: null,
          typeFamily: 'weird',
          sizeBytes: -1,
          sha256: 'XYZ',
          verdict: null,
          reasonCodes: [],
          downloadable: true,
        },
      ],
    });
    expect(p.attachments).toEqual([
      {
        partIndex: 2,
        filename: 'invoicefdp.exe',
        declaredType: 'application/pdf',
        detectedType: 'application/x-dosexec',
        typeFamily: 'executable',
        sizeBytes: 1024,
        sha256: 'a'.repeat(64),
        verdict: 'malicious',
        reasonCodes: ['attachment.malware'],
        downloadable: false,
      },
      {
        partIndex: 3,
        filename: null,
        declaredType: null,
        detectedType: null,
        typeFamily: null,
        sizeBytes: 0,
        sha256: null,
        verdict: null,
        reasonCodes: [],
        downloadable: true,
      },
    ]);
  });
  it('lists at most maxLinks links', () => {
    const links = Array.from(
      { length: 5 },
      (_, i) => `<a href="https://l${i}.example/">l</a>`,
    ).join(' ');
    const p = preview({ htmlPart: links, limits: { maxLinks: 3 } });
    expect(p.links).toHaveLength(3);
    expect(p.linksTruncated).toBe(true);
  });
});

describe('htmlToPreviewText', () => {
  it('registers links in document order', () => {
    const seen: string[] = [];
    const r = htmlToPreviewText(
      '<a href="b">x</a><area href="c">',
      { maxChars: 1000, maxNodes: 1000 },
      (h) => {
        seen.push(h);
        return seen.length;
      },
    );
    expect(seen).toEqual(['b', 'c']);
    expect(r.text).toBe('x [link 1] [link 2]');
  });
});
