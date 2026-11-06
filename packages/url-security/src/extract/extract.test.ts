import iconv from 'iconv-lite';
import { describe, expect, it } from 'vitest';
import { decodeLossless, decodeText, isRewritableCharset, sniffHtmlCharset } from './charset';
import { anchorTextMismatch, extractMessageUrls, rewritableOccurrences } from './collect';
import { extractFromHtml, findMetaRefresh, metaRefreshUrl, srcsetUrls } from './html';
import { extractFromText } from './text';
import { normalizeUrl } from '../normalize/url';

const candidates = (html: string): string[] =>
  extractFromHtml(html).occurrences.map((o) => o.candidate);

describe('extractFromHtml', () => {
  it('reads every listed URL attribute with its source kind', () => {
    const html = `
      <a href="http://a.test/1">a</a>
      <area href="http://a.test/2">
      <link href="http://a.test/3" rel=stylesheet>
      <form action="http://a.test/4"><button formaction="http://a.test/5">b</button><input formaction="http://a.test/6"></form>
      <iframe src="http://a.test/7"></iframe>
      <img src="http://a.test/9"><script src="http://a.test/10"></script><embed src="http://a.test/11">
      <video src="http://a.test/12"><source src="http://a.test/13"><track src="http://a.test/14"></video>
      <audio src="http://a.test/15"></audio><object data="http://a.test/16"></object>
      <img srcset="http://a.test/17 1x, http://a.test/18 2x">
      <meta http-equiv="Refresh" content="0; URL='http://a.test/19'">`;
    const result = extractFromHtml(html);
    const bySource = Object.fromEntries(
      result.occurrences.map((o) => [o.candidate.split('/').pop(), o.source]),
    );
    expect(Object.keys(bySource)).toHaveLength(18);
    expect(bySource['1']).toBe('html_href');
    expect(bySource['3']).toBe('html_href');
    expect(bySource['4']).toBe('form_action');
    expect(bySource['5']).toBe('form_action');
    expect(bySource['7']).toBe('html_src');
    expect(bySource['16']).toBe('html_src');
    expect(bySource['17']).toBe('srcset');
    expect(bySource['19']).toBe('meta_refresh');
    const rewritable = result.occurrences.filter((o) => o.rewritable).map((o) => o.candidate);
    expect(rewritable).toEqual(['http://a.test/1', 'http://a.test/2']);
  });

  it('reads frame[src] inside a frameset', () => {
    const result = extractFromHtml('<frameset><frame src="http://a.test/8"></frameset>');
    expect(result.occurrences.map((o) => [o.candidate, o.source])).toEqual([
      ['http://a.test/8', 'html_src'],
    ]);
  });

  it('resolves relative URLs against the first absolute http(s) base, ignores them without one', () => {
    expect(candidates('<base href="http://b.test/x/"><a href="y">1</a><a href="/z">2</a>')).toEqual(
      ['http://b.test/x/y', 'http://b.test/z'],
    );
    expect(candidates('<a href="relative">x</a><a href="//proto.test/">y</a>')).toEqual([]);
    expect(candidates('<base href="file:///etc/"><a href="y">x</a>')).toEqual([]);
  });

  it('ignores mailto, tel, sms, cid and fragments', () => {
    expect(
      candidates(
        '<a href="mailto:a@b.test">m</a><a href="tel:+1">t</a><a href="sms:1">s</a><img src="cid:x"><a href="#top">f</a>',
      ),
    ).toEqual([]);
  });

  it('counts dangerous schemes per message without URL rows', () => {
    const result = extractFromHtml(
      '<a href="javascript:alert(1)">j</a><a href=" JaVaScRiPt:x">j2</a><a href="vbscript:x">v</a>' +
        '<a href="data:text/html;base64,AAAA">d</a><iframe src="data:text/html,x"></iframe><img src="data:image/png;base64,AA">' +
        '<a href="file:///etc/passwd">f</a><a href="smb://host/share">s</a><a href="\\\\host\\share">u</a>',
    );
    expect(result.occurrences).toEqual([]);
    expect(result.messageCodes).toEqual({
      'url.script_scheme': 3,
      'url.data_uri': 2,
      'url.unsafe_scheme': 3,
    });
  });

  it('flags entities in the scheme/host part of the raw attribute source and control characters', () => {
    const result = extractFromHtml(
      '<a href="&#104;ttp://a.test/">1</a><a href="http&colon;//b.test/">2</a><a href="http://c.test/&amp;x">3</a>' +
        '<a href="http://d.te&#x73;t/">4</a><a href="http://e.test/\tx">5</a>',
    );
    expect(result.occurrences.map((o) => o.candidate)).toEqual([
      'http://a.test/',
      'http://b.test/',
      'http://c.test/&x',
      'http://d.test/',
      'http://e.test/\tx',
    ]);
    expect(result.occurrences[0]?.flags).toContain('url.entity_obfuscation');
    expect(result.occurrences[1]?.flags).toContain('url.entity_obfuscation');
    expect(result.occurrences[2]?.flags).not.toContain('url.entity_obfuscation');
    expect(result.occurrences[3]?.flags).toContain('url.entity_obfuscation');
    expect(result.occurrences[4]?.flags).toContain('url.control_chars');
  });

  it('reports the whole attribute range in the source (single, double and no quotes; CRLF and emoji)', () => {
    const html =
      '😀<a\r\nHREF="http://a.test/" class=x>x</a><a href=\'http://b.test/\'>y</a><a href=http://c.test/>z</a>';
    const result = extractFromHtml(html);
    expect(result.occurrences.map((o) => html.slice(o.range.start, o.range.end))).toEqual([
      'HREF="http://a.test/"',
      "href='http://b.test/'",
      'href=http://c.test/',
    ]);
  });

  it('keeps the anchor text in memory for a', () => {
    const [occurrence] = extractFromHtml(
      '<a href="http://evil.test/">https://<b>paypal.com</b>/login</a>',
    ).occurrences;
    expect(occurrence?.anchorText).toBe('https://paypal.com/login');
  });

  it('parses srcset candidates and meta refresh content', () => {
    expect(srcsetUrls('a.png 1x, b.png 2x,c.png,  d,e.png 100w')).toEqual([
      'a.png',
      'b.png',
      'c.png',
      'd,e.png',
    ]);
    expect(metaRefreshUrl('5; url=http://x.test/')).toBe('http://x.test/');
    expect(metaRefreshUrl("0;URL='http://y.test/a b'")).toBe('http://y.test/a b');
    expect(metaRefreshUrl('10')).toBeNull();
    expect(
      findMetaRefresh(
        '<html><head><meta http-equiv="refresh" content="0;url=/next"></head></html>',
      ),
    ).toBe('/next');
    expect(findMetaRefresh('<p>no</p>')).toBeNull();
  });

  it('stops at the occurrence bound and sets limit.url_count', () => {
    const html = Array.from({ length: 20 }, (_, i) => `<a href="http://a.test/${i}">x</a>`).join(
      '',
    );
    const result = extractFromHtml(html, { maxOccurrences: 5 });
    expect(result.occurrences).toHaveLength(5);
    expect(result.limitHit).toBe(true);
    expect(result.messageCodes['limit.url_count']).toBe(1);
  });

  it('survives deeply nested markup (no recursion)', () => {
    const html = `${'<div>'.repeat(5000)}<a href="http://deep.test/">d</a>`;
    expect(candidates(html)).toEqual(['http://deep.test/']);
  });
});

describe('extractFromText', () => {
  const urls = (text: string): string[] => extractFromText(text).occurrences.map((o) => o.raw);

  it('finds http, https (any case) and www. URLs', () => {
    expect(urls('see http://a.test/x and HTTPS://B.test/y or www.c.test/z.')).toEqual([
      'http://a.test/x',
      'HTTPS://B.test/y',
      'www.c.test/z',
    ]);
    expect(extractFromText('www.c.test').occurrences[0]?.candidate).toBe('http://www.c.test');
  });

  it('terminates at whitespace, <, >, " and drops trailing punctuation unless balanced', () => {
    expect(urls('(see http://a.test/x).')).toEqual(['http://a.test/x']);
    expect(urls('http://a.test/wiki/Foo_(bar) and more')).toEqual(['http://a.test/wiki/Foo_(bar)']);
    expect(urls('"http://a.test/q"')).toEqual(['http://a.test/q']);
    expect(urls('http://a.test/a,http://b.test/b')).toEqual(['http://a.test/a,http://b.test/b']);
    expect(urls("end http://a.test/x?!;:'")).toEqual(['http://a.test/x']);
    expect(urls('[http://a.test/x]')).toEqual(['http://a.test/x']);
  });

  it('handles <URL:…> and <…> wrappers', () => {
    expect(urls('<URL:http://a.test/x> <http://b.test/y>')).toEqual([
      'http://a.test/x',
      'http://b.test/y',
    ]);
  });

  it('does not start inside words, hosts or paths', () => {
    expect(urls('xhttp://a.test/ foo.www.b.test /www.c.test http://')).toEqual([]);
  });

  it('reports exact ranges', () => {
    const text = 'go http://a.test/x.';
    const [occurrence] = extractFromText(text).occurrences;
    expect(text.slice(occurrence?.range.start, occurrence?.range.end)).toBe('http://a.test/x');
  });

  it('applies the occurrence bound', () => {
    const result = extractFromText('http://a.test/ '.repeat(10), { maxOccurrences: 3 });
    expect(result.occurrences).toHaveLength(3);
    expect(result.messageCodes['limit.url_count']).toBe(1);
  });
});

describe('extractMessageUrls', () => {
  it('dedupes by identity hash, counts sources and occurrences, keeps first-seen order', () => {
    const result = extractMessageUrls([
      {
        kind: 'text',
        origin: 'body',
        content: 'http://a.test/x http://b.test/ http://A.test/x#frag',
      },
      {
        kind: 'html',
        origin: 'body',
        content: '<a href="http://a.test/x">x</a><img src="http://c.test/i.png">',
      },
    ]);
    expect(result.urls.map((u) => u.url.identity)).toEqual([
      'http://a.test/x',
      'http://b.test/',
      'http://c.test/i.png',
    ]);
    expect(result.urls[0]?.sources).toEqual({ text: 2, html_href: 1 });
    expect(result.urls[0]?.occurrences).toBe(3);
    expect(result.sourceCounts).toEqual({ text: 3, html_href: 1, html_src: 1 });
    expect(result.limitHit).toBe(false);
  });

  it('marks attachment-only URLs and never marks body URLs', () => {
    const result = extractMessageUrls([
      { kind: 'text', origin: 'body', content: 'http://body.test/' },
      {
        kind: 'html',
        origin: 'attachment',
        content: '<a href="http://att.test/">x</a><a href="http://body.test/">y</a>',
      },
    ]);
    const att = result.urls.find((u) => u.url.host === 'att.test');
    const body = result.urls.find((u) => u.url.host === 'body.test');
    expect(att?.attachmentOnly).toBe(true);
    expect(att?.flags).toContain('url.in_attachment');
    expect(att?.sources).toEqual({ attachment: 1 });
    expect(body?.attachmentOnly).toBe(false);
    expect(body?.flags).not.toContain('url.in_attachment');
  });

  it('applies the unique-URL bound and the occurrence bound across parts', () => {
    const many = Array.from({ length: 10 }, (_, i) => `http://u${i}.test/`).join(' ');
    const limited = extractMessageUrls([{ kind: 'text', origin: 'body', content: many }], {
      maxOccurrences: 100,
      maxUrls: 4,
      maxLength: 2048,
    });
    expect(limited.urls).toHaveLength(4);
    expect(limited.messageCodes['limit.url_count']).toBe(1);
    const occurrences = extractMessageUrls(
      [
        { kind: 'text', origin: 'body', content: many },
        { kind: 'text', origin: 'body', content: many },
      ],
      { maxOccurrences: 12, maxUrls: 200, maxLength: 2048 },
    );
    expect(occurrences.limitHit).toBe(true);
  });

  it('counts invalid URLs, merges message codes, adds charset_guess and text mismatch', () => {
    const result = extractMessageUrls([
      {
        kind: 'html',
        origin: 'body',
        content:
          '<a href="http://xn--a.com/">bad</a><a href="javascript:x">j</a><a href="http://evil.test/">https://paypal.com/</a>',
      },
      { kind: 'text', origin: 'attachment', content: 'http://guess.test/', charsetGuess: true },
    ]);
    expect(result.messageCodes).toMatchObject({ 'url.invalid': 1, 'url.script_scheme': 1 });
    expect(result.urls.find((u) => u.url.host === 'evil.test')?.flags).toContain(
      'url.text_mismatch',
    );
    expect(result.urls.find((u) => u.url.host === 'guess.test')?.flags).toContain(
      'url.charset_guess',
    );
  });

  it('keeps too-long URLs truncated with the full-form hash', () => {
    const long = `http://long.test/${'x'.repeat(3000)}`;
    const result = extractMessageUrls([{ kind: 'text', origin: 'body', content: long }]);
    expect(result.urls[0]?.url.truncated).toBe(true);
    expect(result.urls[0]?.url.stored).toHaveLength(2048);
    expect(result.urls[0]?.flags).toContain('url.too_long');
  });
});

describe('anchorTextMismatch', () => {
  const href = (url: string) => {
    const r = normalizeUrl(url);
    if (!r.ok) throw new Error('bad');
    return r.url;
  };
  it('flags URL-like text on another registrable domain only', () => {
    expect(anchorTextMismatch('https://paypal.com/login', href('http://evil.test/'))).toBe(true);
    expect(anchorTextMismatch('www.paypal.com', href('http://evil.test/'))).toBe(true);
    expect(anchorTextMismatch('paypal.com', href('http://evil.test/'))).toBe(true);
    expect(anchorTextMismatch('https://www.paypal.com/x', href('https://login.paypal.com/'))).toBe(
      false,
    );
    expect(anchorTextMismatch('Click here', href('http://evil.test/'))).toBe(false);
    expect(anchorTextMismatch('report.pdf', href('http://evil.test/'))).toBe(false);
    expect(anchorTextMismatch(null, href('http://evil.test/'))).toBe(false);
  });
});

describe('rewritableOccurrences', () => {
  it('returns a/area hrefs (html) and every text URL', () => {
    expect(
      rewritableOccurrences('html', '<a href="http://a.test/">a</a><img src="http://b.test/">').map(
        (o) => o.candidate,
      ),
    ).toEqual(['http://a.test/']);
    expect(
      rewritableOccurrences('text', 'http://a.test/ www.b.test').map((o) => o.candidate),
    ).toEqual(['http://a.test/', 'http://www.b.test']);
  });
});

describe('charset helpers', () => {
  it('decodes attachments with the declared charset, the meta charset, else UTF-8 (guessed)', () => {
    const latin = iconv.encode('<p>café http://a.test/</p>', 'iso-8859-1');
    expect(decodeText(latin, 'ISO-8859-1', 'html')).toMatchObject({
      charset: 'iso-8859-1',
      guessed: false,
    });
    const meta = Buffer.concat([
      Buffer.from('<meta charset="windows-1252">'),
      iconv.encode('€', 'windows-1252'),
    ]);
    expect(sniffHtmlCharset(meta)).toBe('windows-1252');
    expect(decodeText(meta, null, 'html')).toMatchObject({
      charset: 'windows-1252',
      guessed: false,
      text: '<meta charset="windows-1252">€',
    });
    expect(decodeText(Buffer.from('x'), null, 'text')).toMatchObject({
      charset: 'utf-8',
      guessed: true,
    });
    expect(decodeText(Buffer.from('x'), 'x-unknown', 'text')).toMatchObject({ guessed: true });
  });

  it('requires a lossless round trip and refuses ASCII-incompatible charsets for rewriting', () => {
    expect(decodeLossless(Buffer.from('héllo', 'utf8'), 'utf-8')).toBe('héllo');
    expect(decodeLossless(Buffer.from([0xff, 0xfe, 0x41]), 'utf-8')).toBeNull();
    expect(decodeLossless(iconv.encode('日本語', 'shift_jis'), 'shift_jis')).toBe('日本語');
    expect(isRewritableCharset('utf-8')).toBe(true);
    expect(isRewritableCharset('windows-1252')).toBe(true);
    for (const charset of [
      'utf-16',
      'UTF-16LE',
      'utf-32',
      'utf-7',
      'iso-2022-jp',
      'cp037',
      'x-nonexistent',
    ]) {
      expect(isRewritableCharset(charset)).toBe(false);
    }
  });
});
