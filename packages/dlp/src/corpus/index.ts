import type {
  DlpDetectorId,
  DlpNotExtractedReason,
  DlpSourceKind,
} from '@email-gateway/security-contracts';
import type { TenantPatternInput } from '../custom';
import type { TenantDictionaryInput } from '../dictionaries';
import {
  buildDocx,
  buildOdt,
  buildOds,
  buildPptx,
  buildXlsx,
  buildZip,
  markZipEncrypted,
  OLE_HEADER,
  TINY_PNG,
} from './office';
import { buildPdf } from './pdf-writer';
import { Prng, Synthetic, type Manifest } from './synthetic';

export * from './office';
export * from './pdf-writer';
export * from './synthetic';

/**
 * The DLP fixture corpus (step 4.5 §9), built in memory from a seeded PRNG: true positives for
 * every detector in plain text, HTML, CSV, PDF, DOCX, XLSX, PPTX, ODT, ODS, ZIP and nested ZIP
 * with expected findings and coverage; the false-positive set (no reportable finding); and the
 * not-extracted set (never clean). Every sensitive-looking value is in the manifest.
 */

export interface CorpusExpectation {
  /** Reportable findings: detector → distinct count (exact; no other detector may report). */
  findings: Partial<Record<DlpDetectorId, number>>;
  coverage: 'complete' | 'partial';
  /** Not-extracted reasons of the attachment (attachment fixtures). */
  reasons?: DlpNotExtractedReason[];
}

export interface TextFixture {
  id: string;
  kind: 'text';
  source: DlpSourceKind;
  format: 'text' | 'html' | 'csv';
  segmentKind: 'text' | 'html' | 'table';
  text: string;
  expected: CorpusExpectation;
  aadhaarEnabled?: boolean;
  envelopeAddresses?: string[];
}

export interface AttachmentFixture {
  id: string;
  kind: 'attachment';
  bytes: Buffer;
  filenameExt: string | null;
  declaredContentType: string | null;
  expected: CorpusExpectation;
  aadhaarEnabled?: boolean;
}

export type CorpusFixture = TextFixture | AttachmentFixture;

export interface FalsePositiveFixture {
  id: string;
  text: string;
  /** The detector a careless implementation would fire. */
  confusable: DlpDetectorId;
}

export interface DlpCorpus {
  fixtures: CorpusFixture[];
  falsePositives: FalsePositiveFixture[];
  /** Attachments that cannot be (fully) extracted: never clean. */
  notExtracted: AttachmentFixture[];
  tenantDictionaries: TenantDictionaryInput[];
  tenantPatterns: TenantPatternInput[];
  manifest: Manifest;
}

const FILLER =
  'The quarterly planning notes follow below, with the usual agenda items and room bookings for the week.';

const group4 = (digits: string) => digits.replace(/(.{4})(?=.)/g, '$1 ');
const ibanPrint = (iban: string) => iban.replace(/(.{4})(?=.)/g, '$1 ');

export const CORPUS_DICTIONARY_ID = '0196f3a0-0000-7000-8000-00000000d1c1';
export const CORPUS_PATTERN_ID = '0196f3a0-0000-7000-8000-00000000c0de';

/** Builds the corpus for a seed (default 4505). */
export async function buildCorpus(seed = 4505): Promise<DlpCorpus> {
  const s = new Synthetic(new Prng(seed));
  const fixtures: CorpusFixture[] = [];

  // --- plain text: one value per detector, separated by neutral filler (> context window) ---
  const card = s.card('4532');
  const iban = s.iban('GB');
  const ifsc = s.ifsc();
  const account = s.accountNumber(14);
  const swift = s.swift();
  const pan = s.pan('P');
  const aadhaar = s.aadhaar();
  const passport = s.passport();
  const mrz = s.mrzTd3();
  const email = s.email();
  const mobile = s.mobile();
  const dob = s.dob();
  const gstin = s.gstin();
  const pem = s.pemPrivateKey();
  const awsId = s.awsKeyId();
  const awsSecret = s.awsSecret();
  const jwt = s.jwt();
  const github = s.githubToken();
  const lines = [
    `Card: ${group4(card)} exp 09/29`,
    `IBAN: ${ibanPrint(iban)}`,
    `Bank IFSC ${ifsc} account number ${account}`,
    `SWIFT code ${swift}`,
    `PAN: ${pan}`,
    `Aadhaar: ${group4(aadhaar)}`,
    `Passport no ${passport}`,
    `${mrz.lines[0]}\n${mrz.lines[1]}`,
    `Write to ${email}`,
    `Mobile: +91 ${mobile.slice(0, 5)} ${mobile.slice(5)}`,
    `Date of birth: ${dob}`,
    `GSTIN ${gstin}`,
    'STRICTLY CONFIDENTIAL',
    'Attached: the merger agreement and the term sheet.',
    pem,
    `aws_access_key_id = ${awsId}\naws_secret_access_key = ${awsSecret}`,
    `Bearer ${jwt}`,
    `token ${github}`,
  ];
  fixtures.push({
    id: 'text.every-detector',
    kind: 'text',
    source: 'body_text',
    format: 'text',
    segmentKind: 'text',
    text: lines.join(`\n${FILLER}\n`),
    aadhaarEnabled: true,
    expected: {
      findings: {
        PC1: 1,
        BA1: 1,
        BA2: 1,
        BA3: 1,
        NI1: 1,
        NI2: 1,
        PP1: 1,
        PP2: 1,
        PI1: 1,
        PI2: 1,
        PI3: 1,
        PI4: 1,
        CF1: 2,
        CF2: 2,
        CR1: 1,
        CR2: 1,
        CR3: 1,
        CR4: 1,
        CR5: 1,
      },
      coverage: 'complete',
    },
  });
  fixtures.push({
    id: 'text.aadhaar-gated-off',
    kind: 'text',
    source: 'body_text',
    format: 'text',
    segmentKind: 'text',
    text: `Aadhaar: ${group4(aadhaar)}`,
    aadhaarEnabled: false,
    expected: { findings: {}, coverage: 'complete' },
  });

  // --- HTML body ---
  const htmlCard = s.card('5412');
  const htmlPan = s.pan('C');
  fixtures.push({
    id: 'html.table',
    kind: 'text',
    source: 'body_html',
    format: 'html',
    segmentKind: 'html',
    text: `<!doctype html><html><head><style>.x{}</style></head><body><p>Hello,</p><table><tr><td>Credit card</td><td>${group4(htmlCard)}</td></tr></table><p>${FILLER}</p><p>Company PAN ${htmlPan}</p><script>var t = "${s.card('4532')}";</script></body></html>`,
    expected: { findings: { PC1: 1, NI1: 1 }, coverage: 'complete' },
  });

  // --- CSV: column context + bulk ---
  const csvCards = Array.from({ length: 20 }, () => s.card('4485'));
  fixtures.push({
    id: 'csv.card-column',
    kind: 'text',
    source: 'attachment',
    format: 'csv',
    segmentKind: 'table',
    text: ['name\tcard_number\tcity', ...csvCards.map((c, i) => `Person ${i}\t${c}\tPune`)].join(
      '\n',
    ),
    expected: { findings: { PC1: 20 }, coverage: 'complete' },
  });

  // --- FI1, SC1 ---
  fixtures.push({
    id: 'text.salary-slip',
    kind: 'text',
    source: 'body_text',
    format: 'text',
    segmentKind: 'text',
    text: 'Salary slip for October 2026. Gross pay ₹ 85,000; deductions Rs. 5,000; net pay INR 80,000.',
    expected: { findings: { FI1: 1 }, coverage: 'complete' },
  });
  const python = [
    '#!/usr/bin/env python3',
    'import os',
    'from pathlib import Path',
    '',
    'def load(path):',
    '    with open(path) as handle:',
    '        return handle.read()',
    '',
    'class Report:',
    '    def __init__(self, rows):',
    '        self.rows = rows',
    '',
    '    def total(self):',
    '        return sum(row.amount for row in self.rows)',
    '',
    'if __name__ == "__main__":',
    '    print(Report([]).total())',
  ].join('\n');
  fixtures.push({
    id: 'text.source-code',
    kind: 'text',
    source: 'body_text',
    format: 'text',
    segmentKind: 'text',
    text: python,
    expected: { findings: { SC1: 1 }, coverage: 'complete' },
  });

  // --- DC1, CU1 (tenant data) ---
  const employee = s.manifest.add('CU1', `EMP-${s.rng.digits(6)}`);
  fixtures.push({
    id: 'text.tenant-dictionary-and-pattern',
    kind: 'text',
    source: 'body_text',
    format: 'text',
    segmentKind: 'text',
    text: `Status of Project Nightingale: on track.\n${FILLER}\nEmployee id ${employee} joined.`,
    expected: { findings: { DC1: 1, CU1: 1 }, coverage: 'complete' },
  });

  // --- attachments ---
  const pdfCard = s.card('4916');
  const pdfPan = s.pan('P');
  fixtures.push({
    id: 'pdf.text-layer',
    kind: 'attachment',
    bytes: buildPdf([[`Card number ${group4(pdfCard)}`, FILLER], [`PAN ${pdfPan}`]], {
      compress: true,
    }),
    filenameExt: 'pdf',
    declaredContentType: 'application/pdf',
    expected: { findings: { PC1: 1, NI1: 1 }, coverage: 'complete' },
  });
  const docxCard = s.card('4024');
  const docxPan = s.pan('P');
  const docxIban = s.iban('DE');
  fixtures.push({
    id: 'docx.body-header-footnote',
    kind: 'attachment',
    bytes: await buildDocx({
      body: [`Debit card ${group4(docxCard)}`, FILLER],
      header: [`PAN ${docxPan}`],
      footnote: [`Beneficiary IBAN ${docxIban}`],
    }),
    filenameExt: 'docx',
    declaredContentType: null,
    expected: { findings: { PC1: 1, NI1: 1, BA1: 1 }, coverage: 'complete' },
  });
  const xlsxPans = Array.from({ length: 6 }, () => s.pan('P'));
  const xlsxIfsc = s.ifsc();
  const xlsxAccounts = xlsxPans.map(() => Number(s.accountNumber(12)));
  fixtures.push({
    id: 'xlsx.shared-numeric-header',
    kind: 'attachment',
    bytes: await buildXlsx({
      rows: [
        ['Employee', 'PAN', 'IFSC', 'Account', 'Salary'],
        ...xlsxPans.map((p, i) => [`Employee ${i}`, p, xlsxIfsc, xlsxAccounts[i]!, 50_000 + i]),
      ],
    }),
    filenameExt: 'xlsx',
    declaredContentType: null,
    expected: { findings: { NI1: 6, BA2: 6 }, coverage: 'complete' },
  });
  const pptxPassport = s.passport();
  const pptxMobile = s.mobile();
  fixtures.push({
    id: 'pptx.slide-notes',
    kind: 'attachment',
    bytes: await buildPptx(
      [[`Travel desk: passport number ${pptxPassport}`]],
      [`Contact mobile ${pptxMobile}`],
    ),
    filenameExt: 'pptx',
    declaredContentType: null,
    expected: { findings: { PP1: 1, PI2: 1 }, coverage: 'complete' },
  });
  const odtGstin = s.gstin();
  fixtures.push({
    id: 'odt.body-footer',
    kind: 'attachment',
    bytes: await buildOdt([`Supplier GSTIN ${odtGstin}`], ['COMPANY CONFIDENTIAL']),
    filenameExt: 'odt',
    declaredContentType: null,
    expected: { findings: { PI4: 1, CF1: 2 }, coverage: 'complete' },
  });
  const odsCards = Array.from({ length: 5 }, () => s.card('4539'));
  fixtures.push({
    id: 'ods.table',
    kind: 'attachment',
    bytes: await buildOds([
      ['Card number', 'Holder'],
      ...odsCards.map((c, i) => [c, `Holder ${i}`]),
    ]),
    filenameExt: 'ods',
    declaredContentType: null,
    expected: { findings: { PC1: 5 }, coverage: 'complete' },
  });
  const zipDocxCard = s.card('4556');
  const zipCsvCards = Array.from({ length: 5 }, () => s.card('4716'));
  const innerDocx = await buildDocx({ body: [`Visa card ${group4(zipDocxCard)}`] });
  const zip = await buildZip([
    { name: 'letters/offer.docx', data: innerDocx },
    {
      name: 'exports/cards.csv',
      data: ['holder,card_number', ...zipCsvCards.map((c, i) => `H${i},${c}`)].join('\n'),
    },
  ]);
  fixtures.push({
    id: 'zip.docx-and-csv',
    kind: 'attachment',
    bytes: zip,
    filenameExt: 'zip',
    declaredContentType: 'application/zip',
    expected: { findings: { PC1: 6 }, coverage: 'complete' },
  });
  const nestedKey = s.pemPrivateKey('OPENSSH PRIVATE KEY');
  const nested = await buildZip([
    { name: 'inner.zip', data: await buildZip([{ name: 'keys/id_ed25519', data: nestedKey }]) },
    { name: 'readme.txt', data: 'Deployment notes for the build server.' },
  ]);
  fixtures.push({
    id: 'zip.nested-depth-2',
    kind: 'attachment',
    bytes: nested,
    filenameExt: 'zip',
    declaredContentType: 'application/zip',
    expected: { findings: { CR1: 1 }, coverage: 'complete' },
  });
  const docxWithImage = await buildDocx({
    body: ['Quarterly update, no sensitive content.'],
    image: TINY_PNG,
  });
  fixtures.push({
    id: 'docx.embedded-image',
    kind: 'attachment',
    bytes: docxWithImage,
    filenameExt: 'docx',
    declaredContentType: null,
    expected: { findings: {}, coverage: 'partial', reasons: ['image'] },
  });

  // --- not extracted (never clean) ---
  const notExtracted: AttachmentFixture[] = [];
  const secretCard = s.card('4532');
  notExtracted.push({
    id: 'zip.encrypted',
    kind: 'attachment',
    bytes: markZipEncrypted(await buildZip([{ name: 'cards.txt', data: `Card ${secretCard}` }])),
    filenameExt: 'zip',
    declaredContentType: 'application/zip',
    expected: { findings: {}, coverage: 'partial', reasons: ['encrypted'] },
  });
  notExtracted.push({
    id: 'pdf.password',
    kind: 'attachment',
    bytes: buildPdf([[`Card ${group4(secretCard)}`]], { userPassword: 'synthetic' }),
    filenameExt: 'pdf',
    declaredContentType: 'application/pdf',
    expected: { findings: {}, coverage: 'partial', reasons: ['encrypted'] },
  });
  notExtracted.push({
    id: 'pdf.image-only',
    kind: 'attachment',
    bytes: buildPdf([[], []], { imageOnly: true }),
    filenameExt: 'pdf',
    declaredContentType: 'application/pdf',
    expected: { findings: {}, coverage: 'partial', reasons: ['no_text_layer'] },
  });
  notExtracted.push({
    id: 'png.image',
    kind: 'attachment',
    bytes: TINY_PNG,
    filenameExt: 'png',
    declaredContentType: 'image/png',
    expected: { findings: {}, coverage: 'partial', reasons: ['image'] },
  });
  notExtracted.push({
    id: 'doc.ole',
    kind: 'attachment',
    bytes: OLE_HEADER,
    filenameExt: 'doc',
    declaredContentType: 'application/msword',
    expected: { findings: {}, coverage: 'partial', reasons: ['unsupported_type'] },
  });
  notExtracted.push({
    id: 'zip.over-entry-limit',
    kind: 'attachment',
    bytes: await buildZip(
      Array.from({ length: 6 }, (_, i) => ({ name: `f${i}.txt`, data: `note ${i}` })),
    ),
    filenameExt: 'zip',
    declaredContentType: 'application/zip',
    expected: { findings: {}, coverage: 'partial', reasons: ['archive_limit'] },
  });

  // --- false positives (expected: no reportable finding) ---
  const fp = (id: string, confusable: DlpDetectorId, text: string): FalsePositiveFixture => ({
    id,
    text,
    confusable,
  });
  const bareLuhn = s.card('4532');
  const orderLuhn = s.card('4539');
  const failing = s.aadhaarInvalid();
  const falsePositives: FalsePositiveFixture[] = [
    fp('luhn-without-context', 'PC1', `Reference list: ${bareLuhn} was printed on the label.`),
    fp('order-id', 'PC1', `Order #${orderLuhn} has shipped and will arrive on Friday.`),
    fp('tracking-number', 'PC1', 'Tracking no. 1Z999AA10123456784 via the courier.'),
    fp('awb-number', 'NI2', 'AWB 7834 5612 9087 for the parcel.'),
    fp('invoice-number', 'PC1', 'Please pay invoice INV-2026-000123 by the end of the month.'),
    fp('phone-like-card', 'PC1', 'Call +91 98765 43210 or the IVR line 1800 2345 6789 0123.'),
    fp('verhoeff-invalid', 'NI2', `Aadhaar ${group4(failing)}`),
    fp('aadhaar-leading-0-1', 'NI2', 'Aadhaar 1234 5678 9012 and 0987 6543 2109'),
    fp('test-card-visa', 'PC1', 'Use the card 4111 1111 1111 1111 in the sandbox.'),
    fp('test-card-stripe', 'PC1', 'Card 4242 4242 4242 4242 expires 12/34.'),
    fp('pan-in-code', 'NI1', 'const PAN = "ABCPD1234E";'),
    fp('pan-regex', 'NI1', 'PAN_REGEX = /[A-Z]{5}[0-9]{4}[A-Z]/'),
    fp(
      'base64-image',
      'CR3',
      'data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNkYPhfDwAChwGA60e6kgAAAABJRU5ErkJggg==',
    ),
    fp(
      'pgp-public-key',
      'CR1',
      '-----BEGIN PGP PUBLIC KEY BLOCK-----\nmQINBGB1c2VzeW50aGV0aWNwdWJsaWNrZXlibG9ja2Zvcm5vdGhpbmc=\n-----END PGP PUBLIC KEY BLOCK-----',
    ),
    fp('uuid', 'PC1', 'Request id 123e4567-e89b-12d3-a456-426614174000 failed.'),
    fp('timestamps', 'PI2', 'Logged at 1730956800 (2026-11-07T10:20:30Z).'),
    fp('git-sha', 'CR3', 'Fixed in commit 3f786850e387550fdab836ed7e6dc881de23001b on main.'),
    fp('iban-bad-checksum', 'BA1', 'IBAN GB82 WEST 1234 5698 7654 33'),
    fp('swift-like-word', 'BA3', 'The DEUTDEFF report and the BARCGB22 summary are attached.'),
    fp(
      'disclaimer',
      'CF1',
      'CONFIDENTIALITY NOTICE: This e-mail and any attachments are confidential and intended solely for the addressee. If you have received this email in error, please notify the sender.',
    ),
    fp(
      'aws-example-key',
      'CR2',
      'aws_access_key_id = AKIAIOSFODNN7EXAMPLE\naws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY',
    ),
    fp('jwt-like-not-json', 'CR4', 'session eyJub3QganNvbg.eyJhYmM.c2lnbmF0dXJl'),
    fp('passport-like-without-context', 'PP1', 'Room K1234567 on floor two.'),
    fp('date-without-context', 'PI3', 'The meeting was moved to 12/03/2026.'),
  ];

  const tenantDictionaries: TenantDictionaryInput[] = [
    {
      id: CORPUS_DICTIONARY_ID,
      version: 1,
      category: 'confidential',
      terms: ['Project Nightingale', 'Falcon launch plan'],
      severity: 'high',
      baseConfidence: 0.7,
      minMatches: 1,
    },
  ];
  const tenantPatterns: TenantPatternInput[] = [
    {
      id: CORPUS_PATTERN_ID,
      version: 1,
      pattern: 'EMP-[0-9]{6}',
      caseInsensitive: false,
      validator: 'none',
      contextKeywords: ['employee'],
      requireContext: false,
      severity: 'medium',
      baseConfidence: 0.6,
      maskStyle: 'last4',
    },
  ];
  return {
    fixtures,
    falsePositives,
    notExtracted,
    tenantDictionaries,
    tenantPatterns,
    manifest: s.manifest,
  };
}
