import { describe, expect, it } from 'vitest';
import { postfixPostmasterCopy, singleHardBounce } from '../../integration/support/dsn-fixtures';
import {
  headerTraces,
  parseDeliveryStatus,
  parseDeliveryStatusGroups,
  parseDsnDate,
  parseDsnNotice,
  typedValue,
} from './dsn-parser';

describe('parseDsnNotice (Postfix 3.7 postmaster copies)', () => {
  it('parses a single hard bounce', async () => {
    const notice = await parseDsnNotice(
      Buffer.from(singleHardBounce('4ZbK3B2xyzQ', 'alice@Acme.Test', 'Hard-Bounce@sink.test')),
    );
    expect(notice).toEqual({
      reportingMta: 'out.gateway.local',
      queueId: '4ZbK3B2xyzQ',
      sender: 'alice@Acme.Test',
      occurredAt: new Date('2026-11-02T10:00:00.000Z'),
      noticeDate: new Date('2026-11-02T10:05:00.000Z'),
      envelopeId: null,
      recipients: [
        {
          finalRecipient: 'hard-bounce@sink.test',
          originalRecipient: 'Hard-Bounce@sink.test',
          action: 'failed',
          status: '5.1.1',
          remoteMta: 'mx.sink.test',
          diagnosticCode:
            'smtp; 550 5.1.1 <Hard-Bounce@sink.test>: Recipient address rejected: User unknown in virtual mailbox table',
          smtpCode: 550,
        },
      ],
      originalTraces: [],
    });
  });

  it('returns the X-Gateway-Trace values of the undelivered message headers', async () => {
    const notice = await parseDsnNotice(
      Buffer.from(
        singleHardBounce('Q7', 'alice@acme.test', 'x@sink.test', [
          'X-Gateway-Trace: v=1; g=gw-local; d=out; t=1762077600;',
          '\ts=AAAAAAAAAAAAAAAAAAAAAA',
          'x-gateway-trace: v=1; g=gw-local; d=in; t=1; s=BBBBBBBBBBBBBBBBBBBBBB',
        ]),
      ),
    );
    expect(notice?.originalTraces).toEqual([
      'v=1; g=gw-local; d=out; t=1762077600; s=AAAAAAAAAAAAAAAAAAAAAA',
      'v=1; g=gw-local; d=in; t=1; s=BBBBBBBBBBBBBBBBBBBBBB',
    ]);
  });

  it('parses a multi-recipient notice with mixed results', async () => {
    const notice = await parseDsnNotice(
      Buffer.from(
        postfixPostmasterCopy({
          queueId: '4ZbMULTI1',
          sender: 'bob@acme.test',
          recipients: [
            {
              address: 'a@sink.test',
              action: 'failed',
              status: '5.2.1',
              remoteMta: 'mx.sink.test',
              diagnostic: 'smtp; 550 5.2.1 Mailbox disabled',
            },
            {
              address: 'b@sink.test',
              action: 'failed',
              status: '5.7.1',
              remoteMta: 'mx.sink.test',
              diagnostic: 'smtp; 550 5.7.1 Blocked',
            },
            {
              address: 'c@nowhere.test',
              action: 'failed',
              status: '5.4.4',
              diagnostic:
                'X-Postfix; Host or domain name not found. Name service error for name=nowhere.test type=MX: Host not found',
            },
          ],
        }),
      ),
    );
    expect(notice?.recipients.map((r) => [r.finalRecipient, r.status, r.smtpCode])).toEqual([
      ['a@sink.test', '5.2.1', 550],
      ['b@sink.test', '5.7.1', 550],
      ['c@nowhere.test', '5.4.4', null],
    ]);
    expect(notice?.recipients[2]?.diagnosticCode).toMatch(
      /^X-Postfix; Host or domain name not found/,
    );
  });

  it('parses a delay warning', async () => {
    const notice = await parseDsnNotice(
      Buffer.from(
        postfixPostmasterCopy({
          kind: 'delay',
          queueId: '4ZbDELAY1',
          sender: 'carol@acme.test',
          recipients: [
            {
              address: 'soft-bounce@sink.test',
              action: 'delayed',
              status: '4.2.1',
              remoteMta: 'mx.sink.test',
              diagnostic: 'smtp; 450 4.2.1 Mailbox busy',
            },
          ],
        }),
      ),
    );
    expect(notice?.recipients[0]).toMatchObject({
      action: 'delayed',
      status: '4.2.1',
      smtpCode: 450,
    });
  });

  it('falls back to the notice Date when Arrival-Date is missing', async () => {
    const notice = await parseDsnNotice(
      Buffer.from(
        postfixPostmasterCopy({
          queueId: 'Q1',
          sender: 'a@acme.test',
          arrivalDate: null,
          recipients: [{ address: 'x@sink.test', action: 'failed', status: '5.1.1' }],
        }),
      ),
    );
    expect(notice?.occurredAt).toEqual(new Date('2026-11-02T10:05:00.000Z'));
  });

  it('extracts Original-Envelope-Id (the reinjection token, xtext-decoded)', async () => {
    const token = `dw1-${'0195f3c17a2b7c3d8e4f5a6b7c8d9e0f'}`;
    const notice = await parseDsnNotice(
      Buffer.from(
        postfixPostmasterCopy({
          queueId: 'QENV1',
          sender: 'a@acme.test',
          envelopeId: token,
          recipients: [{ address: 'x@sink.test', action: 'failed', status: '5.1.1' }],
        }),
      ),
    );
    expect(notice?.envelopeId).toBe(token);
    const encoded = parseDeliveryStatus(
      'Original-Envelope-Id: a+2Bb+3Dc\nX-Postfix-Queue-ID: Q\n',
      null,
    );
    expect(encoded?.envelopeId).toBe('a+b=c');
    for (const bad of ['x+zz', 'x'.repeat(101), 'two words', '']) {
      const parsed = parseDeliveryStatus(
        `Original-Envelope-Id: ${bad}\nX-Postfix-Queue-ID: Q\n`,
        null,
      );
      expect(parsed?.envelopeId, bad).toBeNull();
    }
  });

  it('returns null for mail without a delivery-status part', async () => {
    await expect(
      parseDsnNotice(Buffer.from('From: a@b.test\r\nSubject: hi\r\n\r\nplain text\r\n')),
    ).resolves.toBeNull();
    await expect(parseDsnNotice(Buffer.from('garbage without headers'))).resolves.toBeNull();
  });

  it('reports a null sender (bounce of a bounce) as empty', async () => {
    const notice = await parseDsnNotice(
      Buffer.from(
        postfixPostmasterCopy({
          queueId: 'Q2',
          sender: '',
          recipients: [{ address: 'x@sink.test', action: 'failed', status: '5.1.1' }],
        }),
      ),
    );
    expect(notice?.sender).toBe('');
  });
});

describe('delivery-status helpers', () => {
  it('headerTraces reads only the header block and ignores look-alike fields', () => {
    expect(
      headerTraces(
        [
          'X-Gateway-Trace-Other: no',
          'X-Gateway-Trace : v=1; a',
          '  b',
          'Subject: x',
          '',
          'X-Gateway-Trace: in the body',
        ].join('\r\n'),
      ),
    ).toEqual(['v=1; a b']);
    expect(headerTraces('')).toEqual([]);
  });

  it('splits groups and unfolds continuation lines', () => {
    const groups = parseDeliveryStatusGroups(
      'Reporting-MTA: dns; x\r\n\r\nFinal-Recipient: rfc822; a@b\r\nDiagnostic-Code: smtp; 550\r\n  more\r\n\r\n\r\n',
    );
    expect(groups).toHaveLength(2);
    expect(groups[1]!.get('diagnostic-code')).toBe('smtp; 550 more');
  });

  it('skips recipient groups without Final-Recipient or Action and invalid statuses', () => {
    const notice = parseDeliveryStatus(
      'X-Postfix-Queue-ID: Q\n\nAction: failed\n\nFinal-Recipient: rfc822; a@b.test\nAction: Failed\nStatus: 5.1.1 (user unknown)\n\nFinal-Recipient: rfc822; c@d.test\nAction: failed\nStatus: bogus\n',
      null,
    );
    expect(notice?.recipients.map((r) => [r.finalRecipient, r.action, r.status])).toEqual([
      ['a@b.test', 'failed', '5.1.1'],
      ['c@d.test', 'failed', null],
    ]);
    expect(notice?.occurredAt).toBeNull();
    expect(parseDeliveryStatus('Final-Recipient: rfc822; a@b\n', null)).toBeNull();
  });

  it('typedValue and parseDsnDate', () => {
    expect(typedValue('rfc822; <A@B.test>')).toBe('A@B.test');
    expect(typedValue('dns;mx.example')).toBe('mx.example');
    expect(typedValue(undefined)).toBeNull();
    expect(parseDsnDate('Tue,  3 Nov 2026 01:02:03 +0530 (IST)')).toEqual(
      new Date('2026-11-02T19:32:03.000Z'),
    );
    expect(parseDsnDate('not a date')).toBeNull();
  });
});
