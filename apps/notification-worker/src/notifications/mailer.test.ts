import { describe, expect, it } from 'vitest';
import { createTransport } from 'nodemailer';
import { createNoticeMailer, noticeMessageOptions, relayTransportOptions } from './mailer';

const base = {
  NOTIFY_SMTP_HOST: 'relay.example',
  NOTIFY_SMTP_PORT: 587,
  NOTIFY_SMTP_SECURE: 'starttls' as const,
  NOTIFY_SMTP_USER: undefined,
  NOTIFY_SMTP_PASSWORD: undefined,
  NOTIFY_SMTP_CA_PATH: undefined,
};

describe('relay transport (same options as the api SmtpEmailSender)', () => {
  it('requires STARTTLS, verifies certificates and disables file and URL access', () => {
    const o = relayTransportOptions(base);
    expect(o).toMatchObject({
      host: 'relay.example',
      port: 587,
      secure: false,
      requireTLS: true,
      ignoreTLS: false,
      disableFileAccess: true,
      disableUrlAccess: true,
      tls: { rejectUnauthorized: true, minVersion: 'TLSv1.2', servername: 'relay.example' },
    });
    expect(o.auth).toBeUndefined();
    expect(relayTransportOptions({ ...base, NOTIFY_SMTP_SECURE: 'tls' })).toMatchObject({
      secure: true,
    });
    expect(relayTransportOptions({ ...base, NOTIFY_SMTP_SECURE: 'none' })).toMatchObject({
      ignoreTLS: true,
      requireTLS: false,
    });
    expect(
      relayTransportOptions({ ...base, NOTIFY_SMTP_USER: 'u', NOTIFY_SMTP_PASSWORD: 'p' }).auth,
    ).toEqual({ user: 'u', pass: 'p' });
  });

  it('is disabled without NOTIFY_SMTP_HOST', () => {
    const mailer = createNoticeMailer({
      NOTIFY_SMTP_PORT: 25,
      NOTIFY_SMTP_SECURE: 'none',
      NOTIFY_SMTP_FROM: undefined,
    });
    expect(mailer.configured).toBe(false);
    expect(mailer.from).toBeNull();
    const smtp = createNoticeMailer({ ...base, NOTIFY_SMTP_FROM: 'no-reply@gw.example' });
    expect(smtp.configured).toBe(true);
    smtp.close();
  });
});

describe('notice message options (step AI-R D8)', () => {
  const FROM = 'Email Gateway <no-reply@gw.example>';
  const HEADERS = { 'Auto-Submitted': 'auto-generated', 'X-Auto-Response-Suppress': 'All' };

  it('keeps existing notices unchanged: Bcc only, plain text, no To, no HTML, no attachment', () => {
    expect(
      noticeMessageOptions(FROM, {
        recipients: ['a@acme.example', 'b@acme.example'],
        subject: 'S',
        text: 'T',
        messageId: '<policy-notice.1@gw.example>',
      }),
    ).toEqual({
      from: FROM,
      bcc: ['a@acme.example', 'b@acme.example'],
      subject: 'S',
      text: 'T',
      messageId: '<policy-notice.1@gw.example>',
      headers: HEADERS,
      disableFileAccess: true,
      disableUrlAccess: true,
    });
  });

  it('addresses one To recipient without Bcc and carries the HTML part and Buffer attachments', () => {
    const content = Buffer.from('<!doctype html><p>r</p>', 'utf8');
    const o = noticeMessageOptions(FROM, {
      recipients: ['ignored@acme.example'],
      to: 'owner@acme.example',
      subject: 'Security report',
      text: 'T',
      html: content.toString('utf8'),
      attachments: [
        { filename: 'security-report-2026-11-23.html', content, contentType: 'text/html' },
      ],
      messageId: '<assistant-report.x@gw.example>',
    });
    expect(o.to).toBe('owner@acme.example');
    expect(o).not.toHaveProperty('bcc');
    expect(o.html).toEqual({
      content: '<!doctype html><p>r</p>',
      contentTransferEncoding: 'base64',
    });
    expect(o.attachments).toEqual([
      {
        filename: 'security-report-2026-11-23.html',
        content,
        contentType: 'text/html',
        contentDisposition: 'attachment',
      },
    ]);
    expect(o).toMatchObject({ headers: HEADERS, disableFileAccess: true, disableUrlAccess: true });
  });

  it('builds one multipart message with the To header, no Bcc and no file or URL access', async () => {
    const transport = createTransport({ streamTransport: true, buffer: true, newline: 'unix' });
    const content = Buffer.from(
      '<p>caf\u00e9</p>\n.dot line\r\n' + 'x'.repeat(2000) + '\n',
      'utf8',
    );
    const info = await transport.sendMail(
      noticeMessageOptions(FROM, {
        recipients: [],
        to: 'owner@acme.example',
        subject: 'Security report',
        text: 'plain',
        html: content.toString('utf8'),
        attachments: [{ filename: 'r.html', content, contentType: 'text/html; charset=utf-8' }],
        messageId: '<assistant-report.x@gw.example>',
      }),
    );
    expect(info.envelope.to).toEqual(['owner@acme.example']);
    const raw = (info.message as Buffer).toString('utf8');
    expect(raw).toMatch(/^To: owner@acme\.example$/m);
    expect(raw).not.toMatch(/^Bcc:/m);
    expect(raw).toMatch(/^Content-Type: multipart\/mixed/m);
    expect(raw).toMatch(/^Content-Type: multipart\/alternative/m);
    expect(raw).toContain('Content-Disposition: attachment; filename=r.html');
    expect(raw).toMatch(/^Auto-Submitted: auto-generated$/m);
    // The HTML alternative is base64 and decodes to exactly the given bytes (line ends kept).
    const htmlPart =
      /Content-Type: text\/html; charset=utf-8\nContent-Transfer-Encoding: base64\n\n([A-Za-z0-9+/=\n]+)/.exec(
        raw,
      );
    expect(htmlPart).not.toBeNull();
    expect(Buffer.from(htmlPart![1]!.replace(/\n/g, ''), 'base64').equals(content)).toBe(true);
    // A path or URL given as content would be refused (file and URL access stay off).
    await expect(
      transport.sendMail({
        ...noticeMessageOptions(FROM, {
          recipients: [],
          to: 'o@acme.example',
          subject: 's',
          text: 't',
          messageId: '<m@gw.example>',
        }),
        attachments: [{ filename: 'x', path: '/etc/hosts' }],
      }),
    ).rejects.toThrow();
  });
});
