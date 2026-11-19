import { describe, expect, it } from 'vitest';
import { buildIncidentReport, maskAddress } from './report';
import { buildIncidentEventRow, buildIncidentRow } from './testing';

describe('maskAddress (ADR-0062 rule)', () => {
  it('keeps the first code point and the domain', () => {
    expect(maskAddress('john@example.com')).toBe('j***@example.com');
    expect(maskAddress('élise@exämple.com')).toBe('é***@exämple.com');
    expect(maskAddress('"a@b"@example.com')).toBe('"***@example.com');
    expect(maskAddress('nope')).toBe('***');
  });
});

describe('buildIncidentReport', () => {
  it('assembles summary, timeline, notes, resolution and sections', () => {
    const incident = buildIncidentRow({
      status: 'resolved',
      resolutionCode: 'remediated',
      resolutionNote: 'Password reset and sessions revoked.',
      resolvedAt: new Date('2026-11-18T12:00:00.000Z'),
    });
    const report = buildIncidentReport({
      incident,
      events: [
        buildIncidentEventRow(),
        buildIncidentEventRow({ eventType: 'note_added', note: 'Called the user.' }),
      ],
      evidence: { ato_signal: 3 },
      messages: [],
      sections: [{ id: 'ato', title: 'ATO', data: {} }],
      truncated: false,
      generatedAt: new Date('2026-11-18T13:00:00.000Z'),
    });
    expect(report.version).toBe('security-incident-report/1');
    expect(report.incident.id).toBe(incident.publicId);
    expect(report.resolution).toEqual({
      code: 'remediated',
      note: 'Password reset and sessions revoked.',
    });
    expect(report.timeline).toHaveLength(2);
    expect(report.notes).toEqual([
      expect.objectContaining({ note: 'Called the user.', actorType: 'system' }),
    ]);
    expect(report.evidence).toEqual({ ato_signal: 3 });
    expect(report.sections[0]?.id).toBe('ato');
  });

  it('has no resolution while active', () => {
    const report = buildIncidentReport({
      incident: buildIncidentRow(),
      events: [],
      evidence: {},
      messages: [],
      sections: [],
      truncated: true,
      generatedAt: new Date(),
    });
    expect(report.resolution).toBeNull();
    expect(report.truncated).toBe(true);
  });
});
