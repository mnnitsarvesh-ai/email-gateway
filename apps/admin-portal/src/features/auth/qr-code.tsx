'use client';

import QRCode from 'qrcode';
import { useMemo } from 'react';

/**
 * A QR code rendered locally as SVG elements (no network, no data URL, no innerHTML). Used for
 * the TOTP `otpauth://` URI, which must never leave the browser.
 */
export function QrCode({
  value,
  size = 176,
  label,
}: {
  value: string;
  size?: number;
  label: string;
}) {
  const path = useMemo(() => {
    const qr = QRCode.create(value, { errorCorrectionLevel: 'M' });
    const count = qr.modules.size;
    let d = '';
    for (let y = 0; y < count; y += 1) {
      for (let x = 0; x < count; x += 1) {
        if (qr.modules.get(y, x)) d += `M${x + 4},${y + 4}h1v1h-1z`;
      }
    }
    return { d, count: count + 8 };
  }, [value]);
  return (
    <svg
      role="img"
      aria-label={label}
      width={size}
      height={size}
      viewBox={`0 0 ${path.count} ${path.count}`}
      shapeRendering="crispEdges"
      className="rounded-md bg-white"
    >
      <rect width={path.count} height={path.count} fill="#ffffff" />
      <path d={path.d} fill="#000000" />
    </svg>
  );
}
