/**
 * Chromium flags of the isolated browser (step 4.3 U15). The proxy itself is passed through
 * Playwright's `proxy` launch option (which adds `--proxy-server` and forces loopback through the
 * proxy with `<-loopback>`); these flags make the proxy the ONLY network path: no direct DNS
 * (every name except the proxy's maps to NOTFOUND), no QUIC, no non-proxied WebRTC UDP, no
 * background/component/sync traffic.
 */
export function chromiumArgs(proxyHost: string): string[] {
  if (!/^[A-Za-z0-9.-]{1,253}$|^\[[0-9a-fA-F:.]+\]$/.test(proxyHost))
    throw new Error('invalid proxy host');
  return [
    `--host-resolver-rules=MAP * ~NOTFOUND , EXCLUDE ${proxyHost}`,
    '--disable-quic',
    '--force-webrtc-ip-handling-policy=disable_non_proxied_udp',
    '--disable-background-networking',
    '--disable-component-update',
    '--disable-sync',
    '--no-first-run',
    '--disable-dev-shm-usage',
    '--disable-domain-reliability',
    '--disable-breakpad',
    '--no-pings',
  ];
}

/** Browser context options of every job (U15): incognito, no downloads, no service workers. */
export const CONTEXT_OPTIONS = {
  acceptDownloads: false,
  serviceWorkers: 'block',
  permissions: [] as string[],
  ignoreHTTPSErrors: false,
  javaScriptEnabled: true,
  viewport: { width: 1280, height: 800 },
  locale: 'en-US',
} as const;
