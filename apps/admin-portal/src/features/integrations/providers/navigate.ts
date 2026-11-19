/**
 * Leaves the portal for Microsoft's admin-consent page in the same tab (D3, §6). The consent URL
 * comes from the api (built from configuration, never from user input) and carries the single-use
 * state, so it is used once and never stored. A separate module so tests can replace it.
 */
export function openConsentUrl(url: string): void {
  window.location.assign(url);
}

/** Scrubs the query string of the current page from the address bar and its history entry. */
export function scrubQueryString(): void {
  const { pathname, hash } = window.location;
  window.history.replaceState(window.history.state, '', `${pathname}${hash}`);
}
