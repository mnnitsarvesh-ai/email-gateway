import { describe, expect, it } from 'vitest';
import {
  DATABASE_SOCKET_TIMEOUT_ENV,
  databaseClientUrl,
  socketTimeoutFromEnv,
  transactionOutlastsSocket,
} from './client-url';

const URL_WITH_SECRET =
  'mysql://app:NeverLogThis@db.internal:3306/email_gateway?connection_limit=5';

describe('databaseClientUrl', () => {
  it('leaves the URL unchanged without a socket timeout (the default)', () => {
    expect(databaseClientUrl(URL_WITH_SECRET)).toBe(URL_WITH_SECRET);
    expect(databaseClientUrl(URL_WITH_SECRET, { socketTimeoutSeconds: 0 })).toBe(URL_WITH_SECRET);
  });

  it('adds socket_timeout and keeps the other parameters', () => {
    const out = new URL(databaseClientUrl(URL_WITH_SECRET, { socketTimeoutSeconds: 30 }));
    expect(out.searchParams.get('socket_timeout')).toBe('30');
    expect(out.searchParams.get('connection_limit')).toBe('5');
    expect(out.username).toBe('app');
    expect(out.host).toBe('db.internal:3306');
    expect(out.pathname).toBe('/email_gateway');
  });

  it('replaces a socket_timeout already in the URL', () => {
    const out = databaseClientUrl(`${URL_WITH_SECRET}&socket_timeout=5`, {
      socketTimeoutSeconds: 12,
    });
    expect(new URL(out).searchParams.getAll('socket_timeout')).toEqual(['12']);
  });

  it.each([-1, 1.5, 3601, Number.NaN])('refuses socketTimeoutSeconds %s', (value) => {
    expect(() => databaseClientUrl(URL_WITH_SECRET, { socketTimeoutSeconds: value })).toThrow(
      RangeError,
    );
  });

  it('never puts the URL into an error', () => {
    let message = '';
    try {
      databaseClientUrl('not a url NeverLogThis', { socketTimeoutSeconds: 3 });
    } catch (error) {
      message = (error as Error).message;
    }
    expect(message).toBe('The database URL is not a valid URL');
  });
});

describe('socketTimeoutFromEnv', () => {
  it('defaults to 0 when unset or empty', () => {
    expect(socketTimeoutFromEnv({})).toBe(0);
    expect(socketTimeoutFromEnv({ [DATABASE_SOCKET_TIMEOUT_ENV]: ' ' })).toBe(0);
  });

  it('reads an integer number of seconds', () => {
    expect(socketTimeoutFromEnv({ [DATABASE_SOCKET_TIMEOUT_ENV]: '45' })).toBe(45);
  });

  it.each(['-1', '2.5', '30s', '3601'])('refuses %s, naming the key', (value) => {
    expect(() => socketTimeoutFromEnv({ [DATABASE_SOCKET_TIMEOUT_ENV]: value })).toThrow(
      DATABASE_SOCKET_TIMEOUT_ENV,
    );
  });
});

describe('transactionOutlastsSocket', () => {
  it('holds without a socket timeout', () => {
    expect(transactionOutlastsSocket(1, 0)).toBe(true);
  });

  it('requires the transaction timeout to be longer than the socket timeout', () => {
    expect(transactionOutlastsSocket(30_001, 30)).toBe(true);
    expect(transactionOutlastsSocket(30_000, 30)).toBe(false);
  });
});
