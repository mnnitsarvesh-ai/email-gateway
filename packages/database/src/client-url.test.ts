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

describe('databaseClientUrl pool options (step AI-4 D14)', () => {
  it('sets connection_limit and pool_timeout and keeps the other parameters', () => {
    const out = new URL(
      databaseClientUrl('mysql://app:NeverLogThis@db.internal:3306/email_gateway?a=1', {
        connectionLimit: 32,
        poolTimeoutSeconds: 30,
      }),
    );
    expect(out.searchParams.get('connection_limit')).toBe('32');
    expect(out.searchParams.get('pool_timeout')).toBe('30');
    expect(out.searchParams.get('a')).toBe('1');
    expect(out.searchParams.has('socket_timeout')).toBe(false);
    expect(out.username).toBe('app');
    expect(out.pathname).toBe('/email_gateway');
  });

  it('lets the option win over a value already in the URL', () => {
    const out = new URL(
      databaseClientUrl(`${URL_WITH_SECRET}&pool_timeout=5`, {
        connectionLimit: 40,
        poolTimeoutSeconds: 60,
      }),
    );
    expect(out.searchParams.getAll('connection_limit')).toEqual(['40']);
    expect(out.searchParams.getAll('pool_timeout')).toEqual(['60']);
  });

  it('keeps the URL values when only one option is given', () => {
    const out = new URL(databaseClientUrl(URL_WITH_SECRET, { poolTimeoutSeconds: 20 }));
    expect(out.searchParams.get('connection_limit')).toBe('5');
    expect(out.searchParams.get('pool_timeout')).toBe('20');
  });

  it('combines with a socket timeout', () => {
    const out = new URL(
      databaseClientUrl(URL_WITH_SECRET, { socketTimeoutSeconds: 9, connectionLimit: 7 }),
    );
    expect(out.searchParams.get('socket_timeout')).toBe('9');
    expect(out.searchParams.get('connection_limit')).toBe('7');
  });

  it.each([0, -1, 2.5, 501, Number.NaN])('refuses connectionLimit %s', (value) => {
    expect(() => databaseClientUrl(URL_WITH_SECRET, { connectionLimit: value })).toThrow(
      /connectionLimit must be an integer from 1 to 500/,
    );
  });

  it.each([0, -1, 1.5, 601, Number.NaN])('refuses poolTimeoutSeconds %s', (value) => {
    expect(() => databaseClientUrl(URL_WITH_SECRET, { poolTimeoutSeconds: value })).toThrow(
      /poolTimeoutSeconds must be an integer from 1 to 600/,
    );
  });

  it('never puts the URL into an error', () => {
    for (const options of [
      { connectionLimit: 3 },
      { poolTimeoutSeconds: 3 },
      { connectionLimit: 0 },
    ]) {
      let message = '';
      try {
        databaseClientUrl('not a url NeverLogThis', options);
      } catch (error) {
        message = (error as Error).message;
      }
      expect(message).not.toContain('NeverLogThis');
      expect(message).not.toBe('');
    }
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
