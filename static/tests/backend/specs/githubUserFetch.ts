'use strict';

// Covers the GitHub user lookup performed by the `/auth/callback` middleware.
// That lookup used to go through the deprecated `request` package; it now uses
// the global fetch built into Node, so this exercises the replacement: the
// access token is sent as an Authorization header (not a query parameter), a
// successful response is stored in the database keyed by session id, and a
// failing response is logged without writing anything or throwing.

import {strict as assert} from 'assert';
import {init} from 'ep_etherpad-lite/tests/backend/common';

const db = require('ep_etherpad-lite/node/db/DB');
const settings = require('ep_etherpad-lite/node/utils/Settings');
const {OAuth2} = require('oauth');

const ACCESS_TOKEN = 'gho_testtoken';

// Captures the middleware ep_oauth registers via `app.use()` so it can be
// driven directly, without standing up an HTTP listener.
const loadMiddleware = () => {
  delete require.cache[require.resolve('ep_oauth/auth')];
  const auth = require('ep_oauth/auth');
  let middleware: any = null;
  const app = {
    use: (fn: any) => { middleware = fn; },
    get: () => {},
  };
  auth.expressConfigure('expressConfigure', {app});
  assert.ok(middleware, 'ep_oauth did not register its /auth/callback middleware');
  return middleware;
};

const runCallback = async (middleware: any, sessionID: string) => {
  const req = {url: `/auth/callback?code=abc&state=${sessionID}`, query: {code: 'abc', state: sessionID}};
  await new Promise<void>((resolve) => middleware(req, {}, resolve));
  // The middleware calls next() without waiting for the lookup, so give the
  // fetch/db promise chain a turn to settle.
  await new Promise((resolve) => setTimeout(resolve, 100));
};

describe('ep_oauth GitHub user lookup', function () {
  let origSettings: any;
  let origFetch: any;
  let origGetToken: any;
  let fetchCalls: any[] = [];

  before(async function () {
    await init();
    origSettings = settings.ep_oauth;
    settings.ep_oauth = {
      clientID: 'test-client-id',
      clientSecret: 'test-client-secret',
      callbackURL: 'http://localhost/auth/callback',
    };
    origGetToken = OAuth2.prototype.getOAuthAccessToken;
    OAuth2.prototype.getOAuthAccessToken = function (code: string, params: any, cb: any) {
      cb(null, ACCESS_TOKEN, 'refresh', {});
    };
  });

  after(function () {
    settings.ep_oauth = origSettings;
    OAuth2.prototype.getOAuthAccessToken = origGetToken;
    delete require.cache[require.resolve('ep_oauth/auth')];
  });

  beforeEach(function () {
    fetchCalls = [];
    origFetch = globalThis.fetch;
  });

  afterEach(function () {
    globalThis.fetch = origFetch;
  });

  it('sends the access token as an Authorization header, not a query parameter', async function () {
    globalThis.fetch = (async (url: any, opts: any) => {
      fetchCalls.push({url, opts});
      return {ok: true, status: 200, json: async () => ({login: 'octocat', id: 583231})};
    }) as any;

    await runCallback(loadMiddleware(), 'session-header');

    assert.equal(fetchCalls.length, 1);
    const {url, opts} = fetchCalls[0];
    assert.equal(url, 'https://api.github.com/user');
    assert.equal(opts.headers.Authorization, `Bearer ${ACCESS_TOKEN}`);
    assert.ok(!String(url).includes('access_token'), `token leaked into the URL: ${url}`);
    assert.ok(opts.headers['User-Agent'], 'GitHub rejects requests without a User-Agent');
  });

  it('stores the user info against the session id on success', async function () {
    globalThis.fetch = (async () => ({
      ok: true,
      status: 200,
      json: async () => ({login: 'octocat', id: 583231}),
    })) as any;

    await runCallback(loadMiddleware(), 'session-success');

    const stored = await db.get('oauth:session-success');
    assert.ok(stored, 'nothing was written to the database');
    assert.equal(stored.access_token, ACCESS_TOKEN);
    assert.equal(stored.userInfo.login, 'octocat');
  });

  it('writes nothing when GitHub rejects the token', async function () {
    globalThis.fetch = (async () => ({
      ok: false,
      status: 401,
      text: async () => 'Bad credentials',
    })) as any;

    await runCallback(loadMiddleware(), 'session-failure');

    assert.ok(await db.get('oauth:session-failure') == null, 'a rejected token was stored');
  });

  it('writes nothing when the request itself fails', async function () {
    globalThis.fetch = (async () => { throw new Error('ECONNREFUSED'); }) as any;

    await runCallback(loadMiddleware(), 'session-error');

    assert.ok(await db.get('oauth:session-error') == null, 'a failed lookup was stored');
  });
});
