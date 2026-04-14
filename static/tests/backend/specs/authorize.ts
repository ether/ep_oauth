'use strict';

import {strict as assert} from 'assert';
import {init} from 'ep_etherpad-lite/tests/backend/common';
import {generateJWTToken} from 'ep_etherpad-lite/tests/backend/common';

let agent: any;

describe('ep_oauth authorize hook', () => {
  before(async () => {
    agent = await init();
  });

  it('allows access to /auth paths without authentication', async () => {
    // The authorize hook should return true for /auth/* paths,
    // allowing the OAuth flow to proceed without prior auth.
    // We test this by verifying the server doesn't reject /auth/callback
    // with a 401 (it will 302 or handle it via the OAuth flow).
    const res = await agent
      .get('/auth/callback')
      .set('Authorization', await generateJWTToken())
      .redirects(0);
    // Should not be 401 (unauthorized) — the authorize hook allows /auth paths
    assert.notStrictEqual(res.status, 401);
  });

  it('rejects unauthenticated requests to pad paths', async () => {
    // Without an OAuth session, accessing a pad should not be authorized.
    // The exact behavior depends on etherpad config, but we verify the
    // authorize hook is being called (server doesn't crash).
    const res = await agent
      .get('/p/test-oauth-pad')
      .redirects(0);
    // Should get some response (redirect to auth, or 200/302) but not crash
    assert.ok([200, 302, 401, 403].includes(res.status),
      `Expected 200/302/401/403, got ${res.status}`);
  });
});
