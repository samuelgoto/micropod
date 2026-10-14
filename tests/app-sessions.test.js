import 'dotenv/config';
import { jest } from '@jest/globals';
import http from 'http';
import axios from 'axios';
import app from '../src/server.js';
import { db, setUpForTesting, create } from '../src/db.js';
import { setUpRepo } from '../src/repo.js';
import { sequencer } from '../src/sequencer.js';
import { ACCESS_TOKEN_TTL_SECONDS, REFRESH_SCOPE } from '../src/app-sessions.js';
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));

const PORT = 3014;
const HOST = `http://localhost:${PORT}`;
const PASSWORD = 'app-session-pass';

const decode = (token) => JSON.parse(Buffer.from(token.split('.')[1], 'base64url').toString());
const bearer = (token) => ({ headers: { Authorization: `Bearer ${token}` }, validateStatus: () => true });

describe('Legacy app sessions (createSession / refreshSession / deleteSession)', () => {
  let server;
  let dbPath;

  const login = async () => {
    const res = await axios.post(`${HOST}/xrpc/com.atproto.server.createSession`, {
      identifier: 'localhost.test', password: PASSWORD,
    });
    return res.data;
  };
  const getSession = (token) => axios.get(`${HOST}/xrpc/com.atproto.server.getSession`, bearer(token));
  const refresh = (token) => axios.post(`${HOST}/xrpc/com.atproto.server.refreshSession`, null, bearer(token));
  const logout = (token) => axios.post(`${HOST}/xrpc/com.atproto.server.deleteSession`, null, bearer(token));

  beforeAll(async () => {
    jest.spyOn(console, 'log').mockImplementation(() => {});
    jest.spyOn(console, 'error').mockImplementation(() => {});
    process.env.PASSWORD = PASSWORD;
    process.env.HANDLE = 'localhost.test';
    dbPath = path.join(__dirname, `app-sessions-${Date.now()}.db`);
    await setUpForTesting(`file:${dbPath}`); await create(); await setUpRepo();
    server = http.createServer(app);
    await new Promise((resolve) => server.listen(PORT, resolve));
  });

  afterAll(async () => {
    sequencer.close();
    db.close();
    await new Promise((resolve) => server.close(resolve));
    for (const p of [dbPath, `${dbPath}-shm`, `${dbPath}-wal`]) {
      if (fs.existsSync(p)) fs.unlinkSync(p);
    }
  });

  test('createSession issues distinct short-lived access and long-lived refresh tokens', async () => {
    const session = await login();
    expect(session.accessJwt).not.toBe(session.refreshJwt);
    expect(session.didDoc?.id).toBe(session.did);
    expect(session.active).toBe(true);

    const access = decode(session.accessJwt);
    const refreshClaims = decode(session.refreshJwt);
    expect(access.exp - access.iat).toBe(ACCESS_TOKEN_TTL_SECONDS);
    expect(access.sid).toBeTruthy();
    expect(refreshClaims.scope).toBe(REFRESH_SCOPE);
    expect(refreshClaims.sid).toBe(access.sid);
    expect(refreshClaims.exp - refreshClaims.iat).toBeGreaterThan(30 * 24 * 3600);

    expect((await getSession(session.accessJwt)).status).toBe(200);
  });

  test('refresh tokens cannot be used as access tokens', async () => {
    const session = await login();
    expect((await getSession(session.refreshJwt)).status).toBe(401);
    const proxied = await axios.get(`${HOST}/xrpc/app.bsky.feed.getTimeline`, {
      headers: { Authorization: `Bearer ${session.refreshJwt}`, 'atproto-proxy': 'did:web:api.bsky.app#bsky_appview' },
      validateStatus: () => true,
    });
    expect(proxied.status).toBe(401);
  });

  test('access tokens cannot be used to refresh a session', async () => {
    const session = await login();
    expect((await refresh(session.accessJwt)).status).toBe(401);
  });

  test('refreshSession rotates the refresh token', async () => {
    const session = await login();
    const res = await refresh(session.refreshJwt);
    expect(res.status).toBe(200);
    expect(res.data.refreshJwt).not.toBe(session.refreshJwt);
    expect(decode(res.data.refreshJwt).sid).toBe(decode(session.refreshJwt).sid);
    expect((await getSession(res.data.accessJwt)).status).toBe(200);

    // The new refresh token works.
    const again = await refresh(res.data.refreshJwt);
    expect(again.status).toBe(200);
  });

  test('a just-rotated refresh token is still accepted briefly (concurrent refresh), then rejected', async () => {
    const session = await login();
    const first = await refresh(session.refreshJwt);
    expect(first.status).toBe(200);

    // e.g. another tab refreshing with the old token at the same time
    const concurrent = await refresh(session.refreshJwt);
    expect(concurrent.status).toBe(200);
    expect(concurrent.data.refreshJwt).toBe(first.data.refreshJwt);

    // After the grace window, the old token is dead.
    await db.execute({
      sql: 'UPDATE app_sessions SET prev_valid_until = ? WHERE sid = ?',
      args: [Math.floor(Date.now() / 1000) - 1, decode(session.refreshJwt).sid],
    });
    expect((await refresh(session.refreshJwt)).status).toBe(401);
    expect((await refresh(first.data.refreshJwt)).status).toBe(200);
  });

  test('deleteSession revokes both the refresh token and outstanding access tokens', async () => {
    const session = await login();
    expect((await getSession(session.accessJwt)).status).toBe(200);

    expect((await logout(session.accessJwt)).status).toBe(401); // needs the refresh token
    const res = await logout(session.refreshJwt);
    expect(res.status).toBe(200);

    expect((await getSession(session.accessJwt)).status).toBe(401);
    expect((await refresh(session.refreshJwt)).status).toBe(401);
  });

  test('deleting one session does not affect another', async () => {
    const a = await login();
    const b = await login();
    expect((await logout(a.refreshJwt)).status).toBe(200);
    expect((await getSession(b.accessJwt)).status).toBe(200);
    expect((await refresh(b.refreshJwt)).status).toBe(200);
  });

  test('works end-to-end with the official @atproto/api client (as used by bsky.app)', async () => {
    const { AtpAgent } = await import('@atproto/api');
    const agent = new AtpAgent({ service: HOST });
    await agent.login({ identifier: 'localhost.test', password: PASSWORD });
    const firstRefresh = agent.session.refreshJwt;

    // Force an expired access token so the client must refresh transparently.
    agent.sessionManager.session = { ...agent.session, accessJwt: 'expired.invalid.token' };
    await agent.sessionManager.refreshSession();
    expect(agent.session.refreshJwt).not.toBe(firstRefresh);
    const me = await agent.com.atproto.server.getSession();
    expect(me.data.did).toBe(process.env.PDS_DID.trim());

    // Resuming a stored session (app reload) works.
    const stored = { ...agent.session };
    const resumed = new AtpAgent({ service: HOST });
    await resumed.resumeSession(stored);
    expect(resumed.session?.did).toBe(stored.did);

    // Logging out revokes the stored access token.
    const accessBeforeLogout = resumed.session.accessJwt;
    await resumed.logout();
    expect((await getSession(accessBeforeLogout)).status).toBe(401);
  });
});
