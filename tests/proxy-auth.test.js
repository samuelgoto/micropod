import 'dotenv/config';
import { jest } from '@jest/globals';
import http from 'http';
import axios from 'axios';
import nock from 'nock';
import app from '../src/server.js';
import { db, setUpForTesting, create } from '../src/db.js';
import { setUpRepo } from '../src/repo.js';
import { sequencer } from '../src/sequencer.js';
import { createServiceAuthToken } from '../src/auth.js';
import { createIdToken, createAccessToken } from '../src/oauth.js';
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));

const PORT = 3012;
const PDS_URL = `http://localhost:${PORT}`;
const APPVIEW_DID = 'did:web:appview.test';
const APPVIEW_URL = 'https://appview.test';
const PROXY_HEADER = `${APPVIEW_DID}#bsky_appview`;

const decodeJwt = (token) => JSON.parse(Buffer.from(token.split('.')[1], 'base64url').toString());

describe('XRPC proxy authentication', () => {
  let server;
  let dbPath;
  let userDid;
  let sessionToken;

  const proxiedGet = (headers = {}) => axios.get(`${PDS_URL}/xrpc/app.bsky.feed.getTimeline?limit=1`, {
    headers: { 'atproto-proxy': PROXY_HEADER, ...headers },
    validateStatus: () => true,
  });

  beforeAll(async () => {
    jest.spyOn(console, 'log').mockImplementation(() => {});
    jest.spyOn(console, 'error').mockImplementation(() => {});
    jest.spyOn(console, 'warn').mockImplementation(() => {});
    process.env.PASSWORD = 'proxy-auth-pass';
    process.env.HANDLE = 'localhost.test';
    dbPath = path.join(__dirname, `proxy-auth-${Date.now()}.db`);

    await setUpForTesting(`file:${dbPath}`); await create(); await setUpRepo();
    userDid = process.env.PDS_DID.trim();

    server = http.createServer(app);
    await new Promise((resolve) => server.listen(PORT, resolve));

    const login = await axios.post(`${PDS_URL}/xrpc/com.atproto.server.createSession`, {
      identifier: 'localhost.test',
      password: process.env.PASSWORD,
    });
    sessionToken = login.data.accessJwt;

    // The AppView's DID document (resolved once, then cached by the proxy).
    nock(APPVIEW_URL)
      .persist()
      .get('/.well-known/did.json')
      .reply(200, {
        id: APPVIEW_DID,
        service: [{ id: '#bsky_appview', type: 'BskyAppView', serviceEndpoint: APPVIEW_URL }],
      });
  });

  afterEach(() => {
    // Only clear per-test upstream interceptors, keep the persisted did.json one.
    nock.abortPendingRequests();
  });

  afterAll(async () => {
    nock.cleanAll();
    sequencer.close();
    db.close();
    await new Promise((resolve) => server.close(resolve));
    for (const p of [dbPath, `${dbPath}-shm`, `${dbPath}-wal`]) {
      if (fs.existsSync(p)) fs.unlinkSync(p);
    }
  });

  const expectUpstreamNotCalled = () => {
    const upstream = nock(APPVIEW_URL).get('/xrpc/app.bsky.feed.getTimeline').query(true).reply(200, { feed: [] });
    return () => {
      expect(upstream.isDone()).toBe(false);
      nock.removeInterceptor(upstream.interceptors[0]);
    };
  };

  test('rejects proxied requests without an Authorization header', async () => {
    const check = expectUpstreamNotCalled();
    const res = await proxiedGet();
    expect(res.status).toBe(401);
    check();
  });

  test('rejects proxied requests with an invalid token', async () => {
    const check = expectUpstreamNotCalled();
    const res = await proxiedGet({ Authorization: 'Bearer not.a.jwt' });
    expect(res.status).toBe(401);
    check();
  });

  test('rejects outbound service-auth tokens replayed as bearer tokens', async () => {
    const serviceToken = await createServiceAuthToken(PROXY_HEADER, 'app.bsky.feed.getTimeline', userDid);
    const check = expectUpstreamNotCalled();
    const res = await proxiedGet({ Authorization: `Bearer ${serviceToken}` });
    expect(res.status).toBe(401);
    check();

    const refresh = await axios.post(`${PDS_URL}/xrpc/com.atproto.server.refreshSession`, null, {
      headers: { Authorization: `Bearer ${serviceToken}` },
      validateStatus: () => true,
    });
    expect(refresh.status).toBe(401);
  });

  test('rejects OIDC id_tokens used as bearer tokens', async () => {
    const idToken = await createIdToken(userDid, 'localhost.test', 'https://client.example/metadata.json', PDS_URL);
    const check = expectUpstreamNotCalled();
    const res = await proxiedGet({ Authorization: `Bearer ${idToken}` });
    expect(res.status).toBe(401);
    check();

    const refresh = await axios.post(`${PDS_URL}/xrpc/com.atproto.server.refreshSession`, null, {
      headers: { Authorization: `Bearer ${idToken}` },
      validateStatus: () => true,
    });
    expect(refresh.status).toBe(401);
  });

  test('rejects DPoP-bound OAuth access tokens used as plain bearer tokens', async () => {
    const accessToken = await createAccessToken(userDid, 'localhost.test', 'some-jkt', PDS_URL, 'https://client.example/metadata.json', 'atproto');
    const check = expectUpstreamNotCalled();
    const res = await proxiedGet({ Authorization: `Bearer ${accessToken}` });
    expect(res.status).toBe(401);
    check();
  });

  test('proxies authenticated requests with a service-auth token for the account', async () => {
    let upstreamAuth;
    const upstream = nock(APPVIEW_URL)
      .get('/xrpc/app.bsky.feed.getTimeline')
      .query({ limit: '1' })
      .reply(function () {
        upstreamAuth = this.req.headers.authorization;
        return [200, { feed: [] }, { 'Access-Control-Allow-Origin': '*', 'Content-Type': 'application/json' }];
      });

    const res = await proxiedGet({ Authorization: `Bearer ${sessionToken}`, Origin: 'https://bsky.app' });
    expect(res.status).toBe(200);
    expect(res.data).toEqual({ feed: [] });
    expect(upstream.isDone()).toBe(true);

    // Our CORS headers must win over the upstream's.
    expect(res.headers['access-control-allow-origin']).toBe('https://bsky.app');

    const claims = decodeJwt(upstreamAuth.replace(/^Bearer /, ''));
    expect(claims.iss).toBe(userDid);
    expect(claims.sub).toBe(userDid);
    expect(claims.aud).toBe(APPVIEW_DID);
    expect(claims.lxm).toBe('app.bsky.feed.getTimeline');
  });

  test('requests without atproto-proxy still fall through to the 404 handler', async () => {
    const res = await axios.get(`${PDS_URL}/xrpc/app.bsky.feed.getTimeline`, { validateStatus: () => true });
    expect(res.status).toBe(404);
    expect(res.data.error).toBe('MethodNotFound');
  });
});
